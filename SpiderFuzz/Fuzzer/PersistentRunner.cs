using System.Diagnostics;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Unicode;

namespace SpiderFuzz.Fuzzer;

/// <summary>
/// High-performance persistent runner that keeps a js.exe process alive and communicates
/// via redirected standard input/output pipes with JSON serialization and newGlobal realm isolation.
/// Avoids spawning cmd.exe processes, avoids disk churn, and prevents worker collisions.
/// </summary>
internal sealed class PersistentRunner : IDisposable
{
    private readonly string _jsExePath;
    private readonly int _timeoutMs;
    private readonly bool _useAsan;
    private readonly string _workDir;
    private readonly string _driverPath;
    private readonly string[] _extraArgs;

    private Process? _process;
    private StreamWriter? _processStdin;
    private StreamReader? _processStdout;
    private readonly object _lock = new();
    private bool _disposed;
    private int _inputsSinceRestart;
    private string _stderrTail = "";

    // Lower than before: even with per-iteration realm cleanup + periodic gc()
    // in the driver, native allocations that the JS GC cannot reclaim slowly
    // accumulate. Recycling the process bounds that growth and keeps eps flat.
    private const int InputsBeforeRestart = 3000;

    // SpiderMonkey shell's readline() is byte-oriented on stdin. Keep the
    // transport ASCII-only so UTF-8 input cannot be decoded as mojibake before
    // JSON.parse() reconstructs the original JavaScript string.
    private static readonly JsonSerializerOptions TransportJsonOptions = new()
    {
        Encoder = JavaScriptEncoder.Create(UnicodeRanges.BasicLatin),
    };

    // Encoding.UTF8's preamble (the 3-byte BOM) gets written by the
    // StreamWriter/StreamReader ProcessStartInfo creates internally on their
    // very FIRST read/write - once per process (i.e. once per restart, since
    // _processStdin/_processStdout are recreated every restart). On the read
    // side StreamReader auto-strips a leading BOM, but on the WRITE side
    // nothing strips it: the driver's very first readline() would see
    // "\uFEFF" + json glued onto the same line, which JSON.parse rejects as
    // "unexpected character at line 1 column 1" - silently corrupting exactly
    // the first input after every single restart (every ~3000 inputs) into a
    // bogus SyntaxError instead of its real result. A BOM-less UTF8Encoding
    // avoids the preamble on all three streams.
    private static readonly UTF8Encoding NoBomUtf8 = new(encoderShouldEmitUTF8Identifier: false);

    public int RestartCount { get; private set; }
    public long TotalInputs { get; private set; }

    public PersistentRunner(string jsExePath, int timeoutMs = 5000, bool useAsan = true, int workerId = 0, string[]? extraArgs = null)
    {
        _jsExePath = Path.GetFullPath(jsExePath);
        _timeoutMs = timeoutMs;
        _useAsan = useAsan;
        _extraArgs = extraArgs ?? [];
        _workDir = Path.GetFullPath(Path.Combine(Path.GetTempPath(), $"spiderfuzz_persist_{workerId}_{Environment.ProcessId}"));
        Directory.CreateDirectory(_workDir);
        _driverPath = Path.Combine(_workDir, "driver.js");

        if (!File.Exists(_jsExePath))
            throw new FileNotFoundException($"js.exe not found at {_jsExePath}");

        WriteDriver();
    }

    public RunResult Run(string jsCode)
    {
        lock (_lock)
        {
            TotalInputs++;

            if (_process == null || _process.HasExited || _inputsSinceRestart >= InputsBeforeRestart)
            {
                if (TryRestartProcess() is RunResult restartCrash)
                    return restartCrash;
            }

            string jsonLine;
            try
            {
                jsonLine = JsonSerializer.Serialize(jsCode, TransportJsonOptions);
            }
            catch (Exception ex)
            {
                return new RunResult { Status = RunStatus.Error, ErrorMessage = ex.Message };
            }

            try
            {
                _processStdin!.WriteLine(jsonLine);
                _processStdin.Flush();
            }
            catch
            {
                var crash = BuildCrashResult();
                KillProcess();
                return crash;
            }

            var stdoutBuilder = new StringBuilder();
            var sw = Stopwatch.StartNew();
            string? marker = null;

            while (sw.ElapsedMilliseconds < _timeoutMs)
            {
                if (_process == null || _process.HasExited)
                {
                    var crash = BuildCrashResult();
                    KillProcess();
                    return crash;
                }

                var readTask = _processStdout!.ReadLineAsync();
                var remainingMs = Math.Max(1, _timeoutMs - (int)sw.ElapsedMilliseconds);
                if (readTask.Wait(remainingMs))
                {
                    var line = readTask.Result;
                    if (line == null)
                    {
                        var crash = BuildCrashResult();
                        KillProcess();
                        return crash;
                    }

                    if (line.StartsWith("__SF_DONE__:", StringComparison.Ordinal))
                    {
                        marker = line["__SF_DONE__:".Length..].Trim();
                        break;
                    }

                    stdoutBuilder.AppendLine(line);
                }
                else
                {
                    break;
                }
            }

            if (marker == null)
            {
                var hangResult = new RunResult
                {
                    Status = RunStatus.Timeout,
                    TimedOut = true,
                    CodeLength = Encoding.UTF8.GetByteCount(jsCode),
                    Stdout = stdoutBuilder.ToString(),
                    Stderr = _stderrTail,
                };
                KillProcess();
                return hangResult;
            }

            _inputsSinceRestart++;

            // marker is either "OK" or "JERR:<ErrorName>:<url-encoded message>".
            // The driver runs each input in its own realm and catches JS
            // exceptions, so a thrown error never reaches process stderr.
            // Surface both the error class name AND its message here: many
            // seeds/custom mutators throw a plain `new Error('some distinct
            // regression signature')` as an in-band oracle, and without the
            // message every single one of those collapses into the exact same
            // "JERR:Error" signal, so only the very first oracle failure ever
            // seen would ever count as new coverage while every later, actually
            // different regression gets silently discarded as "already seen".
            var isJsError = marker.StartsWith("JERR", StringComparison.Ordinal);
            var jsErrorName = "Error";
            var jsErrorMessage = "";

            if (isJsError)
            {
                var rest = marker.Length > 5 ? marker[5..] : "";
                var sepIdx = rest.IndexOf(':');
                if (sepIdx >= 0)
                {
                    jsErrorName = rest[..sepIdx];
                    var encoded = rest[(sepIdx + 1)..];
                    try { jsErrorMessage = Uri.UnescapeDataString(encoded); } catch { jsErrorMessage = encoded; }
                }
                else if (rest.Length > 0)
                {
                    jsErrorName = rest;
                }

                if (string.IsNullOrWhiteSpace(jsErrorName)) jsErrorName = "Error";
            }

            // A plain `new Error(...)` (not one of the built-in TypeError/
            // RangeError/... subclasses) is exactly the pattern our own seeds
            // and structured mutators use to flag a semantic engine
            // regression, so surface it as a distinct finding for the user.
            var isSemanticFinding = isJsError && jsErrorName == "Error" && !string.IsNullOrEmpty(jsErrorMessage);
            var stderrText = isJsError
                ? "JS-ERROR: " + jsErrorName + (jsErrorMessage.Length > 0 ? ": " + jsErrorMessage : "")
                : _stderrTail;

            return new RunResult
            {
                Status = isJsError ? RunStatus.NonZeroExit : RunStatus.Ok,
                ExitCode = isJsError ? 1 : 0,
                CodeLength = Encoding.UTF8.GetByteCount(jsCode),
                Stdout = stdoutBuilder.ToString(),
                Stderr = stderrText,
                IsSemanticFinding = isSemanticFinding,
                AssertionMessage = isSemanticFinding ? jsErrorMessage : null,
            };
        }
    }

    private RunResult BuildCrashResult()
    {
        var exitCode = 0;
        try { exitCode = _process?.ExitCode ?? 0; } catch { }

        Thread.Sleep(50);

        var isCrash = ProcessRunner.IsCrash(exitCode, _stderrTail);
        return new RunResult
        {
            Status = isCrash ? RunStatus.Crash : (exitCode != 0 ? RunStatus.NonZeroExit : RunStatus.Ok),
            ExitCode = exitCode,
            CodeLength = 0,
            CrashType = isCrash ? ProcessRunner.ClassifyCrash(exitCode, _stderrTail) : null,
            Stderr = _stderrTail,
        };
    }

    private RunResult? TryRestartProcess()
    {
        KillProcess();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = _jsExePath,
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardInputEncoding = NoBomUtf8,
                StandardOutputEncoding = NoBomUtf8,
                StandardErrorEncoding = NoBomUtf8,
                WorkingDirectory = _workDir,
            };
            foreach (var arg in _extraArgs) psi.ArgumentList.Add(arg);
            psi.ArgumentList.Add(_driverPath);

            var binDir = Path.GetDirectoryName(_jsExePath)!;
            var currentPath = Environment.GetEnvironmentVariable("PATH");
            psi.EnvironmentVariables["PATH"] = string.IsNullOrEmpty(currentPath)
                ? binDir
                : binDir + Path.PathSeparator + currentPath;

            if (_useAsan)
            {
                psi.EnvironmentVariables["ASAN_OPTIONS"] =
                    "detect_leaks=0:abort_on_error=1:print_stacktrace=1:symbolize=1:handle_abort=1:handle_sigfpe=1:handle_sigill=1:handle_sigbus=1:handle_sigsegv=1:detect_invalid_pointer_pairs=2";
                psi.EnvironmentVariables["MOZ_CRASHREPORTER_DISABLE"] = "1";
                psi.EnvironmentVariables["MOZ_DISABLE_NONLOCAL_CONNECTIONS"] = "1";
            }

            _process = Process.Start(psi);
            if (_process == null)
                throw new InvalidOperationException("Failed to start driver process");

            _processStdin = _process.StandardInput;
            _processStdout = _process.StandardOutput;
            _stderrTail = "";

            StartStderrReader(_process);

            _inputsSinceRestart = 0;
            RestartCount++;
            return null;
        }
        catch (Exception ex)
        {
            _process = null;
            _processStdin = null;
            _processStdout = null;
            return new RunResult { Status = RunStatus.Error, ErrorMessage = ex.Message };
        }
    }

    private void StartStderrReader(Process p)
    {
        ThreadPool.QueueUserWorkItem(_ =>
        {
            try
            {
                var reader = p.StandardError;
                var lines = new Queue<string>();
                while (true)
                {
                    var line = reader.ReadLine();
                    if (line == null) break;
                    lock (_lock)
                    {
                        lines.Enqueue(line);
                        while (lines.Count > 200) lines.Dequeue();
                        _stderrTail = string.Join("\n", lines);
                    }
                }
            }
            catch { }
        });
    }

    private void KillProcess()
    {
        if (_process != null)
        {
            try
            {
                if (!_process.HasExited)
                {
                    _process.Kill(true);
                    _process.WaitForExit(500);
                }
            }
            catch { }
            finally
            {
                _process.Dispose();
                _process = null;
                _processStdin = null;
                _processStdout = null;
            }
        }
    }

    private void WriteDriver()
    {
        var driver = new StringBuilder();
        driver.AppendLine("var _sf_print = typeof print === 'function' ? print : console.log;");
        driver.AppendLine("var _sf_readline = readline;");
        driver.AppendLine("var _sf_parse = JSON.parse;");
        driver.AppendLine("var _sf_hasGlobal = typeof newGlobal === 'function';");
        driver.AppendLine("var _sf_hasGc = typeof gc === 'function';");
        driver.AppendLine("var _sf_hasDrain = typeof drainJobQueue === 'function';");
        driver.AppendLine("var _sf_failuresMain = [];");
        driver.AppendLine("var _sf_count = 0;");
        driver.AppendLine("while (true) {");
        driver.AppendLine("  var _sf_line = _sf_readline();");
        driver.AppendLine("  if (_sf_line === null || _sf_line === undefined) break;");
        driver.AppendLine("  var _sf_marker = 'OK';");
        driver.AppendLine("  var _sf_g = null;");
        driver.AppendLine("  _sf_failuresMain.length = 0;");
        driver.AppendLine("  try {");
        driver.AppendLine("    var _sf_code = _sf_parse(_sf_line);");
        driver.AppendLine("    if (_sf_hasGlobal) {");
        // Fresh isolated compartment per input so state cannot leak between
        // inputs, then drop the reference so the realm becomes collectable.
        driver.AppendLine("      _sf_g = newGlobal({ newCompartment: true });");
        // A bare `throw` inside a .then()/async-function continuation never
        // reaches this try/catch: it just becomes an "unhandled rejection"
        // that SpiderMonkey only reports much later, at process exit, after
        // countless unrelated inputs already ran - i.e. never, in practice,
        // since the host normally kills/recycles this process long before it
        // would exit on its own. Give seeds/mutators an explicit, synchronous
        // way to flag such an async assertion failure against *this* input.
        driver.AppendLine("      _sf_g.__sf_failures = [];");
        driver.AppendLine("      _sf_g.__sf_fail = function(msg) { _sf_g.__sf_failures.push('' + msg); };");
        driver.AppendLine("      _sf_g.evaluate(_sf_code);");
        // Promise reactions and async function continuations are queued as
        // jobs, not run inline: without forcing them to run here, before the
        // marker for *this* input is emitted, every .then()/await in a seed
        // would silently never execute during fuzzing, so any real engine bug
        // it could catch would (at best) surface much later against whatever
        // unrelated input happens to be running when the job finally fires.
        driver.AppendLine("      if (_sf_hasDrain) _sf_g.drainJobQueue();");
        driver.AppendLine("      if (_sf_g.__sf_failures.length > 0) throw new Error(_sf_g.__sf_failures.join('; '));");
        driver.AppendLine("    } else {");
        driver.AppendLine("      globalThis.__sf_fail = function(msg) { _sf_failuresMain.push('' + msg); };");
        driver.AppendLine("      eval(_sf_code);");
        driver.AppendLine("      if (_sf_hasDrain) drainJobQueue();");
        driver.AppendLine("      if (_sf_failuresMain.length > 0) throw new Error(_sf_failuresMain.join('; '));");
        driver.AppendLine("    }");
        driver.AppendLine("  } catch (_sf_e) {");
        // Report the concrete error class (TypeError, RangeError, SyntaxError,
        // ...) AND its message so the host can use both as a coverage signal.
        // Without the message, every plain `new Error(msg)` oracle assertion
        // used by seeds/custom mutators collapses into the same 'JERR:Error'
        // signature no matter what distinct condition it actually flags.
        driver.AppendLine("    var _sf_name = 'Error';");
        driver.AppendLine("    var _sf_msg = '';");
        driver.AppendLine("    try {");
        driver.AppendLine("      if (_sf_e && _sf_e.constructor && _sf_e.constructor.name) _sf_name = '' + _sf_e.constructor.name;");
        driver.AppendLine("      else if (_sf_e && _sf_e.name) _sf_name = '' + _sf_e.name;");
        driver.AppendLine("    } catch (_sf_ignore) {}");
        driver.AppendLine("    try {");
        driver.AppendLine("      var _sf_rawmsg = (_sf_e && _sf_e.message !== undefined) ? ('' + _sf_e.message) : ('' + _sf_e);");
        driver.AppendLine("      if (_sf_rawmsg.length > 120) _sf_rawmsg = _sf_rawmsg.substring(0, 120);");
        driver.AppendLine("      _sf_msg = encodeURIComponent(_sf_rawmsg);");
        driver.AppendLine("    } catch (_sf_ignore2) {}");
        driver.AppendLine("    _sf_marker = 'JERR:' + _sf_name + ':' + _sf_msg;");
        driver.AppendLine("  }");
        // Release the realm and reclaim memory periodically. Without this the
        // per-input globals pile up in the live process and throughput decays.
        driver.AppendLine("  _sf_g = null;");
        driver.AppendLine("  _sf_count++;");
        driver.AppendLine("  if (_sf_hasGc && (_sf_count % 128 === 0)) { try { gc(); } catch (_sf_ignore) {} }");
        driver.AppendLine("  _sf_print('__SF_DONE__:' + _sf_marker);");
        driver.AppendLine("}");

        File.WriteAllText(_driverPath, driver.ToString(), Encoding.UTF8);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        lock (_lock)
        {
            KillProcess();
            try { Directory.Delete(_workDir, true); } catch { }
        }
    }
}
