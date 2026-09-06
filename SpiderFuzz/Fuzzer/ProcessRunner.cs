using System.Diagnostics;
using System.Text;

namespace SpiderFuzz.Fuzzer;

internal sealed class ProcessRunner : IDisposable
{
    private readonly string _jsExePath;
    private readonly int _timeoutMs;
    private readonly bool _useAsan;

    public ProcessRunner(string jsExePath, int timeoutMs = 5000, bool useAsan = false)
    {
        _jsExePath = Path.GetFullPath(jsExePath);
        _timeoutMs = timeoutMs;
        _useAsan = useAsan;

        if (!File.Exists(_jsExePath))
            throw new FileNotFoundException($"js.exe not found at {_jsExePath}");
    }

    /// <summary>
    /// Runs <paramref name="jsCode"/> once. <paramref name="extraArgs"/> are inserted
    /// before the script path, e.g. shell tier flags like <c>--ion-eager</c> or
    /// <c>--no-baseline</c> used by <see cref="DifferentialTester"/> and the
    /// experimental-features runner - never trusted as raw shell text, always
    /// individual argv entries via <see cref="ProcessStartInfo.ArgumentList"/>.
    /// </summary>
    public RunResult Run(string jsCode, IReadOnlyList<string>? extraArgs = null)
    {
        var result = new RunResult { CodeLength = Encoding.UTF8.GetByteCount(jsCode) };
        string? tempFile = null;

        try
        {
            tempFile = Path.Combine(Path.GetTempPath(), $"sf_{Guid.NewGuid():N}.js");
            File.WriteAllText(tempFile, jsCode, Encoding.UTF8);

            var psi = new ProcessStartInfo
            {
                FileName = _jsExePath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };

            if (extraArgs != null)
                foreach (var arg in extraArgs) psi.ArgumentList.Add(arg);
            psi.ArgumentList.Add(tempFile);

            // ASAN needs the binary dir in PATH so its runtime is found.
            var binDir = Path.GetDirectoryName(_jsExePath)!;
            var currentPath = Environment.GetEnvironmentVariable("PATH");
            psi.EnvironmentVariables["PATH"] = string.IsNullOrEmpty(currentPath)
                ? binDir
                : binDir + Path.PathSeparator + currentPath;

            if (_useAsan)
            {
                psi.EnvironmentVariables["ASAN_OPTIONS"] =
                    "detect_leaks=0:abort_on_error=1:print_stacktrace=1:symbolize=1:handle_abort=1:handle_sigfpe=1:handle_sigill=1:handle_sigbus=1:handle_sigsegv=1:detect_invalid_pointer_pairs=2:print_legend=0:allow_user_segv_handler=1";
                psi.EnvironmentVariables["MOZ_CRASHREPORTER_DISABLE"] = "1";
                psi.EnvironmentVariables["MOZ_DISABLE_NONLOCAL_CONNECTIONS"] = "1";
            }

            using var process = new Process { StartInfo = psi };
            process.Start();

            var stdoutTask = process.StandardOutput.ReadToEndAsync();
            var stderrTask = process.StandardError.ReadToEndAsync();

            var exited = process.WaitForExit(_timeoutMs);

            if (!exited)
            {
                try { process.Kill(true); } catch { }
                result.Status = RunStatus.Timeout;
                result.TimedOut = true;
                return result;
            }

            process.WaitForExit();
            Task.WaitAll([stdoutTask, stderrTask], 2000);

            result.ExitCode = process.ExitCode;
            result.Stdout = stdoutTask.IsCompletedSuccessfully ? stdoutTask.Result : "";
            result.Stderr = stderrTask.IsCompletedSuccessfully ? stderrTask.Result : "";

            if (IsCrash(result.ExitCode, result.Stderr))
            {
                result.Status = RunStatus.Crash;
                result.CrashType = ClassifyCrash(result.ExitCode, result.Stderr);
            }
            else if (result.ExitCode != 0)
            {
                result.Status = RunStatus.NonZeroExit;
            }
            else
            {
                result.Status = RunStatus.Ok;
            }
        }
        catch (Exception ex)
        {
            result.Status = RunStatus.Error;
            result.ErrorMessage = ex.Message;
        }
        finally
        {
            if (tempFile != null)
            {
                try { File.Delete(tempFile); } catch { }
            }
        }

        return result;
    }

    internal static bool IsCrash(int exitCode, string stderr)
    {
        if (IsCrashExitCode(exitCode)) return true;
        if (!string.IsNullOrEmpty(stderr) && IsCrashOutput(stderr)) return true;
        return false;
    }

    internal static bool IsCrashOutput(string stderr)
    {
        return stderr.Contains("AddressSanitizer", StringComparison.OrdinalIgnoreCase) ||
               stderr.Contains("Assertion failure:", StringComparison.OrdinalIgnoreCase) ||
               stderr.Contains("MOZ_ASSERT", StringComparison.OrdinalIgnoreCase) ||
               stderr.Contains("MOZ_RELEASE_ASSERT", StringComparison.OrdinalIgnoreCase) ||
               stderr.Contains("MOZ_CRASH", StringComparison.OrdinalIgnoreCase) ||
               stderr.Contains("UndefinedBehaviorSanitizer", StringComparison.OrdinalIgnoreCase) ||
               stderr.Contains("Fatal signal", StringComparison.OrdinalIgnoreCase) ||
               stderr.Contains("CHECK failed:", StringComparison.OrdinalIgnoreCase);
    }

    internal static bool IsCrashExitCode(int exitCode)
    {
        if (exitCode == 0) return false;

        var code = unchecked((uint)exitCode);
        return code switch
        {
            0x40000015 => true, // STATUS_FATAL_APP_EXIT / abort()
            0xC0000005 => true, // ACCESS_VIOLATION
            0xC0000008 => true, // INVALID_HANDLE
            0xC000001D => true, // ILLEGAL_INSTRUCTION
            0xC0000094 => true, // INTEGER_DIVIDE_BY_ZERO
            0xC00000FD => true, // STACK_OVERFLOW
            0xC0000409 => true, // STACK_BUFFER_OVERRUN
            0xC0000374 => true, // HEAP_CORRUPTION
            0xC0000420 => true, // ASSERTION_FAILURE
            0xC000041C => true,
            0xC000013A => false, // STATUS_CONTROL_C_EXIT is NOT a crash
            0xC000026B => true,
            0xC00002B8 => true,
            0xC00002C5 => true,
            0xC00002E2 => true,
            >= 0xC0000000 and <= 0xDFFFFFFF => true,
            132 => true, // SIGILL
            133 => true, // SIGTRAP
            134 => true, // SIGABRT
            136 => true, // SIGFPE
            137 => true, // SIGKILL
            138 => true, // SIGBUS
            139 => true, // SIGSEGV
            _ => false,
        };
    }

    internal static string ClassifyCrash(int exitCode, string stderr)
    {
        var code = unchecked((uint)exitCode);
        var reason = code switch
        {
            0x40000015 => "FATAL_APP_EXIT",
            0xC0000005 => "ACCESS_VIOLATION",
            0xC0000008 => "INVALID_HANDLE",
            0xC000001D => "ILLEGAL_INSTRUCTION",
            0xC0000094 => "INTEGER_DIVIDE_BY_ZERO",
            0xC00000FD => "STACK_OVERFLOW",
            0xC0000409 => "STACK_BUFFER_OVERRUN",
            0xC0000374 => "HEAP_CORRUPTION",
            0xC0000420 => "ASSERTION_FAILURE",
            0xC000041C => "RPC_INVALID_STRING_BINDING",
            132 => "SIGILL",
            133 => "SIGTRAP",
            134 => "SIGABRT",
            136 => "SIGFPE",
            137 => "SIGKILL",
            138 => "SIGBUS",
            139 => "SIGSEGV",
            _ => $"UNKNOWN_0x{code:X8}",
        };

        if (!string.IsNullOrEmpty(stderr))
        {
            if (stderr.Contains("AddressSanitizer")) reason += "+ASAN";
            if (stderr.Contains("heap-buffer-overflow")) reason += "+HEAP_BUF";
            if (stderr.Contains("heap-use-after-free")) reason += "+UAF";
            if (stderr.Contains("stack-buffer-overflow")) reason += "+STACK_BUF";
            if (stderr.Contains("stack-overflow")) reason += "+STACK_OVERFLOW";
            if (stderr.Contains("global-buffer-overflow")) reason += "+GLOBAL_BUF";
            if (stderr.Contains("double-free")) reason += "+DOUBLE_FREE";
            if (stderr.Contains("out-of-memory")) reason += "+OOM";
            if (stderr.Contains("SEGV on unknown address")) reason += "+SEGV";
            if (stderr.Contains("Fatal signal")) reason += "+SIGNAL";
            if (stderr.Contains("undefined behavior")) reason += "+UB";
            if (stderr.Contains("misaligned")) reason += "+MISALIGN";
            if (stderr.Contains("stack-use-after-return")) reason += "+USE_AFTER_RETURN";
            if (stderr.Contains("stack-use-after-scope")) reason += "+USE_AFTER_SCOPE";
            if (stderr.Contains("initialization-order-fiasco")) reason += "+INIT_ORDER";
            if (stderr.Contains("vptr")) reason += "+VPTR";
            if (stderr.Contains("use-after-poison")) reason += "+AFTER_POISON";
            if (stderr.Contains("container-overflow")) reason += "+CONTAINER_OVF";
            if (stderr.Contains("CHECK failed")) reason += "+MOZ_ASSERT";
            if (stderr.Contains("MOZ_RELEASE_ASSERT")) reason += "+MOZ_RELEASE_ASSERT";

            var assertMsg = ExtractAssertion(stderr);
            if (assertMsg != null)
                reason += "+" + assertMsg;
        }

        return reason;
    }

    /// <summary>Извлекает текст сработавшего ассерта из stderr, если он есть.</summary>
    internal static string? ExtractAssertion(string stderr)
    {
        if (string.IsNullOrEmpty(stderr)) return null;

        foreach (var line in stderr.Split('\n'))
        {
            var t = line.Trim();
            if (t.StartsWith("Assertion failure:", StringComparison.Ordinal) ||
                t.StartsWith("MOZ_RELEASE_ASSERT:", StringComparison.Ordinal) ||
                t.StartsWith("MOZ_ASSERT:", StringComparison.Ordinal) ||
                t.StartsWith("MOZ_CRASH:", StringComparison.Ordinal) ||
                t.StartsWith("CHECK failed:", StringComparison.Ordinal))
            {
                // короткий безопасный токен для имени файла / сигнатуры
                var msg = t.Length > 60 ? t[..60] : t;
                msg = msg.Replace(' ', '_').Replace('/', '_').Replace('\\', '_')
                       .Replace(':', '_').Replace('(', '_').Replace(')', '_')
                       .Replace('"', '_').Replace('\'', '_').Replace('<', '_').Replace('>', '_')
                       .Replace('|', '_').Replace('&', '_').Replace('*', '_').Replace('!', '_');
                var keep = new System.Text.StringBuilder();
                foreach (var c in msg)
                    keep.Append(char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.' ? c : '_');
                return keep.ToString();
            }
        }
        return null;
    }

    public void Dispose()
    {
    }
}

internal sealed class RunResult
{
    public int ExitCode { get; set; }
    public string Stdout { get; set; } = "";
    public string Stderr { get; set; } = "";
    public RunStatus Status { get; set; }
    public bool TimedOut { get; set; }
    public int CodeLength { get; set; }
    public string? CrashType { get; set; }
    public string? ErrorMessage { get; set; }

    // Set by PersistentRunner when the JS driver caught a plain `new Error(...)`
    // (not one of the built-in TypeError/RangeError/... subclasses). Generated
    // seeds and custom mutators use exactly this pattern as an in-band oracle
    // for semantic engine regressions, so it deserves its own reporting path
    // instead of being silently folded into generic "JS error" coverage noise.
    public bool IsSemanticFinding { get; set; }
    public string? AssertionMessage { get; set; }

    public bool IsInteresting => Status == RunStatus.Crash || TimedOut;

    public string? ExtractStackTrace()
    {
        if (string.IsNullOrEmpty(Stderr)) return null;

        var lines = Stderr.Split('\n');
        var stackLines = new List<string>();
        var inAsan = Stderr.Contains("AddressSanitizer") || Stderr.Contains("ERROR:");
        var inStack = false;

        foreach (var line in lines)
        {
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("#0 "))
            {
                inStack = true;
            }

            if (inStack)
            {
                if (trimmed.StartsWith('#') ||
                    trimmed.Contains(" in ") ||
                    trimmed.Contains(":0x") ||
                    trimmed.Contains("AddressSanitizer") ||
                    trimmed.Contains("SUMMARY:"))
                {
                    stackLines.Add(line.Trim());
                }
                else if (inStack && trimmed.Length == 0)
                {
                    break;
                }
            }
            else if (trimmed.StartsWith("==ERROR") ||
                     trimmed.StartsWith("ERROR: "))
            {
                stackLines.Add(line.Trim());
            }
        }

        return stackLines.Count > 0 ? string.Join('\n', stackLines) : null;
    }
}

internal enum RunStatus
{
    Ok,
    Crash,
    Timeout,
    NonZeroExit,
    Error,
}
