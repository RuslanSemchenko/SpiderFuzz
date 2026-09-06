using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SpiderFuzz.Fuzzer;

internal sealed class CoverageTracker
{
    private readonly ConcurrentDictionary<string, int> _outputHashes = new();
    private readonly ConcurrentDictionary<string, int> _errorHashes = new();
    private readonly ConcurrentDictionary<string, int> _crashHashes = new();
    private readonly ConcurrentDictionary<int, bool> _coverageBitmap = new();
    private int _uniqueOutputs;
    private int _uniqueErrors;
    private int _uniqueCrashes;
    private long _totalPaths;

    public int UniqueOutputs => _uniqueOutputs;
    public int UniqueErrors => _uniqueErrors;
    public int UniqueCrashes => _uniqueCrashes;
    public long TotalPaths => _totalPaths;

    public CoverageRecord Record(RunResult result, string? inputCode = null)
    {
        var record = new CoverageRecord();
        Interlocked.Increment(ref _totalPaths);

        if (result.Status == RunStatus.Ok || result.Status == RunStatus.NonZeroExit)
        {
            var outputHash = ComputeHash(result.Stdout);
            if (_outputHashes.TryAdd(outputHash, 1))
            {
                Interlocked.Increment(ref _uniqueOutputs);
                record.NewOutput = true;
                record.OutputHash = outputHash;
            }
        }

        if (!string.IsNullOrEmpty(result.Stderr))
        {
            var normalizedError = NormalizeError(result.Stderr);
            var errorHash = ComputeHash(normalizedError);
            if (_errorHashes.TryAdd(errorHash, 1))
            {
                Interlocked.Increment(ref _uniqueErrors);
                record.NewError = true;
                record.ErrorHash = errorHash;
            }
        }

        if (result.Status == RunStatus.Crash)
        {
            var crashSig = ExtractCrashSignature(result);
            var crashHash = ComputeHash(crashSig);
            if (_crashHashes.TryAdd(crashHash, 1))
            {
                Interlocked.Increment(ref _uniqueCrashes);
                record.NewCrash = true;
                record.CrashHash = crashHash;
            }
        }

        if (result.TimedOut)
        {
            var codeHash = inputCode != null ? CorpusEntryEx.ComputeHash(inputCode) : result.CodeLength.ToString();
            var timeoutHash = ComputeHash("TIMEOUT_" + codeHash);
            if (_crashHashes.TryAdd(timeoutHash, 1))
            {
                Interlocked.Increment(ref _uniqueCrashes);
                record.NewCrash = true;
                record.CrashHash = timeoutHash;
            }
        }

        if ((result.Status == RunStatus.Ok || result.Status == RunStatus.NonZeroExit) && result.CodeLength < 50000)
        {
            var features = ExtractFeatures(result, inputCode);
            foreach (var feature in features)
            {
                if (_coverageBitmap.TryAdd(feature, true))
                {
                    record.NewFeature = true;
                }
            }
        }

        return record;
    }

    public bool IsInteresting(CoverageRecord record)
        => record.NewOutput || record.NewError || record.NewCrash || record.NewFeature;

    private static string ExtractCrashSignature(RunResult result)
    {
        var sb = new StringBuilder();
        sb.Append(result.ExitCode);

        if (!string.IsNullOrEmpty(result.Stderr))
        {
            var lines = result.Stderr.Split('\n');
            foreach (var line in lines)
            {
                var trimmed = line.Trim();
                if (trimmed.Contains("SUMMARY:") ||
                    trimmed.Contains("ERROR:") ||
                    trimmed.Contains("SEGV") ||
                    trimmed.Contains("Fatal signal") ||
                    trimmed.Contains("stack-buffer-overflow") ||
                    trimmed.Contains("heap-buffer-overflow") ||
                    trimmed.Contains("heap-use-after-free") ||
                    trimmed.Contains("AddressSanitizer"))
                {
                    sb.Append('|');
                    sb.Append(trimmed);
                }
            }
        }

        return sb.ToString();
    }

    // Engine addresses (ASLR, heap pointers, ...) change from run to run even
    // when the underlying bug is identical, so strip them before hashing -
    // otherwise every occurrence of the very same error looks "new".
    private static readonly Regex HexAddressRegex = new(@"0x[0-9a-fA-F]{6,}", RegexOptions.Compiled);

    private static string NormalizeError(string stderr)
    {
        var sb = new StringBuilder(stderr.Length);
        foreach (var line in stderr.Split('\n'))
        {
            var trimmed = line.Trim();
            if (string.IsNullOrEmpty(trimmed)) continue;
            if (trimmed.StartsWith("==") && trimmed.Contains("==")) continue;
            if (trimmed.StartsWith("    #")) continue;
            trimmed = HexAddressRegex.Replace(trimmed, "0xADDR");
            sb.AppendLine(trimmed);
        }
        return sb.ToString();
    }

    private static HashSet<int> ExtractFeatures(RunResult result, string? inputCode)
    {
        var features = new HashSet<int>();
        var output = result.Stdout + result.Stderr;

        foreach (var keyword in FeatureKeywords)
        {
            if (output.Contains(keyword, StringComparison.Ordinal))
            {
                features.Add(keyword.GetHashCode());
            }
        }

        // Text-based signals above saturate almost immediately (a few dozen
        // keywords, mostly-empty stdout): they alone cannot tell two inputs
        // that exercise genuinely different language constructs apart. Layer a
        // cheap syntactic proxy for real code coverage on top: hash the shape
        // of the input itself (sequences of normalized tokens), so exploring a
        // new combination of constructs counts as new coverage even when the
        // engine's observable output is identical.
        if (!string.IsNullOrEmpty(inputCode))
        {
            AddStructuralFeatures(inputCode, features);
        }

        return features;
    }

    private static readonly Regex TokenRegex = new(
        @"[A-Za-z_$][A-Za-z0-9_$]*|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|""(?:[^""\\]|\\.)*""|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`|=>|\.\.\.|===|!==|>>>=|>>>|<<=|>>=|\*\*=|&&=|\|\|=|\?\?=|\?\.|==|!=|<=|>=|&&|\|\||\?\?|\+\+|--|\*\*|<<|>>|\S",
        RegexOptions.Compiled);

    private const int MaxStructuralTokens = 4000;

    private static readonly Lazy<HashSet<string>> MeaningfulTokens = new(() =>
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var k in Dictionary.Keywords) set.Add(k);
        foreach (var k in Dictionary.Builtins) set.Add(k);
        foreach (var k in Dictionary.MethodNames) set.Add(k);
        foreach (var k in Dictionary.PropertyNames) set.Add(k);
        return set;
    });

    // Turns the source into a stream of normalized tokens (identifiers ->
    // "ID", numbers -> "NUM", strings/templates -> "STR", keywords/builtins/
    // operators kept as-is) and records every consecutive triple as a
    // feature. This rewards exploring new combinations of language
    // constructs, not just new literal values or variable names.
    private static void AddStructuralFeatures(string code, HashSet<int> features)
    {
        string? prev2 = null;
        string? prev1 = null;
        var count = 0;
        var meaningful = MeaningfulTokens.Value;

        var m = TokenRegex.Match(code);
        while (m.Success && count < MaxStructuralTokens)
        {
            var raw = m.Value;
            var c0 = raw[0];
            string norm;
            if (c0 == '"' || c0 == '\'' || c0 == '`') norm = "STR";
            else if (char.IsDigit(c0)) norm = "NUM";
            else if ((char.IsLetter(c0) || c0 == '_' || c0 == '$') && !meaningful.Contains(raw)) norm = "ID";
            else norm = raw;

            if (prev2 != null && prev1 != null)
            {
                var tri = string.Concat(prev2, "\u0001", prev1, "\u0001", norm);
                features.Add(tri.GetHashCode());
            }

            prev2 = prev1;
            prev1 = norm;
            count++;
            m = m.NextMatch();
        }
    }

    private static readonly string[] FeatureKeywords =
    [
        "TypeError", "ReferenceError", "SyntaxError", "RangeError",
        "InternalError", "OOM", "stack overflow",
        "SyntaxError", "missing ;", "unexpected",
        "undefined", "is not", "cannot",
        "iteration", "proxy", "reflect",
        "wasm", "WebAssembly",
        "generator", "iterator", "async", "await",
        "destructure", "spread", "rest",
        "class", "extends", "super",
        "import", "export", "module",
        "template", "tagged",
    ];

    private static string ComputeHash(string content)
    {
        if (string.IsNullOrEmpty(content)) return "empty";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexString(bytes.AsSpan(0, 8)).ToLowerInvariant();
    }

    public void Reset()
    {
        _outputHashes.Clear();
        _errorHashes.Clear();
        _crashHashes.Clear();
        _coverageBitmap.Clear();
        _uniqueOutputs = 0;
        _uniqueErrors = 0;
        _uniqueCrashes = 0;
        _totalPaths = 0;
    }
}

internal sealed class CoverageRecord
{
    public bool NewOutput { get; set; }
    public bool NewError { get; set; }
    public bool NewCrash { get; set; }
    public bool NewFeature { get; set; }
    public string OutputHash { get; set; } = "";
    public string ErrorHash { get; set; } = "";
    public string CrashHash { get; set; } = "";

    public int Score => (NewOutput ? 1 : 0) + (NewError ? 2 : 0) + (NewCrash ? 10 : 0) + (NewFeature ? 1 : 0);
}
