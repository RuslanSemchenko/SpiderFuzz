using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace SpiderFuzz.Fuzzer;

internal sealed class CrashManager : IDisposable
{
    private readonly string _outputDir;
    private readonly string _crashesDir;
    private readonly string _corpusDir;
    private readonly string _hangsDir;
    private readonly string _findingsDir;
    private readonly string _diffsDir;

    private readonly ConcurrentDictionary<string, bool> _seenHashes = new();
    // Findings are deduplicated fuzzily (by edit distance), not by exact hash:
    // a stray byte-level mutation landing inside the literal message text
    // ("expected wasm trap" -> "exXpected wasm trap") would otherwise be
    // reported as a brand new regression every time, flooding the same real
    // signal under a dozen near-identical entries.
    private readonly List<string> _findingMessages = [];
    private readonly object _findingsLock = new();
    private int _crashCount;
    private int _hangCount;
    private int _uniqueCrashCount;
    private int _uniqueHangCount;
    private int _findingCount;
    private int _uniqueFindingCount;
    private int _differentialCount;
    private int _uniqueDifferentialCount;

    public int CrashCount => _crashCount;
    public int HangCount => _hangCount;
    public int UniqueCrashCount => _uniqueCrashCount;
    public int UniqueHangCount => _uniqueHangCount;
    public int FindingCount => _findingCount;
    public int UniqueFindingCount => _uniqueFindingCount;
    public int DifferentialCount => _differentialCount;
    public int UniqueDifferentialCount => _uniqueDifferentialCount;

    public CrashManager(string outputDir)
    {
        _outputDir = Path.GetFullPath(outputDir);
        _crashesDir = Path.Combine(_outputDir, "crashes");
        _corpusDir = Path.Combine(_outputDir, "corpus");
        _hangsDir = Path.Combine(_outputDir, "hangs");
        _findingsDir = Path.Combine(_outputDir, "findings");
        _diffsDir = Path.Combine(_outputDir, "diffs");

        Directory.CreateDirectory(_crashesDir);
        Directory.CreateDirectory(_corpusDir);
        Directory.CreateDirectory(_hangsDir);
        Directory.CreateDirectory(_findingsDir);
        Directory.CreateDirectory(_diffsDir);

        LoadExistingHashes();
    }

    private void LoadExistingHashes()
    {
        try
        {
            if (Directory.Exists(_crashesDir))
            {
                foreach (var file in Directory.GetFiles(_crashesDir, "*.js"))
                {
                    _crashCount++;
                    if (!file.EndsWith("_min.js", StringComparison.OrdinalIgnoreCase))
                        _uniqueCrashCount++;

                    try
                    {
                        var content = File.ReadAllText(file);
                        ExtractHeaderHashes(content, "crash");
                    }
                    catch { }
                }
            }

            if (Directory.Exists(_hangsDir))
            {
                foreach (var file in Directory.GetFiles(_hangsDir, "*.js"))
                {
                    _hangCount++;
                    if (!file.EndsWith("_min.js", StringComparison.OrdinalIgnoreCase))
                        _uniqueHangCount++;

                    try
                    {
                        var content = File.ReadAllText(file);
                        ExtractHeaderHashes(content, "hang");
                    }
                    catch { }
                }
            }

            if (Directory.Exists(_findingsDir))
            {
                foreach (var file in Directory.GetFiles(_findingsDir, "*.js"))
                {
                    _findingCount++;
                    _uniqueFindingCount++;

                    try
                    {
                        var content = File.ReadAllText(file);
                        ExtractHeaderHashes(content, "finding");

                        foreach (var line in content.Split('\n'))
                        {
                            var trimmed = line.Trim();
                            if (trimmed.StartsWith("// Message: ", StringComparison.Ordinal))
                            {
                                _findingMessages.Add(NormalizeMessage(trimmed["// Message: ".Length..]));
                                break;
                            }
                            if (!trimmed.StartsWith("//", StringComparison.Ordinal)) break;
                        }
                    }
                    catch { }
                }
            }

            if (Directory.Exists(_diffsDir))
            {
                foreach (var file in Directory.GetFiles(_diffsDir, "*.js"))
                {
                    _differentialCount++;
                    _uniqueDifferentialCount++;

                    try
                    {
                        var content = File.ReadAllText(file);
                        ExtractHeaderHashes(content, "diff");
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private void ExtractHeaderHashes(string content, string kind)
    {
        foreach (var line in content.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith("// Hash: ", StringComparison.Ordinal))
            {
                var h = trimmed["// Hash: ".Length..].Trim();
                _seenHashes.TryAdd($"{kind}_{h}", true);
            }
            else if (trimmed.StartsWith("// Stack Hash: ", StringComparison.Ordinal))
            {
                var sh = trimmed["// Stack Hash: ".Length..].Trim();
                _seenHashes.TryAdd($"stack_{sh}", true);
            }
            else if (trimmed.StartsWith("// Message Hash: ", StringComparison.Ordinal))
            {
                var mh = trimmed["// Message Hash: ".Length..].Trim();
                _seenHashes.TryAdd($"finding_{mh}", true);
            }
            else if (trimmed.StartsWith("// Diff Signature Hash: ", StringComparison.Ordinal))
            {
                var dh = trimmed["// Diff Signature Hash: ".Length..].Trim();
                _seenHashes.TryAdd($"diffsig_{dh}", true);
            }
            else if (!trimmed.StartsWith("//", StringComparison.Ordinal))
            {
                break;
            }
        }
    }

    public static string ComputeStackSignature(string? stackTrace, string? assertMsg, int exitCode)
    {
        if (!string.IsNullOrEmpty(assertMsg))
            return $"ASSERT:{assertMsg}";

        if (string.IsNullOrEmpty(stackTrace))
            return $"EXIT:0x{unchecked((uint)exitCode):X8}";

        var frames = stackTrace.Split('\n')
            .Select(l => l.Trim())
            .Where(l => !string.IsNullOrEmpty(l) && (l.StartsWith('#') || l.Contains("ERROR") || l.Contains("SUMMARY:")))
            .Take(5)
            .Select(l => System.Text.RegularExpressions.Regex.Replace(l, @"0x[0-9a-fA-F]{4,16}", "0x..."));

        return string.Join(";", frames);
    }

    public bool SaveCrash(RunResult result, string jsCode, int iteration, bool isMinimized = false)
    {
        if (!isMinimized)
            Interlocked.Increment(ref _crashCount);

        var assertMsg = result.Stderr != null ? ProcessRunner.ExtractAssertion(result.Stderr) : null;
        var stackTrace = result.ExtractStackTrace();
        var stackSig = ComputeStackSignature(stackTrace, assertMsg, result.ExitCode);
        var stackHash = ComputeHash(stackSig);

        if (!isMinimized)
        {
            if (!_seenHashes.TryAdd($"stack_{stackHash}", true))
                return false;
        }

        var hash = ComputeHash(jsCode);
        if (!isMinimized && !_seenHashes.TryAdd($"crash_{hash}", true))
            return false;

        if (!isMinimized)
            Interlocked.Increment(ref _uniqueCrashCount);

        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var minSuffix = isMinimized ? "_min" : "";
        var fileName = $"{timestamp}_iter{iteration}_{result.CrashType ?? "unknown"}_{hash[..12]}{minSuffix}.js";
        var filePath = Path.Combine(_crashesDir, SanitizeFileName(fileName));

        var sb = new StringBuilder();
        sb.AppendLine($"// Crash Type: {result.CrashType}");
        sb.AppendLine($"// Exit Code: 0x{unchecked((uint)result.ExitCode):X8}");
        sb.AppendLine($"// Iteration: {iteration}");
        sb.AppendLine($"// Date: {DateTime.Now:O}");
        sb.AppendLine($"// Code Length (UTF-8 bytes): {Encoding.UTF8.GetByteCount(jsCode)}");
        sb.AppendLine($"// Hash: {hash}");
        sb.AppendLine($"// Stack Hash: {stackHash}");
        if (isMinimized) sb.AppendLine("// Minimized: true");

        if (assertMsg != null)
        {
            sb.AppendLine($"// ASSERTION: {assertMsg}");
        }

        if (stackTrace != null)
        {
            sb.AppendLine($"// STACK TRACE:");
            foreach (var line in stackTrace.Split('\n'))
                sb.AppendLine($"// {line.TrimEnd()}");
        }
        if (!string.IsNullOrEmpty(result.Stderr))
        {
            sb.AppendLine($"// STDERR:");
            foreach (var line in result.Stderr.Split('\n').Take(50))
                sb.AppendLine($"// {line.TrimEnd()}");
        }
        sb.AppendLine();
        sb.AppendLine(jsCode);

        File.WriteAllText(filePath, sb.ToString());
        return true;
    }

    public bool SaveHang(RunResult result, string jsCode, int iteration, bool isMinimized = false)
    {
        if (!isMinimized)
            Interlocked.Increment(ref _hangCount);

        var hash = ComputeHash(jsCode);
        if (!isMinimized && !_seenHashes.TryAdd($"hang_{hash}", true))
            return false;

        if (!isMinimized)
            Interlocked.Increment(ref _uniqueHangCount);

        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var minSuffix = isMinimized ? "_min" : "";
        var fileName = $"{timestamp}_iter{iteration}_TIMEOUT_{hash[..12]}{minSuffix}.js";
        var filePath = Path.Combine(_hangsDir, SanitizeFileName(fileName));

        var sb = new StringBuilder();
        sb.AppendLine($"// Type: TIMEOUT");
        sb.AppendLine($"// Iteration: {iteration}");
        sb.AppendLine($"// Date: {DateTime.Now:O}");
        sb.AppendLine($"// Code Length (UTF-8 bytes): {Encoding.UTF8.GetByteCount(jsCode)}");
        sb.AppendLine($"// Hash: {hash}");
        if (isMinimized) sb.AppendLine("// Minimized: true");
        sb.AppendLine();
        sb.AppendLine(jsCode);

        File.WriteAllText(filePath, sb.ToString());
        return true;
    }

    /// <summary>
    /// Saves a semantic engine regression: a plain `new Error(msg)` thrown by one
    /// of our own in-band oracle assertions (seeds/custom mutators), as opposed
    /// to a generic built-in TypeError/RangeError/etc. Deduplicated fuzzily by
    /// message text (see <see cref="_findingMessages"/>), since the message IS
    /// the regression's identity here and byte-level mutation can nudge a
    /// single character inside that literal without changing its meaning.
    /// </summary>
    public bool SaveFinding(string jsCode, string message, int iteration)
    {
        Interlocked.Increment(ref _findingCount);

        var normalized = NormalizeMessage(message);
        lock (_findingsLock)
        {
            foreach (var seen in _findingMessages)
            {
                if (IsNearDuplicateMessage(normalized, seen)) return false;
            }
            _findingMessages.Add(normalized);
        }

        Interlocked.Increment(ref _uniqueFindingCount);

        var msgHash = ComputeHash(string.IsNullOrEmpty(message) ? "empty" : message);
        var hash = ComputeHash(jsCode);
        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var fileName = $"{timestamp}_iter{iteration}_{hash[..12]}.js";
        var filePath = Path.Combine(_findingsDir, SanitizeFileName(fileName));

        var sb = new StringBuilder();
        sb.AppendLine("// Type: SEMANTIC_REGRESSION");
        sb.AppendLine($"// Message: {message}");
        sb.AppendLine($"// Iteration: {iteration}");
        sb.AppendLine($"// Date: {DateTime.Now:O}");
        sb.AppendLine($"// Code Length (UTF-8 bytes): {Encoding.UTF8.GetByteCount(jsCode)}");
        sb.AppendLine($"// Hash: {hash}");
        sb.AppendLine($"// Message Hash: {msgHash}");
        sb.AppendLine();
        sb.AppendLine(jsCode);

        File.WriteAllText(filePath, sb.ToString());
        return true;
    }

    /// <summary>
    /// Saves a JIT-tier differential: the same deterministic input observably
    /// behaved differently (threw vs. not, or printed something different)
    /// depending on which SpiderMonkey execution tier ran it. See
    /// <see cref="DifferentialTester"/> for how tiers are chosen and mismatches
    /// confirmed before ever reaching here. Deduplicated by the combined
    /// per-tier signature (not raw source), since many differently-mutated
    /// inputs can trip over the exact same underlying tier bug.
    /// </summary>
    public bool SaveDifferential(string jsCode, IReadOnlyDictionary<string, string> signatures, int iteration)
    {
        Interlocked.Increment(ref _differentialCount);

        var sigText = string.Join("||", signatures.OrderBy(kv => kv.Key, StringComparer.Ordinal).Select(kv => $"{kv.Key}={kv.Value}"));
        var sigHash = ComputeHash(sigText);
        if (!_seenHashes.TryAdd($"diffsig_{sigHash}", true))
            return false;

        Interlocked.Increment(ref _uniqueDifferentialCount);

        var hash = ComputeHash(jsCode);
        var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var fileName = $"{timestamp}_iter{iteration}_{hash[..12]}.js";
        var filePath = Path.Combine(_diffsDir, SanitizeFileName(fileName));

        var sb = new StringBuilder();
        sb.AppendLine("// Type: JIT_TIER_DIFFERENTIAL");
        sb.AppendLine($"// Iteration: {iteration}");
        sb.AppendLine($"// Date: {DateTime.Now:O}");
        sb.AppendLine($"// Code Length (UTF-8 bytes): {Encoding.UTF8.GetByteCount(jsCode)}");
        sb.AppendLine($"// Hash: {hash}");
        sb.AppendLine($"// Diff Signature Hash: {sigHash}");
        foreach (var kv in signatures.OrderBy(kv => kv.Key, StringComparer.Ordinal))
            sb.AppendLine($"// Tier [{kv.Key}]: {kv.Value}");
        sb.AppendLine();
        sb.AppendLine(jsCode);

        File.WriteAllText(filePath, sb.ToString());
        return true;
    }

    private static string NormalizeMessage(string message)
    {
        if (string.IsNullOrEmpty(message)) return "";
        var sb = new StringBuilder(message.Length);
        foreach (var c in message)
        {
            if (char.IsLetterOrDigit(c)) sb.Append(char.ToLowerInvariant(c));
        }
        return sb.ToString();
    }

    private static bool IsNearDuplicateMessage(string a, string b)
    {
        if (a == b) return true;
        if (a.Length == 0 || b.Length == 0) return false;

        // Wildly different lengths can never be a small typo of one another,
        // so skip the (relatively) expensive edit-distance computation.
        var maxLen = Math.Max(a.Length, b.Length);
        if (Math.Abs(a.Length - b.Length) > Math.Max(3, maxLen / 4))
            return false;

        // Scales with message length: a couple of stray/removed characters in
        // a long sentence (byte-level mutation landing inside the literal)
        // should still count as the same finding, while short one-word
        // messages ("gc", "realm", "array") stay tightly matched so distinct
        // short oracle labels never collapse into each other.
        var threshold = Math.Clamp(maxLen / 6, 1, 4);
        return LevenshteinDistance(a, b, threshold) <= threshold;
    }

    /// <summary>Bounded edit distance: returns a value &gt; <paramref name="maxDistance"/> early once exceeded.</summary>
    private static int LevenshteinDistance(string a, string b, int maxDistance)
    {
        var lenA = a.Length;
        var lenB = b.Length;
        var prev = new int[lenB + 1];
        var curr = new int[lenB + 1];

        for (var j = 0; j <= lenB; j++) prev[j] = j;

        for (var i = 1; i <= lenA; i++)
        {
            curr[0] = i;
            var rowMin = curr[0];
            for (var j = 1; j <= lenB; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                curr[j] = Math.Min(Math.Min(curr[j - 1] + 1, prev[j] + 1), prev[j - 1] + cost);
                if (curr[j] < rowMin) rowMin = curr[j];
            }

            if (rowMin > maxDistance) return maxDistance + 1;
            (prev, curr) = (curr, prev);
        }

        return prev[lenB];
    }

    public void SaveCorpus(string jsCode, string strategy)
    {
        var hash = ComputeHash(jsCode);
        if (_seenHashes.ContainsKey($"corpus_{hash}"))
            return;

        _seenHashes.TryAdd($"corpus_{hash}", true);

        var fileName = $"{strategy}_{hash[..12]}.js";
        var filePath = Path.Combine(_corpusDir, SanitizeFileName(fileName));
        File.WriteAllText(filePath, jsCode);
    }

    public List<string> LoadCorpus()
    {
        if (!Directory.Exists(_corpusDir))
            return [];

        return Directory.GetFiles(_corpusDir, "*.js")
            .Select(File.ReadAllText)
            .ToList();
    }

    public void SaveStats(FuzzerStats stats)
    {
        var statsFile = Path.Combine(_outputDir, "stats.json");
        var json = System.Text.Json.JsonSerializer.Serialize(stats, new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true,
        });
        File.WriteAllText(statsFile, json);
    }

    private static string ComputeHash(string content)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    private static string SanitizeFileName(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name;
    }

    /// <summary>
    /// Writes a small self-contained status page to "report.html" in the output
    /// directory: totals plus clickable links to every saved crash/hang/finding/
    /// differential. Cheap enough (a handful of directory listings) to call on
    /// every periodic status tick, which matters because a killed/recycled
    /// process never reaches a clean shutdown path - this is how a live "open
    /// this file in a browser" view stays fresh during a long campaign, not just
    /// at the very end.
    /// </summary>
    public void GenerateReport(FuzzerStats stats)
    {
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>SpiderFuzz Report</title>");
            sb.AppendLine("<style>body{font-family:Consolas,monospace;background:#111;color:#ddd;padding:20px}" +
                "h1{color:#fff}a{color:#9cf}table{border-collapse:collapse;margin-bottom:20px}" +
                "td,th{border:1px solid #444;padding:4px 10px;text-align:left}" +
                "tr:nth-child(even){background:#1a1a1a}" +
                ".crash{color:#f66}.hang{color:#fd6}.finding{color:#e9d}.diff{color:#6df}" +
                "ul{max-height:340px;overflow-y:auto;background:#181818;padding:10px 24px}</style></head><body>");
            sb.AppendLine("<h1>SpiderFuzz Report</h1>");
            sb.AppendLine($"<p>Generated: {DateTime.Now:O} | Elapsed: {stats.ElapsedTime} | Iterations: {stats.TotalIterations:N0} | Execs: {stats.TotalExecs:N0} | Exec/s: {stats.ExecPerSecond:N0}</p>");
            sb.AppendLine("<table><tr><th>Category</th><th>Unique</th><th>Total</th></tr>");
            sb.AppendLine($"<tr class=\"crash\"><td>Crashes</td><td>{_uniqueCrashCount}</td><td>{_crashCount}</td></tr>");
            sb.AppendLine($"<tr class=\"hang\"><td>Hangs</td><td>{_uniqueHangCount}</td><td>{_hangCount}</td></tr>");
            sb.AppendLine($"<tr class=\"finding\"><td>Findings</td><td>{_uniqueFindingCount}</td><td>{_findingCount}</td></tr>");
            sb.AppendLine($"<tr class=\"diff\"><td>Tier differentials</td><td>{_uniqueDifferentialCount}</td><td>{_differentialCount}</td></tr>");
            sb.AppendLine($"<tr><td>Corpus</td><td colspan=\"2\">{stats.CorpusSize:N0} ({stats.CorpusSizeBytes:N0} bytes)</td></tr>");
            sb.AppendLine("</table>");

            void ListDir(string label, string dir, string cls)
            {
                if (!Directory.Exists(dir)) return;
                var files = Directory.GetFiles(dir, "*.js").OrderByDescending(File.GetLastWriteTimeUtc).ToList();
                sb.AppendLine($"<h2>{label} ({files.Count})</h2><ul>");
                foreach (var f in files.Take(500))
                {
                    var rel = Path.GetRelativePath(_outputDir, f).Replace('\\', '/');
                    sb.AppendLine($"<li class=\"{cls}\"><a href=\"{Uri.EscapeDataString(rel).Replace("%2F", "/")}\">{System.Net.WebUtility.HtmlEncode(Path.GetFileName(f))}</a></li>");
                }
                sb.AppendLine("</ul>");
            }

            ListDir("Crashes", _crashesDir, "crash");
            ListDir("Hangs", _hangsDir, "hang");
            ListDir("Findings", _findingsDir, "finding");
            ListDir("Tier differentials", _diffsDir, "diff");

            sb.AppendLine("</body></html>");
            File.WriteAllText(Path.Combine(_outputDir, "report.html"), sb.ToString());
        }
        catch { /* best-effort status page, never fatal to the campaign */ }
    }

    public void Dispose()
    {
    }
}

internal sealed class FuzzerStats
{
    public long TotalIterations { get; set; }
    public long ExecPerSecond { get; set; }
    public long TotalExecs { get; set; }
    public int UniqueCrashes { get; set; }
    public int UniqueHangs { get; set; }
    public int TotalCrashes { get; set; }
    public int TotalHangs { get; set; }
    public int UniqueFindings { get; set; }
    public int TotalFindings { get; set; }
    public int UniqueDifferentials { get; set; }
    public int TotalDifferentials { get; set; }
    public int CorpusSize { get; set; }
    public string ElapsedTime { get; set; } = "";
    public long CorpusSizeBytes { get; set; }
}
