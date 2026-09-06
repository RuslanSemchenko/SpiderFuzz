using System.Text;

namespace SpiderFuzz.Fuzzer;

/// <summary>
/// Offline "--triage" pass: replays every saved crash/hang file (or any
/// directory of .js repros) once against the CURRENT target build and
/// reports whether each one still reproduces. Meant to be run after
/// rebuilding the engine (e.g. after landing a fix, or after pulling newer
/// mozilla-central) to separate "already fixed" from "still broken" without
/// re-reading every file by hand.
/// </summary>
internal sealed class TriageRunner : IDisposable
{
    private readonly ProcessRunner _runner;

    public TriageRunner(FuzzerConfig config)
    {
        _runner = new ProcessRunner(config.JsExePath, config.TimeoutMs, config.UseAsan);
    }

    public TriageSummary Run(string targetDir)
    {
        var summary = new TriageSummary();
        if (!Directory.Exists(targetDir))
        {
            summary.Error = $"Directory not found: {targetDir}";
            return summary;
        }

        var files = Directory.GetFiles(targetDir, "*.js", SearchOption.AllDirectories).OrderBy(f => f).ToList();
        var report = new StringBuilder();

        foreach (var file in files)
        {
            string raw;
            try { raw = File.ReadAllText(file); }
            catch { continue; }

            var priorType = ExtractHeaderField(raw, "// Crash Type: ")
                ?? ExtractHeaderField(raw, "// Type: ")
                ?? "unknown";
            var code = ExtractCodeBody(raw);

            RunResult result;
            try { result = _runner.Run(code); }
            catch (Exception ex) { result = new RunResult { Status = RunStatus.Error, ErrorMessage = ex.Message }; }

            // "FIXED" is deliberately conservative: it means the replay ran
            // cleanly to completion (exit 0), nothing less. TriageRunner uses
            // the plain per-process ProcessRunner (no newGlobal driver), which
            // never computes IsSemanticFinding - so a saved semantic-regression
            // finding (a bare uncaught "throw new Error(...)") would otherwise
            // fall through every other branch and get misreported as FIXED
            // even though it still throws exactly as before.
            string verdict;
            if (result.Status == RunStatus.Crash) verdict = $"STILL_CRASHES ({result.CrashType})";
            else if (result.TimedOut) verdict = "STILL_HANGS";
            else if (result.Status == RunStatus.NonZeroExit) verdict = "STILL_FINDING (non-zero exit / uncaught exception)";
            else if (result.Status == RunStatus.Error) verdict = $"ERROR ({result.ErrorMessage})";
            else verdict = "FIXED";

            if (verdict == "FIXED") summary.FixedCount++;
            else summary.StillReproCount++;

            summary.Results.Add(new TriageEntry { File = file, PriorClassification = priorType, CurrentVerdict = verdict });
            report.AppendLine($"{verdict,-28} {Path.GetFileName(file)}  (was: {priorType})");
        }

        summary.ReportText = report.ToString();
        return summary;
    }

    private static string? ExtractHeaderField(string content, string prefix)
    {
        foreach (var line in content.Split('\n'))
        {
            var trimmed = line.TrimStart();
            if (trimmed.StartsWith(prefix, StringComparison.Ordinal))
                return trimmed[prefix.Length..].Trim();
            if (!trimmed.StartsWith("//", StringComparison.Ordinal) && trimmed.Trim().Length > 0)
                break;
        }
        return null;
    }

    /// <summary>
    /// Strips exactly the "// ..." header block plus its single blank
    /// separator line that <see cref="CrashManager"/> writes in front of
    /// every saved repro, leaving the original JS untouched (even if it
    /// legitimately starts with its own "//" comment). Files without that
    /// header (e.g. a hand-picked .js dropped into the directory) pass
    /// through unchanged.
    /// </summary>
    private static string ExtractCodeBody(string fileContent)
    {
        var lines = fileContent.Replace("\r\n", "\n").Split('\n');
        var idx = 0;
        while (idx < lines.Length && lines[idx].TrimStart().StartsWith("//", StringComparison.Ordinal))
            idx++;
        if (idx < lines.Length && lines[idx].Trim().Length == 0)
            idx++;
        return string.Join('\n', lines.Skip(idx));
    }

    public void Dispose() => _runner.Dispose();
}

internal sealed class TriageSummary
{
    public string? Error { get; set; }
    public int FixedCount { get; set; }
    public int StillReproCount { get; set; }
    public List<TriageEntry> Results { get; } = [];
    public string ReportText { get; set; } = "";
}

internal sealed class TriageEntry
{
    public string File { get; set; } = "";
    public string PriorClassification { get; set; } = "";
    public string CurrentVerdict { get; set; } = "";
}
