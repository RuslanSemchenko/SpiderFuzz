using System.Text;

namespace SpiderFuzz.Fuzzer;

internal sealed class InputMinimizer
{
    private readonly ProcessRunner _runner;
    private readonly CrashManager _crashManager;
    private readonly int _maxAttempts;

    public InputMinimizer(ProcessRunner runner, CrashManager crashManager, int maxAttempts = 100)
    {
        _runner = runner;
        _crashManager = crashManager;
        _maxAttempts = maxAttempts;
    }

    public MinimizeResult Minimize(string code, RunResult originalResult)
    {
        var result = new MinimizeResult
        {
            OriginalLength = code.Length,
            OriginalResult = originalResult,
        };

        if (originalResult.Status != RunStatus.Crash && !originalResult.TimedOut)
        {
            result.MinimizedCode = code;
            result.Success = false;
            return result;
        }

        var bestCode = RemoveLines(code, originalResult);
        bestCode = BinaryMinimize(bestCode, originalResult);
        bestCode = RemoveWhitespace(bestCode, originalResult);

        result.MinimizedCode = bestCode;
        result.MinimizedLength = bestCode.Length;
        result.Success = bestCode.Length < code.Length;

        if (result.Success)
        {
            result.Ratio = (1.0 - (double)bestCode.Length / code.Length) * 100;
        }

        return result;
    }

    private string BinaryMinimize(string code, RunResult originalResult)
    {
        var lines = SplitIntoLines(code);
        var best = lines.ToArray();
        var bestLen = code.Length;

        for (var pass = 0; pass < 3; pass++)
        {
            var changed = false;
            var chunkSize = Math.Max(1, best.Length / (4 + pass * 2));

            for (var i = 0; i < best.Length; i += chunkSize)
            {
                var end = Math.Min(i + chunkSize, best.Length);
                var candidate = new string[best.Length - (end - i)];
                Array.Copy(best, 0, candidate, 0, i);
                Array.Copy(best, end, candidate, i, best.Length - end);

                var candidateCode = string.Join("\n", candidate);
                var result = _runner.Run(candidateCode);

                if (MatchesCrash(result, originalResult))
                {
                    best = candidate;
                    bestLen = candidateCode.Length;
                    changed = true;
                    i -= chunkSize;
                }
            }

            if (!changed) break;
        }

        return string.Join("\n", best);
    }

    private string RemoveLines(string code, RunResult originalResult)
    {
        var lines = SplitIntoLines(code).ToList();
        var attempts = 0;

        for (var i = lines.Count - 1; i >= 0 && attempts < _maxAttempts; i--)
        {
            if (i >= lines.Count) continue;
            if (IsStructuralLine(lines[i])) continue;

            var candidate = new List<string>(lines);
            candidate.RemoveAt(i);
            attempts++;

            var candidateCode = string.Join("\n", candidate);
            var result = _runner.Run(candidateCode);

            if (MatchesCrash(result, originalResult))
            {
                lines = candidate;
            }
        }

        return string.Join("\n", lines);
    }

    private string RemoveWhitespace(string code, RunResult originalResult)
    {
        var candidates = new[]
        {
            code.Replace("\r\n", "\n"),
            code.Replace("\r\n", "\n").Replace("\n\n", "\n"),
            code.Replace("\r\n", "\n").Replace("  ", " ").Replace("  ", " "),
            code.Replace("\r\n", "\n").Replace("    ", "\t"),
            code.Replace("\r\n", "\n").Replace("\n {\n", "{\n").Replace("\n }\n", "}\n"),
        };

        foreach (var candidate in candidates)
        {
            if (candidate.Length >= code.Length) continue;
            var result = _runner.Run(candidate);
            if (MatchesCrash(result, originalResult))
            {
                code = candidate;
            }
        }

        return code;
    }

    private static bool MatchesCrash(RunResult result, RunResult original)
    {
        if (result.Status == RunStatus.Crash && original.Status == RunStatus.Crash)
        {
            if (result.ExitCode != original.ExitCode) return false;
            if (!string.IsNullOrEmpty(original.CrashType) && !string.IsNullOrEmpty(result.CrashType))
                return result.CrashType == original.CrashType;
            return true;
        }

        if (result.TimedOut && original.TimedOut)
            return true;

        return false;
    }

    private static bool IsStructuralLine(string line)
    {
        var trimmed = line.Trim();
        return trimmed == "{" || trimmed == "}" ||
               trimmed == "];" || trimmed == "};" ||
               trimmed == "else" || trimmed == "try" ||
               trimmed == "finally";
    }

    private static List<string> SplitIntoLines(string code)
        => code.Split('\n').ToList();
}

internal sealed class MinimizeResult
{
    public string MinimizedCode { get; set; } = "";
    public int OriginalLength { get; set; }
    public int MinimizedLength { get; set; }
    public bool Success { get; set; }
    public double Ratio { get; set; }
    public RunResult OriginalResult { get; set; } = new();
}
