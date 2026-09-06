using System.Text;

namespace SpiderFuzz.Fuzzer;

/// <summary>
/// Offline "--cmin" pass, analogous to afl-cmin: replays every saved corpus
/// file through a brand-new, empty <see cref="CoverageTracker"/> (smallest
/// files first) and keeps only the entries that still contribute something
/// the tracker has not already seen. A long-running campaign accumulates
/// thousands of corpus entries whose coverage is a strict subset of some
/// smaller/earlier file (e.g. many generator outputs differing only in
/// variable names or literal values), which slows every later run down
/// (bigger inputs, more scheduler overhead) without adding fuzzing power.
/// </summary>
internal sealed class CorpusMinimizer : IDisposable
{
    private readonly PersistentRunner _runner;
    private readonly string _corpusDir;

    public CorpusMinimizer(FuzzerConfig config)
    {
        _runner = new PersistentRunner(config.JsExePath, config.TimeoutMs, config.UseAsan, workerId: 9000);
        _corpusDir = Path.Combine(config.OutputDir, "corpus");
    }

    public MinimizationSummary Run()
    {
        var summary = new MinimizationSummary();
        if (!Directory.Exists(_corpusDir))
        {
            summary.Error = $"Corpus directory not found: {_corpusDir}";
            return summary;
        }

        var files = Directory.GetFiles(_corpusDir, "*.js")
            // Size-ordered greedy set cover, like afl-cmin: when two entries
            // exercise the same feature set, keep the cheaper one to re-run.
            .OrderBy(f => new FileInfo(f).Length)
            .ToList();

        var tracker = new CoverageTracker();
        var remove = new List<string>();

        foreach (var file in files)
        {
            string code;
            try { code = File.ReadAllText(file); }
            catch { continue; }

            RunResult result;
            try { result = _runner.Run(code); }
            catch { result = new RunResult { Status = RunStatus.Error }; }

            var record = tracker.Record(result, code);
            summary.Processed++;
            summary.OriginalBytes += Encoding.UTF8.GetByteCount(code);

            if (tracker.IsInteresting(record))
            {
                summary.KeptCount++;
                summary.KeptBytes += Encoding.UTF8.GetByteCount(code);
            }
            else
            {
                remove.Add(file);
            }
        }

        summary.OriginalCount = files.Count;
        summary.RemovedCount = remove.Count;

        if (remove.Count > 0)
        {
            var removedDir = Path.GetFullPath(Path.Combine(_corpusDir, "..", $"corpus_removed_{DateTime.Now:yyyyMMdd_HHmmss}"));
            Directory.CreateDirectory(removedDir);
            foreach (var file in remove)
            {
                try { File.Move(file, Path.Combine(removedDir, Path.GetFileName(file))); }
                catch { /* best-effort: leave it in place rather than lose it */ }
            }
            summary.RemovedDir = removedDir;
        }

        return summary;
    }

    public void Dispose() => _runner.Dispose();
}

internal sealed class MinimizationSummary
{
    public string? Error { get; set; }
    public int Processed { get; set; }
    public int OriginalCount { get; set; }
    public int KeptCount { get; set; }
    public int RemovedCount { get; set; }
    public long OriginalBytes { get; set; }
    public long KeptBytes { get; set; }
    public string? RemovedDir { get; set; }
}
