using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace SpiderFuzz.Fuzzer;

internal sealed class ParallelManager : IDisposable
{
    private readonly FuzzerConfig _config;
    private readonly List<Process> _workers = [];
    private readonly string _sharedCorpusDir;
    private readonly string _sharedCrashesDir;
    private readonly string _sharedHangsDir;
    private readonly string _sharedFindingsDir;
    private readonly string _sharedDiffsDir;
    private readonly string _sharedStatsFile;
    private volatile bool _running;
    private readonly CancellationTokenSource _cts = new();

    public ParallelManager(FuzzerConfig config)
    {
        _config = config;
        _sharedCorpusDir = Path.Combine(config.OutputDir, "corpus");
        _sharedCrashesDir = Path.Combine(config.OutputDir, "crashes");
        _sharedHangsDir = Path.Combine(config.OutputDir, "hangs");
        _sharedFindingsDir = Path.Combine(config.OutputDir, "findings");
        _sharedDiffsDir = Path.Combine(config.OutputDir, "diffs");
        _sharedStatsFile = Path.Combine(config.OutputDir, "parallel_stats.json");
        Directory.CreateDirectory(_sharedCorpusDir);
        Directory.CreateDirectory(_sharedCrashesDir);
        Directory.CreateDirectory(_sharedHangsDir);
        Directory.CreateDirectory(_sharedFindingsDir);
        Directory.CreateDirectory(_sharedDiffsDir);
    }

    public void Run()
    {
        _running = true;
        var workerCount = _config.ParallelWorkers > 0
            ? _config.ParallelWorkers
            : Math.Max(1, Environment.ProcessorCount - 1);

        Console.WriteLine($"=== Parallel Fuzzing: {workerCount} workers ===");

        var workerOutputs = new string[workerCount];
        for (var i = 0; i < workerCount; i++)
        {
            workerOutputs[i] = Path.Combine(_config.OutputDir, $"worker_{i}");
        }

        var tasks = new Task<WorkerResult>[workerCount];
        for (var i = 0; i < workerCount; i++)
        {
            var workerId = i;
            var outputDir = workerOutputs[i];
            tasks[i] = Task.Run(() => RunWorker(workerId, outputDir));
        }

        var statsTask = Task.Run(() => MonitorStats(workerOutputs));

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            _running = false;
            _cts.Cancel();
        };

        Task.WaitAll(tasks);
        _running = false;
        statsTask.Wait(2000);

        Console.WriteLine("\n=== All workers finished ===");
        AggregateResults(workerOutputs);
    }

    private WorkerResult RunWorker(int workerId, string outputDir)
    {
        var result = new WorkerResult { WorkerId = workerId };

        try
        {
            Directory.CreateDirectory(outputDir);

            // Each worker's CrashManager only ever loads corpus from ITS OWN
            // outputDir/corpus, never from the shared aggregated one - without
            // this, a fresh parallel run (or a worker whose own history is
            // thin) starts blind to everything --cmin or earlier campaigns
            // already accumulated in the shared corpus.
            SeedWorkerCorpusFromShared(outputDir);

            var workerConfig = CloneConfig(_config);
            workerConfig.OutputDir = outputDir;
            workerConfig.WorkerId = workerId;
            workerConfig.Seed += workerId * 1000 + 1;

            using var engine = new FuzzerEngine(workerConfig);
            engine.Run();
            result.Success = true;
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
            Console.WriteLine($"[Worker {workerId}] Error: {ex.Message}");
        }

        return result;
    }

    private void SeedWorkerCorpusFromShared(string workerOutputDir)
    {
        if (!Directory.Exists(_sharedCorpusDir)) return;

        var workerCorpusDir = Path.Combine(workerOutputDir, "corpus");
        Directory.CreateDirectory(workerCorpusDir);
        foreach (var file in Directory.GetFiles(_sharedCorpusDir, "*.js"))
        {
            var dest = Path.Combine(workerCorpusDir, Path.GetFileName(file));
            if (!File.Exists(dest))
            {
                try { File.Copy(file, dest); } catch { }
            }
        }
    }

    /// <summary>
    /// Copies every not-yet-seen .js file from each worker's own output
    /// subdirectory into the corresponding shared directory. Crashes/hangs/
    /// findings/diffs are cheap and synced on every tick; corpus can be large
    /// (thousands of files by the time a campaign has run a while) so the
    /// caller only passes <paramref name="includeCorpus"/> = true periodically.
    /// Running this throughout the campaign - not just once at the very end in
    /// <see cref="AggregateResults"/> - matters because a worker that gets
    /// killed (Ctrl+C, OOM, crash) never reaches its own clean shutdown path.
    /// </summary>
    private void SyncSharedArtifacts(string[] workerOutputs, bool includeCorpus)
    {
        static void CopyNewFiles(string srcDir, string destDir)
        {
            if (!Directory.Exists(srcDir)) return;
            foreach (var file in Directory.GetFiles(srcDir, "*.js"))
            {
                var dest = Path.Combine(destDir, Path.GetFileName(file));
                if (!File.Exists(dest))
                {
                    try { File.Copy(file, dest); } catch { }
                }
            }
        }

        foreach (var dir in workerOutputs)
        {
            CopyNewFiles(Path.Combine(dir, "crashes"), _sharedCrashesDir);
            CopyNewFiles(Path.Combine(dir, "hangs"), _sharedHangsDir);
            CopyNewFiles(Path.Combine(dir, "findings"), _sharedFindingsDir);
            CopyNewFiles(Path.Combine(dir, "diffs"), _sharedDiffsDir);
            if (includeCorpus)
                CopyNewFiles(Path.Combine(dir, "corpus"), _sharedCorpusDir);
        }
    }

    private void MonitorStats(string[] workerOutputs)
    {
        var tick = 0;
        while (_running)
        {
            Thread.Sleep(5000);
            if (!_running) break;
            tick++;

            try
            {
                var totalCrashes = 0;
                var totalDifferentials = 0;
                var totalExecs = 0L;

                foreach (var dir in workerOutputs)
                {
                    var statsFile = Path.Combine(dir, "stats.json");
                    if (!File.Exists(statsFile)) continue;
                    try
                    {
                        var json = File.ReadAllText(statsFile);
                        var stats = JsonSerializer.Deserialize<FuzzerStats>(json);
                        if (stats != null)
                        {
                            totalCrashes += stats.UniqueCrashes;
                            totalDifferentials += stats.UniqueDifferentials;
                            totalExecs += stats.TotalExecs;
                        }
                    }
                    catch { }
                }

                var crashCount = 0;
                foreach (var dir in workerOutputs)
                {
                    var wc = Path.Combine(dir, "crashes");
                    if (Directory.Exists(wc))
                        crashCount += Directory.GetFiles(wc, "*.js").Length;
                }

                // Corpus sync is more expensive (far more files) than the other
                // categories, so it only runs roughly every 30s instead of every
                // 5s tick.
                SyncSharedArtifacts(workerOutputs, includeCorpus: tick % 6 == 0);

                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.Write("[PARALLEL] ");
                Console.ResetColor();
                Console.WriteLine($"execs: {totalExecs:N0} | crashes: {totalCrashes} | crash files: {crashCount} | diffs: {totalDifferentials}");
            }
            catch { }
        }
    }

    private void AggregateResults(string[] workerOutputs)
    {
        Console.WriteLine("\n=== Aggregate Results ===");

        var totalCrashes = 0;
        var totalHangs = 0;
        var totalFindings = 0;
        var totalDifferentials = 0;
        var totalExecs = 0L;

        foreach (var dir in workerOutputs)
        {
            var statsFile = Path.Combine(dir, "stats.json");
            if (File.Exists(statsFile))
            {
                try
                {
                    var json = File.ReadAllText(statsFile);
                    var stats = JsonSerializer.Deserialize<FuzzerStats>(json);
                    if (stats != null)
                    {
                        totalCrashes += stats.UniqueCrashes;
                        totalHangs += stats.UniqueHangs;
                        totalFindings += stats.UniqueFindings;
                        totalDifferentials += stats.UniqueDifferentials;
                        totalExecs += stats.TotalExecs;
                    }
                }
                catch { }
            }
        }

        // Final, unconditional sync (including corpus) now that every worker
        // has stopped - covers whatever the periodic MonitorStats ticks in
        // Run() hadn't caught up with yet.
        SyncSharedArtifacts(workerOutputs, includeCorpus: true);

        Console.WriteLine($"Total execs:   {totalExecs:N0}");
        Console.WriteLine($"Total crashes: {totalCrashes}");
        Console.WriteLine($"Total hangs:   {totalHangs}");
        Console.WriteLine($"Total findings: {totalFindings}");
        Console.WriteLine($"Total diffs:   {totalDifferentials}");

        try
        {
            var allCrashes = Directory.GetFiles(_sharedCrashesDir, "*.js");
            var allCorpus = Directory.GetFiles(_sharedCorpusDir, "*.js");
            Console.WriteLine($"Shared crash files: {allCrashes.Length}");
            Console.WriteLine($"Shared corpus files: {allCorpus.Length}");

            var aggStats = new FuzzerStats
            {
                TotalExecs = totalExecs,
                UniqueCrashes = totalCrashes,
                UniqueHangs = totalHangs,
                UniqueFindings = totalFindings,
                UniqueDifferentials = totalDifferentials,
                CorpusSize = allCorpus.Length,
            };
            var json = JsonSerializer.Serialize(aggStats, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(Path.Combine(_config.OutputDir, "stats.json"), json);
            File.WriteAllText(_sharedStatsFile, json);
        }
        catch { }
    }

    private static FuzzerConfig CloneConfig(FuzzerConfig source)
    {
        return new FuzzerConfig
        {
            JsExePath = source.JsExePath,
            OutputDir = source.OutputDir,
            SeedDir = source.SeedDir,
            TimeoutMs = source.TimeoutMs,
            UseAsan = source.UseAsan,
            MaxIterations = source.MaxIterations,
            Seed = source.Seed,
            ReportIntervalMs = source.ReportIntervalMs,
            ParallelWorkers = 0,
            PersistentMode = source.PersistentMode,
            MinimizeCrashes = source.MinimizeCrashes,
            UseDictionary = source.UseDictionary,
            ResumeOnStart = source.ResumeOnStart,
            CoverageGuided = source.CoverageGuided,
            SaveNewCoverage = source.SaveNewCoverage,
            CorpusFuzzChance = source.CorpusFuzzChance,
            // These two were previously dropped, silently resetting every
            // worker back to the class defaults regardless of what was passed
            // on the command line (e.g. --custom-mutator-chance).
            CustomMutators = source.CustomMutators,
            CustomMutatorChance = source.CustomMutatorChance,
            SpliceEnabled = source.SpliceEnabled,
            SpliceChance = source.SpliceChance,
            FreshGenerateChance = source.FreshGenerateChance,
            WorkerId = source.WorkerId,
            DifferentialTesting = source.DifferentialTesting,
            DifferentialChance = source.DifferentialChance,
            ExperimentalFeatures = source.ExperimentalFeatures,
            ExperimentalChance = source.ExperimentalChance,
        };
    }

    public void Dispose()
    {
        _cts.Dispose();
    }
}

internal sealed class WorkerResult
{
    public int WorkerId { get; set; }
    public bool Success { get; set; }
    public string? Error { get; set; }
}
