using System.Collections.Concurrent;
using System.Diagnostics;

namespace SpiderFuzz.Fuzzer;

internal sealed class FuzzerEngine : IDisposable
{
    private readonly ProcessRunner _runner;
    private readonly PersistentRunner? _persistentRunner;
    private readonly CrashManager _crashManager;
    private readonly FuzzerConfig _config;
    private readonly CodeGenerator _generator;
    private readonly CoverageTracker _coverage;
    private readonly EnergyScheduler _scheduler;
    private readonly InputMinimizer _minimizer;
    private readonly DifferentialTester? _differentialTester;
    private readonly PersistentRunner? _experimentalRunner;
    private readonly List<string> _strategyList = [];
    private volatile bool _running;
    private long _totalIterations;
    private long _totalExecs;
    private long _totalNewFeatures;
    private long _totalNewOutputs;
    private long _totalDifferentialChecks;
    private readonly Stopwatch _runtime = new();
    private readonly Random _rng;

    // Flags for language/API surface that is implemented but sits behind a
    // shell flag (not yet on by default) on the build this was verified
    // against - each hand-confirmed to exist and combine cleanly via a real
    // js.exe shell. Kept separate from DifferentialTester.Configs because the
    // point here is coverage of not-yet-shipped surface, not tier comparison.
    private static readonly string[] ExperimentalFlags =
    [
        "--enable-temporal",
        "--enable-iterator-range",
        "--enable-joint-iteration",
        "--enable-iterator-chunking",
        "--enable-promise-allkeyed",
        "--enable-arraybuffer-immutable",
    ];

    public FuzzerEngine(FuzzerConfig config)
    {
        _config = config;
        _rng = new Random(config.Seed);
        _runner = new ProcessRunner(config.JsExePath, config.TimeoutMs, config.UseAsan);

        if (config.PersistentMode)
        {
            _persistentRunner = new PersistentRunner(config.JsExePath, config.TimeoutMs, config.UseAsan, config.WorkerId);
        }

        _crashManager = new CrashManager(config.OutputDir);
        _generator = new CodeGenerator(config.Seed);
        _coverage = new CoverageTracker();
        _scheduler = new EnergyScheduler();
        _minimizer = new InputMinimizer(_runner, _crashManager);

        if (config.DifferentialTesting)
            _differentialTester = new DifferentialTester(config.JsExePath, config.TimeoutMs);

        if (config.ExperimentalFeatures)
            _experimentalRunner = new PersistentRunner(config.JsExePath, config.TimeoutMs, config.UseAsan,
                config.WorkerId + 4000, ExperimentalFlags);

        for (var i = 0; i < 28; i++) _strategyList.Add($"strategy_{i}");

        LoadCorpus();
        _runtime.Start();
    }

    public void Run()
    {
        _running = true;

        PrintBanner();

        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            _running = false;
            Console.WriteLine("\n[!] Stopping gracefully...");
        };

        var lastReportTime = Stopwatch.StartNew();
        long reportExecs = 0;

        while (_running && _totalIterations < _config.MaxIterations)
        {
            var target = SelectTarget();
            var input = CreateInputFromTarget(target);
            var runTarget = _persistentRunner != null ? (object)_persistentRunner : _runner;
            var result = SafeRun(runTarget, input);

            Interlocked.Increment(ref _totalIterations);
            reportExecs++;
            _totalExecs++;

            var record = _coverage.Record(result, input);

            if (result.IsInteresting)
            {
                HandleInteresting(result, input, (int)_totalIterations, target);
            }
            else if (result.IsSemanticFinding)
            {
                HandleSemanticFinding(result, input, (int)_totalIterations);
                if (_coverage.IsInteresting(record) && input.Length < 50000)
                    HandleNewCoverage(input, target, record);
            }
            else if (_coverage.IsInteresting(record) && input.Length < 50000)
            {
                HandleNewCoverage(input, target, record);
            }

            // Both checks below re-execute the SAME input under a different
            // engine configuration, independent of whatever the branches above
            // just decided - they run alongside, not instead of, normal
            // handling, since a boring/already-seen input under the default
            // config can still be the first one to expose a tier- or
            // feature-flag-specific bug.
            if (_differentialTester != null && result.Status == RunStatus.Ok
                && input.Length < 20000 && _rng.Next(100) < _config.DifferentialChance
                && DifferentialTester.LooksDeterministic(input))
            {
                RunDifferential(input, (int)_totalIterations);
            }

            if (_experimentalRunner != null && input.Length < 20000
                && _rng.Next(100) < _config.ExperimentalChance)
            {
                RunExperimental(input, (int)_totalIterations);
            }

            if (_totalIterations % 5000 == 0)
            {
                _scheduler.Decay();
            }

            if (lastReportTime.ElapsedMilliseconds >= _config.ReportIntervalMs)
            {
                var eps = reportExecs * 1000.0 / Math.Max(1, lastReportTime.ElapsedMilliseconds);
                lastReportTime.Restart();
                reportExecs = 0;
                PrintStatus(eps);
                _crashManager.GenerateReport(BuildStats());
            }
        }

        _running = false;
        PrintFinalStats();
        SaveStats();
    }

    private CorpusEntryEx SelectTarget()
    {
        // PickNext() only returns null when the corpus is completely empty,
        // which - once any seed has loaded - never happens again for the
        // rest of the run. Without this standalone chance, CodeGenerator's
        // whole from-scratch strategy library (GC stress, JIT chaos, the
        // 2024-2026 feature generators, etc.) would only ever run during an
        // unreachable cold-start sliver, never for the remainder of a real
        // campaign: everything else is a mutation/splice of existing corpus
        // entries. Rolling it here keeps fresh, unrelated-to-corpus shapes
        // flowing in for the whole campaign, not just its first few inputs.
        if (_config.FreshGenerateChance > 0 && _rng.Next(100) < _config.FreshGenerateChance)
            return MakeFreshGeneratedTarget();

        var entry = _scheduler.PickNext();
        if (entry != null) return entry;

        return MakeFreshGeneratedTarget();
    }

    private CorpusEntryEx MakeFreshGeneratedTarget()
    {
        var code = _generator.Generate();
        return new CorpusEntryEx
        {
            Code = code,
            Strategy = "generate",
            Hash = CorpusEntryEx.ComputeHash(code),
            Energy = 10,
            Priority = 10,
        };
    }

    private string CreateInputFromTarget(CorpusEntryEx target)
    {
        if (_config.CustomMutators && _rng.Next(100) < _config.CustomMutatorChance)
            return _generator.MutateCustom(target.Code);

        // AFL-style crossover between two unrelated corpus entries. This is
        // the main way genuinely new combinations of language features get
        // exercised together, so try it before falling back to mutating a
        // single input in isolation.
        if (_config.SpliceEnabled && _rng.Next(100) < _config.SpliceChance)
        {
            var partner = _scheduler.PickRandomForSplice();
            if (partner != null && partner.Hash != target.Hash)
                return _generator.Splice(target.Code, partner.Code);
        }

        if (target.Strategy == "generate")
        {
            // Raw byte mutation almost always turns JS into a SyntaxError, so
            // give the line/statement-aware mutator the majority share.
            return _rng.Next(100) < 35 ? _generator.Mutate(target.Code) : _generator.MutateLines(target.Code);
        }

        if (_rng.Next(100) < _config.CorpusFuzzChance)
        {
            return MutateWithDictionary(target.Code, _config.UseDictionary && _rng.Next(100) < 30);
        }

        return _rng.Next(100) < 35 ? _generator.Mutate(target.Code) : _generator.MutateLines(target.Code);
    }

    private string MutateWithDictionary(string code, bool useDictionary)
    {
        var sb = new System.Text.StringBuilder(code);
        var mutations = _rng.Next(1, 4);

        for (var i = 0; i < mutations; i++)
        {
            var op = _rng.Next(6);
            switch (op)
            {
                case 0 when useDictionary:
                    InsertToken(sb, Dictionary.Keywords[_rng.Next(Dictionary.Keywords.Length)]);
                    break;
                case 1 when useDictionary:
                    InsertToken(sb, Dictionary.Builtins[_rng.Next(Dictionary.Builtins.Length)]);
                    break;
                case 2 when useDictionary:
                    InsertToken(sb, Dictionary.PropertyNames[_rng.Next(Dictionary.PropertyNames.Length)]);
                    break;
                case 3 when useDictionary:
                    InsertToken(sb, Dictionary.MethodNames[_rng.Next(Dictionary.MethodNames.Length)]);
                    break;
                case 4:
                    InsertToken(sb, Dictionary.SpecialValues[_rng.Next(Dictionary.SpecialValues.Length)]);
                    break;
                default:
                    if (sb.Length > 0)
                    {
                        var pos = _rng.Next(sb.Length);
                        sb.Insert(pos, (char)_rng.Next(256));
                    }
                    break;
            }
        }

        return sb.ToString();
    }

    private void InsertToken(System.Text.StringBuilder sb, string token)
    {
        if (sb.Length == 0)
        {
            sb.Append(token);
            return;
        }

        var pos = sb.Length > 2 ? _rng.Next(2, sb.Length) : 0;
        var sep = _rng.Next(3) switch
        {
            0 => " ",
            1 => "\n",
            _ => ";\n",
        };
        sb.Insert(pos, sep + token + " ");
    }

    private void HandleInteresting(RunResult result, string code, int iteration, CorpusEntryEx target)
    {
        if (result.Status == RunStatus.Crash)
        {
            _scheduler.NotifyCrash(target.Hash);
            var saved = _crashManager.SaveCrash(result, code, iteration);

            if (saved)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[CRASH] Unique #{_crashManager.UniqueCrashCount} | Type: {result.CrashType} | Exit: 0x{unchecked((uint)result.ExitCode):X8} | Iter: {iteration}");
                Console.ResetColor();

                if (_config.MinimizeCrashes)
                {
                    MinimizeCrash(result, code, iteration);
                }
            }
        }
        else if (result.TimedOut)
        {
            _scheduler.NotifyCrash(target.Hash);
            var saved = _crashManager.SaveHang(result, code, iteration);
            if (saved)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"\n[HANG] Unique #{_crashManager.UniqueHangCount} | Iter: {iteration}");
                Console.ResetColor();

                if (_config.MinimizeCrashes)
                {
                    MinimizeCrash(result, code, iteration);
                }
            }
        }
    }

    private void HandleSemanticFinding(RunResult result, string code, int iteration)
    {
        var saved = _crashManager.SaveFinding(code, result.AssertionMessage ?? "", iteration);
        if (saved)
        {
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine($"\n[FINDING] Unique #{_crashManager.UniqueFindingCount} | \"{result.AssertionMessage}\" | Iter: {iteration}");
            Console.ResetColor();
        }
    }

    private void MinimizeCrash(RunResult result, string code, int iteration)
    {
        try
        {
            Console.Write("  [MINIMIZE] ");
            var min = _minimizer.Minimize(code, result);

            if (min.Success)
            {
                Console.WriteLine($"reduced {min.OriginalLength} -> {min.MinimizedLength} bytes ({min.Ratio:F1}%)");
                var isCrash = result.Status == RunStatus.Crash;
                var saved = isCrash
                    ? _crashManager.SaveCrash(result, min.MinimizedCode, iteration, isMinimized: true)
                    : _crashManager.SaveHang(result, min.MinimizedCode, iteration, isMinimized: true);
                if (saved)
                    Console.WriteLine($"  [MINIMIZE] saved minimized repro to {(isCrash ? "crashes/" : "hangs/")} (iter {iteration})");
            }
            else
            {
                Console.WriteLine("could not reduce further.");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"minimize error: {ex.Message}");
        }
    }

    private void HandleNewCoverage(string code, CorpusEntryEx target, CoverageRecord record)
    {
        var score = record.Score;
        _totalNewFeatures++;
        if (record.NewOutput) _totalNewOutputs++;

        _scheduler.Add(code, target.Strategy, record);
        _scheduler.NotifyFind(target.Hash, score);

        if (_config.SaveNewCoverage)
        {
            _crashManager.SaveCorpus(code, target.Strategy);
        }
    }

    /// <summary>
    /// Re-runs <paramref name="code"/> against a few alternate JIT-tier
    /// configurations via <see cref="DifferentialTester"/>. Independent of the
    /// normal crash/finding/coverage handling above - see the call site in
    /// <see cref="Run"/> for why this runs alongside it rather than instead.
    /// </summary>
    private void RunDifferential(string code, int iteration)
    {
        if (_differentialTester == null) return;

        DifferentialOutcome outcome;
        try { outcome = _differentialTester.Check(code); }
        catch { return; }

        _totalDifferentialChecks++;
        if (!outcome.IsInteresting) return;

        if (outcome.CrashConfig != null && outcome.CrashResult != null)
        {
            var cr = outcome.CrashResult;
            var baseType = cr.CrashType ?? ProcessRunner.ClassifyCrash(cr.ExitCode, cr.Stderr);
            cr.CrashType = $"TIER_{outcome.CrashConfig.ToUpperInvariant().Replace('-', '_')}_{baseType}";

            var saved = cr.TimedOut
                ? _crashManager.SaveHang(cr, code, iteration)
                : _crashManager.SaveCrash(cr, code, iteration);

            if (saved)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[TIER-CRASH] Unique #{_crashManager.UniqueCrashCount} | Config: {outcome.CrashConfig} | Iter: {iteration}");
                Console.ResetColor();
            }
            return;
        }

        if (outcome.Mismatch)
        {
            var saved = _crashManager.SaveDifferential(code, outcome.Signatures, iteration);
            if (saved)
            {
                Console.ForegroundColor = ConsoleColor.DarkCyan;
                Console.WriteLine($"\n[TIER-DIFF] Unique #{_crashManager.UniqueDifferentialCount} | tiers disagree | Iter: {iteration}");
                Console.ResetColor();
            }
        }
    }

    /// <summary>
    /// Re-runs <paramref name="code"/> against a build configured with
    /// <see cref="ExperimentalFlags"/> enabled, looking for crashes/hangs/
    /// semantic-oracle failures in surface that is not exercised at all under
    /// the default persistent runner. Independent of the normal handling above,
    /// same reasoning as <see cref="RunDifferential"/>.
    /// </summary>
    private void RunExperimental(string code, int iteration)
    {
        if (_experimentalRunner == null) return;

        RunResult result;
        try { result = _experimentalRunner.Run(code); }
        catch { return; }

        if (result.Status == RunStatus.Crash)
        {
            result.CrashType = $"EXPERIMENTAL_{result.CrashType ?? ProcessRunner.ClassifyCrash(result.ExitCode, result.Stderr)}";
            var saved = _crashManager.SaveCrash(result, code, iteration);
            if (saved)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"\n[EXPERIMENTAL-CRASH] Unique #{_crashManager.UniqueCrashCount} | Type: {result.CrashType} | Iter: {iteration}");
                Console.ResetColor();
            }
        }
        else if (result.TimedOut)
        {
            var saved = _crashManager.SaveHang(result, code, iteration);
            if (saved)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"\n[EXPERIMENTAL-HANG] Unique #{_crashManager.UniqueHangCount} | Iter: {iteration}");
                Console.ResetColor();
            }
        }
        else if (result.IsSemanticFinding)
        {
            var saved = _crashManager.SaveFinding(code, "EXPERIMENTAL: " + (result.AssertionMessage ?? ""), iteration);
            if (saved)
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine($"\n[EXPERIMENTAL-FINDING] Unique #{_crashManager.UniqueFindingCount} | \"{result.AssertionMessage}\" | Iter: {iteration}");
                Console.ResetColor();
            }
        }
    }

    private RunResult SafeRun(object runner, string code)
    {
        try
        {
            return runner switch
            {
                PersistentRunner p => p.Run(code),
                ProcessRunner r => r.Run(code),
                _ => _runner.Run(code),
            };
        }
        catch (Exception ex)
        {
            return new RunResult { Status = RunStatus.Error, ErrorMessage = ex.Message };
        }
    }

    private void LoadCorpus()
    {
        var seeds = new List<string>();

        if (_config.SeedDir != null && Directory.Exists(_config.SeedDir))
        {
            foreach (var file in Directory.GetFiles(_config.SeedDir, "*.js"))
            {
                try
                {
                    seeds.Add(File.ReadAllText(file));
                    _crashManager.SaveCorpus(File.ReadAllText(file), "seed");
                }
                catch { }
            }
        }

        if (seeds.Count == 0)
        {
            foreach (var seedCode in Seeds.Common)
            {
                seeds.Add(seedCode);
                _crashManager.SaveCorpus(seedCode, "builtin");
            }
        }

        foreach (var targetedSeed in Seeds.Targeted)
        {
            if (!seeds.Contains(targetedSeed))
            {
                seeds.Add(targetedSeed);
                _crashManager.SaveCorpus(targetedSeed, "targeted-poc");
            }
        }

        foreach (var regressionSeed in Seeds.Targeted2026)
        {
            if (!seeds.Contains(regressionSeed))
            {
                seeds.Add(regressionSeed);
                _crashManager.SaveCorpus(regressionSeed, "targeted-2026");
            }
        }

        foreach (var modernSeed in Seeds.Modern2026)
        {
            if (!seeds.Contains(modernSeed))
            {
                seeds.Add(modernSeed);
                _crashManager.SaveCorpus(modernSeed, "modern-2026");
            }
        }

        // Feature-gated on ExperimentalFlags, so under the DEFAULT persistent
        // runner these mostly no-op (harmless) - the point is that they still
        // get mutated/spliced like any other corpus entry, so by the time a
        // mutated descendant is sampled into RunExperimental() it is far more
        // likely to actually exercise the gated surface than starting from
        // scratch every time.
        foreach (var experimentalSeed in Seeds.Experimental2026)
        {
            if (!seeds.Contains(experimentalSeed))
            {
                seeds.Add(experimentalSeed);
                _crashManager.SaveCorpus(experimentalSeed, "experimental-2026");
            }
        }

        if (_config.ResumeOnStart)
        {
            try
            {
                seeds.AddRange(_crashManager.LoadCorpus());
            }
            catch { }
        }

        var distinctSeeds = seeds.Distinct().ToList();
        var runTarget = _persistentRunner != null ? (object)_persistentRunner : _runner;

        for (var i = 0; i < distinctSeeds.Count; i++)
        {
            var seed = distinctSeeds[i];
            var result = SafeRun(runTarget, seed);
            _totalExecs++;

            if ((result.Status == RunStatus.Ok || result.Status == RunStatus.NonZeroExit) && seed.Length < 50000)
            {
                var record = _coverage.Record(result, seed);
                _scheduler.Add(seed, "seed", record);

                // A built-in seed whose own oracle assertion fails right at
                // load time is a real, immediately actionable regression.
                if (result.IsSemanticFinding)
                    HandleSemanticFinding(result, seed, 0);
            }
            else if (result.IsInteresting)
            {
                HandleInteresting(result, seed, 0, new CorpusEntryEx
                {
                    Code = seed,
                    Strategy = "seed",
                    Hash = CorpusEntryEx.ComputeHash(seed),
                });
            }
        }

        Console.WriteLine($"  Loaded {_scheduler.Count} seed inputs");
    }

    private void PrintBanner()
    {
        Console.WriteLine("=== SpiderFuzz - SpiderMonkey JS Engine Fuzzer ===");
        Console.WriteLine($"Target:       {_config.JsExePath}");
        Console.WriteLine($"Output:       {_config.OutputDir}");
        Console.WriteLine($"Timeout:      {_config.TimeoutMs}ms");
        Console.WriteLine($"ASAN:         {_config.UseAsan}");
        Console.WriteLine($"Persistent:   {_config.PersistentMode}");
        Console.WriteLine($"Coverage:     {_config.CoverageGuided}");
        Console.WriteLine($"Minimize:     {_config.MinimizeCrashes}");
        Console.WriteLine($"Dictionary:   {_config.UseDictionary}");
        Console.WriteLine($"Custom muts:  {_config.CustomMutators} ({_config.CustomMutatorChance}%)");
        Console.WriteLine($"Splice:       {_config.SpliceEnabled} ({_config.SpliceChance}%)");
        Console.WriteLine($"Fresh gen:    {_config.FreshGenerateChance}% (46 strategies)");
        Console.WriteLine($"Differential: {_config.DifferentialTesting} ({_config.DifferentialChance}%, {DifferentialTester.Configs.Length} tiers)");
        Console.WriteLine($"Experimental: {_config.ExperimentalFeatures} ({_config.ExperimentalChance}%, {ExperimentalFlags.Length} flags)");
        Console.WriteLine($"Resume:       {_config.ResumeOnStart}");
        Console.WriteLine($"Corpus:       {_scheduler.Count} seeds");
        Console.WriteLine($"Max Iter:     {(_config.MaxIterations == long.MaxValue ? "unlimited" : _config.MaxIterations.ToString("N0"))}");
        Console.WriteLine($"Started:      {DateTime.Now:O}");
        Console.WriteLine(new string('=', 50));
    }

    private void PrintStatus(double eps)
    {
        Console.ForegroundColor = ConsoleColor.DarkGray;
        Console.Write($"[{_runtime.Elapsed:hh\\:mm\\:ss}] ");
        Console.ResetColor();

        Console.Write($"execs: {_totalExecs:N0} | ");
        Console.Write($"eps: {eps:N0} | ");
        Console.Write($"corpus: {_scheduler.Count} | ");

        Console.ForegroundColor = _crashManager.UniqueCrashCount > 0 ? ConsoleColor.Red : ConsoleColor.Green;
        Console.Write($"crashes: {_crashManager.UniqueCrashCount} | ");
        Console.ForegroundColor = _crashManager.UniqueHangCount > 0 ? ConsoleColor.Yellow : ConsoleColor.Green;
        Console.Write($"hangs: {_crashManager.UniqueHangCount} | ");
        Console.ForegroundColor = _crashManager.UniqueFindingCount > 0 ? ConsoleColor.Magenta : ConsoleColor.Green;
        Console.Write($"findings: {_crashManager.UniqueFindingCount} | ");
        Console.ForegroundColor = _crashManager.UniqueDifferentialCount > 0 ? ConsoleColor.DarkCyan : ConsoleColor.Green;
        Console.Write($"diffs: {_crashManager.UniqueDifferentialCount}");
        Console.ResetColor();
        Console.WriteLine();
    }

    private void PrintFinalStats()
    {
        Console.WriteLine();
        Console.WriteLine(new string('=', 50));
        Console.WriteLine("=== FUZZING COMPLETE ===");
        Console.WriteLine($"Duration:        {_runtime.Elapsed:hh\\:mm\\:ss}");
        Console.WriteLine($"Total Execs:     {_totalExecs:N0}");
        Console.WriteLine($"Exec/sec:        {_totalExecs / Math.Max(1, _runtime.Elapsed.TotalSeconds):N0}");
        Console.WriteLine($"Corpus Entries:  {_scheduler.Count}");
        Console.WriteLine($"Unique Paths:    {_coverage.TotalPaths:N0}");
        Console.WriteLine($"New Features:    {_totalNewFeatures:N0}");
        Console.WriteLine($"New Outputs:     {_totalNewOutputs:N0}");
        Console.WriteLine($"Unique Crashes:  {_crashManager.UniqueCrashCount}");
        Console.WriteLine($"Total Crashes:   {_crashManager.CrashCount:N0}");
        Console.WriteLine($"Unique Hangs:    {_crashManager.UniqueHangCount}");
        Console.WriteLine($"Total Hangs:     {_crashManager.HangCount:N0}");
        Console.WriteLine($"Unique Findings: {_crashManager.UniqueFindingCount}");
        Console.WriteLine($"Total Findings:  {_crashManager.FindingCount:N0}");
        Console.WriteLine($"Unique Diffs:    {_crashManager.UniqueDifferentialCount}");
        Console.WriteLine($"Total Diffs:     {_crashManager.DifferentialCount:N0}");
        Console.WriteLine($"Diff Checks Run: {_totalDifferentialChecks:N0}");
        if (_persistentRunner != null)
            Console.WriteLine($"Restarts:        {_persistentRunner.RestartCount}");
        if (_experimentalRunner != null)
            Console.WriteLine($"Exp. Restarts:   {_experimentalRunner.RestartCount}");
        Console.WriteLine(new string('=', 50));
    }

    private FuzzerStats BuildStats() => new()
    {
        TotalIterations = _totalIterations,
        TotalExecs = _totalExecs,
        ExecPerSecond = (long)(_totalExecs / Math.Max(1, _runtime.Elapsed.TotalSeconds)),
        UniqueCrashes = _crashManager.UniqueCrashCount,
        UniqueHangs = _crashManager.UniqueHangCount,
        TotalCrashes = _crashManager.CrashCount,
        TotalHangs = _crashManager.HangCount,
        UniqueFindings = _crashManager.UniqueFindingCount,
        TotalFindings = _crashManager.FindingCount,
        UniqueDifferentials = _crashManager.UniqueDifferentialCount,
        TotalDifferentials = _crashManager.DifferentialCount,
        CorpusSize = _scheduler.Count,
        ElapsedTime = _runtime.Elapsed.ToString(),
    };

    private void SaveStats()
    {
        try
        {
            _crashManager.SaveStats(BuildStats());
            _crashManager.GenerateReport(BuildStats());
        }
        catch { }
    }

    public void Dispose()
    {
        _runner.Dispose();
        _persistentRunner?.Dispose();
        _differentialTester?.Dispose();
        _experimentalRunner?.Dispose();
        _crashManager.Dispose();
    }
}

internal sealed class FuzzerConfig
{
    public string JsExePath { get; set; } = "";
    public string OutputDir { get; set; } = "output";
    public string? SeedDir { get; set; }
    public int TimeoutMs { get; set; } = 5000;
    public bool UseAsan { get; set; } = true;
    public bool PersistentMode { get; set; } = true;
    public bool CoverageGuided { get; set; } = true;
    public bool MinimizeCrashes { get; set; } = true;
    public bool UseDictionary { get; set; } = true;
    public bool ResumeOnStart { get; set; } = true;
    public bool SaveNewCoverage { get; set; } = true;
    public long MaxIterations { get; set; } = long.MaxValue;
    public int Seed { get; set; } = Environment.TickCount;
    public int ReportIntervalMs { get; set; } = 2000;
    public int CorpusFuzzChance { get; set; } = 40;
    public bool CustomMutators { get; set; } = true;
    public int CustomMutatorChance { get; set; } = 35;
    public bool SpliceEnabled { get; set; } = true;
    public int SpliceChance { get; set; } = 20;
    public int FreshGenerateChance { get; set; } = 12;
    public int ParallelWorkers { get; set; }
    public int WorkerId { get; set; }
    public bool DifferentialTesting { get; set; } = true;
    public int DifferentialChance { get; set; } = 3;
    public bool ExperimentalFeatures { get; set; } = true;
    public int ExperimentalChance { get; set; } = 5;
}
