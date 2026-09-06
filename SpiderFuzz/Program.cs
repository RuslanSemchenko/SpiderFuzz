using SpiderFuzz.Fuzzer;

var config = new FuzzerConfig
{
    JsExePath = OperatingSystem.IsWindows()
        ? @"C:\mozilla-source\firefox\obj-x86_64-pc-windows-msvc\dist\bin\js.exe"
        : "./js",
    OutputDir = "output",
    TimeoutMs = 5000,
    UseAsan = true,
    PersistentMode = true,
    CoverageGuided = true,
    MinimizeCrashes = true,
    UseDictionary = true,
    ResumeOnStart = true,
    SaveNewCoverage = true,
    MaxIterations = long.MaxValue,
};

var runCmin = false;
string? triageDir = null;

for (var i = 0; i < args.Length; i++)
{
    string NextArg()
    {
        if (i + 1 >= args.Length)
        {
            Console.WriteLine($"Error: Missing value for option '{args[i]}'");
            PrintHelp();
            Environment.Exit(1);
        }
        return args[++i];
    }

    switch (args[i])
    {
        case "--js":
        case "-j":
            config.JsExePath = NextArg();
            break;
        case "--output":
        case "-o":
            config.OutputDir = NextArg();
            break;
        case "--timeout":
        case "-t":
            if (int.TryParse(NextArg(), out var timeout)) config.TimeoutMs = timeout;
            break;
        case "--iterations":
        case "-n":
            if (long.TryParse(NextArg(), out var iters)) config.MaxIterations = iters;
            break;
        case "--seed":
        case "-s":
            if (int.TryParse(NextArg(), out var seed)) config.Seed = seed;
            break;
        case "--seeds":
            config.SeedDir = NextArg();
            break;
        case "--workers":
        case "-w":
            if (int.TryParse(NextArg(), out var workers)) config.ParallelWorkers = workers;
            break;
        case "--asan":
            config.UseAsan = true;
            break;
        case "--no-asan":
            config.UseAsan = false;
            break;
        case "--persistent":
            config.PersistentMode = true;
            break;
        case "--no-persistent":
            config.PersistentMode = false;
            break;
        case "--coverage":
            config.CoverageGuided = true;
            break;
        case "--no-coverage":
            config.CoverageGuided = false;
            break;
        case "--minimize":
            config.MinimizeCrashes = true;
            break;
        case "--no-minimize":
            config.MinimizeCrashes = false;
            break;
        case "--dictionary":
            config.UseDictionary = true;
            break;
        case "--no-dictionary":
            config.UseDictionary = false;
            break;
        case "--custom-mutators":
            config.CustomMutators = true;
            break;
        case "--no-custom-mutators":
            config.CustomMutators = false;
            break;
        case "--custom-mutator-chance":
            if (int.TryParse(NextArg(), out var customChance))
                config.CustomMutatorChance = Math.Clamp(customChance, 0, 100);
            break;
        case "--splice":
            config.SpliceEnabled = true;
            break;
        case "--no-splice":
            config.SpliceEnabled = false;
            break;
        case "--splice-chance":
            if (int.TryParse(NextArg(), out var spliceChance))
                config.SpliceChance = Math.Clamp(spliceChance, 0, 100);
            break;
        case "--fresh-generate-chance":
            if (int.TryParse(NextArg(), out var freshChance))
                config.FreshGenerateChance = Math.Clamp(freshChance, 0, 100);
            break;
        case "--no-resume":
            config.ResumeOnStart = false;
            break;
        case "--no-save-coverage":
            config.SaveNewCoverage = false;
            break;
        case "--differential":
            config.DifferentialTesting = true;
            break;
        case "--no-differential":
            config.DifferentialTesting = false;
            break;
        case "--differential-chance":
            if (int.TryParse(NextArg(), out var diffChance))
                config.DifferentialChance = Math.Clamp(diffChance, 0, 100);
            break;
        case "--experimental":
            config.ExperimentalFeatures = true;
            break;
        case "--no-experimental":
            config.ExperimentalFeatures = false;
            break;
        case "--experimental-chance":
            if (int.TryParse(NextArg(), out var expChance))
                config.ExperimentalChance = Math.Clamp(expChance, 0, 100);
            break;
        case "--cmin":
            runCmin = true;
            break;
        case "--triage":
            triageDir = NextArg();
            break;
        case "--help":
        case "-h":
            PrintHelp();
            return 0;
        default:
            Console.WriteLine($"Unknown option: {args[i]}");
            PrintHelp();
            return 1;
    }
}

if (!File.Exists(config.JsExePath))
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine($"Error: SpiderMonkey shell not found at '{config.JsExePath}'");
    Console.WriteLine("Please specify the path with --js <path> or -j <path>");
    Console.ResetColor();
    return 1;
}

if (runCmin)
{
    return RunCorpusMinimization(config);
}

if (triageDir != null)
{
    return RunTriage(config, triageDir);
}

if (config.ParallelWorkers > 0)
{
    using var parallel = new ParallelManager(config);
    parallel.Run();
    return 0;
}

using var fuzzer = new FuzzerEngine(config);
fuzzer.Run();
return 0;

static int RunCorpusMinimization(FuzzerConfig config)
{
    Console.WriteLine("=== SpiderFuzz Corpus Minimization (--cmin) ===");
    using var minimizer = new CorpusMinimizer(config);
    var summary = minimizer.Run();

    if (summary.Error != null)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Error: {summary.Error}");
        Console.ResetColor();
        return 1;
    }

    Console.WriteLine($"Processed:    {summary.Processed:N0} / {summary.OriginalCount:N0} files");
    Console.WriteLine($"Kept:         {summary.KeptCount:N0} ({summary.KeptBytes:N0} bytes)");
    Console.WriteLine($"Removed:      {summary.RemovedCount:N0} ({summary.OriginalBytes - summary.KeptBytes:N0} bytes freed)");
    if (summary.RemovedDir != null)
        Console.WriteLine($"Removed files moved to: {summary.RemovedDir}");
    return 0;
}

static int RunTriage(FuzzerConfig config, string dir)
{
    Console.WriteLine($"=== SpiderFuzz Triage (--triage {dir}) ===");
    using var triage = new TriageRunner(config);
    var summary = triage.Run(dir);

    if (summary.Error != null)
    {
        Console.ForegroundColor = ConsoleColor.Red;
        Console.WriteLine($"Error: {summary.Error}");
        Console.ResetColor();
        return 1;
    }

    Console.Write(summary.ReportText);
    Console.WriteLine();
    Console.WriteLine($"Still reproduces: {summary.StillReproCount:N0} | Fixed/no longer reproduces: {summary.FixedCount:N0}");

    try
    {
        var reportPath = Path.Combine(dir, "triage_report.txt");
        File.WriteAllText(reportPath, summary.ReportText);
        Console.WriteLine($"Report written to: {reportPath}");
    }
    catch { }

    return 0;
}

static void PrintHelp()
{
    Console.WriteLine("SpiderFuzz - SpiderMonkey JS Engine Fuzzer");
    Console.WriteLine();
    Console.WriteLine("Usage: SpiderFuzz [options]");
    Console.WriteLine();
    Console.WriteLine("Target / paths:");
    Console.WriteLine("  --js, -j <path>       Path to SpiderMonkey shell (js/js.exe)");
    Console.WriteLine("  --output, -o <dir>    Output directory (default: output)");
    Console.WriteLine("  --seeds <dir>         Directory with seed JS files");
    Console.WriteLine();
    Console.WriteLine("Execution tuning:");
    Console.WriteLine("  --timeout, -t <ms>    Timeout per execution in ms (default: 5000)");
    Console.WriteLine("  --iterations, -n <n>  Max iterations (default: unlimited)");
    Console.WriteLine("  --workers, -w <n>     Parallel worker count (0 = single)");
    Console.WriteLine("  --seed, -s <n>        Random seed");
    Console.WriteLine("  --persistent          Use persistent mode (default: on)");
    Console.WriteLine("  --no-persistent       Spawn process per input");
    Console.WriteLine();
    Console.WriteLine("Features:");
    Console.WriteLine("  --asan                Enable AddressSanitizer (default: on)");
    Console.WriteLine("  --no-asan             Disable AddressSanitizer");
    Console.WriteLine("  --coverage            Coverage-guided scheduling (default: on)");
    Console.WriteLine("  --no-coverage         Disable coverage guidance");
    Console.WriteLine("  --minimize            Minimize crashes on save (default: on)");
    Console.WriteLine("  --no-minimize         Disable crash minimization");
    Console.WriteLine("  --dictionary          Use JS dictionary for mutation (default: on)");
    Console.WriteLine("  --no-dictionary       Disable dictionary mutation");
    Console.WriteLine("  --custom-mutators     Use structured CacheIR/JIT mutators (default: on)");
    Console.WriteLine("  --no-custom-mutators  Disable structured CacheIR/JIT mutators");
    Console.WriteLine("  --custom-mutator-chance <0-100>  Structured mutator probability (default: 35)");
    Console.WriteLine("  --splice              Crossover between two corpus entries (default: on)");
    Console.WriteLine("  --no-splice           Disable crossover");
    Console.WriteLine("  --splice-chance <0-100>  Crossover probability (default: 20)");
    Console.WriteLine("  --fresh-generate-chance <0-100>  Chance to generate a brand-new input from");
    Console.WriteLine("                        scratch instead of mutating the corpus (default: 12)");
    Console.WriteLine("  --no-resume           Don't load previous corpus on start");
    Console.WriteLine("  --no-save-coverage    Don't save new coverage inputs");
    Console.WriteLine("  --differential        Re-check inputs across JIT tiers: interpreter/baseline-eager/");
    Console.WriteLine("                        ion-eager (default: on). Saves crashes/'diffs/' mismatches.");
    Console.WriteLine("  --no-differential     Disable JIT-tier differential testing");
    Console.WriteLine("  --differential-chance <0-100>  Per-input probability to run it (default: 3)");
    Console.WriteLine("  --experimental        Also run inputs against not-yet-shipped engine flags");
    Console.WriteLine("                        (Temporal, Iterator.range/zip/chunks, Promise.allKeyed,");
    Console.WriteLine("                        immutable ArrayBuffer) (default: on)");
    Console.WriteLine("  --no-experimental     Disable the experimental-features runner");
    Console.WriteLine("  --experimental-chance <0-100>  Per-input probability to run it (default: 5)");
    Console.WriteLine();
    Console.WriteLine("Offline tools (run once and exit, need --js / --output to point at a campaign):");
    Console.WriteLine("  --cmin                Minimize output/corpus/ in place (afl-cmin style); moves");
    Console.WriteLine("                        redundant entries into a corpus_removed_<timestamp>/ dir");
    Console.WriteLine("  --triage <dir>        Re-run every .js under <dir> (e.g. output/crashes) against");
    Console.WriteLine("                        the current --js build and report STILL_CRASHES/STILL_HANGS/FIXED");
    Console.WriteLine();
    Console.WriteLine("  --help, -h            Show this help");
}
