using System.Text;
using System.Text.RegularExpressions;

namespace SpiderFuzz.Fuzzer;

/// <summary>
/// Re-executes an input that already ran cleanly under the default persistent
/// driver against a handful of alternate SpiderMonkey JIT-tier configurations
/// (forced eager Baseline/Ion compilation, or the plain bytecode interpreter
/// with every JIT disabled). This buys two signals the default persistent
/// runner structurally cannot provide on its own:
///
///  1. Crash-under-tier: --ion-eager/--baseline-eager force compilation far
///     earlier than the default warmup thresholds (on the order of a
///     thousand calls/iterations), so a short-lived fuzzer input that never
///     triggers JIT compilation under normal conditions still gets to
///     exercise Ion/Baseline codegen here. A crash that only reproduces
///     under one of these configs would otherwise never be seen at all in a
///     normal campaign.
///  2. Semantic differential: per spec, the observable behavior (stdout,
///     thrown exceptions) of deterministic code must be identical no matter
///     which tier actually executed it. A mismatch between tiers is the
///     classic signal used by SpiderMonkey's own jsfunfuzz/compareJIT lineage
///     to find real JIT correctness bugs.
///
/// Every mismatch is confirmed with a second, independent re-run of every
/// config before being trusted, so a single flaky/non-deterministic input
/// that slipped past <see cref="LooksDeterministic"/> cannot masquerade as a
/// tier-dependent engine bug.
/// </summary>
internal sealed class DifferentialTester : IDisposable
{
    private readonly ProcessRunner _runner;

    // --ion-eager implies --baseline-eager, so it alone still exercises the
    // baseline tier on the way up; --no-blinterp+--no-baseline+--no-ion
    // forces the plain bytecode (C++) interpreter with every JIT disabled.
    // All four flags were hand-verified against a real js.exe shell.
    public static readonly (string Name, string[] Args)[] Configs =
    [
        ("interpreter", ["--no-blinterp", "--no-baseline", "--no-ion"]),
        ("baseline-eager", ["--baseline-eager", "--no-ion"]),
        ("ion-eager", ["--ion-eager"]),
    ];

    public DifferentialTester(string jsExePath, int timeoutMs)
    {
        _runner = new ProcessRunner(jsExePath, timeoutMs, useAsan: true);
    }

    // Cheap static gate: skip inputs whose observable behavior can legitimately
    // differ from run to run for reasons that have nothing to do with JIT
    // tiering (wall-clock time, RNG, weak references, GC-observable identity).
    // Without this, those inputs would just be pure noise for this technique.
    private static readonly Regex NondeterministicRegex = new(
        @"Math\.random|Date\.now|performance\.now|new Date\s*\(\s*\)|Atomics\.wait|WeakRef|FinalizationRegistry",
        RegexOptions.Compiled);

    public static bool LooksDeterministic(string code) => !NondeterministicRegex.IsMatch(code);

    public DifferentialOutcome Check(string code)
    {
        var outcome = new DifferentialOutcome();
        var firstPass = new List<(string Name, RunResult Result)>(Configs.Length);

        foreach (var (name, args) in Configs)
        {
            var result = _runner.Run(code, args);
            if (result.Status == RunStatus.Error) return outcome; // infra hiccup, not a signal

            if (result.Status == RunStatus.Crash || result.TimedOut)
            {
                // Confirm before reporting: re-run the same config once more so
                // a one-off flaky hiccup can't masquerade as a tier-specific bug.
                var confirm = _runner.Run(code, args);
                if (confirm.Status == result.Status && (confirm.Status == RunStatus.Crash || confirm.TimedOut))
                {
                    outcome.CrashConfig = name;
                    outcome.CrashResult = result;
                }
                return outcome; // either confirmed (reported) or flaky (dropped) - both stop here
            }

            firstPass.Add((name, result));
        }

        if (firstPass.Count != Configs.Length) return outcome;

        var firstSigCount = firstPass.Select(r => Normalize(r.Result)).Distinct().Count();
        if (firstSigCount <= 1) return outcome;

        // Re-run every config once more before trusting the mismatch: if a
        // second run now agrees across tiers, the first result was noise from
        // an uncontrolled dependency our static filter missed, not a genuine
        // tier-dependent difference.
        var secondPass = new List<(string Name, string Sig)>();
        foreach (var (name, args) in Configs)
        {
            var second = _runner.Run(code, args);
            if (second.Status == RunStatus.Error || second.Status == RunStatus.Crash || second.TimedOut)
                return outcome; // flaky at the process level - bail out rather than report noise
            secondPass.Add((name, Normalize(second)));
        }

        if (secondPass.Select(s => s.Sig).Distinct().Count() <= 1) return outcome;

        outcome.Mismatch = true;
        foreach (var (name, result) in firstPass)
            outcome.Signatures[name] = Normalize(result);
        return outcome;
    }

    private static readonly Regex HexAddr = new(@"0x[0-9a-fA-F]{4,}", RegexOptions.Compiled);

    // ProcessRunner writes every run to a FRESH randomly-named temp file
    // (Guid.NewGuid() each time), and SpiderMonkey embeds that source path in
    // error contexts (e.g. an unhandled-rejection's location). Comparing raw
    // text would then see three DIFFERENT paths - one per tier's own separate
    // process invocation - as a "mismatch" even when the actual JS-level error
    // (class, message) is identical across every tier. Strip any absolute
    // path ending in .js before hashing so only genuine behavioral
    // differences survive into the comparison.
    private static readonly Regex TempFilePath = new(@"[A-Za-z]:[\\/][^\s""']*\.js|/[^\s""']*\.js", RegexOptions.Compiled);

    private static string Normalize(RunResult r)
    {
        // NonZeroExit means the script threw an uncaught JS exception - the
        // exact channel our own seeds/generators use as an in-band oracle
        // (`throw new Error(...)`), so "did it throw" plus "what was printed"
        // together capture the observable behavior spec requires to be
        // tier-independent.
        var threw = r.Status != RunStatus.Ok;
        var stdout = Sanitize(r.Stdout).Trim();
        var errClass = "";
        if (threw)
        {
            var line = r.Stderr.Split('\n').FirstOrDefault(l => l.Contains("Error", StringComparison.Ordinal))?.Trim() ?? "";
            errClass = Sanitize(line);
        }
        return $"{threw}|{stdout}|{errClass}";
    }

    private static string Sanitize(string text) => TempFilePath.Replace(HexAddr.Replace(text, "0x..."), "<file>");

    public void Dispose() => _runner.Dispose();
}

internal sealed class DifferentialOutcome
{
    public string? CrashConfig { get; set; }
    public RunResult? CrashResult { get; set; }
    public bool Mismatch { get; set; }
    public Dictionary<string, string> Signatures { get; } = new();

    public bool IsInteresting => CrashConfig != null || Mismatch;
}
