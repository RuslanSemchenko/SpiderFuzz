using System.Collections.Concurrent;

namespace SpiderFuzz.Fuzzer;

internal sealed class EnergyScheduler
{
    private readonly ConcurrentDictionary<string, CorpusEntryEx> _entries = new();
    private int _corpusVersion;

    public int Count => _entries.Count;

    public void Add(string code, string strategy, CoverageRecord? record = null)
    {
        var hash = CorpusEntryEx.ComputeHash(code);
        var energy = CalculateInitialEnergy(record);

        var entry = new CorpusEntryEx
        {
            Code = code,
            Strategy = strategy,
            Hash = hash,
            Energy = energy,
            Visits = 0,
            Finds = 0,
            Timestamp = DateTime.UtcNow,
            Priority = energy,
        };

        _entries.TryAdd(entry.Hash, entry);
        Interlocked.Increment(ref _corpusVersion);
    }

    public CorpusEntryEx? PickNext()
    {
        if (_entries.IsEmpty) return null;

        var values = _entries.Values;
        if (values.Count == 0) return null;

        var candidates = values
            .Where(it => it.Energy > 0)
            .OrderByDescending(it => it.Priority)
            .Take(32)
            .ToArray();

        if (candidates.Length == 0)
        {
            // Reset energy if all depleted
            foreach (var e in values)
            {
                e.Energy = 10;
                RecalcPriority(e);
            }
            candidates = values.Take(32).ToArray();
            if (candidates.Length == 0) return null;
        }

        var totalPriority = candidates.Sum(c => c.Priority);
        if (totalPriority <= 0) return candidates[0];

        var rng = Random.Shared;
        var pick = rng.Next(totalPriority);
        var cumulative = 0;

        foreach (var entry in candidates)
        {
            cumulative += entry.Priority;
            if (pick < cumulative)
            {
                entry.Visits++;
                entry.Energy = Math.Max(1, entry.Energy - 1);
                RecalcPriority(entry);
                return entry;
            }
        }

        var last = candidates[^1];
        last.Visits++;
        last.Energy = Math.Max(1, last.Energy - 1);
        RecalcPriority(last);
        return last;
    }

    /// <summary>
    /// Samples a random corpus entry without touching its energy/visit stats,
    /// meant as a crossover partner for splicing - unlike <see cref="PickNext"/>
    /// this must not bias future scheduling of the sampled entry.
    /// </summary>
    public CorpusEntryEx? PickRandomForSplice()
    {
        var values = _entries.Values;
        if (values.Count == 0) return null;

        var arr = values as CorpusEntryEx[] ?? values.ToArray();
        return arr.Length == 0 ? null : arr[Random.Shared.Next(arr.Length)];
    }

    public void NotifyFind(string entryHash, int score)
    {
        if (_entries.TryGetValue(entryHash, out var entry))
        {
            entry.Finds++;
            entry.Energy += score * 2;
            RecalcPriority(entry);
        }
    }

    public void NotifyCrash(string entryHash)
    {
        if (_entries.TryGetValue(entryHash, out var entry))
        {
            entry.Finds++;
            entry.Energy += 50;
            RecalcPriority(entry);
        }
    }

    public void Decay()
    {
        foreach (var entry in _entries.Values)
        {
            entry.Energy = Math.Max(1, entry.Energy * 9 / 10);
            RecalcPriority(entry);
        }
    }

    public List<CorpusEntryEx> GetAll() => _entries.Values.ToList();

    public int GetVersion() => _corpusVersion;

    public static int CalculateInitialEnergy(CoverageRecord? record)
    {
        if (record == null) return 10;
        return 10 + record.Score * 5;
    }

    private static void RecalcPriority(CorpusEntryEx entry)
    {
        entry.Priority = Math.Max(1, entry.Energy + entry.Finds * 5 - entry.Visits);
    }

    public void LoadFrom(List<CorpusEntryEx> entries)
    {
        foreach (var entry in entries)
        {
            _entries.TryAdd(entry.Hash, entry);
        }
        Interlocked.Increment(ref _corpusVersion);
    }
}

internal sealed class CorpusEntryEx : IEquatable<CorpusEntryEx>
{
    public string Code { get; set; } = "";
    public string Strategy { get; set; } = "";
    public string Hash { get; set; } = "";
    public int Energy { get; set; } = 10;
    public int Priority { get; set; } = 10;
    public int Visits { get; set; }
    public int Finds { get; set; }
    public DateTime Timestamp { get; set; }

    public static string ComputeHash(string code)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(code));
        return Convert.ToHexString(hash.AsSpan(0, 8)).ToLowerInvariant();
    }

    public bool Equals(CorpusEntryEx? other) => other != null && Hash == other.Hash;
    public override bool Equals(object? obj) => Equals(obj as CorpusEntryEx);
    public override int GetHashCode() => Hash.GetHashCode();
}
