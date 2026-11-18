using System.Text.RegularExpressions;

namespace RansomGuard.Core.Detection;

/// <summary>Chave de correlação: quem (usuário), de onde (IP), em quê (share). Comparação sem distinção de caixa.</summary>
public readonly record struct ActorKey(string User, string SourceIp, string Share)
{
    public bool Equals(ActorKey other) =>
        string.Equals(User, other.User, StringComparison.OrdinalIgnoreCase)
        && string.Equals(SourceIp, other.SourceIp, StringComparison.OrdinalIgnoreCase)
        && string.Equals(Share, other.Share, StringComparison.OrdinalIgnoreCase);
    public override int GetHashCode() => HashCode.Combine(
        User.ToUpperInvariant(), SourceIp.ToUpperInvariant(), Share.ToUpperInvariant());
}

/// <summary>
/// G1 — memória do motor de detecção entre ciclos. O agente drena eventos a cada 5 s; sem esta memória a
/// "janela de 60 s" valia 5 s e o ransomware lento (30 arquivos/min) nunca cruzava o limiar. Guarda, por ator,
/// contagens de escritas/renomeações em baldes de 1 minuto, com retenção limitada. Lógica pura: o relógio
/// é o dos eventos.
/// </summary>
public sealed class ActorActivityTracker
{
    private readonly TimeSpan _retention;
    private readonly Dictionary<ActorKey, SortedDictionary<long, int>> _buckets = new();
    private readonly Dictionary<ActorKey, DateTime> _firstSeen = new();
    private readonly Dictionary<ActorKey, DateTime> _lastSustained = new();

    private readonly Func<FileOp, bool> _counts;

    /// <param name="counts">Quais operações este rastreador soma. Padrão: gravação e renomeação.</param>
    public ActorActivityTracker(TimeSpan? retention = null, Func<FileOp, bool>? counts = null)
    {
        _retention = retention ?? TimeSpan.FromHours(25);
        _counts = counts ?? (op => op is FileOp.Write or FileOp.Rename);
    }

    private static long Bucket(DateTime at) => at.Ticks / TimeSpan.TicksPerMinute;

    public void Record(IEnumerable<FileEvent> events)
    {
        DateTime? latest = null;
        // Um arquivo conta uma vez por lote, por mais checagens de acesso que o Windows registre para ele.
        var seen = new HashSet<(ActorKey Actor, string Path)>();
        foreach (var e in events)
        {
            if (!_counts(e.Op)) continue;
            var key = new ActorKey(e.User, e.SourceIp, e.Share);
            if (!seen.Add((key, e.Path.ToUpperInvariant()))) continue;
            if (!_buckets.TryGetValue(key, out var b)) { b = new SortedDictionary<long, int>(); _buckets[key] = b; _firstSeen[key] = e.At; }
            var k = Bucket(e.At);
            b[k] = b.TryGetValue(k, out var n) ? n + 1 : 1;
            if (latest is null || e.At > latest) latest = e.At;
        }
        if (latest is { } l) Prune(l);
    }

    /// <summary>Escritas/renomeações do ator em (until − window, until].</summary>
    public int CountInWindow(ActorKey actor, DateTime until, TimeSpan window)
    {
        if (!_buckets.TryGetValue(actor, out var b)) return 0;
        var from = Bucket(until - window);
        var to = Bucket(until);
        var sum = 0;
        foreach (var (k, n) in b) { if (k < from) continue; if (k > to) break; sum += n; }
        return sum;
    }

    /// <summary>Média por minuto do ator nas 24 h anteriores a <paramref name="until"/> (exclui o último minuto). Null sem histórico mínimo.</summary>
    public double? BaselinePerMinute(ActorKey actor, DateTime until, TimeSpan minHistory)
    {
        if (!_buckets.TryGetValue(actor, out _) || !_firstSeen.TryGetValue(actor, out var first)) return null;
        if (until - first < minHistory) return null;
        var span = TimeSpan.FromHours(24);
        var total = CountInWindow(actor, until - TimeSpan.FromMinutes(1), span);
        var minutes = Math.Min(span.TotalMinutes, Math.Max(1, (until - first).TotalMinutes));
        return total / minutes;
    }

    /// <summary>Marca/consulta a emissão de "escrita sustentada" para não repetir a cada ciclo.</summary>
    public bool TryMarkSustained(ActorKey actor, DateTime now, TimeSpan cooldown)
    {
        if (_lastSustained.TryGetValue(actor, out var last) && now - last < cooldown) return false;
        _lastSustained[actor] = now;
        return true;
    }

    private void Prune(DateTime now)
    {
        var cutoff = Bucket(now - _retention);
        foreach (var (actor, b) in _buckets.ToList())
        {
            foreach (var k in b.Keys.TakeWhile(k => k < cutoff).ToList()) b.Remove(k);
            if (b.Count == 0) { _buckets.Remove(actor); _firstSeen.Remove(actor); _lastSustained.Remove(actor); }
        }
    }
}

/// <summary>Nomes de nota de resgate: curingas simples (<c>*</c>) sobre o nome do arquivo, sem distinção de caixa.</summary>
public static class RansomNoteNames
{
    private static readonly Dictionary<string, Regex> Cache = new(StringComparer.Ordinal);

    public static bool Matches(string path, IEnumerable<string> patterns)
    {
        var name = path.Replace('/', '\\');
        var slash = name.LastIndexOf('\\');
        if (slash >= 0) name = name[(slash + 1)..];
        foreach (var p in patterns)
        {
            if (!Cache.TryGetValue(p, out var rx))
            {
                rx = new Regex("^" + Regex.Escape(p).Replace("\\*", ".*") + "$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
                lock (Cache) Cache[p] = rx;
            }
            if (rx.IsMatch(name)) return true;
        }
        return false;
    }

    public static string FileOf(string path)
    {
        var name = path.Replace('/', '\\');
        var slash = name.LastIndexOf('\\');
        return slash >= 0 ? name[(slash + 1)..] : name;
    }

    public static string DirectoryOf(string path)
    {
        var name = path.Replace('/', '\\');
        var slash = name.LastIndexOf('\\');
        return slash > 0 ? name[..slash] : "";
    }
}
