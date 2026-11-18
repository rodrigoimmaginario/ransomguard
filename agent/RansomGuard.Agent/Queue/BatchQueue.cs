namespace RansomGuard.Agent.Queue;

/// <summary>
/// F34 — fila durável de lotes não entregues. Painel fora do ar = eventos do ataque guardados em disco, entregues
/// em ordem quando ele volta; nada se perde, nada duplica (a ingestão é idempotente por incidente). Teto por
/// quantidade e por idade: o mais antigo é descartado com log, nunca o mais novo.
/// </summary>
public interface IBatchQueue
{
    int Count { get; }
    void Enqueue(AgentBatch batch);
    /// <summary>Lotes pendentes em ordem de chegada (sem remover).</summary>
    IReadOnlyList<AgentBatch> Peek(int max);
    /// <summary>Remove o lote mais antigo (depois de entregue).</summary>
    void DequeueOldest();
    /// <summary>Descarta os que ultrapassam os tetos; devolve quantos foram descartados.</summary>
    int Prune(DateTime now, int maxCount, TimeSpan maxAge);
}

public sealed class InMemoryBatchQueue : IBatchQueue
{
    private readonly List<AgentBatch> _items = new();
    public int Count => _items.Count;
    public void Enqueue(AgentBatch batch) => _items.Add(batch);
    public IReadOnlyList<AgentBatch> Peek(int max) => _items.Take(max).ToList();
    public void DequeueOldest() { if (_items.Count > 0) _items.RemoveAt(0); }
    public int Prune(DateTime now, int maxCount, TimeSpan maxAge)
    {
        var before = _items.Count;
        _items.RemoveAll(b => now - b.At > maxAge);
        while (_items.Count > maxCount) _items.RemoveAt(0);
        return before - _items.Count;
    }
}

/// <summary>Política da fila: tetos e ritmo de reentrega.</summary>
public static class BatchQueuePolicy
{
    public const int MaxQueuedBatches = 2_000;          // ~3 h de ciclos de 5 s
    public static readonly TimeSpan MaxAge = TimeSpan.FromDays(7);
    public const int FlushPerCycle = 20;                 // reentrega gradual: não afoga o painel que acabou de voltar
    /// <summary>Lote vale a pena guardar se carrega algo além do batimento.</summary>
    public static bool WorthQueuing(AgentBatch b) =>
        b.Events.Count > 0 || b.HostSignals.Count > 0 || (b.Incidents?.Count ?? 0) > 0 || (b.CommandResults?.Count ?? 0) > 0 || b.Posture is not null;
}
