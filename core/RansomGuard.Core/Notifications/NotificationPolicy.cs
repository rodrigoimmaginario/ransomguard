namespace RansomGuard.Core.Notifications;

/// <summary>
/// Decide se um alerta deve mesmo sair. Duas regras, ambas para proteger o admin da fadiga:
/// **severidade mínima** (o que ele escolheu receber) e **anti-flood** (não repetir o mesmo ator
/// em janela curta — um ataque gera muitos eventos e viraria dezenas de push idênticos).
///
/// Lógica pura: o "agora" é injetado e o estado de supressão é do chamador, para ser testável.
/// </summary>
public sealed class NotificationPolicy
{
    private readonly Dictionary<string, DateTime> _lastSent = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Severidade mínima para notificar. Default: Critical (só o que importa de verdade).
    /// Mutável para o painel poder aplicar a preferência do admin **sem perder o estado de
    /// anti-flood** — recriar a política a cada mudança zeraria a memória de supressão, e um ataque
    /// em curso voltaria a gerar dezenas de push idênticos.
    /// </summary>
    public AlertSeverity MinimumSeverity { get; set; } = AlertSeverity.Critical;

    /// <summary>Janela em que repetições do mesmo <see cref="AlertMessage.DedupKey"/> são suprimidas.</summary>
    public TimeSpan FloodWindow { get; set; } = TimeSpan.FromMinutes(10);

    public enum Decision { Send, BelowSeverity, Flooded }

    /// <summary>
    /// Avalia e, se aprovar, **registra** o envio (para a próxima repetição ser suprimida).
    /// Alertas sem <see cref="AlertMessage.DedupKey"/> (ex.: teste) nunca são agrupados.
    /// </summary>
    public Decision Evaluate(AlertMessage message, DateTime now)
    {
        if (message.Severity < MinimumSeverity) return Decision.BelowSeverity;

        // Trava porque, no painel, esta política é um singleton e ingestões concorrentes de vários
        // agentes podem avaliar ao mesmo tempo — o dicionário de supressão não é thread-safe.
        lock (_lastSent)
        {
            if (!string.IsNullOrEmpty(message.DedupKey))
            {
                if (_lastSent.TryGetValue(message.DedupKey, out var last) && now - last < FloodWindow)
                    return Decision.Flooded;
                _lastSent[message.DedupKey] = now;
            }
        }
        return Decision.Send;
    }
}
