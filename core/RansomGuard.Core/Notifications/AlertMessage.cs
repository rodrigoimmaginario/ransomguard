using System.Text;
using DetectionModel = RansomGuard.Core.Detection.Detection;

namespace RansomGuard.Core.Notifications;

/// <summary>Urgência do alerta — dirige ícone/prioridade nos canais que suportam.</summary>
public enum AlertSeverity
{
    /// <summary>Informativo (ex.: teste de configuração).</summary>
    Info,
    /// <summary>Merece atenção, mas não é certeza de ataque (confiança média).</summary>
    Warning,
    /// <summary>Incidente de alta confiança ou agente silencioso — acorde alguém.</summary>
    Critical
}

/// <summary>
/// A mensagem que chega no bolso do admin. Precisa responder, em 5 segundos: onde, quem, de onde,
/// quanto, por quê e **o que já foi feito**.
///
/// Princípio do produto respeitado aqui: **metadado, nunca conteúdo**. Nome de arquivo individual e
/// conteúdo jamais entram — só contagens, share, usuário e IP.
/// </summary>
/// <param name="Severity">Urgência.</param>
/// <param name="Title">Título curto (cabe na notificação do celular).</param>
/// <param name="ShortBody">Corpo compacto, para push.</param>
/// <param name="RichBody">Corpo detalhado, para chat/e-mail.</param>
/// <param name="Tags">Rótulos curtos (ntfy usa como emoji/tag).</param>
public sealed record AlertMessage(
    AlertSeverity Severity,
    string Title,
    string ShortBody,
    string RichBody,
    IReadOnlyList<string> Tags)
{
    /// <summary>Chave de agrupamento para o anti-flood: mesmo ator + servidor + share.</summary>
    public string? DedupKey { get; init; }
}

/// <summary>Monta <see cref="AlertMessage"/> a partir dos eventos do produto. Lógica pura.</summary>
public static class AlertComposer
{
    /// <summary>
    /// Alerta de incidente detectado. <paramref name="containment"/> descreve o que a contenção fez
    /// (vazio = apenas alertado) — é a informação que evita o admin correr à toa.
    /// </summary>
    public static AlertMessage ForDetection(DetectionModel d, string? containment = null)
    {
        var severity = d.Confidence == Detection.Confidence.High ? AlertSeverity.Critical : AlertSeverity.Warning;
        var icon = severity == AlertSeverity.Critical ? "🚨" : "⚠️";

        var title = $"{icon} RansomGuard · {d.Server}";

        var reasons = string.Join(" + ", d.Reasons.Select(Humanize));
        var acao = string.IsNullOrWhiteSpace(containment)
            ? "Somente alertado (sem contenção)."
            : $"CONTIDO: {containment}";

        var shortBody = new StringBuilder()
            .Append($"{d.User} de {d.SourceIp}\n")
            .Append($"{d.AffectedFiles} arquivos em {d.Share}\n")
            .Append($"{reasons}\n")
            .Append(acao)
            .ToString();

        var richBody = new StringBuilder()
            .AppendLine($"Servidor: {d.Server}")
            .AppendLine($"Usuário: {d.User}")
            .AppendLine($"Origem (IP): {d.SourceIp}")
            .AppendLine($"Share: {d.Share}")
            .AppendLine($"Arquivos afetados: {d.AffectedFiles}")
            .AppendLine($"Confiança: {d.Confidence}")
            .AppendLine($"Motivos: {reasons}")
            .AppendLine($"Janela: {d.FirstAt:dd/MM HH:mm:ss} → {d.LastAt:HH:mm:ss}")
            .AppendLine(acao)
            .ToString();

        return new AlertMessage(severity, title, shortBody, richBody,
            new[] { "rotating_light", "ransomware" })
        {
            DedupKey = $"det:{d.Server}|{d.User}|{d.SourceIp}|{d.Share}"
        };
    }

    /// <summary>Alerta de agente silencioso — pode indicar adulteração (EDR killer).</summary>
    public static AlertMessage ForAgentSilent(string server, DateTime lastBeat, DateTime now)
    {
        var minutos = (int)Math.Max(1, (now - lastBeat).TotalMinutes);
        return new AlertMessage(
            AlertSeverity.Critical,
            $"🔕 RansomGuard · agente mudo em {server}",
            $"Sem contato há {minutos} min.\nPode ser desligamento, rede — ou adulteração.\nVerifique o servidor.",
            $"O agente de {server} parou de reportar (último contato {lastBeat:dd/MM HH:mm}, há {minutos} min).\n" +
            "Agente silencioso pode indicar manutenção, falha de rede ou adulteração deliberada " +
            "(técnica comum antes de um ataque). Verifique o servidor.",
            new[] { "no_bell", "warning" })
        {
            DedupKey = $"silent:{server}"
        };
    }

    /// <summary>Mensagem de teste, disparada pelo botão da tela de configuração.</summary>
    public static AlertMessage ForTest(string channelName) => new(
        AlertSeverity.Info,
        "✅ RansomGuard · teste de notificação",
        $"Se você está lendo isto, o canal {channelName} está configurado corretamente.",
        $"Teste enviado pelo painel do RansomGuard.\n\n" +
        $"O canal {channelName} está funcionando. Alertas reais de incidente chegarão por aqui.",
        new[] { "white_check_mark" });

    /// <summary>Traduz o motivo técnico para linguagem que o admin entende no susto.</summary>
    private static string Humanize(Detection.DetectionReason r) => r switch
    {
        Detection.DetectionReason.CanaryTouched => "canário tocado",
        Detection.DetectionReason.MassRewrite => "reescrita em massa",
        Detection.DetectionReason.MassRename => "renomeação em massa",
        Detection.DetectionReason.ExtensionFlip => "troca de extensão",
        Detection.DetectionReason.VssDeletion => "VSS apagado",
        Detection.DetectionReason.AgentTamper => "agente adulterado",
        Detection.DetectionReason.VssReduction => "cópias de sombra reduzidas",
        Detection.DetectionReason.MassOverwrite => "arquivos existentes regravados em massa",
        Detection.DetectionReason.RecoveryToolUse => "utilitário de snapshot em uso",
        Detection.DetectionReason.CanaryRemoved => "canários apagados",
        Detection.DetectionReason.NoteLikeFiles => "mesmo arquivo de nome suspeito em várias pastas",
        Detection.DetectionReason.RansomNote => "nota de resgate",
        Detection.DetectionReason.KnownRansomExtension or Detection.DetectionReason.KnownExtensionSeen => "extensão de ransomware conhecida",
        _ => r.ToString()
    };
}
