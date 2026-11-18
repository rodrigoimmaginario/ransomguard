using System.Collections.Concurrent;
using System.Xml.Linq;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Score;

namespace RansomGuard.Agent.Sensors;

/// <summary>
/// G2 — fila de sinais produzidos fora do ciclo de coleta (reparo de visibilidade, canário sumido). O coletor de
/// sinais drena a cada ciclo. Thread-safe; nunca perde: quem produz não espera quem consome.
/// </summary>
public sealed class HostSignalBuffer
{
    private readonly ConcurrentQueue<HostSignal> _queue = new();
    public void Push(HostSignal signal) => _queue.Enqueue(signal);
    public IReadOnlyList<HostSignal> Drain()
    {
        var list = new List<HostSignal>();
        while (_queue.TryDequeue(out var s)) list.Add(s);
        return list;
    }
}

/// <summary>
/// Traduz eventos do Security log que falam do PRÓPRIO log/auditoria: 4719 (política de auditoria alterada) e
/// 1102 (log limpo). Só o 4719 que toca as subcategorias de arquivo/share interessa; mudanças em logon etc. são
/// ruído administrativo normal.
/// </summary>
public static class VisibilityEventParser
{
    private static readonly string[] WatchedSubcategories = { "Detailed File Share", "File Share", "File System", "Object Access" };

    public static HostSignal? Parse(string? eventXml, DateTime? nowOverride = null)
    {
        if (string.IsNullOrWhiteSpace(eventXml)) return null;
        XElement root;
        try { root = XElement.Parse(eventXml); } catch (System.Xml.XmlException) { return null; }

        var id = root.Descendants().FirstOrDefault(e => e.Name.LocalName == "EventID")?.Value;
        var computer = root.Descendants().FirstOrDefault(e => e.Name.LocalName == "Computer")?.Value ?? "";
        var server = computer.Split('.')[0];
        var at = nowOverride ?? ParseTime(root);
        string Data(string name) => root.Descendants().FirstOrDefault(e => e.Name.LocalName == "Data"
            && string.Equals(e.Attribute("Name")?.Value, name, StringComparison.OrdinalIgnoreCase))?.Value ?? "";

        switch (id)
        {
            case "1102":
                return new HostSignal(at, HostSignalKind.SecurityLogCleared, server,
                    $"Security log limpo por {Data("SubjectDomainName")}\\{Data("SubjectUserName")}".TrimEnd('\\'));
            case "4719":
            {
                var sub = Data("SubcategoryName");
                var guid = Data("SubcategoryGuid");
                var touches = WatchedSubcategories.Any(w => sub.Contains(w, StringComparison.OrdinalIgnoreCase))
                              || guid.Equals("{0CCE9244-69AE-11D9-BED3-505054503030}", StringComparison.OrdinalIgnoreCase)   // Detailed File Share
                              || guid.Equals("{0CCE9224-69AE-11D9-BED3-505054503030}", StringComparison.OrdinalIgnoreCase)   // File Share
                              || guid.Equals("{0CCE921D-69AE-11D9-BED3-505054503030}", StringComparison.OrdinalIgnoreCase);  // File System
                if (!touches) return null;
                var changes = Data("AuditPolicyChanges");
                // L2 (laboratório, sessão 1): o agente, ao LIGAR a auditoria que faltava, gerava este evento e se acusava de
                // adulteração — todo servidor recém-instalado nascia com um incidente de Alta. O que cega é REMOVER a
                // auditoria de sucesso (%%8448). Adicionar (%%8449, %%8451) não cega; remover só a de falha (%%8450)
                // também não, porque o produto lê acessos bem-sucedidos. Sem código legível, na dúvida, é sinal.
                var readable = changes.Contains("%%844", StringComparison.Ordinal) || changes.Contains("%%845", StringComparison.Ordinal);
                if (readable && !changes.Contains("%%8448", StringComparison.Ordinal)) return null;
                return new HostSignal(at, HostSignalKind.AuditPolicyChanged, server,
                    $"Auditoria '{(string.IsNullOrWhiteSpace(sub) ? guid : sub)}' alterada ({changes}) por {Data("SubjectDomainName")}\\{Data("SubjectUserName")}".TrimEnd('\\'));
            }
            default:
                return null;
        }
    }

    private static DateTime ParseTime(XElement root)
    {
        var tc = root.Descendants().FirstOrDefault(e => e.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
        return DateTime.TryParse(tc, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var t)
            ? t : DateTime.UtcNow;
    }
}

/// <summary>
/// L2b/L13 (laboratório, sessão 2) — memória da auditoria de compartilhamento entre checagens.
///
/// Auditoria desligada só é adulteração se o agente já a viu ligada: numa instalação nova ela está desligada porque é
/// o padrão do Windows, e o agente nascia com um alarme de Alta contra si mesmo. E, como a checagem passou a rodar a
/// cada minuto, o alarme sai na transição de ligada para desligada — não a cada minuto em que o reparo falhar.
/// </summary>
public sealed class VisibilityState(bool seenOn)
{
    private bool _alerted;

    /// <summary>O agente já viu a auditoria ligada nesta máquina (persistido pelo chamador).</summary>
    public bool SeenOn { get; private set; } = seenOn;

    public bool ShouldAlert(bool auditOn)
    {
        if (auditOn) { SeenOn = true; _alerted = false; return false; }
        if (!SeenOn || _alerted) return false;
        _alerted = true;
        return true;
    }
}

public enum RepairAction { EnableDetailedFileShareAudit, GrowSecurityLog, EnableProcessCreationAudit, EnableFileSystemAudit }

/// <summary>
/// Decisão pura do reparo de visibilidade: dado o que a postura leu, que reparos fazer (quando o auto-reparo está
/// ligado) e que sinais emitir. Sem I/O — o executor Windows aplica.
/// </summary>
public static class VisibilityGuard
{
    public sealed record Plan(IReadOnlyList<RepairAction> Repairs, IReadOnlyList<HostSignal> Signals);

    public static Plan Evaluate(bool? detailedFileShareAuditEnabled, long? securityLogMaxBytes, bool autoRepair, string server, DateTime now,
        bool? processCreationAuditWithCommandLine = null, bool? fileSystemAuditEnabled = null, bool shareAuditSeenOnBefore = true)
    {
        var repairs = new List<RepairAction>();
        var signals = new List<HostSignal>();

        // D4: sem 'File System' não há 4663 — o canário tocado por processo local não aparece. É o padrão do Windows,
        // então não vira sinal; só reparo.
        if (fileSystemAuditEnabled == false && autoRepair)
            repairs.Add(RepairAction.EnableFileSystemAudit);

        // G3: sem 4688 com linha de comando, os sinais de pré-cifra (vssadmin/wbadmin/bcdedit…) não existem. Não é tamper
        // (é o padrão do Windows), então não vira sinal — só reparo.
        if (processCreationAuditWithCommandLine == false && autoRepair)
            repairs.Add(RepairAction.EnableProcessCreationAudit);

        if (detailedFileShareAuditEnabled == false)
        {
            // L2b: desligada sem nunca ter sido vista ligada é o padrão do Windows — repara, sem alarme.
            if (shareAuditSeenOnBefore)
                signals.Add(new HostSignal(now, HostSignalKind.AuditDisabled, server,
                    "Auditoria 'Detailed File Share' desligada: sem 5145 o agente não vê o ataque remoto."));
            if (autoRepair) repairs.Add(RepairAction.EnableDetailedFileShareAudit);
        }
        if (securityLogMaxBytes is { } b && b < ScoreRules.SecurityLogMinimumBytes && autoRepair)
            repairs.Add(RepairAction.GrowSecurityLog);

        return new Plan(repairs, signals);
    }

    /// <summary>Sinal informativo após um reparo bem-sucedido (não é detecção; fica na trilha do painel).</summary>
    public static HostSignal Repaired(RepairAction action, string server, DateTime now) =>
        new(now, HostSignalKind.VisibilityRepaired, server, action switch
        {
            RepairAction.EnableDetailedFileShareAudit => "Auditoria 'Detailed File Share' religada pelo agente.",
            RepairAction.GrowSecurityLog => "Security log ampliado para 1 GB pelo agente.",
            RepairAction.EnableProcessCreationAudit => "Auditoria de criação de processo (4688 com linha de comando) ligada pelo agente.",
            RepairAction.EnableFileSystemAudit => "Auditoria 'File System' (evento 4663, canários e pastas com SACL) ligada pelo agente.",
            _ => action.ToString()
        });
}
