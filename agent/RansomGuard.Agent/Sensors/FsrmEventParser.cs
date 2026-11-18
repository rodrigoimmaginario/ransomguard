using System.Globalization;
using System.Xml.Linq;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Fsrm;

namespace RansomGuard.Agent.Sensors;

/// <summary>
/// E3 — traduz o evento que o file screen do produto grava no log de Aplicativo (provedor SRMSVC, 8215) em evento
/// de arquivo. O texto do evento é o que o próprio produto configurou (<see cref="FsrmPlan.EventBody"/>):
/// <c>RansomGuard-FSRM|user=…|file=…|screen=…|group=…|pid=…|image=…</c>.
///
/// Por que importa: quando um arquivo é RENOMEADO, o evento de share (5145) só mostra o nome antigo. O FSRM olha o
/// nome de destino — é ele que vê <c>contrato.docx</c> virar <c>contrato.docx.lockbit</c>. Criar e renomear chegam
/// iguais: "apareceu um arquivo cujo nome casa com o catálogo".
///
/// Puro: entra XML, sai evento. A fixture dos testes é um evento real capturado na CI.
/// </summary>
public static class FsrmEventParser
{
    /// <summary><c>null</c> quando o evento não é do file screen do produto, ou veio incompleto.</summary>
    public static ParsedFileEvent? Parse(string? eventXml)
    {
        if (string.IsNullOrWhiteSpace(eventXml) || !eventXml.Contains(FsrmPlan.EventMarker, StringComparison.Ordinal)) return null;

        XElement root;
        try { root = XElement.Parse(eventXml); }
        catch (System.Xml.XmlException) { return null; }

        var body = root.Descendants().Where(e => e.Name.LocalName == "Data").Select(e => e.Value)
            .FirstOrDefault(v => v.StartsWith(FsrmPlan.EventMarker + "|", StringComparison.Ordinal));
        if (body is null) return null;

        var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in body.Split('|').Skip(1))       // '|' não é válido em nome de arquivo nem de conta
        {
            var eq = part.IndexOf('=');
            if (eq > 0) fields[part[..eq].Trim()] = part[(eq + 1)..].Trim();
        }

        if (!fields.TryGetValue("user", out var user) || user.Length == 0) return null;
        if (!fields.TryGetValue("file", out var file) || file.Length == 0) return null;

        var name = System.IO.Path.GetFileName(file);
        if (name.Length == 0) return null;
        var ext = System.IO.Path.GetExtension(name);

        // PID 4 (System) = a operação veio pela rede (SMB): não há processo local a apontar. Qualquer outro PID é um
        // processo deste servidor — alvo do degrau que encerra processo.
        int? pid = fields.TryGetValue("pid", out var pidText) && int.TryParse(pidText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var p) && p > 4
            ? p : null;
        var image = pid is not null && fields.TryGetValue("image", out var img) && img.Length > 0 ? img : null;

        var e = new FileEvent(
            At: TimeOf(root),
            User: user,
            SourceIp: SecurityEventParser.LocalOrigin,       // o FSRM não conhece o IP do cliente; o coletor atribui
            Share: System.IO.Path.GetDirectoryName(file) ?? "",
            Op: FileOp.Write,
            Path: name,
            NewExtension: string.IsNullOrEmpty(ext) ? null : ext,
            IsCanary: CanaryPlan.IsCanary(name),
            ProcessId: pid,
            ProcessName: image);
        return new ParsedFileEvent(e, null, file);
    }

    private static DateTime TimeOf(XElement root)
    {
        var raw = root.Descendants().FirstOrDefault(e => e.Name.LocalName == "TimeCreated")?.Attribute("SystemTime")?.Value;
        return DateTime.TryParse(raw, CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var t) ? t : DateTime.UtcNow;
    }
}
