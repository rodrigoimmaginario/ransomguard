using System.Globalization;
using System.Text;
using RansomGuard.Core.Response;
using DetectionModel = RansomGuard.Core.Detection.Detection;

namespace RansomGuard.Core.Siem;

/// <summary>
/// Exporta incidentes e ações de resposta no formato **CEF** (Common Event Format) sobre uma linha
/// de syslog RFC 5424 — o que a maioria dos SIEMs ingere. Conteúdo-zero: só metadado. Faz o escaping
/// exigido pelo CEF (cabeçalho: \ e |; extensão: \ e =).
/// </summary>
public static class CefExporter
{
    private const string Vendor = "RansomGuard";
    private const string Product = "RansomGuard";
    private const string Version = "1.0";

    /// <summary>CEF de um incidente detectado. severity 0–10 conforme a confiança.</summary>
    public static string Incident(DetectionModel d)
    {
        var sev = d.Confidence switch
        {
            Detection.Confidence.High => 9,
            Detection.Confidence.Medium => 6,
            _ => 3
        };
        var header = Header("100", "Ransomware incident detected", sev);
        var ext = Extension(new (string, string)[]
        {
            ("dvchost", d.Server),
            ("suser", d.User),
            ("src", d.SourceIp),
            ("fname", d.Share),
            ("cnt", d.AffectedFiles.ToString(CultureInfo.InvariantCulture)),
            ("reason", string.Join("+", d.Reasons)),
            ("rt", Millis(d.LastAt)),
        });
        return $"{header}{ext}";
    }

    /// <summary>CEF de uma ação de contenção executada.</summary>
    public static string ResponseAction(AuditEntry entry)
    {
        var a = entry.Action;
        var header = Header("200", $"Response {a.Step}", 8);
        var ext = Extension(new (string, string)[]
        {
            ("dvchost", a.Server),
            ("act", a.Step.ToString()),
            ("dst", a.Target),
            ("suser", entry.Actor),
            ("msg", entry.Justification),
            ("rt", Millis(entry.At)),
        });
        return $"{header}{ext}";
    }

    private static string Header(string sig, string name, int severity)
        => $"CEF:0|{Esc(Vendor, header: true)}|{Esc(Product, header: true)}|{Version}|{sig}|{Esc(name, header: true)}|{severity}|";

    private static string Extension(IEnumerable<(string Key, string Value)> pairs)
        => string.Join(" ", pairs.Select(p => $"{p.Key}={Esc(p.Value, header: false)}"));

    private static string Millis(DateTime dt)
        => ((long)(dt.ToUniversalTime() - DateTime.UnixEpoch).TotalMilliseconds)
            .ToString(CultureInfo.InvariantCulture);

    /// <summary>Escaping do CEF: no cabeçalho escapa \ e |; na extensão escapa \ e =. Novas linhas viram espaço.</summary>
    private static string Esc(string s, bool header)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
        {
            switch (c)
            {
                case '\\': sb.Append("\\\\"); break;
                case '|' when header: sb.Append("\\|"); break;
                case '=' when !header: sb.Append("\\="); break;
                case '\n' or '\r': sb.Append(' '); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString();
    }
}
