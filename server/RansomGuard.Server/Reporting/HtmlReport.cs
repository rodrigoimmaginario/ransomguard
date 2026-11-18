using System.Net;
using System.Text;
using RansomGuard.Core.Score;

namespace RansomGuard.Server.Reporting;

/// <summary>
/// Gera o relatório executivo do Score em HTML com CSS de impressão (print-to-PDF pelo navegador).
/// Sem dependência externa (decisão D5). Identidade visual roxa da marca. Metadado apenas.
/// </summary>
public static class HtmlReport
{
    private static string E(string s) => WebUtility.HtmlEncode(s);

    private static string BandColor(RiskBand b) => b switch
    {
        RiskBand.Critical => "#C0433B",
        RiskBand.Attention => "#9A6A0C",
        RiskBand.Good => "#157F55",
        _ => "#7A5374"
    };

    public static string BuildExecutive(NetworkScore net, DateTime generatedAt)
    {
        var sb = new StringBuilder();
        sb.Append("""
        <!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
        <title>RansomGuard — Relatório de Risco</title>
        <style>
          @media print { .noprint { display:none } @page { margin: 18mm } }
          body{font-family:"Segoe UI",system-ui,sans-serif;color:#2B1527;margin:32px;line-height:1.5}
          h1{font-size:22px;margin:0 0 2px} h2{font-size:16px;margin:22px 0 8px;color:#86336A}
          .sub{color:#7A5374;font-size:13px}
          .score{font-size:44px;font-weight:800;line-height:1}
          .band{font-size:13px;font-weight:700;padding:2px 10px;border-radius:20px;color:#fff}
          table{width:100%;border-collapse:collapse;margin-top:6px;font-size:13px}
          th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #EDDAEA}
          th{color:#8B6284;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
          .fix{color:#7A5374}
          .warn{color:#C0433B;font-weight:600}
          .btn{background:#9C3F7C;color:#fff;border:0;padding:9px 16px;border-radius:8px;cursor:pointer;font-size:14px}
        </style></head><body>
        """);

        sb.Append($"<h1>RansomGuard — Relatório de Risco de Ransomware</h1>");
        sb.Append($"<div class='sub'>Gerado em {E(generatedAt.ToString("dd/MM/yyyy HH:mm"))} · metadado, nunca conteúdo</div>");
        sb.Append("<button class='btn noprint' onclick='window.print()' style='margin-top:14px'>Imprimir / salvar PDF</button>");

        sb.Append($"<h2>Nota consolidada da rede</h2>");
        sb.Append($"<div class='score' style='color:{BandColor(net.Band)}'>{net.Score}<span style='font-size:18px;color:#8B6284'>/100</span></div>");
        sb.Append($"<span class='band' style='background:{BandColor(net.Band)}'>{E(ScoreReport.BandLabel(net.Band))}</span>");
        sb.Append($"<div class='sub' style='margin-top:8px'>{net.Servers.Count} servidor(es) avaliado(s)");
        if (net.ServersWithoutAgent > 0)
            sb.Append($" · <span class='warn'>{net.ServersWithoutAgent} sem agente (visibilidade cega)</span>");
        sb.Append("</div>");

        var top = net.Servers.SelectMany(s => s.Findings)
            .OrderByDescending(f => f.Priority).Take(8).ToList();
        if (top.Count > 0)
        {
            sb.Append("<h2>Prioridades — o que corrigir primeiro</h2><table>");
            sb.Append("<tr><th>Servidor</th><th>Achado</th><th>Correção</th></tr>");
            foreach (var f in top)
                sb.Append($"<tr><td>{E(f.Server)}</td><td>{E(f.Rule.Title)}</td><td class='fix'>{E(f.Rule.Fix)}</td></tr>");
            sb.Append("</table>");
        }

        sb.Append("<h2>Servidores (pior primeiro)</h2><table>");
        sb.Append("<tr><th>Servidor</th><th>Nota</th><th>Faixa</th><th>Achados</th></tr>");
        foreach (var s in net.Servers)
            sb.Append($"<tr><td>{E(s.Server)}</td><td>{s.Score}/100</td>" +
                      $"<td>{E(ScoreReport.BandLabel(s.Band))}</td><td>{s.Findings.Count}</td></tr>");
        sb.Append("</table>");

        sb.Append("</body></html>");
        return sb.ToString();
    }
}
