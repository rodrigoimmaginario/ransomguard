using System.Text;

namespace RansomGuard.Core.Score;

/// <summary>
/// Gera o conteúdo estruturado do relatório executivo do Score de Risco — o documento que o admin
/// leva à diretoria. Aqui produz-se o conteúdo (texto/estrutura) e ele é testável; o render em PDF
/// (via Blazor/servidor) entra na fatia 2. Metadado apenas.
/// </summary>
public static class ScoreReport
{
    /// <summary>Rótulo de faixa em PT-BR para o relatório.</summary>
    public static string BandLabel(RiskBand band) => band switch
    {
        RiskBand.Critical => "Crítico",
        RiskBand.Attention => "Atenção",
        RiskBand.Good => "Bom",
        _ => "Desconhecido"
    };

    /// <summary>Monta o relatório executivo consolidado da rede em texto.</summary>
    public static string BuildExecutive(NetworkScore network)
    {
        var sb = new StringBuilder();
        sb.AppendLine("RansomGuard — Relatório de Risco de Ransomware");
        sb.AppendLine(new string('=', 52));
        sb.AppendLine($"Nota consolidada da rede: {network.Score}/100 ({BandLabel(network.Band)})");
        sb.AppendLine($"Servidores avaliados: {network.Servers.Count}");
        if (network.ServersWithoutAgent > 0)
            sb.AppendLine($"⚠ Servidores sem agente (visibilidade cega): {network.ServersWithoutAgent}");
        sb.AppendLine();

        // Top correções da rede inteira, por prioridade — o que fazer primeiro.
        var top = network.Servers
            .SelectMany(s => s.Findings)
            .OrderByDescending(f => f.Priority)
            .Take(5)
            .ToList();

        if (top.Count > 0)
        {
            sb.AppendLine("Prioridades (o que corrigir primeiro):");
            foreach (var f in top)
                sb.AppendLine($"  • [{f.Server}] {f.Rule.Title} — {f.Rule.Fix}");
            sb.AppendLine();
        }

        sb.AppendLine("Por servidor (pior primeiro):");
        foreach (var s in network.Servers)
            sb.AppendLine($"  {s.Score,3}/100 {BandLabel(s.Band),-8} {s.Server} " +
                          $"({s.Findings.Count} achado(s))");

        return sb.ToString();
    }

    /// <summary>Detalhe de um servidor: cada achado com a premissa de ataque e a correção.</summary>
    public static string BuildServerDetail(ServerScore server)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Servidor {server.Server}: {server.Score}/100 ({BandLabel(server.Band)})");
        sb.AppendLine(new string('-', 52));
        if (server.Findings.Count == 0)
        {
            sb.AppendLine("Sem achados — postura em conformidade com o catálogo.");
            return sb.ToString();
        }
        foreach (var f in server.Findings)
        {
            sb.AppendLine($"[{f.Rule.Severity}] {f.Rule.Title}  (-{f.Rule.Weight} pts)");
            sb.AppendLine($"   Porquê: {f.Rule.AttackPremise}");
            sb.AppendLine($"   Correção: {f.Rule.Fix}");
        }
        return sb.ToString();
    }
}
