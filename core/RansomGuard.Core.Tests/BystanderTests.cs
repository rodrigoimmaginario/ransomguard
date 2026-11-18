using RansomGuard.Core.Detection;

namespace RansomGuard.Core.Tests;

/// <summary>
/// Um sinal do servidor (cópias de sombra removidas, auditoria alterada, serviço instalado) não pode transformar
/// em suspeito quem só estava trabalhando naquele minuto. Ele reforça quem JÁ tem comportamento suspeito próprio;
/// para os demais, o sinal continua existindo — como incidente do servidor, sem usuário nem IP para conter.
///
/// O defeito ficou dormente enquanto o nome do servidor não batia com o do share; com a identidade canônica
/// (<c>\\SERVIDOR\Share</c>) qualquer usuário ativo perto de um sinal de Alta seria contido em modo Block.
/// </summary>
public class BystanderTests
{
    private static readonly DateTime T0 = new(2026, 11, 16, 10, 0, 0, DateTimeKind.Utc);

    private static FileEvent Ev(string user, string ip, FileOp op, string path) =>
        new(T0, user, ip, @"\\FS01\Financeiro", op, path, ".xlsx");

    private static readonly HostSignal VssRemovido = new(T0.AddSeconds(10), HostSignalKind.VssDeleted, "FS01", "2 cópias de sombra removidas");

    [Fact]
    public void Quem_so_estava_trabalhando_nao_herda_o_sinal_do_servidor()
    {
        var eventos = new[]
        {
            Ev(@"CORP\ana", "10.0.4.11", FileOp.Read, "relatorio.xlsx"),
            Ev(@"CORP\ana", "10.0.4.11", FileOp.Write, "relatorio.xlsx"),
            Ev(@"CORP\bia", "10.0.4.12", FileOp.Read, "folha.xlsx"),
        };

        var deteccoes = new DetectionEngine().Analyze(eventos, new[] { VssRemovido });

        var d = Assert.Single(deteccoes);            // só o incidente do servidor
        Assert.Equal("", d.User);
        Assert.Equal("", d.SourceIp);
        Assert.Equal("FS01", d.Server);
        Assert.Contains(DetectionReason.VssDeletion, d.Reasons);
    }

    [Fact]
    public void O_sinal_reforca_apenas_o_ator_que_ja_era_suspeito()
    {
        var eventos = Enumerable.Range(0, 60).Select(i => Ev(@"CORP\invasor", "10.0.9.66", FileOp.Write, $"doc{i}.xlsx"))
            .Append(Ev(@"CORP\ana", "10.0.4.11", FileOp.Write, "relatorio.xlsx"))
            .ToList();

        var deteccoes = new DetectionEngine().Analyze(eventos, new[] { VssRemovido });

        var d = Assert.Single(deteccoes);
        Assert.Equal(@"CORP\invasor", d.User);
        Assert.Equal(Confidence.High, d.Confidence);
        Assert.Contains(DetectionReason.VssDeletion, d.Reasons);
        Assert.Contains(DetectionReason.MassRewrite, d.Reasons);
    }

    [Fact]
    public void Sinal_de_outro_servidor_nao_reforca_ninguem_aqui()
    {
        var eventos = Enumerable.Range(0, 60).Select(i => Ev(@"CORP\joao", "10.0.4.20", FileOp.Write, $"doc{i}.xlsx")).ToList();
        var deOutro = new HostSignal(T0, HostSignalKind.VssDeleted, "FS02", "cópias de sombra removidas");

        var deteccoes = new DetectionEngine().Analyze(eventos, new[] { deOutro });

        Assert.Equal(2, deteccoes.Count);
        Assert.Equal(Confidence.Medium, deteccoes.Single(d => d.User == @"CORP\joao").Confidence);
        Assert.Equal("FS02", deteccoes.Single(d => d.User == "").Server);
    }
}
