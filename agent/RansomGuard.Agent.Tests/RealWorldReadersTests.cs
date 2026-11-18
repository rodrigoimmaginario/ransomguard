using RansomGuard.Agent.Posture;
using RansomGuard.Agent.Sensors;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// Política de auditoria sem depender do idioma do Windows: a subcategoria é apontada pelo GUID e o estado vem da API
/// do sistema como bits, sem passar por texto. (A leitura anterior, pelo relatório do <c>auditpol /r</c>, voltou
/// "não sei" em Windows real; ver <c>WindowsAudit</c>.)
/// </summary>
public class AuditPolicyBitsTests
{
    [Theory]
    [InlineData(0u, false)]     // sem auditoria
    [InlineData(2u, false)]     // só falha: o acesso bem-sucedido não é gravado
    [InlineData(1u, true)]
    [InlineData(3u, true)]
    public void So_o_bit_de_sucesso_conta(uint valor, bool esperado)
        => Assert.Equal(esperado, AuditPolicyReader.IsSuccess(valor));

    [Fact]
    public void O_comando_que_liga_usa_o_guid_e_nao_o_nome()
    {
        Assert.Contains("{0CCE921D-69AE-11D9-BED3-505054503030}", AuditSubcategory.FileSystem.EnableArguments);
        Assert.Contains("/success:enable", AuditSubcategory.FileSystem.EnableArguments);
        Assert.DoesNotContain("File System", AuditSubcategory.FileSystem.EnableArguments);
        Assert.True(Guid.TryParse(AuditSubcategory.DetailedFileShare.Guid, out _));
        Assert.True(Guid.TryParse(AuditSubcategory.ProcessCreation.Guid, out _));
    }
}

/// <summary>
/// Sessões SMB em formato próprio (<c>cliente|usuário|aberturas</c>), uma por linha — em vez de recortar a tabela que
/// o PowerShell desenha para humanos. O nome do cliente vem do Windows com enfeites (<c>\\10.0.9.66</c>,
/// <c>[::1]</c>); aqui ele vira o mesmo texto que o evento de share traz como IP.
/// </summary>
public class SmbSessionLinesTests
{
    [Fact]
    public void Le_cliente_e_usuario_de_cada_linha()
    {
        var s = SessionCorrelator.ParseSessionLines("10.0.9.66|CORP\\vendas1|3\r\n10.0.4.20|CORP\\ana|0\r\n");

        Assert.Equal(2, s.Count);
        Assert.Equal(new SmbSession(@"CORP\vendas1", "10.0.9.66"), s[0]);
        Assert.Equal(@"CORP\ana", s[1].User);
    }

    [Theory]
    [InlineData(@"\\10.0.9.66", "10.0.9.66")]
    [InlineData("[fe80::1c2b:3d4e]", "fe80::1c2b:3d4e")]
    [InlineData("[::1]", "local")]
    [InlineData("127.0.0.1", "local")]
    [InlineData(@"\\ESTACAO-07", "ESTACAO-07")]
    public void Nome_do_cliente_e_normalizado_como_a_origem_dos_eventos(string cliente, string esperado)
        => Assert.Equal(esperado, SessionCorrelator.ParseSessionLines($"{cliente}|CORP\\vendas1|1").Single().SourceIp);

    [Theory]
    [InlineData("")]
    [InlineData("Get-SmbSession : Acesso negado.")]
    [InlineData("|CORP\\x|1")]
    [InlineData("10.0.0.1||1")]
    public void Linha_que_nao_e_sessao_e_ignorada(string saida)
        => Assert.Empty(SessionCorrelator.ParseSessionLines(saida));
}
