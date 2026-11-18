using RansomGuard.Agent.Sensors;

namespace RansomGuard.Agent.Tests;

/// <summary>D1 — o parser entrega, além do evento, o que o resolvedor de share precisa: nome do share e caminho local completo.</summary>
public class ParsedFileEventTests
{
    private static string Xml5145(string shareLocal = @"\??\D:\Shares\Financeiro", string target = @"2024\contrato.docx", string share = @"\\*\Financeiro") => $"""
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><EventID>5145</EventID><TimeCreated SystemTime='2026-07-26T14:30:00.000000000Z'/></System>
          <EventData>
            <Data Name='SubjectUserName'>vendas1</Data><Data Name='SubjectDomainName'>CORP</Data>
            <Data Name='IpAddress'>10.0.9.66</Data><Data Name='ShareName'>{share}</Data>
            <Data Name='ShareLocalPath'>{shareLocal}</Data>
            <Data Name='RelativeTargetName'>{target}</Data><Data Name='AccessList'>%%4417</Data>
          </EventData>
        </Event>
        """;

    private const string Xml4663 = """
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><EventID>4663</EventID><TimeCreated SystemTime='2026-07-26T14:30:00.000000000Z'/></System>
          <EventData>
            <Data Name='SubjectUserName'>vendas1</Data><Data Name='SubjectDomainName'>CORP</Data>
            <Data Name='ObjectName'>D:\Shares\Financeiro\2024\folha.xlsx</Data><Data Name='AccessList'>%%4417</Data>
            <Data Name='ProcessId'>0x1a2c</Data><Data Name='ProcessName'>C:\Temp\x.exe</Data>
          </EventData>
        </Event>
        """;

    [Fact]
    public void Evento_de_share_traz_nome_e_caminho_local_completo()
    {
        var p = SecurityEventParser.ParseDetailed(Xml5145())!;

        Assert.Equal("Financeiro", p.ShareName);
        Assert.Equal(@"D:\Shares\Financeiro\2024\contrato.docx", p.LocalFullPath);
        Assert.Equal("Financeiro", p.Event.Share);              // contrato antigo do Parse preservado
    }

    [Fact]
    public void Share_na_raiz_do_volume_nao_duplica_a_barra()
    {
        var p = SecurityEventParser.ParseDetailed(Xml5145(shareLocal: @"\??\C:\", target: @"Shares\a.docx", share: @"\\*\C$"))!;

        Assert.Equal("C$", p.ShareName);
        Assert.Equal(@"C:\Shares\a.docx", p.LocalFullPath);
    }

    [Fact]
    public void Sem_caminho_local_do_share_o_caminho_completo_fica_desconhecido()
    {
        var p = SecurityEventParser.ParseDetailed(Xml5145(shareLocal: ""))!;

        Assert.Null(p.LocalFullPath);
        Assert.Equal("Financeiro", p.ShareName);
    }

    [Fact]
    public void Evento_de_objeto_traz_o_caminho_local_e_nenhum_nome_de_share()
    {
        var p = SecurityEventParser.ParseDetailed(Xml4663)!;

        Assert.Null(p.ShareName);
        Assert.Equal(@"D:\Shares\Financeiro\2024\folha.xlsx", p.LocalFullPath);
        Assert.Equal(0x1a2c, p.Event.ProcessId);
    }

    [Fact]
    public void Parse_continua_equivalente_ao_evento_do_ParseDetailed()
        => Assert.Equal(SecurityEventParser.ParseDetailed(Xml4663)!.Event, SecurityEventParser.Parse(Xml4663));
}
