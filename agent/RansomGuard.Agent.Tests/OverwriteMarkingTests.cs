using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Tests;

/// <summary>
/// Laboratório, sessão 3 — quem sabe se um arquivo gravado já existia é o disco: um arquivo regravado no lugar mantém a
/// data de criação antiga; um arquivo novo nasce com ela no instante da gravação. O coletor consulta só arquivos
/// gravados, uma vez por arquivo por ciclo.
/// </summary>
public class OverwriteMarkingTests
{
    private sealed class Log : ISecurityLogSource
    {
        public readonly SortedDictionary<long, string> Records = new();
        public long? NewestRecordId() => Records.Count == 0 ? null : Records.Keys.Max();
        public IEnumerable<SecurityLogRecord> ReadAfter(long recordId, int max) =>
            Records.Where(r => r.Key > recordId).Take(max).Select(r => new SecurityLogRecord(r.Key, r.Value)).ToList();
    }

    private sealed class Memory : ICursorStore
    {
        public string? Content = "0";
        public string? Read() => Content;
        public void Write(string content) => Content = content;
    }

    private static string Xml5145(string target, string access) => $"""
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System><EventID>5145</EventID><TimeCreated SystemTime='2026-11-17T11:00:05.000000000Z'/><Computer>rg-fs1.lab.ransomguard.test</Computer></System>
          <EventData>
            <Data Name='SubjectUserName'>atk09</Data><Data Name='SubjectDomainName'>RGLAB</Data>
            <Data Name='IpAddress'>10.88.1.40</Data><Data Name='ShareName'>\\*\Dados</Data>
            <Data Name='ShareLocalPath'>\??\C:\Shares\Dados</Data>
            <Data Name='RelativeTargetName'>{target}</Data><Data Name='AccessList'>{access}</Data>
          </EventData>
        </Event>
        """;

    private static readonly DateTime EventAt = new(2026, 11, 17, 11, 0, 5, DateTimeKind.Utc);

    [Fact]
    public void Arquivo_antigo_gravado_e_regravacao_e_arquivo_novo_nao()
    {
        var created = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase)
        {
            [@"C:\Shares\Dados\a9\antigo.docx"] = EventAt.AddDays(-30),
            [@"C:\Shares\Dados\a9\novo.docx"] = EventAt.AddSeconds(-1)
        };
        var asked = new List<string>();
        var log = new Log();
        log.Records[1] = Xml5145(@"a9\antigo.docx", "%%4417");
        log.Records[2] = Xml5145(@"a9\antigo.docx", "%%4417");      // segunda checagem do mesmo arquivo
        log.Records[3] = Xml5145(@"a9\novo.docx", "%%4417");
        log.Records[4] = Xml5145(@"a9\sumiu.docx", "%%4417");      // já renomeado/apagado: não se sabe
        log.Records[5] = Xml5145(@"a9\lido.docx", "%%4416");        // leitura: nem se consulta
        var collector = new SecurityLogCollector(log, new EventCursor(new Memory()),
            () => new ShareMap("rg-fs1", new[] { new ShareEntry("Dados", @"C:\Shares\Dados") }), () => Array.Empty<SmbSession>(),
            creationTimeOf: path => { asked.Add(path); return created.TryGetValue(path, out var at) ? at : null; });

        var events = collector.Drain();

        Assert.All(events.Where(e => e.Path == @"a9\antigo.docx"), e => Assert.True(e.Overwrite));
        Assert.False(events.Single(e => e.Path == @"a9\novo.docx").Overwrite);
        Assert.False(events.Single(e => e.Path == @"a9\sumiu.docx").Overwrite);
        Assert.False(events.Single(e => e.Path == @"a9\lido.docx").Overwrite);
        Assert.Equal(3, asked.Count);                                  // uma consulta por arquivo gravado
        Assert.DoesNotContain(asked, p => p.EndsWith("lido.docx"));
    }

    [Fact]
    public void Sem_acesso_ao_disco_nada_e_marcado_e_a_coleta_segue()
    {
        var log = new Log();
        log.Records[1] = Xml5145(@"a9\antigo.docx", "%%4417");
        var collector = new SecurityLogCollector(log, new EventCursor(new Memory()),
            () => new ShareMap("rg-fs1", new[] { new ShareEntry("Dados", @"C:\Shares\Dados") }), () => Array.Empty<SmbSession>(),
            creationTimeOf: _ => throw new UnauthorizedAccessException());

        Assert.False(Assert.Single(collector.Drain()).Overwrite);
    }
}
