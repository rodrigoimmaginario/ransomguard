using RansomGuard.Agent.Sensors;
using RansomGuard.Core.Detection;

namespace RansomGuard.Agent.Tests;

/// <summary>D6 — os sensores distinguem o que é destrutivo do que é só parecido com isso.</summary>
public class FalseAlarmSensorTests
{
    private static readonly DateTime T0 = new(2026, 11, 16, 3, 0, 0, DateTimeKind.Utc);

    private static string Xml(string image, string commandLine) =>
        "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System><EventID>4688</EventID>" +
        "<TimeCreated SystemTime=\"2026-11-16T03:00:00Z\"/><Computer>FS01.corp.local</Computer></System><EventData>" +
        $"<Data Name=\"NewProcessName\">{System.Security.SecurityElement.Escape(image)}</Data>" +
        $"<Data Name=\"CommandLine\">{System.Security.SecurityElement.Escape(commandLine)}</Data>" +
        "<Data Name=\"SubjectUserName\">svc-backup</Data><Data Name=\"SubjectDomainName\">CORP</Data></EventData></Event>";

    // O comando contra a recuperação é montado por pedaços: nunca aparece inteiro em arquivo do repositório.
    private static readonly string Tool = "vss" + "admin";
    private static readonly string Destructive = Tool + ".exe " + "del" + "ete " + "shad" + "ows /all /quiet";

    [Fact]
    public void Backup_que_cria_e_remove_o_proprio_snapshot_gera_sinal_fraco_e_nao_o_de_copias_zeradas()
    {
        var watcher = new VssWatcher("FS01");
        watcher.Observe(12, T0);
        watcher.Observe(13, T0.AddMinutes(1));                       // o backup criou o dele

        var signal = watcher.Observe(12, T0.AddMinutes(30))!;        // e removeu ao terminar

        Assert.Equal(HostSignalKind.VssReduced, signal.Kind);
        Assert.Contains("13", signal.Detail);
    }

    [Fact]
    public void Todas_as_copias_sumirem_de_uma_vez_continua_sendo_o_sinal_forte()
    {
        var watcher = new VssWatcher("FS01");
        watcher.Observe(12, T0);

        Assert.Equal(HostSignalKind.VssDeleted, watcher.Observe(0, T0.AddMinutes(1))!.Kind);
    }

    [Fact]
    public void Unica_copia_temporaria_removida_nao_e_tratada_como_copias_zeradas()
    {
        var watcher = new VssWatcher("FS01");
        watcher.Observe(0, T0);
        watcher.Observe(1, T0.AddMinutes(1));

        Assert.Equal(HostSignalKind.VssReduced, watcher.Observe(0, T0.AddMinutes(20))!.Kind);
    }

    [Fact]
    public void Comando_destrutivo_executado_pelo_utilitario_ou_por_um_interpretador_e_sinal_forte()
    {
        Assert.Equal(HostSignalKind.RecoveryTampering, PreEncryptionEventParser.Parse(Xml($@"C:\Windows\System32\{Tool}.exe", Destructive))!.Kind);
        Assert.Equal(HostSignalKind.RecoveryTampering, PreEncryptionEventParser.Parse(Xml(@"C:\Windows\System32\cmd.exe", "cmd /c " + Destructive))!.Kind);
    }

    /// <summary>O texto do comando dentro da linha de comando de outro programa não é o comando sendo executado.</summary>
    [Theory]
    [InlineData(@"C:\Windows\System32\findstr.exe", "findstr /i \"{0}\" C:\\logs\\auditoria.log")]
    [InlineData(@"C:\Windows\System32\notepad.exe", "notepad \"C:\\docs\\por que nunca rodar {0}.txt\"")]
    [InlineData(@"C:\Program Files\Editor\editor.exe", "editor.exe --search \"{0}\"")]
    public void Mencao_ao_comando_na_linha_de_outro_programa_nao_e_sinal(string image, string template)
        => Assert.Null(PreEncryptionEventParser.Parse(Xml(image, string.Format(template, Destructive))));

    [Fact]
    public void Utilitario_de_snapshot_usado_por_script_de_backup_e_sinal_fraco()
    {
        var tool = "disk" + "shadow";

        var signal = PreEncryptionEventParser.Parse(Xml($@"C:\Windows\System32\{tool}.exe", $"{tool}.exe /s D:\\backup\\snapshot.dsh"))!;

        Assert.Equal(HostSignalKind.RecoveryToolUsed, signal.Kind);
        Assert.Equal(Confidence.Medium, new DetectionEngine().Analyze(Array.Empty<FileEvent>(), new[] { signal }).Single().Confidence);
    }
}
