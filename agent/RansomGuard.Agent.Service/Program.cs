using RansomGuard.Agent;
using RansomGuard.Agent.Drill;
using RansomGuard.Agent.Protection;
using RansomGuard.Agent.Sensors;
using RansomGuard.Agent.Service;
using RansomGuard.Agent.Service.Windows;
using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;
using RansomGuard.Core.Signing;

var builder = Host.CreateApplicationBuilder(args);

// Roda como Serviço do Windows. O nome DEVE casar com o ServiceInstall do MSI (deploy/msi/agente.wxs).
builder.Services.AddWindowsService(o => o.ServiceName = "RansomGuardAgent");

// Config vinda do REGISTRO (gravada pelo MSI a partir das propriedades passadas na instalação por
// GPO) tem precedência sobre o appsettings.json — é o que permite implantar em massa sem editar
// arquivo em cada servidor. Fora do Windows/sem as chaves, cai no appsettings normalmente.
builder.Configuration.AddInMemoryCollection(RegistryConfig.Read());

var cfg = builder.Configuration;
var dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RansomGuard");
var serverName = cfg["Agent:ServerName"] ?? Environment.MachineName;
var backendUrl = cfg["Agent:BackendUrl"] ?? "http://localhost:5000";
var mode = Enum.TryParse<ResponseMode>(cfg["Agent:Mode"], out var m) ? m : ResponseMode.Monitor;

// O produto é gratuito: não há licença nem override de laboratório. A contenção depende só do modo —
// Agent:Mode até o painel publicar a política assinada, que passa a valer. Fail-safe: nasce em Monitor.

// Efetores/coletores reais do Windows.
// Pastas protegidas: onde o produto planta canário e aplica o file screen. Caminho perigoso
// (raiz de volume, Windows, Program Files) é recusado com motivo — um erro de digitação numa GPO
// não pode virar incidente no parque inteiro.
var pathSet = ProtectedPaths.Parse(cfg["Agent:ProtectedPaths"]);
var protectedPaths = pathSet.Accepted;

// FSRM começa em AUDITORIA. Bloquear extensão em share de produção sem o admin pedir
// transformaria o produto no incidente.
var fsrmBlocking = bool.TryParse(cfg["Agent:FsrmBlocking"], out var fb) && fb;

// B4: manifesto local dos canários — nomes e conteúdo desta instalação, e as pastas em que já foram plantados.
builder.Services.AddSingleton(sp => CanaryManifest.Load(dataDir, cfg["Agent:CanaryNames"], sp.GetRequiredService<ILogger<CanaryManifest>>()));
builder.Services.AddSingleton<IPostureCollector>(sp =>
    new WindowsPostureCollector(sp.GetRequiredService<ILogger<WindowsPostureCollector>>(), protectedPaths,
        canaryNames: () => sp.GetRequiredService<CanaryManifest>().Names));

// Cursor do Security log em ProgramData: sobrevive a reinício do serviço e a atualização do MSI.
// Sem ele, cada restart reprocessaria o log (tempestade de alertas falsos) ou pularia a janela em
// que o serviço esteve parado — justamente quando um EDR killer teria agido.
var cursorPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "RansomGuard", "agent-cursor.txt");

// G2: buffer de sinais fora do ciclo (visibilidade reparada, canário sumido, 4719/1102).
var signalBuffer = new RansomGuard.Agent.Sensors.HostSignalBuffer();
builder.Services.AddSingleton(signalBuffer);
var autoRepairVisibility = !bool.TryParse(cfg["Agent:AutoRepairVisibility"], out var arv) || arv;

// D1: tabela de shares deste servidor (registro do LanmanServer, com cache). Todo evento sai com o share na
// forma canônica \\SERVIDOR\Share — a mesma do motor, da escada de resposta e dos shares-isca.
var shareTable = new WindowsShareTable(serverName);

// E3: cursor próprio para o log de Aplicativo, onde o FSRM grava as violações do file screen do produto.
var fsrmCursorPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "RansomGuard", "agent-cursor-fsrm.txt");

builder.Services.AddSingleton<WindowsFileEventCollector>(sp => new WindowsFileEventCollector(
    sp.GetRequiredService<ILogger<WindowsFileEventCollector>>(),
    new EventCursor(new FileCursorStore(cursorPath)),
    shares: shareTable.Current,
    signals: signalBuffer,
    fsrmCursor: new EventCursor(new FileCursorStore(fsrmCursorPath))));
builder.Services.AddSingleton<IFileEventCollector>(sp => sp.GetRequiredService<WindowsFileEventCollector>());

// O coletor de sinais pergunta ao de eventos quantas falhas seguidas houve: coletor cego precisa
// aparecer como sinal, não como silêncio.
builder.Services.AddSingleton<IHostSignalCollector>(sp => new WindowsHostSignalCollector(
    sp.GetRequiredService<ILogger<WindowsHostSignalCollector>>(),
    serverName,
    () => sp.GetRequiredService<WindowsFileEventCollector>().ConsecutiveFailures,
    signalBuffer));
// B1 — guarda da blocklist: o executor real só é alcançado depois de recusar o bloqueio de endereços de que este
// servidor depende (gateway, servidores de nomes/controladores, painel, os próprios).
builder.Services.AddSingleton<WindowsResponseExecutor>();
builder.Services.AddSingleton<IResponseExecutor>(sp => new RansomGuard.Core.Response.InfrastructureGuardExecutor(
    sp.GetRequiredService<WindowsResponseExecutor>(), () => InfrastructureAddresses.Current(backendUrl)));

// B1 — identidade do agente: chave própria, gerada aqui e guardada protegida; o painel só a conhece depois do
// enrolamento com um token de uso limitado (Agent:EnrollToken, vindo do instalador). Não há segredo compartilhado.
string? enrollToken = cfg["Agent:EnrollToken"];
builder.Services.AddSingleton(sp => new AgentIdentity(dataDir, serverName, sp.GetRequiredService<ILogger<AgentIdentity>>()));

// R9: postura de transporte. O agente avisa (não bloqueia) quando o canal com o painel está em claro ou quando
// ainda não há enrolamento nem token para fazê-lo.
var transport = RansomGuard.Core.Auth.TransportPosture.Evaluate(
    backendUrl, enrolled: File.Exists(Path.Combine(dataDir, AgentIdentity.EnrolledFileName)) || !string.IsNullOrWhiteSpace(enrollToken));
if (!transport.Secure)
    foreach (var aviso in transport.Warnings)
        Console.Error.WriteLine($"[RansomGuard][transporte] {aviso}");

// F39: pin do certificado TLS do painel (configurado em Agent:PanelCertThumbprint ou TOFU em ProgramData).
var certPinPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RansomGuard", "panel-cert.sha256");
var configuredCert = cfg["Agent:PanelCertThumbprint"];
builder.Services.AddHttpClient("enroll", c => c.BaseAddress = new Uri(backendUrl))
    .ConfigurePrimaryHttpMessageHandler(sp => PinnedHttpHandler.Create(certPinPath, configuredCert, sp.GetRequiredService<ILogger<AgentEnroller>>()));
builder.Services.AddSingleton(sp => new AgentEnroller(
    sp.GetRequiredService<IHttpClientFactory>().CreateClient("enroll"), sp.GetRequiredService<AgentIdentity>(),
    token: () => enrollToken,
    discardToken: () => { enrollToken = null; RegistryConfig.ClearEnrollToken(); },
    sp.GetRequiredService<ILogger<AgentEnroller>>()));
// Sessão 5 do laboratório: sem teto, um envio ao painel parado ficava ~21 s preso (padrão do HttpClient: 100 s).
builder.Services.AddHttpClient<IBatchSink, HttpBatchSink>(c => { c.BaseAddress = new Uri(backendUrl); c.Timeout = TimeSpan.FromSeconds(10); })
    .ConfigurePrimaryHttpMessageHandler(sp => PinnedHttpHandler.Create(certPinPath, configuredCert, sp.GetRequiredService<ILogger<HttpBatchSink>>()));

// F38: confiança no painel. A decisão "pode conter?" só é aceita assinada pela chave da instalação do painel.
// Chave fixada por configuração (Agent:PanelPublicKey) ou no primeiro contato (TOFU, guardada em ProgramData).
var panelKeyPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RansomGuard", "panel-key.pub");
var panelTrust = new RansomGuard.Agent.Auth.PanelTrust(new FilePanelKeyStore(panelKeyPath), cfg["Agent:PanelPublicKey"]);
builder.Services.AddSingleton(panelTrust);
// F33: a política de resposta vem do painel, assinada; a do registro (Agent:Mode) vale só até a primeira publicação.
var policyPath = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RansomGuard", "agent-policy.json");
var policyStore = new FilePolicyStore(policyPath);
// F34: fila durável de lotes (painel fora = nada se perde).
var queueDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RansomGuard", "queue");
builder.Services.AddHttpClient<PanelIdentityPinner>(c => c.BaseAddress = new Uri(backendUrl))
    .ConfigurePrimaryHttpMessageHandler(sp => PinnedHttpHandler.Create(certPinPath, configuredCert, sp.GetRequiredService<ILogger<PanelIdentityPinner>>()));

// F18 — coordenador do catálogo assinado. Trust anchor EMBUTIDO (config em Dev; a chave real vem
// da cerimônia do owner). Fail-closed: sem chave de produção, o coordenador não é criado e o
// applier segue na semente conservadora — nunca aplica lista não verificada.
var catalogKeyB64 = cfg["Agent:CatalogPublicKeyBase64"];
RansomGuard.Agent.Catalog.CatalogCoordinator? catalogCoordinator = null;
if (!string.IsNullOrWhiteSpace(catalogKeyB64))
{
    try
    {
        var blob = Convert.FromBase64String(catalogKeyB64);
        var trustedKey = MinisignPublicKey.FromRaw(blob.AsSpan(0, 8), blob.AsSpan(8, 32));
        var store = new FileCatalogStore();
        // D8: o catálogo vem do painel pelo mesmo canal com pin dos lotes. Antes usava um cliente comum, que recusa
        // o certificado autoassinado do painel, e registrava a falha num logger nulo: o agente ficava na semente.
        var catalogLog = LoggerFactory.Create(b => { b.AddConsole(); if (OperatingSystem.IsWindows()) b.AddEventLog(); })
            .CreateLogger<HttpCatalogSource>();
        var source = new HttpCatalogSource(
            AgentHttp.CreatePinned(backendUrl, certPinPath, configuredCert, catalogLog),
            catalogLog);
        catalogCoordinator = new RansomGuard.Agent.Catalog.CatalogCoordinator(source, store, trustedKey);
        catalogCoordinator.Initialize();
    }
    catch
    {
        catalogCoordinator = null;   // chave malformada = fail-closed (semente)
    }
}
// Registrado só quando existe (fail-closed): o Worker o recebe como opcional.
if (catalogCoordinator is not null)
    builder.Services.AddSingleton(catalogCoordinator);

// As MÃOS do agente: planta canários e aplica o file screen nas pastas configuradas.
// F18: o applier consome o catálogo ativo do coordenador (último assinado bom), ou a semente.
builder.Services.AddSingleton(sp => new ProtectionApplier(
    sp.GetRequiredService<ILogger<ProtectionApplier>>(), protectedPaths, fsrmBlocking,
    activeCatalog: catalogCoordinator is not null ? () => catalogCoordinator.Active : null,
    signals: signalBuffer, autoRepairVisibility: autoRepairVisibility, server: serverName,
    learnedExtensions: () => sp.GetRequiredService<AgentCycle>().LearnedExtensions,
    canaries: sp.GetRequiredService<CanaryManifest>()));

// G1 — detecção em profundidade: extensões conhecidas vêm do catálogo assinado ATIVO (provedor, para refletir
// atualizações sem recriar o motor); shares-isca do registro; memória entre ciclos (tracker) para a janela de 60 s
// real, low-and-slow e anomalia de ritmo.
// D1: o admin pode escrever o share-isca como UNC (com qualquer nome de servidor) ou só o nome; vira a forma canônica.
var decoyShares = (cfg["Agent:DecoyShares"] ?? "")
    .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
    .Select(shareTable.Current().NormalizeConfigured)
    .OfType<string>()
    .ToHashSet(StringComparer.OrdinalIgnoreCase);
var detectionOptions = new DetectionOptions
{
    DecoyShares = decoyShares,
    KnownExtensionsProvider = () => (catalogCoordinator?.Active ?? RansomGuard.Core.Fsrm.SeedCatalog.AsCatalog).Extensions,
    // G7: notas de resgate extras e afinação de limiares vêm do catálogo assinado ativo.
    CatalogProvider = () => catalogCoordinator?.Active
};
builder.Services.AddSingleton(new ActorActivityTracker());

// O ciclo do agente: default fail-safe = monitor; contenção exige modo bloqueio, definido pelo administrador
// (registro até a primeira política assinada do painel; depois, a política).
builder.Services.AddSingleton(sp => new AgentCycle(
    serverName,
    sp.GetRequiredService<IPostureCollector>(),
    sp.GetRequiredService<IFileEventCollector>(),
    sp.GetRequiredService<IHostSignalCollector>(),
    sp.GetRequiredService<IBatchSink>(),
    new ResponseLadder(),
    new ResponsePolicy { Mode = mode },
    sp.GetRequiredService<IResponseExecutor>(),
    detectionOptions, trust: panelTrust, policyStore: policyStore,
    tracker: sp.GetRequiredService<ActorActivityTracker>(),
    queue: new FileBatchQueue(queueDir, sp.GetRequiredService<ILogger<FileBatchQueue>>()),
    // B5: o que a blocklist de rede bloqueou no firewall fica lembrado em disco (libera certo depois de um reinício).
    blocklistStore: new FileAppliedBlocklistStore(Path.Combine(dataDir, "blocklist-applied.json"))));

// Modo diagnóstico: responde "por que não vejo nada?" sem alterar nada no sistema. É também a
// única forma de provar em máquina real que o coletor lê o Security log — o teste automatizado
// roda sem elevação e o log exige privilégio.
if (args.Contains("--diagnostico") || args.Contains("--diagnose"))
    return Diagnostico.Executar(pathSet);

// Ensaio de ataque controlado: prova a cadeia detecção→incidente num ambiente real, e é o que o
// tester usa para ver o produto pegar um ataque. Imita ransomware com travas de segurança —
// só opera em pasta de ensaio marcada, nunca criptografa, só age com --confirmar.
if (args.Any(a => a.StartsWith("--ensaio")))
{
    CanaryManifest.RecognizeExisting(dataDir);   // B4: o ensaio precisa saber quais arquivos são canário para não tratá-los como dado
    return DrillCli.Run(args);
}

// Preparar/reverter sem subir o serviço: o admin precisa poder plantar agora e, principalmente,
// **desfazer** com um comando. Um produto que escreve no ambiente do cliente e não oferece o
// caminho de volta não merece a confiança de mexer nas pastas dele.
if (args.Contains("--preparar") || args.Contains("--reverter"))
{
    using var host = builder.Build();
    var applier = host.Services.GetRequiredService<ProtectionApplier>();

    if (args.Contains("--reverter"))
    {
        var removidos = applier.Revert();
        foreach (var r in removidos)
            Console.WriteLine(r.Ok
                ? $"  [ OK ] {r.Path} — {r.Planted} canário(s) removido(s)"
                : $"  [FALHA] {r.Path} — {r.Error}");
        return removidos.All(r => r.Ok) ? 0 : 1;
    }

    var status = applier.Apply();
    Console.WriteLine($"\n  Modo de proteção: {status.Mode}\n  {status.Explanation}");
    return status.Mode == ProtectionMode.None ? 1 : 0;
}

// D9: a pasta de dados do agente (cursor, pin do painel, política, fila de lotes) só para SYSTEM, administradores e
// a conta do serviço. Com a permissão herdada de ProgramData, qualquer usuário do servidor podia plantar um lote na
// fila — que o agente enviaria ao painel como seu — ou o pin do painel antes do primeiro contato.
try { RansomGuard.Core.Security.SecureDirectory.Ensure(dataDir); }
catch (Exception ex) { Console.Error.WriteLine($"[RansomGuard][dados] Não foi possível restringir {dataDir}: {ex.Message}"); }

builder.Services.AddHostedService<Worker>();

builder.Build().Run();
return 0;
