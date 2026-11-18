using System.Text;
using RansomGuard.Agent.Catalog;
using RansomGuard.Core.Catalog;
using RansomGuard.Core.Fsrm;
using RansomGuard.Core.Signing;

// SecurityAuditSimulator — simulador ADVERSARIAL dos mecanismos de confiança do produto: o catálogo
// assinado, a confiança do agente no painel e a superfície do painel. Diferente dos outros simuladores (que provam que o
// caminho feliz funciona), este tenta QUEBRAR e falha (exit 1) quando um ataque tem sucesso.
//
// Serve de portão de regressão para as correções: enquanto um furo estiver aberto, ele fica
// VERMELHO de propósito e diz exatamente o que falta.

Console.OutputEncoding = Encoding.UTF8;

var abertos = new List<string>();
var fechados = 0;

void Ataque(string nome, bool bemSucedido, string detalhe)
{
    // "Bem-sucedido" para o ATACANTE = furo aberto = ruim para nós.
    Console.WriteLine($"  [{(bemSucedido ? "FURO ABERTO" : "bloqueado ")}] {nome}");
    Console.WriteLine($"                 {detalhe}");
    if (bemSucedido) abertos.Add(nome); else fechados++;
}

Console.WriteLine("RansomGuard · SecurityAuditSimulator (adversarial)");
Console.WriteLine(new string('─', 74));

// ─────────────────────────────────────────────────────────────────────────────
// PARTE 1 — CATÁLOGO ASSINADO
// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\n▌ PARTE 1 · Catálogo assinado\n");

var catSeed = Enumerable.Range(11, 32).Select(i => (byte)i).ToArray();
var catKeyId = new byte[] { 1, 1, 2, 2, 3, 3, 4, 4 };
var catPub = MinisignPublicKey.FromRaw(catKeyId, Minisign.PublicKeyFromSeed(catSeed));

string CatJson(int v) =>
    $"{{\"version\":{v},\"patterns\":[\"*.locked\",\"*.lockbit\"],\"ransomNotes\":[\"HOW_TO_DECRYPT*\"]}}";
string CatSign(string json) => Minisign.Sign(Encoding.UTF8.GetBytes(json), catSeed, catKeyId, "catalog");

// Ataque 1.1 — atacante distribui um catálogo VAZIO (cega o produto) sem a chave do owner.
{
    var v = new CatalogVerifier(catPub, lastAcceptedVersion: 5);
    var vazio = "{\"version\":99,\"patterns\":[],\"ransomNotes\":[]}";
    var forjado = Minisign.Sign(Encoding.UTF8.GetBytes(vazio),
        Enumerable.Range(200, 32).Select(i => (byte)i).ToArray(), catKeyId, "fake");
    var r = v.TryLoad(vazio, forjado);
    Ataque("Catálogo vazio assinado por chave falsa (cegar o agente)",
        r.Accepted, $"resultado: {r.Status} — {r.Detail}");
}

// Ataque 1.2 — atacante devolve um catálogo ANTIGO legítimo (rollback para versão sem LockBit).
{
    var v = new CatalogVerifier(catPub, lastAcceptedVersion: 9);
    var antigo = CatJson(4);
    var r = v.TryLoad(antigo, CatSign(antigo));
    Ataque("Replay de catálogo antigo legítimo (anti-rollback)",
        r.Accepted, $"resultado: {r.Status} — {r.Detail}");
}

// Ataque 1.3 — 1 byte alterado num catálogo legítimo (remover um padrão).
{
    var v = new CatalogVerifier(catPub, lastAcceptedVersion: 1);
    var bom = CatJson(7);
    var sig = CatSign(bom);
    var adulterado = bom.Replace("*.lockbit", "*.lockbiT");
    var r = v.TryLoad(adulterado, sig);
    Ataque("Adulteração de 1 byte mantendo a assinatura original",
        r.Accepted, $"resultado: {r.Status} — {r.Detail}");
}

// Verificação 1.4 — o catálogo aceito realmente vira defesa (não é verificação decorativa).
{
    var v = new CatalogVerifier(catPub, lastAcceptedVersion: 0);
    var bom = CatJson(7);
    var r = v.TryLoad(bom, CatSign(bom));
    var virouDefesa = r.Accepted && r.Catalog is not null &&
                      FsrmPlan.BuildPowerShell(r.Catalog, new[] { @"D:\Shares\Financeiro" })
                          .Contains("*.lockbit");
    Ataque("Catálogo verificado NÃO chega ao FSRM (verificação decorativa)",
        !virouDefesa, virouDefesa
            ? "OK — catálogo aceito gera o file group do FSRM"
            : "o catálogo é verificado mas não vira defesa");
}

// Verificação 1.5 — ELO DE CÓDIGO (F18). Prova que o agente REALMENTE consome um catálogo assinado:
// com chaves de teste, o CatalogCoordinator busca, verifica (assinatura + anti-rollback + policy)
// e passa a lista adiante. Antes, o AUD-1 era 100% aberto (nem código, nem artefato); agora o lado
// do código está fechado — o simulador registra isso como bloqueado.
{
    var sSeed = Enumerable.Range(11, 32).Select(i => (byte)i).ToArray();
    var sKeyId = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
    var sPub = MinisignPublicKey.FromRaw(sKeyId, Minisign.PublicKeyFromSeed(sSeed));
    var cjson = new RansomwareCatalog { Version = 1, Patterns = new[] { "*.locked", "*.lockbit" } }.ToJson();
    var csig = Minisign.Sign(Encoding.UTF8.GetBytes(cjson), sSeed, sKeyId, "catalog v1");

    var src = new OneShotSource(new CatalogArtifact(cjson, csig));
    var coord = new CatalogCoordinator(src, new NullStore(), sPub);
    coord.Initialize();
    var aplicou = coord.RefreshAsync().GetAwaiter().GetResult()
                  && coord.State == CatalogState.Updated
                  && coord.Active.Patterns.Contains("*.lockbit");
    Ataque("Elo de código do catálogo AUSENTE (agente não consome lista assinada)",
        !aplicou, aplicou
            ? "F18: CatalogCoordinator busca+verifica+aplica catálogo assinado (chaves de teste)"
            : "o agente não consome catálogo assinado");
}

// Lacuna 1.6 — ARTEFATO PUBLICADO. O código está pronto (1.5), mas fechar o AUD-1 por inteiro ainda
// exige a cerimônia do owner: gerar a chave, assinar o catalog.json e publicá-lo. Enquanto o
// artefato não existe, este item segue aberto — é o que mantém o simulador em amarelo.
{
    // Cerimônia feita em 2026-10-04 (keyId CCCF0CA23A0B75AC). Não basta o arquivo existir: a assinatura tem de verificar
    // com a chave pública EMBARCADA no agente (appsettings.json) — a mesma que o parque instalado usa.
    var raizRepo = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..");
    var listDir = Path.Combine(raizRepo, "list");
    var verificado = false; var motivo = "artefato assinado ausente";
    try
    {
        var catalogPath = Path.Combine(listDir, "catalog.json");
        var sigPath = Path.Combine(listDir, "catalog.json.minisig");
        if (File.Exists(catalogPath) && File.Exists(sigPath))
        {
            using var cfg = System.Text.Json.JsonDocument.Parse(File.ReadAllText(Path.Combine(raizRepo, "agent", "RansomGuard.Agent.Service", "appsettings.json")));
            var blob = Convert.FromBase64String(cfg.RootElement.GetProperty("Agent").GetProperty("CatalogPublicKeyBase64").GetString()!);
            var embarcada = MinisignPublicKey.FromRaw(blob.AsSpan(0, 8), blob.AsSpan(8, 32));
            var r = Minisign.Verify(File.ReadAllBytes(catalogPath), MinisignSignature.Parse(File.ReadAllText(sigPath)), embarcada);
            verificado = r == MinisignVerificationResult.Valid;
            motivo = verificado ? $"catálogo publicado verifica com a chave embarcada (keyId {embarcada.KeyIdHex})" : $"assinatura NÃO verifica: {r}";
        }
    }
    catch (Exception ex) { motivo = "falha ao verificar: " + ex.Message; }
    Ataque("Catálogo assinado não publicado ou não verifica com a chave embarcada",
        !verificado, motivo);
}

// ──────────────────────────────────────────────────────────────────────────
// PARTE 2 — CONFIANÇA ENTRE AGENTE E PAINEL
// ──────────────────────────────────────────────────────────────────────────
// O produto é gratuito: não existe licença para forjar. O que um atacante ganharia é mudar o COMPORTAMENTO do
// agente — ligar a contenção para derrubar usuários legítimos, ou desligá-la antes de cifrar.
Console.WriteLine("\n▌ PARTE 2 · Confiança entre agente e painel\n");

// Ataque 2.1 — AUD-4 (revisto) — atalho de configuração local que ligue a contenção sem a política do
// administrador. FECHADO: o agente não lê mais nenhum booleano de "licenciado" nem override de laboratório;
// nasce em Monitor e só muda pelo modo configurado ou pela política assinada.
{
    var raiz = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
    var agente = Path.Combine(raiz, "agent", "RansomGuard.Agent.Service", "Program.cs");
    var registro = Path.Combine(raiz, "agent", "RansomGuard.Agent.Service", "Windows", "RegistryConfig.cs");
    var fonte = (File.Exists(agente) ? File.ReadAllText(agente) : "") + (File.Exists(registro) ? File.ReadAllText(registro) : "");
    var atalho = fonte.Contains("LicensedForResponse") || fonte.Contains("\"Agent:LabOverride\"");
    var nasceMonitor = fonte.Contains(": ResponseMode.Monitor;");
    Ataque("[AUD-4] Atalho de configuração liga a contenção sem política do administrador",
        atalho || !nasceMonitor,
        atalho ? "ainda existe booleano/override local que liga a contenção"
        : !nasceMonitor ? "o agente não nasce em Monitor"
        : "sem licença e sem override: o agente nasce em Monitor e só a política muda o modo");
}

// Ataque 2.2 — AUD-14 (F38) — painel FALSO na rede responde ao lote tentando ligar ou DESLIGAR a contenção.
// FECHADO: só política assinada pela chave fixada da instalação (PanelTrust) muda o modo. Prova funcional com
// ciclos reais: resposta sem política e política de chave estranha não movem o modo; a legítima move.
{
    var keyId = new byte[] { 3, 3, 3, 3, 3, 3, 3, 3 };
    var painel = Enumerable.Range(40, 32).Select(i => (byte)i).ToArray();
    var falso = Enumerable.Range(80, 32).Select(i => (byte)i).ToArray();
    var trust = new RansomGuard.Agent.Auth.PanelTrust(new RansomGuard.Agent.Auth.InMemoryPanelKeyStore(),
        RansomGuard.Core.Signing.MinisignPublicKey.FromRaw(keyId, RansomGuard.Core.Signing.Minisign.PublicKeyFromSeed(painel)).ToFileContent("aud"));
    var agora = DateTime.UtcNow;
    RansomGuard.Core.Auth.SignedAssertion Pol(long v, string mode, byte[] seed) => RansomGuard.Core.Policy.AgentPolicyDocument.Sign(
        new RansomGuard.Core.Policy.AgentPolicyDocument("*", v, mode, "DenyUserOnShare", Array.Empty<string>(), Array.Empty<string>(), false, agora), seed, keyId);
    RansomGuard.Core.Response.ResponsePolicy atual = new() { Mode = RansomGuard.Core.Response.ResponseMode.Monitor };
    async Task<RansomGuard.Core.Response.ResponseMode> Ciclo(RansomGuard.Agent.BatchResponse r)
    {
        var c = new RansomGuard.Agent.AgentCycle("FS01", new AudPosture(), new AudNoEvents(), new AudNoSignals(), new AudSink(r),
            new RansomGuard.Core.Response.ResponseLadder(), atual, new AudExecutor(), trust: trust);
        await c.RunOnceAsync(agora);
        atual = c.Policy;
        return c.Policy.Mode;
    }
    var semPolitica = Ciclo(new RansomGuard.Agent.BatchResponse()).GetAwaiter().GetResult();
    var ligouFalso = Ciclo(new RansomGuard.Agent.BatchResponse(Policy: Pol(1, "Block", falso))).GetAwaiter().GetResult();
    var ligouLegitimo = Ciclo(new RansomGuard.Agent.BatchResponse(Policy: Pol(2, "Block", painel))).GetAwaiter().GetResult();
    var desligouFalso = Ciclo(new RansomGuard.Agent.BatchResponse(Policy: Pol(3, "Monitor", falso))).GetAwaiter().GetResult();

    var monitor = RansomGuard.Core.Response.ResponseMode.Monitor;
    var block = RansomGuard.Core.Response.ResponseMode.Block;
    var furo = semPolitica != monitor || ligouFalso != monitor || ligouLegitimo != block || desligouFalso != block;
    Ataque("[AUD-14] Painel falso na rede liga/desliga a contenção respondendo ao lote",
        furo,
        furo ? "o agente ainda muda de modo sem política assinada pela chave fixada"
             : "só política assinada pela chave fixada da instalação muda o modo (F38)");
}

// Ataque 2.10 — AUD-15 (F33) — política de resposta vinha do registro local (ou, pior, poderia vir de um
// painel falso em claro). FECHADO: só política ASSINADA pela chave fixada muda o agente, e versão menor que
// a última aceita é rollback. Prova funcional: forjada e rollback não mudam o modo; legítima muda.
{
    var keyId = new byte[] { 6, 6, 6, 6, 6, 6, 6, 6 };
    var painel = Enumerable.Range(50, 32).Select(i => (byte)i).ToArray();
    var falso = Enumerable.Range(85, 32).Select(i => (byte)i).ToArray();
    var trust = new RansomGuard.Agent.Auth.PanelTrust(new RansomGuard.Agent.Auth.InMemoryPanelKeyStore(),
        RansomGuard.Core.Signing.MinisignPublicKey.FromRaw(keyId, RansomGuard.Core.Signing.Minisign.PublicKeyFromSeed(painel)).ToFileContent("aud"));
    var agora = DateTime.UtcNow;
    RansomGuard.Core.Auth.SignedAssertion Pol(long v, string mode, byte[] seed) => RansomGuard.Core.Policy.AgentPolicyDocument.Sign(
        new RansomGuard.Core.Policy.AgentPolicyDocument("*", v, mode, "IsolateShare", Array.Empty<string>(), Array.Empty<string>(), false, agora), seed, keyId);
    RansomGuard.Core.Response.ResponsePolicy atual = new() { Mode = RansomGuard.Core.Response.ResponseMode.Monitor };
    async Task<RansomGuard.Core.Response.ResponseMode> Ciclo(RansomGuard.Core.Auth.SignedAssertion pol)
    {
        var c = new RansomGuard.Agent.AgentCycle("FS01", new AudPosture(), new AudNoEvents(), new AudNoSignals(),
            new AudSink(new RansomGuard.Agent.BatchResponse(Policy: pol)),
            new RansomGuard.Core.Response.ResponseLadder(), atual, new AudExecutor(), trust: trust);
        await c.RunOnceAsync(agora);
        atual = c.Policy;
        return c.Policy.Mode;
    }
    var aposForjada = Ciclo(Pol(10, "Block", falso)).GetAwaiter().GetResult();
    var aposLegitima = Ciclo(Pol(2, "Alert", painel)).GetAwaiter().GetResult();
    var aposRollback = Ciclo(Pol(1, "Block", painel)).GetAwaiter().GetResult();
    var furo = aposForjada != RansomGuard.Core.Response.ResponseMode.Monitor
            || aposLegitima != RansomGuard.Core.Response.ResponseMode.Alert
            || aposRollback != RansomGuard.Core.Response.ResponseMode.Alert;
    Ataque("[AUD-15] Política de resposta forjada ou antiga reconfigura o agente",
        furo,
        furo ? "o agente aceita política sem assinatura válida ou regride de versão"
             : "só política assinada pela chave fixada e com versão não menor muda o agente (F33)");
}

// Ataques 2.11/2.12 — AUD-16/AUD-17 (F39/F40) — superfície do painel. Verificação estrutural no Program.cs do painel:
// (16) ingestão aberta ou com segredo único para todos os agentes → FECHADO: lote assinado pela chave de cada agente (B1); (17) /setup sem token de primeira execução e endpoints de auth sem antiforgery → FECHADO.
{
    var raiz = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
    var prog = Path.Combine(raiz, "server", "RansomGuard.Server", "Program.cs");
    var fonte = File.Exists(prog) ? File.ReadAllText(prog) : "";
    // B1: a ingestão deixou de usar segredo compartilhado; cada lote é assinado pela chave do próprio agente.
    var segredoCompartilhado = fonte.Contains("SharedSecret.IsAuthorized(ingestSecret") || fonte.Contains("Ingest:SharedSecret");
    var assinaturaPorAgente = fonte.Contains("BatchSignature.Verify(") && fonte.Contains("agents.FindAsync(agent");
    Ataque("[AUD-16] Ingestão do agente aberta, ou protegida só por um segredo igual para todos",
        segredoCompartilhado || !assinaturaPorAgente,
        segredoCompartilhado || !assinaturaPorAgente ? "quem lê a configuração de um servidor injeta lotes em nome de qualquer outro"
                                                     : "cada lote é conferido contra a chave enrolada para aquele servidor");

    // [AUD-18] B1 — com o que existe num servidor (a chave DELE), falar em nome de outro, alterar o lote ou reapresentá-lo depois.
    var agora = new DateTime(2026, 11, 16, 12, 0, 0, DateTimeKind.Utc);
    var fs01 = RansomGuard.Core.Auth.AgentKey.Generate();
    var fs02 = RansomGuard.Core.Auth.AgentKey.Generate();
    var corpo = System.Text.Encoding.UTF8.GetBytes("{\"server\":\"FS02\",\"incidents\":[]}");
    var ts = RansomGuard.Core.Auth.BatchSignature.Timestamp(agora);
    var assinadoPorFs01 = RansomGuard.Core.Auth.BatchSignature.Sign(fs01, "FS02", ts, corpo);
    var emNomeDeOutro = RansomGuard.Core.Auth.BatchSignature.Verify(fs02.PublicKey, "FS02", ts, assinadoPorFs01, corpo, agora);
    var legitimo = RansomGuard.Core.Auth.BatchSignature.Sign(fs02, "FS02", ts, corpo);
    var alterado = RansomGuard.Core.Auth.BatchSignature.Verify(fs02.PublicKey, "FS02", ts, legitimo, System.Text.Encoding.UTF8.GetBytes("{\"server\":\"FS02\",\"incidents\":[1]}"), agora);
    var tardio = RansomGuard.Core.Auth.BatchSignature.Verify(fs02.PublicKey, "FS02", ts, legitimo, corpo, agora.AddMinutes(30));
    var aceitoLegitimo = RansomGuard.Core.Auth.BatchSignature.Verify(fs02.PublicKey, "FS02", ts, legitimo, corpo, agora);
    var furoIdentidade = emNomeDeOutro == RansomGuard.Core.Auth.BatchSignatureResult.Valid
                         || alterado == RansomGuard.Core.Auth.BatchSignatureResult.Valid
                         || tardio == RansomGuard.Core.Auth.BatchSignatureResult.Valid
                         || aceitoLegitimo != RansomGuard.Core.Auth.BatchSignatureResult.Valid;
    Ataque("[AUD-18] Servidor comprometido forja lote em nome de outro, altera um lote ou o reapresenta depois",
        furoIdentidade,
        furoIdentidade ? "a assinatura do lote não amarra servidor, conteúdo e instante"
                       : $"em nome de outro: {emNomeDeOutro}; alterado: {alterado}; 30 min depois: {tardio}");

    var setupComToken = fonte.Contains("s.SetupToken") && fonte.Contains("/auth/setup");
    var antiforgeryDesligado = System.Text.RegularExpressions.Regex.IsMatch(fonte, @"/auth/(setup|login|logout)[\s\S]{0,1500}?\.DisableAntiforgery\(\)");
    var antiforgeryExplicito = fonte.Contains("AntiforgeryOk(ctx)");
    Ataque("[AUD-17] Takeover no primeiro boot (/setup sem token) ou CSRF nos endpoints de auth",
        !setupComToken || antiforgeryDesligado || !antiforgeryExplicito,
        !setupComToken ? "quem alcança a porta antes do admin cria a conta de dono"
        : antiforgeryDesligado || !antiforgeryExplicito ? "login/logout/setup aceitam POST de outro site"
        : "setup exige token de primeira execução; antiforgery validado explicitamente");
}

// ─────────────────────────────────────────────────────────────────────────────
Console.WriteLine("\n" + new string('─', 74));
Console.WriteLine($"Ataques bloqueados: {fechados} · Furos abertos: {abertos.Count}");

if (abertos.Count == 0)
{
    Console.WriteLine("VERDE — nenhum furo aberto nos mecanismos de confiança.");
    return 0;
}

Console.WriteLine("\nVERMELHO — furos abertos (este simulador só fica verde quando fecharem):");
foreach (var f in abertos) Console.WriteLine($"  ✗ {f}");
return 1;

// Fonte/armazenamento mínimos para provar o elo de código do catálogo (verificação 1.5).
sealed class OneShotSource(CatalogArtifact artifact) : ICatalogSource
{
    public Task<CatalogArtifact?> FetchAsync(CancellationToken ct = default)
        => Task.FromResult<CatalogArtifact?>(artifact);
}

sealed class NullStore : ICatalogStore
{
    public CatalogArtifact? Load() => null;
    public int LoadVersion() => 0;
    public void Save(CatalogArtifact artifact, int version) { }
}

sealed class AudPosture : RansomGuard.Agent.IPostureCollector { public RansomGuard.Core.Score.PostureSnapshot Collect(string s) => new() { Server = s }; }
sealed class AudNoEvents : RansomGuard.Agent.IFileEventCollector { public IReadOnlyList<RansomGuard.Core.Detection.FileEvent> Drain() => Array.Empty<RansomGuard.Core.Detection.FileEvent>(); }
sealed class AudNoSignals : RansomGuard.Agent.IHostSignalCollector { public IReadOnlyList<RansomGuard.Core.Detection.HostSignal> Drain() => Array.Empty<RansomGuard.Core.Detection.HostSignal>(); }
sealed class AudExecutor : RansomGuard.Core.Response.IResponseExecutor
{
    public Task<RansomGuard.Core.Response.ResponseOutcome> ExecuteAsync(RansomGuard.Core.Response.ResponseAction a, CancellationToken ct = default) => Task.FromResult(RansomGuard.Core.Response.ResponseOutcome.Done());
    public Task<RansomGuard.Core.Response.ResponseOutcome> RevertAsync(RansomGuard.Core.Response.ResponseAction a, CancellationToken ct = default) => Task.FromResult(RansomGuard.Core.Response.ResponseOutcome.Done());
}
sealed class AudSink(RansomGuard.Agent.BatchResponse? reply) : RansomGuard.Agent.IBatchSink
{
    public Task<RansomGuard.Agent.BatchResponse?> SendAsync(RansomGuard.Agent.AgentBatch b, CancellationToken ct = default) => Task.FromResult(reply);
}
