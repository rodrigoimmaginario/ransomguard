using RansomGuard.Core.Detection;
using RansomGuard.Core.Response;

// ResponseLadderSimulator — portão de regressão da escada de contenção (Fatia 4). Exercita a
// decisão real da ResponseLadder + a execução via RecordingExecutor com auditoria. Cenários:
// High em bloqueio → escada na ordem; monitor → nada; sem licença → forçado a monitor; Medium →
// só alerta; desbloqueio auditado. exit 0 = verde.

Console.OutputEncoding = System.Text.Encoding.UTF8;

var failures = new List<string>();
void Check(string name, bool ok, string detail)
{
    Console.WriteLine($"  [{(ok ? "OK" : "FALHOU")}] {name} — {detail}");
    if (!ok) failures.Add(name);
}

var t0 = new DateTime(2026, 7, 23, 2, 0, 0, DateTimeKind.Utc);
Detection High() => new("FS01", @"CORP\vendas1", "10.0.9.66", @"\\FS01\Financeiro",
    Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched, DetectionReason.VssDeletion },
    120, t0, t0.AddSeconds(30));
Detection Medium() => new("FS02", @"CORP\bob", "10.0.5.20", @"\\FS02\Sh",
    Confidence.Medium, new HashSet<DetectionReason> { DetectionReason.MassRewrite }, 60, t0, t0.AddSeconds(20));

Console.WriteLine("RansomGuard · ResponseLadderSimulator");
Console.WriteLine(new string('─', 60));

// 1. Licenciado + modo bloqueio + High → escada completa executada na ordem.
Console.WriteLine("\nCenário 1 · Bloqueio de incidente High (licenciado)");
var licensed = new ResponseLadder();
var policy = new ResponsePolicy { Mode = ResponseMode.Block, MaxStep = ResponseStep.DisableAdAccount };
var decision = licensed.Decide(High(), policy);
var exec = new RecordingExecutor();
var runner = new ResponseRunner(exec);
await runner.RunAsync(decision, t0);
Console.WriteLine("  Ações: " + string.Join(" → ", exec.Executed.Select(a => a.Step)));
// L4 (laboratório): bloqueio primeiro, snapshot por último. L5: negar no share ANTES de derrubar a sessão — a regra de
// firewall não derruba as conexões TCP já abertas e o cliente SMB reconecta por elas. Negar no share antes do AD.
Check("escada-na-ordem",
    exec.Executed.Select(a => a.Step).SequenceEqual(new[]
        { ResponseStep.BlockIp, ResponseStep.DenyUserOnShare,
          ResponseStep.KillSmbSession, ResponseStep.DisableAdAccount, ResponseStep.PreemptiveSnapshot }),
    $"{exec.Executed.Count} passos");
Check("mira-ip-share-usuario-conta",
    exec.Executed[0].Target == "10.0.9.66"
    && exec.Executed[1].Target == @"\\FS01\Financeiro" && exec.Executed[1].Account == @"CORP\vendas1"
    && exec.Executed[3].Target == @"CORP\vendas1" && exec.Executed[4].Target == @"\\FS01\Financeiro",
    "IP/sessão no atacante, usuário negado no share, conta no usuário, snapshot do share por último");
Check("auditado", runner.Audit.Count(a => a.Operation == "execute") == 5 && runner.ExecutedCount == 4,
    "5 registros de auditoria; 4 contenções (snapshot não conta)");
Check("padrao-nao-toca-ad",
    !licensed.Decide(High(), new ResponsePolicy { Mode = ResponseMode.Block }).Actions.Any(a => a.Step == ResponseStep.DisableAdAccount),
    "sem MaxStep explícito, a escada para em DenyUserOnShare — falso positivo não tranca conta no AD");

// 2. Modo monitor → nenhuma ação, nenhum alerta.
Console.WriteLine("\nCenário 2 · Modo monitor");
var mon = licensed.Decide(High(), new ResponsePolicy { Mode = ResponseMode.Monitor });
Check("monitor-nao-age", !mon.Contains && !mon.Alert, "sem ação e sem alerta");

// 3. Produto gratuito: em Block, a contenção não depende de licença nenhuma.
Console.WriteLine("\nCenário 3 · Block sem licença");
var free = new ResponseLadder().Decide(High(), new ResponsePolicy { Mode = ResponseMode.Block });
Check("block-contem-sem-licenca", free.Contains && !free.Rationale.Contains("licença", StringComparison.OrdinalIgnoreCase),
    "quem liga a contenção é o administrador, pelo modo");

// 4. Medium em bloqueio → só alerta.
Console.WriteLine("\nCenário 4 · Confiança Medium");
var med = licensed.Decide(Medium(), new ResponsePolicy { Mode = ResponseMode.Block });
Check("medium-so-alerta", med.Alert && !med.Contains, "alerta sem contenção");
Check("medium-snapshot-preventivo", med.Actions.Count == 1 && med.Actions[0].Step == ResponseStep.PreemptiveSnapshot,
    "Médio em Block: snapshot VSS preventivo garante o restore enquanto aguarda confirmação");
var alertMode = licensed.Decide(High(), new ResponsePolicy { Mode = ResponseMode.Alert });
Check("alert-snapshot-sem-contencao", alertMode.Alert && !alertMode.Contains && alertMode.Actions.Single().Step == ResponseStep.PreemptiveSnapshot,
    "Alert: snapshot e alerta, nenhum degrau de contenção");

// 5. Desbloqueio (remediação) auditado.
Console.WriteLine("\nCenário 5 · Remediação (desbloqueio)");
await runner.RevertAsync(exec.Executed.Last(), t0.AddHours(1), @"CORP\admin", "revisado pelo admin");
Check("desbloqueio-auditado",
    runner.Audit.Any(a => a.Operation == "revert" && a.Actor == @"CORP\admin"),
    "reversão registrada com autor e justificativa");

// 6. R3 — alvo com forma insegura (metadado de evento manipulado) é pulado, nunca executado.
Console.WriteLine("\nCenário 6 · Alvo inseguro recusado (R3)");
Detection Injecao() => new("FS01", "x'; Remove-Item C:\\ -Recurse; #", "10.0.9.66", @"\\FS01\Financeiro",
    Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched },
    120, t0, t0.AddSeconds(30));
var execInj = new RecordingExecutor();
var runnerInj = new ResponseRunner(execInj);
await runnerInj.RunAsync(licensed.Decide(Injecao(),
    new ResponsePolicy { Mode = ResponseMode.Block, MaxStep = ResponseStep.DisableAdAccount }), t0);
Check("conta-insegura-pulada",
    execInj.Executed.All(a => a.Step != ResponseStep.DisableAdAccount && a.Step != ResponseStep.DenyUserOnShare) &&
    runnerInj.Audit.Any(a => a.Operation == "skip" && a.Action.Step == ResponseStep.DisableAdAccount) &&
    runnerInj.Audit.Any(a => a.Operation == "skip" && a.Action.Step == ResponseStep.DenyUserOnShare),
    "alvo com aspas/metacaractere não chega ao executor (nem como conta, nem como conta-no-share)");
Check("ip-legitimo-segue",
    execInj.Executed.Any(a => a.Step == ResponseStep.BlockIp),
    "passo de IP com alvo válido executa normalmente");

// 7. G4b — ataque de DENTRO do servidor (RDP/exploit): não há IP nem sessão; o alvo é o processo do 4663.
Console.WriteLine("\nCenário 7 · G4b — origem local: encerra o processo, protege os de sistema");
Detection Local() => new("FS01", @"FS01\rdp-user", Detection.LocalOrigin, "Financeiro",
    Confidence.High, new HashSet<DetectionReason> { DetectionReason.CanaryTouched }, 80, t0, t0.AddSeconds(10),
    new[] { new LocalProcess(4321, @"C:\Users\rdp-user\AppData\Local\Temp\enc.exe"), new LocalProcess(900, @"C:\Windows\System32\svchost.exe") });
var execLocal = new RecordingExecutor();
await new ResponseRunner(execLocal).RunAsync(licensed.Decide(Local(), new ResponsePolicy { Mode = ResponseMode.Block }), t0);
Check("local-encerra-processo",
    execLocal.Executed.Select(a => a.Step).SequenceEqual(new[] { ResponseStep.StopProcess, ResponseStep.DenyUserOnShare, ResponseStep.PreemptiveSnapshot })
    && execLocal.Executed[0].Target == "4321",
    "StopProcess(4321) → usuário negado no share → snapshot; sem IP/sessão");
Check("local-protege-sistema", execLocal.Executed.All(a => a.Target != "900"), "svchost.exe nunca é alvo");

Console.WriteLine("\n" + new string('─', 60));
if (failures.Count == 0) { Console.WriteLine("VERDE — escada de contenção validada."); return 0; }
Console.WriteLine($"VERMELHO — {failures.Count} falha(s): {string.Join(", ", failures)}");
return 1;
