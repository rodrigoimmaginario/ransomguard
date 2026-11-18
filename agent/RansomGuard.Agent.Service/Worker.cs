using RansomGuard.Agent;
using RansomGuard.Agent.Catalog;
using RansomGuard.Agent.Service.Windows;

namespace RansomGuard.Agent.Service;

/// <summary>
/// Serviço Windows do agente: roda o <see cref="AgentCycle"/> em loop. Ciclo rápido (só eventos)
/// com coleta de postura periódica. O ciclo em si (coleta→detecção→resposta→envio) é lógica já
/// provada nos testes; aqui é só o agendamento e o host Windows.
///
/// A preparação do terreno (canários + FSRM) roda na partida e é **reaplicada periodicamente**:
/// canário apagado por engano volta sozinho, e o file screen sobrevive a alguém removê-lo à mão.
/// Como o plantio é idempotente, reaplicar não custa nem polui o backup do cliente.
/// </summary>
public sealed class Worker(AgentCycle cycle, ProtectionApplier protection, ILogger<Worker> log,
    CatalogCoordinator? catalog = null, PanelIdentityPinner? pinner = null)
    : BackgroundService
{
    private static readonly TimeSpan FastInterval = TimeSpan.FromSeconds(5);
    // G1 — polling adaptativo: com atividade relevante no ciclo, o próximo vem em 1 s (menos arquivos cifrados
    // até o primeiro degrau); sem atividade, volta ao ritmo normal.
    private static readonly TimeSpan HotInterval = TimeSpan.FromSeconds(1);
    private const int HotEventsThreshold = 10;
    private static readonly TimeSpan PostureEvery = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan ReapplyEvery = TimeSpan.FromHours(1);
    /// <summary>
    /// L13 (laboratório, sessão 2): a auditoria desligada por um invasor só era religada na reaplicação de hora em hora —
    /// até lá o agente não via ataque pela rede. A checagem de visibilidade (consultas baratas) roda a cada minuto.
    /// </summary>
    private static readonly TimeSpan VisibilityEvery = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan CatalogEvery = TimeSpan.FromHours(6);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        log.LogInformation("RansomGuard Agent iniciado.");

        // Prepara o terreno antes do primeiro ciclo: sem canário, a detecção perde o sinal de
        // maior confiança e passa a depender só de volume e ritmo.
        var status = protection.Apply();
        log.LogInformation("Proteção: {Modo} — {Explicacao}", status.Mode, status.Explanation);

        // F18: busca o catálogo assinado ao subir e periodicamente. Se mudar, reaplica o file screen
        // com a lista nova. Fail-safe: falha mantém o último bom (o próprio coordenador garante).
        var lastCatalog = DateTime.MinValue;
        var lastPosture = DateTime.MinValue;
        var lastReapply = DateTime.UtcNow;
        var lastVisibility = DateTime.UtcNow;

        var hot = false;
        while (!stoppingToken.IsCancellationRequested)
        {
            var now = DateTime.UtcNow;
            var collectPosture = now - lastPosture >= PostureEvery;
            try
            {
                // F38: sem chave do painel fixada, tenta fixar (TOFU) antes do lote — política e comandos do painel só
                // valem depois disso. Com chave fixada, não faz nada (uma chave diferente nunca substitui a atual).
                if (pinner is not null) await pinner.EnsurePinnedAsync(stoppingToken);

                var lastPolicy = cycle.LastPolicyOutcome;
                var modeBefore = cycle.Policy.Mode;
                var result = await cycle.RunOnceAsync(now, collectPosture, stoppingToken);
                if (cycle.LastPolicyOutcome is { } po && po != lastPolicy)
                {
                    if (po == RansomGuard.Core.Policy.PolicyOutcome.Valid)
                        log.LogInformation("Política do painel aplicada: modo {Modo} (antes {Antes}), degrau máximo {Max}, allowlist {U} usuário(s)/{I} IP(s), aprendizado={L}.",
                            cycle.Policy.Mode, modeBefore, cycle.Policy.MaxStep, cycle.Policy.AllowlistedUsers.Count, cycle.Policy.AllowlistedIps.Count, cycle.Policy.LearningMode);
                    else
                        log.LogWarning("Política do painel recusada ({Outcome}); mantida a vigente.", po);
                }
                if (collectPosture) lastPosture = now;
                hot = result.Events >= HotEventsThreshold || result.Detections > 0;
                if (result.Detections > 0 || result.LocalContainments > 0)
                    log.LogWarning("Ciclo: {Ev} eventos, {Det} detecções, {Cont} contenções.",
                        result.Events, result.Detections, result.LocalContainments);

                if (catalog is not null && now - lastCatalog >= CatalogEvery)
                {
                    if (await catalog.RefreshAsync(stoppingToken))
                    {
                        log.LogInformation("Catálogo atualizado (v{Version}); reaplicando file screen.",
                            catalog.Active.Version);
                        protection.Apply();
                    }
                    lastCatalog = now;
                }

                if (now - lastReapply >= ReapplyEvery || protection.NeedsReapplyForLearned)
                {
                    protection.Apply();
                    lastReapply = now;
                    lastVisibility = now;
                }
                else if (now - lastVisibility >= VisibilityEvery)
                {
                    protection.RepairVisibility();
                    lastVisibility = now;
                }
            }
            catch (Exception ex)
            {
                log.LogError(ex, "Falha no ciclo do agente.");
            }
            await Task.Delay(hot ? HotInterval : FastInterval, stoppingToken);
        }
    }
}
