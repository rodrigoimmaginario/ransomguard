namespace RansomGuard.Core.Response;

/// <summary>
/// B1 — guarda da blocklist no ponto em que o bloqueio vira efeito. Qualquer que seja a origem da ordem (incidente
/// local, blocklist de rede assinada pelo painel, incidente forjado por quem comprometeu outro agente), este servidor
/// não bloqueia os endereços de que depende: o próprio gateway, os servidores de nomes (num domínio, os
/// controladores), o painel e os próprios endereços.
///
/// Só o bloqueio de IP é barrado; a reversão nunca é (liberar um endereço é sempre seguro). Se não for possível
/// levantar os endereços protegidos, a contenção segue: a guarda é uma rede de segurança, não uma condição.
/// </summary>
public sealed class InfrastructureGuardExecutor(IResponseExecutor inner, Func<IReadOnlySet<string>> protectedAddresses) : IResponseExecutor
{
    public Task<ResponseOutcome> ExecuteAsync(ResponseAction action, CancellationToken ct = default)
    {
        if (action.Step == ResponseStep.BlockIp && IsProtected(action.Target))
            return Task.FromResult(ResponseOutcome.Skip(
                $"{action.Target} é endereço de infraestrutura deste servidor (gateway, servidor de nomes, painel ou o próprio servidor) — bloqueio recusado."));
        return inner.ExecuteAsync(action, ct);
    }

    public Task<ResponseOutcome> RevertAsync(ResponseAction action, CancellationToken ct = default) => inner.RevertAsync(action, ct);

    private bool IsProtected(string target)
    {
        try { return protectedAddresses().Contains(target.Trim()); }
        catch (Exception) { return false; }
    }
}
