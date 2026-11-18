namespace RansomGuard.Core.Response;

/// <summary>
/// Passos da escada de contenção, em ordem crescente de impacto. A resposta executa o prefixo
/// adequado à confiança/política — sempre do menos ao mais drástico.
/// </summary>
public enum ResponseStep
{
    /// <summary>
    /// G4a: snapshot VSS preventivo do volume do share no primeiro sinal — não contém nada, garante o
    /// restore. Sempre o primeiro; nunca conta como contenção.
    /// </summary>
    PreemptiveSnapshot = 0,
    /// <summary>
    /// G4b: encerra o processo LOCAL que está cifrando (PID do 4663). Única resposta que funciona para ataque de
    /// dentro do servidor (RDP, exploit, serviço) sem driver de kernel. Processos de sistema são protegidos.
    /// </summary>
    StopProcess = 1,
    /// <summary>
    /// Bloqueia o IP de origem no firewall. Barra conexões NOVAS; as já abertas seguem (laboratório, sessão 5) — por
    /// isso a escada nega no share antes de derrubar a sessão.
    /// </summary>
    BlockIp = 2,
    /// <summary>
    /// Derruba a sessão SMB do atacante. Vem DEPOIS da negação no share: o cliente reconecta pelas conexões TCP já
    /// abertas e só a negação faz essa reconexão falhar. O valor no enum é o teto de política, não a ordem de execução.
    /// </summary>
    KillSmbSession = 3,
    /// <summary>
    /// G4a: nega ESTE usuário NESTE share (<c>Block-SmbShareAccess -AccountName</c>). Funciona sem AD, não
    /// afeta os outros usuários e é reversível em um comando — o degrau padrão máximo.
    /// </summary>
    DenyUserOnShare = 4,
    /// <summary>Desabilita a conta no AD (opt-in explícito: exige direitos no AD e tranca o usuário em tudo).</summary>
    DisableAdAccount = 5,
    /// <summary>Isola o share (última instância — afeta todos os usuários daquele share).</summary>
    IsolateShare = 6
}

/// <summary>Uma ação de contenção concreta a executar contra um incidente.</summary>
/// <param name="Step">O passo da escada.</param>
/// <param name="Server">Servidor alvo.</param>
/// <param name="Target">Alvo do passo (IP, conta, share) — metadado.</param>
/// <param name="Reason">Por que a ação foi decidida (para auditoria).</param>
/// <param name="Account">Conta envolvida quando o passo precisa de share E usuário (DenyUserOnShare).</param>
public sealed record ResponseAction(ResponseStep Step, string Server, string Target, string Reason, string? Account = null);
