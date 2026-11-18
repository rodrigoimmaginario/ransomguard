namespace RansomGuard.Core.Detection;

/// <summary>
/// Tipo de operação de arquivo observada num share, derivada de metadado nativo do Windows
/// (eventos 4663/5145, USN Journal). Nunca inclui conteúdo do arquivo.
/// </summary>
public enum FileOp
{
    Write,
    Rename,
    Delete,
    Read
}

/// <summary>
/// Um evento de arquivo observado num servidor — a unidade mínima de metadado que o agente coleta.
/// Sem conteúdo: apenas quem, de onde, o quê e quando.
/// </summary>
/// <param name="At">Instante do evento (UTC).</param>
/// <param name="User">Conta que realizou a operação (ex.: DOMíNIO\usuario).</param>
/// <param name="SourceIp">IP de origem da sessão SMB (chave para atribuir criptografia remota).</param>
/// <param name="Share">Share/pasta alvo (ex.: \\FS01\Financeiro).</param>
/// <param name="Op">Operação realizada.</param>
/// <param name="Path">Caminho relativo do arquivo (metadado; usado para extensão/canário).</param>
/// <param name="NewExtension">Extensão resultante após a operação, se aplicável (ex.: .locked).</param>
/// <param name="IsCanary">Verdadeiro se o alvo é um arquivo-canário plantado pelo produto.</param>
/// <param name="ProcessId">G4b: PID do processo local que fez a operação (4663). Null em acesso remoto (5145).</param>
/// <param name="ProcessName">G4b: imagem do processo local (metadado, para auditoria e lista de proteção).</param>
/// <param name="Overwrite">
/// Laboratório, sessão 3: a gravação foi num arquivo que já existia (data de criação anterior à gravação, conferida no
/// disco pelo agente). É o que separa o ransomware que regrava no lugar de quem copia arquivos novos para o share.
/// </param>
public sealed record FileEvent(
    DateTime At,
    string User,
    string SourceIp,
    string Share,
    FileOp Op,
    string Path,
    string? NewExtension = null,
    bool IsCanary = false,
    int? ProcessId = null,
    string? ProcessName = null,
    bool Overwrite = false);
