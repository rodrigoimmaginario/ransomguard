namespace RansomGuard.Core.Auth;

/// <summary>
/// Envelope assinado que viaja do painel para o agente: o texto exato do documento (política de resposta ou
/// lote de comandos) e a assinatura minisign feita com a chave Ed25519 da instalação do painel. O agente só
/// obedece ao que verifica contra a chave fixada — a rede entre os dois não decide nada.
/// </summary>
public sealed record SignedAssertion(string Payload, string Signature);

/// <summary>Regras de tempo comuns aos documentos assinados pelo painel.</summary>
public static class SignedDocuments
{
    /// <summary>Tolerância de relógio entre painel e agente para a data de emissão.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(2);
}
