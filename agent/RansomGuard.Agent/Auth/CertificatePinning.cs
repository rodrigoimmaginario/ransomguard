namespace RansomGuard.Agent.Auth;

public enum PinDecision { Accept, PinAndAccept, Reject }

/// <summary>
/// F39 — decisão pura sobre o certificado TLS do painel (SHA-256 do certificado em hexa). Configurado
/// (<c>Agent:PanelCertThumbprint</c>) vence tudo; sem configuração, fixa no primeiro contato (TOFU) e, a partir daí,
/// qualquer certificado diferente é recusado — painel reinstalado exige o admin apagar o pin. Certificado válido por
/// CA pública também é aceito (painel atrás de proxy com certificado real).
/// </summary>
public static class CertificatePinning
{
    public static PinDecision Decide(string? presentedThumbprint, string? pinnedThumbprint, string? configuredThumbprint, bool chainValid)
    {
        var presented = Normalize(presentedThumbprint);
        if (presented.Length == 0) return PinDecision.Reject;
        var configured = Normalize(configuredThumbprint);
        if (configured.Length > 0) return presented == configured ? PinDecision.Accept : PinDecision.Reject;
        var pinned = Normalize(pinnedThumbprint);
        if (pinned.Length > 0) return presented == pinned ? PinDecision.Accept : PinDecision.Reject;
        return chainValid ? PinDecision.Accept : PinDecision.PinAndAccept;
    }

    public static string Normalize(string? thumbprint) =>
        (thumbprint ?? "").Replace(":", "").Replace(" ", "").Trim().ToUpperInvariant();
}
