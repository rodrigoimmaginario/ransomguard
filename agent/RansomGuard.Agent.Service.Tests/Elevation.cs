using System.Security.Principal;

namespace RansomGuard.Agent.Service.Tests;

public static class Elevation
{
    public static bool IsElevated
    {
        get
        {
            if (!OperatingSystem.IsWindows()) return false;
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    /// <summary>Na CI, "não elevado" é falha, não motivo para pular.</summary>
    public static bool Required => Environment.GetEnvironmentVariable("RG_REQUIRE_ELEVATED") == "1";
}

/// <summary>
/// Teste que só faz sentido como administrador num Windows real. Pula na estação do desenvolvedor;
/// com <c>RG_REQUIRE_ELEVATED=1</c> (CI) roda sempre — e falha se o processo não estiver elevado.
/// </summary>
public sealed class ElevatedFactAttribute : FactAttribute
{
    public ElevatedFactAttribute()
    {
        if (!Elevation.IsElevated && !Elevation.Required)
            Skip = "Exige administrador (Security log, share, auditoria). Roda na CI em windows-latest.";
    }
}
