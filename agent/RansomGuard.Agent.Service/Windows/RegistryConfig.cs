using Microsoft.Win32;

namespace RansomGuard.Agent.Service;

/// <summary>
/// Lê a configuração que o MSI gravou no registro do Windows durante a instalação.
///
/// Por que registro e não arquivo: a instalação em massa por GPO passa as opções na linha de
/// comando (`msiexec /i Agente.msi BACKENDURL=... SERVERNAME=... /quiet`), e o MSI as grava em
/// HKLM. Assim o administrador não precisa editar um `appsettings.json` em cada servidor.
///
/// Precedência: estes valores entram DEPOIS do appsettings no builder, portanto vencem — a
/// instalação gerenciada manda. Chaves ausentes (ex.: execução portátil pelo .zip) são ignoradas,
/// e o appsettings volta a valer.
/// </summary>
public static class RegistryConfig
{
    /// <summary>Onde o MSI grava a configuração.</summary>
    public const string KeyPath = @"SOFTWARE\RansomGuard\Agent";
    /// <summary>Chave usada até a RC 0.9.0. Só é lida quando a atual não existe (instalação antiga ainda não atualizada).</summary>
    public const string LegacyKeyPath = @"SOFTWARE\IPSEC\RansomGuard\Agent";

    /// <summary>Mapeia as chaves do registro para o formato de configuração do host.</summary>
    public static IEnumerable<KeyValuePair<string, string?>> Read()
    {
        var values = new List<KeyValuePair<string, string?>>();
        if (!OperatingSystem.IsWindows()) return values;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(KeyPath) ?? Registry.LocalMachine.OpenSubKey(LegacyKeyPath);
            return ReadFrom(key);
        }
        catch (Exception)
        {
            // Registro inacessível não pode derrubar o agente — cai no appsettings.
            return values;
        }
    }

    /// <summary>O token de enrolamento já foi usado: sai do registro (não vale mais nada, mas não precisa ficar lá).</summary>
    public static void ClearEnrollToken()
    {
        if (!OperatingSystem.IsWindows()) return;
        foreach (var path in new[] { KeyPath, LegacyKeyPath })
        {
            using var key = Registry.LocalMachine.OpenSubKey(path, writable: true);
            key?.DeleteValue("EnrollToken", throwOnMissingValue: false);
        }
    }

    /// <summary>Mapeia os valores de uma chave já aberta (separado para ser testável sem tocar em HKLM).</summary>
    public static IEnumerable<KeyValuePair<string, string?>> ReadFrom(RegistryKey? key)
    {
        var values = new List<KeyValuePair<string, string?>>();
        if (key is null || !OperatingSystem.IsWindows()) return values;

        try
        {

            Add(values, key, "BackendUrl", "Agent:BackendUrl");
            Add(values, key, "ServerName", "Agent:ServerName");
            Add(values, key, "Mode", "Agent:Mode");
            // Pastas protegidas, separadas por ponto-e-vírgula (ex.: "D:\Shares\Financeiro;E:\Dados").
            Add(values, key, "ProtectedPaths", "Agent:ProtectedPaths");
            // true = file screen bloqueia; padrão audita (bloquear em produção é opt-in do admin).
            Add(values, key, "FsrmBlocking", "Agent:FsrmBlocking");
            // B1: token de enrolamento (uso limitado, com prazo). O agente o apaga daqui assim que o painel o aceita.
            Add(values, key, "EnrollToken", "Agent:EnrollToken");
            // F38: chave pública do painel (formato minisign.pub) fixada por configuração. Vazio = TOFU no 1º contato.
            Add(values, key, "PanelPublicKey", "Agent:PanelPublicKey");
            // F39: SHA-256 (hexa) do certificado TLS do painel. Vazio = fixa no primeiro contato (TOFU).
            Add(values, key, "PanelCertThumbprint", "Agent:PanelCertThumbprint");
            // G1: shares-isca (UNC, separados por ponto-e-vírgula). Ninguém legítimo os usa; qualquer acesso é Alta.
            Add(values, key, "DecoyShares", "Agent:DecoyShares");
            // B4: nomes de canário escolhidos pelo administrador (ponto e vírgula). Vazio = nomes gerados para esta instalação.
            Add(values, key, "CanaryNames", "Agent:CanaryNames");
            // G2: religa a auditoria e amplia o Security log sozinho (padrão: true). "false" só reporta.
            Add(values, key, "AutoRepairVisibility", "Agent:AutoRepairVisibility");
        }
        catch (Exception)
        {
            // Registro inacessível não pode derrubar o agente — cai no appsettings.
        }
        return values;
    }

    private static void Add(List<KeyValuePair<string, string?>> into, RegistryKey key,
        string registryName, string configKey)
    {
        if (key.GetValue(registryName) is string v && !string.IsNullOrWhiteSpace(v))
            into.Add(new KeyValuePair<string, string?>(configKey, v));
    }
}
