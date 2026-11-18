using System.Runtime.Versioning;
using Microsoft.Win32;

namespace RansomGuard.Agent.Service.Tests;

/// <summary>C4 — a configuração que o MSI grava no registro, lida de uma chave de verdade (em HKCU, sem elevação).</summary>
[SupportedOSPlatform("windows")]
public sealed class RegistryConfigTests : IDisposable
{
    private readonly string _path = @"Software\rg-it-" + Guid.NewGuid().ToString("N")[..10];
    private readonly RegistryKey _key;

    public RegistryConfigTests() => _key = Registry.CurrentUser.CreateSubKey(_path);

    public void Dispose()
    {
        _key.Dispose();
        Registry.CurrentUser.DeleteSubKeyTree(_path, throwOnMissingSubKey: false);
    }

    [Fact]
    public void Valores_gravados_pelo_instalador_viram_configuracao_do_agente()
    {
        _key.SetValue("BackendUrl", "https://painel.corp:5001");
        _key.SetValue("Mode", "Monitor");
        _key.SetValue("ProtectedPaths", @"D:\Shares;E:\Dados");
        _key.SetValue("ServerName", "   ");                    // propriedade não informada no MSI: fica vazia

        var config = RegistryConfig.ReadFrom(_key).ToDictionary(kv => kv.Key, kv => kv.Value);

        Assert.Equal("https://painel.corp:5001", config["Agent:BackendUrl"]);
        Assert.Equal("Monitor", config["Agent:Mode"]);
        Assert.Equal(@"D:\Shares;E:\Dados", config["Agent:ProtectedPaths"]);
        Assert.False(config.ContainsKey("Agent:ServerName"));   // vazio não sobrepõe o padrão (nome da máquina)
        Assert.False(config.ContainsKey("Agent:IngestSecret"));
    }

    [Fact]
    public void Chave_ausente_nao_gera_configuracao() => Assert.Empty(RegistryConfig.ReadFrom(null));

    [Fact]
    public void A_chave_do_produto_nao_carrega_mais_o_nome_antigo()
    {
        Assert.Equal(@"SOFTWARE\RansomGuard\Agent", RegistryConfig.KeyPath);
        Assert.DoesNotContain("IPSEC", RegistryConfig.KeyPath, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("IPSEC", RegistryConfig.LegacyKeyPath);   // só como leitura de instalação antiga
    }
}
