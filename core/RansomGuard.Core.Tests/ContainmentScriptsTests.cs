using RansomGuard.Core.Response;

namespace RansomGuard.Core.Tests;

/// <summary>
/// A2 — cada passo de contenção confere o próprio efeito. O comportamento em Windows real é provado nos testes do
/// serviço (CI elevada); aqui fica travado o que o texto do script precisa ter para isso valer.
/// </summary>
public class ContainmentScriptsTests
{
    private static ResponseAction A(ResponseStep step, string target, string? account = null) => new(step, "FS01", target, "teste", account);

    [Fact]
    public void Bloqueio_de_ip_nao_silencia_erro_e_confere_regra_e_firewall()
    {
        var ps = ContainmentScripts.Execute(A(ResponseStep.BlockIp, "10.0.9.66"))!;

        Assert.DoesNotContain("-Action Block -ErrorAction SilentlyContinue", ps);
        Assert.Contains("'RansomGuard-Block-10.0.9.66'", ps);
        Assert.Contains("a regra de bloqueio nao ficou ativa", ps);
        Assert.Contains("Get-NetFirewallProfile", ps);                 // firewall desligado = regra sem efeito
    }

    /// <summary>Repetir o bloqueio (blocklist reaplicada após reinício) não empilha regras iguais.</summary>
    [Fact]
    public void Bloqueio_de_ip_so_cria_a_regra_se_ela_ainda_nao_existe()
    {
        var ps = ContainmentScripts.Execute(A(ResponseStep.BlockIp, "10.0.9.66"))!;

        Assert.True(ps.IndexOf("Get-NetFirewallRule -DisplayName $n", StringComparison.Ordinal) < ps.IndexOf("New-NetFirewallRule", StringComparison.Ordinal));
    }

    [Fact]
    public void Liberar_ip_confere_que_a_regra_saiu()
        => Assert.Contains("a regra de bloqueio continua no firewall", ContainmentScripts.Revert(A(ResponseStep.BlockIp, "10.0.9.66")));

    /// <summary>Antes casava o usuário por "contém": encerrar a sessão de "ana" derrubava "mariana".</summary>
    [Fact]
    public void Sessao_e_encerrada_por_cliente_exato_e_o_fechamento_e_conferido()
    {
        var ps = ContainmentScripts.Execute(A(ResponseStep.KillSmbSession, "10.0.9.66"))!;

        Assert.DoesNotContain("-like", ps);
        Assert.Contains("-eq $t", ps);
        Assert.Contains("a sessao SMB continua aberta", ps);
    }

    [Fact]
    public void Negar_usuario_no_share_confere_a_entrada_de_negacao()
    {
        var ps = ContainmentScripts.Execute(A(ResponseStep.DenyUserOnShare, @"\\FS01\Financeiro", @"CORP\vendas1"))!;

        Assert.Contains("Block-SmbShareAccess -Name 'Financeiro' -AccountName 'CORP\\vendas1'", ps);
        Assert.Contains("Get-SmbShareAccess -Name 'Financeiro'", ps);
        Assert.Contains("a negacao de acesso nao aparece", ps);
        Assert.Contains("a negacao de acesso continua", ContainmentScripts.Revert(A(ResponseStep.DenyUserOnShare, @"\\FS01\Financeiro", @"CORP\vendas1")));
    }

    /// <summary>"Everyone" só existe com esse nome em Windows em inglês.</summary>
    [Fact]
    public void Isolar_o_share_usa_o_sid_de_todos_e_nao_o_nome()
    {
        var ps = ContainmentScripts.Execute(A(ResponseStep.IsolateShare, @"\\FS01\Financeiro"))!;

        Assert.Contains("S-1-1-0", ps);
        Assert.DoesNotContain("'Everyone'", ps);
        Assert.DoesNotContain("'Everyone'", ContainmentScripts.Revert(A(ResponseStep.IsolateShare, @"\\FS01\Financeiro")));
    }

    [Fact]
    public void Desabilitar_conta_no_ad_confere_o_estado_da_conta()
    {
        Assert.Contains("a conta continua habilitada", ContainmentScripts.Execute(A(ResponseStep.DisableAdAccount, @"CORP\vendas1")));
        Assert.Contains("Disable-ADAccount -Identity 'vendas1'", ContainmentScripts.Execute(A(ResponseStep.DisableAdAccount, @"CORP\vendas1")));
    }

    [Fact]
    public void Passos_sem_comando_ou_sem_volta_nao_tem_script()
    {
        Assert.Null(ContainmentScripts.Execute(A(ResponseStep.StopProcess, "4321")));       // roda em processo, não em script
        Assert.Null(ContainmentScripts.Revert(A(ResponseStep.KillSmbSession, "10.0.9.66")));
        Assert.Null(ContainmentScripts.Revert(A(ResponseStep.PreemptiveSnapshot, @"\\FS01\Financeiro")));
    }

    /// <summary>Aspas duplas quebrariam a passagem do script ao PowerShell pelo executor.</summary>
    [Fact]
    public void Nenhum_script_usa_aspas_duplas()
    {
        var all = Enum.GetValues<ResponseStep>().SelectMany(s => new[]
        {
            ContainmentScripts.Execute(A(s, s == ResponseStep.StopProcess ? "4321" : "10.0.9.66", @"CORP\x")),
            ContainmentScripts.Revert(A(s, "10.0.9.66", @"CORP\x"))
        }).OfType<string>();

        Assert.All(all, ps => Assert.DoesNotContain('"', ps));
    }
}
