using RansomGuard.Core.Response;

namespace RansomGuard.Core.Tests;

/// <summary>
/// R3 — os alvos da contenção vêm de metadado de evento do Windows (IP de origem, conta, share).
/// Antes de qualquer alvo chegar a um comando, ele precisa ter forma segura: um valor com aspas ou
/// metacaractere de shell não pode compor o script. Estas provas fixam a fronteira: formato
/// legítimo passa; tentativa de quebrar o comando é recusada.
/// </summary>
public class ResponseTargetTests
{
    [Theory]
    [InlineData(ResponseStep.BlockIp, "10.0.9.66")]
    [InlineData(ResponseStep.BlockIp, "::1")]
    [InlineData(ResponseStep.BlockIp, "2001:db8::1")]
    [InlineData(ResponseStep.KillSmbSession, "10.0.9.66")]
    [InlineData(ResponseStep.DisableAdAccount, @"CORP\vendas1")]
    [InlineData(ResponseStep.DisableAdAccount, "svc_backup$")]
    [InlineData(ResponseStep.IsolateShare, @"\\FS01\Financeiro")]
    [InlineData(ResponseStep.IsolateShare, "Dados 2026")]
    public void Legitimate_targets_are_safe(ResponseStep step, string target)
        => Assert.True(ResponseTarget.IsSafe(step, target));

    [Theory]
    // Aspas simples fecham a string do PowerShell single-quoted.
    [InlineData(ResponseStep.DisableAdAccount, "x'; Remove-Item C:\\ -Recurse; #")]
    // Metacaracteres de shell/subexpressão.
    [InlineData(ResponseStep.IsolateShare, "Share`n$(hostname)")]
    [InlineData(ResponseStep.DisableAdAccount, "a & calc.exe")]
    [InlineData(ResponseStep.IsolateShare, "a | b")]
    [InlineData(ResponseStep.DisableAdAccount, "a; b")]
    // IP que não é IP.
    [InlineData(ResponseStep.BlockIp, "10.0.0.1 -RemoteAddress *")]
    [InlineData(ResponseStep.BlockIp, "notanip")]
    // Vazio/branco.
    [InlineData(ResponseStep.DisableAdAccount, "")]
    [InlineData(ResponseStep.IsolateShare, "   ")]
    public void Dangerous_targets_are_rejected(ResponseStep step, string target)
        => Assert.False(ResponseTarget.IsSafe(step, target));
}
