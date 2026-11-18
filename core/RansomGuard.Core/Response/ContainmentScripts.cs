namespace RansomGuard.Core.Response;

/// <summary>
/// A2 — os comandos de contenção, cada um seguido da CONFERÊNCIA do próprio efeito. Antes o executor rodava o
/// comando e registrava "executada" se nada estourasse — e o bloqueio de IP ainda silenciava os erros. Uma linha do
/// tempo que diz "contido" sem que nada tenha mudado é pior que uma falha visível.
///
/// Regras de cada script:
/// <list type="bullet">
///   <item>roda em modo estrito (qualquer erro encerra com falha) — quem executa é o serviço do agente;</item>
///   <item>depois de agir, consulta o Windows e falha (<c>throw</c>) se o efeito não está lá;</item>
///   <item>é idempotente: repetir não duplica regra nem falha por "já existe";</item>
///   <item>não depende do idioma do Windows (contas conhecidas vão por SID).</item>
/// </list>
/// Lógica pura: gera texto. Os alvos já passaram por <see cref="ResponseTarget"/>; aqui ainda entram só entre aspas simples.
/// </summary>
public static class ContainmentScripts
{
    /// <summary>Prefixo das regras de firewall criadas pelo produto.</summary>
    public const string FirewallRulePrefix = "RansomGuard-Block-";

    // Conta → SID, sem estourar quando a lista do share tem uma conta que não resolve mais (SID órfão).
    private const string ToSid =
        "$toSid = { param($a) try { (New-Object System.Security.Principal.NTAccount([string]$a)).Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { [string]$a } }; ";

    /// <summary>Script que executa o passo e confere o efeito; <c>null</c> para passos sem comando aqui (ex.: StopProcess).</summary>
    /// <summary>D7: abaixo desta fração livre no volume, o snapshot preventivo não é criado.</summary>
    public const double MinFreeFractionForSnapshot = 0.10;

    public static string? Execute(ResponseAction action) => action.Step switch
    {
        // Snapshot VSS do volume onde o share vive (Win32_ShadowCopy.Create: existe em Server e em cliente).
        // ClientAccessible = visível em "Versões anteriores". O retorno diferente de zero é falha.
        ResponseStep.PreemptiveSnapshot =>
            $"$p = (Get-SmbShare -Name '{ShareOf(action.Target)}').Path; " +
            "$q = Split-Path -Qualifier $p; $v = $q + '\\'; " +
            // D7: com pouco espaço livre, criar mais uma cópia de sombra faz o Windows descartar as mais antigas — os
            // pontos de restauração que o cliente já tinha. Melhor não criar e dizer por quê.
            "$vol = Get-Volume -DriveLetter $q.Substring(0,1) -ErrorAction SilentlyContinue; " +
            $"if ($vol -and $vol.Size -gt 0 -and ($vol.SizeRemaining / $vol.Size) -lt {MinFreeFractionForSnapshot.ToString(System.Globalization.CultureInfo.InvariantCulture)}) " +
            "{ throw ('volume ' + $q + ' com menos de 10% livre: snapshot preventivo nao criado, para nao descartar pontos de restauracao existentes') }; " +
            "$r = (Get-WmiObject -List Win32_ShadowCopy).Create($v, 'ClientAccessible'); " +
            "if ($r.ReturnValue -ne 0) { throw ('Win32_ShadowCopy.Create retornou ' + $r.ReturnValue) }",

        // Bloqueia o IP de origem na entrada. Confere: a regra existe, está ativa, e o firewall está ligado no perfil
        // das redes conectadas — regra em firewall desligado não bloqueia nada.
        ResponseStep.BlockIp =>
            $"$n = '{FirewallRulePrefix}{action.Target}'; " +
            "if (-not (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue)) { " +
            $"New-NetFirewallRule -DisplayName $n -Direction Inbound -RemoteAddress '{action.Target}' -Action Block | Out-Null }}; " +
            "$r = @(Get-NetFirewallRule -DisplayName $n | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' }); " +
            "if ($r.Count -lt 1) { throw 'a regra de bloqueio nao ficou ativa' }; " +
            "$cats = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { if ($_.NetworkCategory -eq 'DomainAuthenticated') { 'Domain' } else { [string]$_.NetworkCategory } }); " +
            "$off = @(Get-NetFirewallProfile | Where-Object { $cats -contains $_.Name -and $_.Enabled -ne 'True' }); " +
            "if ($off.Count -gt 0) { throw ('o firewall do Windows esta desligado no perfil ' + (($off | ForEach-Object { $_.Name }) -join ', ') + ': a regra nao tem efeito') }",

        // Encerra as sessões SMB daquele cliente. O Windows mostra o cliente como \\10.0.9.66 ou [fe80::1]: compara sem os enfeites.
        ResponseStep.KillSmbSession =>
            $"$t = '{action.Target}'; " +
            "$mine = { param($s) ([string]$s.ClientComputerName).TrimStart('\\').Trim('[', ']') -eq $t }; " +
            "@(Get-SmbSession | Where-Object { & $mine $_ }) | Close-SmbSession -Force; " +
            "$left = @(Get-SmbSession | Where-Object { & $mine $_ }); " +
            "if ($left.Count -gt 0) { throw 'a sessao SMB continua aberta' }",

        // Nega só esta conta neste share: funciona sem AD, não afeta os outros, reversível.
        ResponseStep.DenyUserOnShare =>
            ToSid +
            $"Block-SmbShareAccess -Name '{ShareOf(action.Target)}' -AccountName '{action.Account}' -Force | Out-Null; " +
            $"$sid = & $toSid '{action.Account}'; " +
            $"$deny = @(Get-SmbShareAccess -Name '{ShareOf(action.Target)}' | Where-Object {{ $_.AccessControlType -eq 'Deny' -and (& $toSid $_.AccountName) -eq $sid }}); " +
            "if ($deny.Count -lt 1) { throw 'a negacao de acesso nao aparece no compartilhamento' }",

        ResponseStep.DisableAdAccount =>
            $"Disable-ADAccount -Identity '{SamOf(action.Target)}'; " +
            $"if ((Get-ADUser -Identity '{SamOf(action.Target)}').Enabled) {{ throw 'a conta continua habilitada no AD' }}",

        // Isola o share de todos. "Todos" vai pelo SID bem conhecido: o nome muda com o idioma do Windows.
        ResponseStep.IsolateShare =>
            ToSid + Everyone +
            $"Block-SmbShareAccess -Name '{ShareOf(action.Target)}' -AccountName $todos -Force | Out-Null; " +
            $"$deny = @(Get-SmbShareAccess -Name '{ShareOf(action.Target)}' | Where-Object {{ $_.AccessControlType -eq 'Deny' -and (& $toSid $_.AccountName) -eq 'S-1-1-0' }}); " +
            "if ($deny.Count -lt 1) { throw 'o isolamento nao aparece no compartilhamento' }",

        _ => null
    };

    /// <summary>Script que desfaz o passo e confere; <c>null</c> para o que não se desfaz (sessão encerrada, snapshot, processo).</summary>
    public static string? Revert(ResponseAction action) => action.Step switch
    {
        ResponseStep.BlockIp =>
            $"$n = '{FirewallRulePrefix}{action.Target}'; " +
            "Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue | Remove-NetFirewallRule; " +
            "if (Get-NetFirewallRule -DisplayName $n -ErrorAction SilentlyContinue) { throw 'a regra de bloqueio continua no firewall' }",

        ResponseStep.DenyUserOnShare =>
            ToSid +
            $"$sid = & $toSid '{action.Account}'; " +
            $"$has = {{ @(Get-SmbShareAccess -Name '{ShareOf(action.Target)}' | Where-Object {{ $_.AccessControlType -eq 'Deny' -and (& $toSid $_.AccountName) -eq $sid }}).Count -gt 0 }}; " +
            $"if (& $has) {{ Unblock-SmbShareAccess -Name '{ShareOf(action.Target)}' -AccountName '{action.Account}' -Force | Out-Null }}; " +
            "if (& $has) { throw 'a negacao de acesso continua no compartilhamento' }",

        ResponseStep.DisableAdAccount =>
            $"Enable-ADAccount -Identity '{SamOf(action.Target)}'; " +
            $"if (-not (Get-ADUser -Identity '{SamOf(action.Target)}').Enabled) {{ throw 'a conta continua desabilitada no AD' }}",

        ResponseStep.IsolateShare =>
            ToSid + Everyone +
            $"$has = {{ @(Get-SmbShareAccess -Name '{ShareOf(action.Target)}' | Where-Object {{ $_.AccessControlType -eq 'Deny' -and (& $toSid $_.AccountName) -eq 'S-1-1-0' }}).Count -gt 0 }}; " +
            $"if (& $has) {{ Unblock-SmbShareAccess -Name '{ShareOf(action.Target)}' -AccountName $todos -Force | Out-Null }}; " +
            "if (& $has) { throw 'o isolamento continua no compartilhamento' }",

        _ => null
    };

    private const string Everyone =
        "$todos = (New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')).Translate([System.Security.Principal.NTAccount]).Value; ";

    /// <summary><c>CORP\ana</c> → <c>ana</c>.</summary>
    public static string SamOf(string user) => user.Contains('\\') ? user[(user.IndexOf('\\') + 1)..] : user;

    /// <summary><c>\\FS01\Financeiro</c> → <c>Financeiro</c>; um nome simples fica como está.</summary>
    public static string ShareOf(string unc)
    {
        var parts = unc.TrimStart('\\').Split('\\');
        return parts.Length >= 2 ? parts[1] : unc;
    }
}
