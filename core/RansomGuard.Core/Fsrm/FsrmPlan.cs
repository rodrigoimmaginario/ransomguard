using System.Text;

namespace RansomGuard.Core.Fsrm;

/// <summary>
/// Traduz um <see cref="RansomwareCatalog"/> nos comandos PowerShell/FSRM que o agente executa no
/// file server (New-FsrmFileGroup / New-FsrmFileScreen). Lógica pura e testável: gera o script,
/// não o executa — a execução real é do serviço do agente (net10-windows) e dos spikes do lab.
///
/// Três compromissos com o servidor do cliente:
/// <list type="number">
///   <item><b>Gera sinal.</b> O file screen leva uma notificação por evento; sem ela, em modo de auditoria ele não
///   avisava ninguém. O FSRM é o único componente que vê o nome de DESTINO de uma renomeação.</item>
///   <item><b>Não mexe no que não é dele.</b> Uma pasta que já tem file screen de outra origem não é alterada: o
///   script a relata e segue. Só os screens marcados com a descrição do produto são atualizados.</item>
///   <item><b>Pode ser desfeito.</b> <see cref="BuildRemovalPowerShell"/> remove os screens do produto e o file group.</item>
/// </list>
/// </summary>
public static class FsrmPlan
{
    public const string FileGroupName = "RansomGuard_Ransomware";

    /// <summary>Descrição gravada nos file screens criados pelo produto — é como ele reconhece os seus.</summary>
    public const string ScreenDescription = "RansomGuard";

    /// <summary>Início do texto do evento que o FSRM grava a cada violação; o agente procura por ele.</summary>
    public const string EventMarker = "RansomGuard-FSRM";

    /// <summary>Linha que o script imprime para cada pasta cujo file screen não é do produto.</summary>
    public const string ForeignScreenMarker = "RG-FSRM-FOREIGN";

    /// <summary>
    /// Corpo do evento, com as variáveis que o FSRM substitui: quem fez a operação, o arquivo (com o nome de destino),
    /// a pasta protegida, o grupo violado e o processo.
    /// </summary>
    public const string EventBody =
        EventMarker + "|user=[Source Io Owner]|file=[Source File Path]|screen=[File Screen Path]" +
        "|group=[Violated File Group]|pid=[Source Process Id]|image=[Source Process Image]";

    /// <summary>Gera o script que cria/atualiza o file group e aplica o file screen às pastas.</summary>
    /// <param name="catalog">Catálogo de padrões.</param>
    /// <param name="protectedPaths">Pastas a proteger (ex.: D:\Shares\Financeiro).</param>
    /// <param name="active">true = bloqueia (active screening); false = só audita (passive).</param>
    public static string BuildPowerShell(
        RansomwareCatalog catalog,
        IEnumerable<string> protectedPaths,
        bool active = true)
    {
        if (catalog.Patterns.Count == 0)
            throw new ArgumentException("Catálogo sem padrões — nada a proteger.", nameof(catalog));

        var paths = protectedPaths.ToList();
        if (paths.Count == 0)
            throw new ArgumentException("Nenhuma pasta informada.", nameof(protectedPaths));

        var patternList = string.Join(",", catalog.Patterns.Select(p => $"'{p.Replace("'", "''")}'"));
        var flag = active ? "$true" : "$false";
        var sb = new StringBuilder();

        sb.AppendLine("# Gerado por RansomGuard.Core — não editar à mão.");
        sb.AppendLine($"# Catálogo v{catalog.Version} · {catalog.Patterns.Count} padrões · modo " +
                      (active ? "ATIVO (bloqueia)" : "PASSIVO (audita)"));
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine("Import-Module FileServerResourceManager");
        sb.AppendLine();

        // File group idempotente: cria se não existe, senão atualiza os padrões.
        sb.AppendLine($"if (Get-FsrmFileGroup -Name '{FileGroupName}' -ErrorAction SilentlyContinue) {{");
        sb.AppendLine($"    Set-FsrmFileGroup -Name '{FileGroupName}' -IncludePattern @({patternList})");
        sb.AppendLine("} else {");
        sb.AppendLine($"    New-FsrmFileGroup -Name '{FileGroupName}' -IncludePattern @({patternList}) | Out-Null");
        sb.AppendLine("}");
        sb.AppendLine();

        // Notificação por evento: é o que transforma o file screen em sensor (e o que revela o nome de destino).
        sb.AppendLine($"$notify = New-FsrmAction -Type Event -EventType Warning -Body '{EventBody}' -RunLimitInterval 0");
        sb.AppendLine();

        foreach (var path in paths)
        {
            var p = path.Replace("'", "''");
            sb.AppendLine($"$s = Get-FsrmFileScreen -Path '{p}' -ErrorAction SilentlyContinue");
            // Do produto = tem a nossa descrição, ou (instalações anteriores) só o nosso grupo e nenhuma descrição.
            sb.AppendLine($"$ours = $s -and ($s.Description -eq '{ScreenDescription}' -or " +
                          $"(-not $s.Description -and @($s.IncludeGroup).Count -eq 1 -and @($s.IncludeGroup)[0] -eq '{FileGroupName}'))");
            sb.AppendLine("if ($s -and -not $ours) {");
            sb.AppendLine($"    Write-Output '{ForeignScreenMarker}|{p}'");
            sb.AppendLine("} elseif ($s) {");
            sb.AppendLine($"    Set-FsrmFileScreen -Path '{p}' -IncludeGroup '{FileGroupName}' -Active:{flag} " +
                          $"-Notification $notify -Description '{ScreenDescription}'");
            sb.AppendLine("} else {");
            sb.AppendLine($"    New-FsrmFileScreen -Path '{p}' -IncludeGroup '{FileGroupName}' -Active:{flag} " +
                          $"-Notification $notify -Description '{ScreenDescription}' | Out-Null");
            sb.AppendLine("}");
        }

        return sb.ToString();
    }

    /// <summary>Pastas que o script relatou como tendo file screen de outra origem (não alteradas).</summary>
    public static IReadOnlyList<string> ForeignScreens(string? scriptOutput)
    {
        var list = new List<string>();
        foreach (var raw in (scriptOutput ?? "").Split('\n'))
        {
            var line = raw.Trim();
            if (!line.StartsWith(ForeignScreenMarker + "|", StringComparison.Ordinal)) continue;
            var path = line[(ForeignScreenMarker.Length + 1)..].Trim();
            if (path.Length > 0) list.Add(path);
        }
        return list;
    }

    /// <summary>
    /// Script de reversão: remove os file screens criados pelo produto e, quando nenhum outro screen o usa, o file
    /// group. Screens de outra origem ficam como estão.
    /// </summary>
    public static string BuildRemovalPowerShell()
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Gerado por RansomGuard.Core — reversão do file screen.");
        sb.AppendLine("$ErrorActionPreference = 'Stop'");
        sb.AppendLine("Import-Module FileServerResourceManager");
        sb.AppendLine($"Get-FsrmFileScreen | Where-Object {{ $_.Description -eq '{ScreenDescription}' -or " +
                      $"(-not $_.Description -and @($_.IncludeGroup).Count -eq 1 -and @($_.IncludeGroup)[0] -eq '{FileGroupName}') }} | " +
                      "ForEach-Object { Remove-FsrmFileScreen -Path $_.Path -Confirm:$false }");
        sb.AppendLine($"if (-not (Get-FsrmFileScreen | Where-Object {{ @($_.IncludeGroup) -contains '{FileGroupName}' }})) {{");
        sb.AppendLine($"    if (Get-FsrmFileGroup -Name '{FileGroupName}' -ErrorAction SilentlyContinue) {{ Remove-FsrmFileGroup -Name '{FileGroupName}' -Confirm:$false }}");
        sb.AppendLine("}");
        return sb.ToString();
    }
}
