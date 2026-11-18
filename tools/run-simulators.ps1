<#
.SYNOPSIS
  Roda todos os simuladores (portões de regressão) e confere o exit code esperado de cada um.

.DESCRIPTION
  Os simuladores regulares provam o caminho feliz e saem 0 no verde. O SecurityAuditSimulator é
  adversarial e sai 1 por desenho enquanto o AUD-1 (distribuição do catálogo) estiver aberto — é
  gate do owner (cerimônia minisign), não furo de código. Este script trata o 1 do SecurityAudit
  como SUCESSO esperado e qualquer desvio como falha.

  Usado localmente e na CI (F21). Retorna exit 0 só se todos baterem o esperado.

.EXAMPLE
  pwsh tools/run-simulators.ps1
#>
$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot

$failures = @()
$projects = Get-ChildItem (Join-Path $repo "spike") -Directory |
    Where-Object { Test-Path (Join-Path $_.FullName "*.csproj") } |
    Sort-Object Name

foreach ($proj in $projects) {
    $name = $proj.Name
    # Desde a cerimônia do catálogo (2026-10-04) o SecurityAuditSimulator também precisa sair 0: nenhum furo aberto.
    $expected = 0

    Write-Host "-> $name (esperado exit=$expected)" -ForegroundColor Cyan
    # Sem --no-build: 3 simuladores (Notification, SecurityAudit, Sensor) ficam fora da .sln, então
    # o build da solução não os gera. Deixar o dotnet run compilar cada um garante todos rodando.
    & dotnet run --project $proj.FullName --configuration Release 2>&1 | Out-Null
    $code = $LASTEXITCODE

    if ($code -ne $expected) {
        Write-Host "  FALHOU: exit=$code, esperado=$expected" -ForegroundColor Red
        $failures += "$name (exit=$code, esperado=$expected)"
    } else {
        Write-Host "  OK" -ForegroundColor Green
    }
}

Write-Host ""
if ($failures.Count -eq 0) {
    Write-Host "VERDE - todos os $($projects.Count) simuladores no exit esperado." -ForegroundColor Green
    exit 0
}
Write-Host "VERMELHO - simuladores com desvio:" -ForegroundColor Red
$failures | ForEach-Object { Write-Host "  x $_" -ForegroundColor Red }
exit 1
