# Liga o portao de pre-push deste clone (varredura estrita + testes). Rode uma vez depois de clonar.
# (Arquivo em ASCII: o Windows PowerShell 5.1 le .ps1 sem BOM como ANSI.)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)
git config core.hooksPath tools/hooks
if ($LASTEXITCODE -ne 0) { throw "git config falhou." }
Write-Host "Portao de pre-push ligado (core.hooksPath = tools/hooks)."
