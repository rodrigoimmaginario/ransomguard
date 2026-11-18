<#
.SYNOPSIS
  Cerimonia do catalogo em um comando - roda NA SUA maquina; a chave privada nunca sai da pasta que voce indicar.

.DESCRIPTION
  1. Gera o par de chaves minisign (uma vez) em -Vault, ou reutiliza se ja existir.
  2. Assina list/catalog.json e verifica a assinatura.
  3. Faz commit de list/catalog.json + catalog.json.minisig NESTE repositorio (o painel busca o catalogo da pasta list/
     da branch main do repositorio publico) e pergunta antes do push.
  4. Imprime a CHAVE PUBLICA no formato que o agente/painel embarcam (base64 de keyId + chave) - e isso que voce cola no chat.

  Nada aqui envia a chave privada para lugar nenhum. Depois de rodar, copie -Vault para duas midias offline.
  (Arquivo mantido em ASCII puro de proposito: o Windows PowerShell 5.1 le .ps1 sem BOM como ANSI.)

.EXAMPLE
  ./tools/ceremony.ps1 -Vault D:\cofre
#>
param(
  [Parameter(Mandatory)] [string]$Vault,
  [string]$Catalog = "list/catalog.json"
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (-not (Get-Command minisign -ErrorAction SilentlyContinue)) {
  Write-Host "minisign nao encontrado - instalando via winget..." -ForegroundColor Yellow
  winget install --id jedisct1.minisign -e --accept-source-agreements --accept-package-agreements | Out-Null
  $env:PATH = [Environment]::GetEnvironmentVariable('PATH', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('PATH', 'User')
  if (-not (Get-Command minisign -ErrorAction SilentlyContinue)) { throw "minisign ainda nao esta no PATH; abra um novo PowerShell e rode de novo." }
}

New-Item -ItemType Directory -Force -Path $Vault | Out-Null
$sec = Join-Path $Vault 'ransomguard-catalog.key'
$pub = Join-Path $Vault 'ransomguard-catalog.pub'

# Nunca dentro de pasta sincronizada com nuvem ou do repositorio.
$lower = (Resolve-Path $Vault).Path.ToLowerInvariant()
foreach ($bad in @('onedrive', 'dropbox', 'google drive', 'googledrive', '\vscode\')) {
  if ($lower.Contains($bad)) { throw "O cofre ($Vault) parece estar em pasta sincronizada/repositorio ('$bad'). Use um caminho local fora de nuvem (ex.: D:\cofre)." }
}

if (Test-Path $sec) {
  Write-Host "Chave privada ja existe em $sec - reutilizando (NAO gere outra: trocar a chave e migracao em todos os agentes)." -ForegroundColor Cyan
} else {
  Write-Host ""
  Write-Host "== 1/4 Gerando o par de chaves (uma vez na vida do produto). Escolha uma senha forte e guarde-a no seu gerenciador." -ForegroundColor Green
  & minisign -G -s $sec -p $pub
  if ($LASTEXITCODE -ne 0) { throw "minisign -G falhou." }
}

Write-Host ""
Write-Host "== 2/4 Validando e assinando $Catalog" -ForegroundColor Green
$json = Get-Content $Catalog -Raw | ConvertFrom-Json
if (-not $json.version -or $json.version -lt 1) { throw "catalog.json sem 'version' >= 1." }
Write-Host "   versao $($json.version) - $($json.patterns.Count) padroes - $(@($json.notePatterns).Count) notas"
& minisign -Sm $Catalog -s $sec -t "RansomGuard catalog v$($json.version)"
if ($LASTEXITCODE -ne 0) { throw "assinatura falhou." }
& minisign -Vm $Catalog -p $pub
if ($LASTEXITCODE -ne 0) { throw "a verificacao da assinatura FALHOU - nao publique." }

Write-Host ""
Write-Host "== 3/4 Commit do catalogo assinado neste repositorio" -ForegroundColor Green
git add -- $Catalog "$Catalog.minisig"
# Autoria: a identidade git configurada nesta maquina (o script nao fixa nome nem e-mail).
git commit -m "catalog v$($json.version) (assinado)" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "commit do catalogo falhou (identidade git configurada?)." }
$answer = Read-Host "Fazer push para origin/main agora? (s/N)"
if ($answer -match '^[sSyY]') { git push origin main } else { Write-Host "   commit local feito; push quando quiser: git push origin main" }

Write-Host ""
Write-Host "== 4/4 Chave PUBLICA para embarcar (cole no chat - nao e segredo):" -ForegroundColor Green
$pubLine = (Get-Content $pub | Where-Object { $_ -and -not $_.StartsWith('untrusted comment') } | Select-Object -First 1).Trim()
$blob = [Convert]::FromBase64String($pubLine)          # 42 bytes: 'Ed' + keyId(8) + chave(32)
if ($blob.Length -ne 42) { throw "formato inesperado da chave publica ($($blob.Length) bytes)." }
$embedded = [Convert]::ToBase64String($blob[2..41])    # 40 bytes: keyId + chave - o que Agent:CatalogPublicKeyBase64 espera
Write-Host ""
Write-Host "CatalogPublicKeyBase64: $embedded" -ForegroundColor White
Write-Host "KeyId (hex, para conferencia): $([BitConverter]::ToString($blob[2..9]).Replace('-',''))"
Write-Host ""
Write-Host "Agora: copie a pasta $Vault para DUAS midias offline." -ForegroundColor Yellow
