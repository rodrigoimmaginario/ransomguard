<#
.SYNOPSIS
  Assina o catálogo de ransomware do RansomGuard (cerimônia do owner — molde ADR-12).

.DESCRIPTION
  Gera list/catalog.json.minisig a partir de list/catalog.json usando a chave PRIVADA de catálogo,
  que fica OFFLINE no cofre (nunca no repositório). O agente confia apenas na chave pública
  embarcada. Editar o catálogo QUEBRA a assinatura → re-assinar é cerimônia do owner.

  ⚠️ NÃO é executado autonomamente por agentes de IA. É um passo manual do owner.

.PARAMETER Catalog
  Caminho do catalog.json a assinar (default: list/catalog.json).

.PARAMETER SecretKey
  Caminho da chave secreta minisign (fora do repo; ex.: no cofre/pendrive).

.EXAMPLE
  minisign -Gm list/catalog.json -s D:\cofre\ransomguard-catalog.key
  # ou, mantendo o comentário confiável versionado:
  ./tools/sign-catalog.ps1 -Catalog list/catalog.json -SecretKey D:\cofre\ransomguard-catalog.key
#>
param(
  [string]$Catalog = "list/catalog.json",
  [Parameter(Mandatory = $true)][string]$SecretKey,
  [string]$TrustedComment
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Catalog)) { throw "Catálogo não encontrado: $Catalog" }
if (-not (Test-Path $SecretKey)) { throw "Chave secreta não encontrada: $SecretKey" }

# Versão vai no trusted comment (assinado) para rastreabilidade.
$version = (Get-Content $Catalog -Raw | ConvertFrom-Json).version
if (-not $TrustedComment) { $TrustedComment = "ransomware catalog v$version $(Get-Date -Format 'yyyy.MM.dd')" }

Write-Host "Assinando $Catalog (v$version)..." -ForegroundColor Cyan
Write-Host "Trusted comment: $TrustedComment"

# minisign deve estar instalado (winget install jedisct1.minisign).
& minisign -Sm $Catalog -s $SecretKey -t $TrustedComment
if ($LASTEXITCODE -ne 0) { throw "minisign falhou (exit $LASTEXITCODE)." }

Write-Host "OK — gerado $Catalog.minisig" -ForegroundColor Green
Write-Host "Lembre: fazer bump da 'version' no catalog.json a cada mudança (anti-rollback)." -ForegroundColor Yellow
