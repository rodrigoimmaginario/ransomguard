<#
.SYNOPSIS
  Monta os artefatos de uma versao do RansomGuard: os dois instaladores MSI e o provocador de ensaio, com SHA-256.

.DESCRIPTION
  1. Publica painel, agente e provocador como executaveis win-x64 self-contained (nao exigem .NET instalado).
  2. Recusa a saida se algo que o painel CRIA ao rodar (chaves, banco, token) entrou na publicacao.
  3. Gera os MSIs com o WiX 5 (instalado como ferramenta dotnet, se faltar).
  4. Escreve um .sha256 por arquivo e um SHA256SUMS.txt com todos.

  Usado pela CI no job de release (tag v*) e pelo laboratorio. Nenhum segredo entra nos artefatos.
  Os instaladores saem SEM assinatura de codigo: o Windows avisa na instalacao; confira o SHA-256 e o atestado
  publicados com a release.
  (Arquivo em ASCII puro: o Windows PowerShell 5.1 le .ps1 sem BOM como ANSI.)

.PARAMETER Version
  Versao semantica (ex.: 1.0.0 ou 0.9.12-rc). O MSI recebe so a parte numerica.

.EXAMPLE
  ./tools/build-release.ps1 -Version 1.0.0 -OutDir out/release
#>
param(
  [Parameter(Mandatory)] [string]$Version,
  [string]$OutDir = "out/release"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot

if ($Version -notmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.]+)?$') { throw "Versao invalida: '$Version' (esperado x.y.z ou x.y.z-sufixo)." }
$msiVersion = ($Version -replace '-.*$', '')

# .NET: usa o dotnet do PATH; se nao estiver la, tenta o SDK por usuario (~/.dotnet).
if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
  $perUser = Join-Path $env:USERPROFILE ".dotnet"
  if (-not (Test-Path (Join-Path $perUser "dotnet.exe"))) { throw "dotnet nao encontrado no PATH nem em $perUser." }
  $env:DOTNET_ROOT = $perUser
  $env:PATH = "$perUser;$env:PATH"
}

$out = if ([IO.Path]::IsPathRooted($OutDir)) { $OutDir } else { Join-Path $repo $OutDir }
$stage = Join-Path $out "stage"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path "$stage/painel", "$stage/agente", "$stage/ensaio" -Force | Out-Null

function Publish([string]$project, [string]$dest, [string]$what) {
  Write-Host "Publicando $what..." -ForegroundColor Cyan
  dotnet publish (Join-Path $repo $project) -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true `
    -p:Version=$msiVersion -o $dest --nologo | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "Falha ao publicar $what." }
}
Publish "server/RansomGuard.Server/RansomGuard.Server.csproj" "$stage/painel" "o painel"
Publish "agent/RansomGuard.Agent.Service/RansomGuard.Agent.Service.csproj" "$stage/agente" "o agente"
Publish "tools/RansomGuard.Ensaio/RansomGuard.Ensaio.csproj" "$stage/ensaio" "o provocador de ensaio"

Get-ChildItem $stage -Recurse -Include *.pdb, appsettings.Development.json -ErrorAction SilentlyContinue | Remove-Item -Force

# B7: nada que o painel CRIA ao rodar pode viajar. O zip da RC 0.9.0 levou a chave de assinatura do painel de
# desenvolvimento porque o publish copiava todo *.json da pasta do projeto; o .csproj ja exclui, e este portao falha
# a montagem se a exclusao regredir.
$forbidden = Get-ChildItem $stage -Recurse -File | Where-Object {
  $_.Name -match '^(install-key|install-secrets)\.json$|\.db$|^token-de-setup\.txt$' -or $_.FullName -match '\\(catalog-cache|keys)\\'
}
if ($forbidden) { throw "Arquivos que nao podem ir na release: $(($forbidden | ForEach-Object FullName) -join ', ')" }

if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  Write-Host "Instalando o WiX 5.0.2..." -ForegroundColor Cyan
  dotnet tool install --global wix --version 5.0.2 | Out-Null
  $env:PATH = "$env:PATH;$(Join-Path $env:USERPROFILE '.dotnet\tools')"
}
wix extension add -g WixToolset.Util.wixext/5.0.2 | Out-Null
wix extension add -g WixToolset.Firewall.wixext/5.0.2 | Out-Null

$painelMsi = Join-Path $out "RansomGuard-Painel-$Version.msi"
$agenteMsi = Join-Path $out "RansomGuard-Agente-$Version.msi"
$ensaioExe = Join-Path $out "RansomGuard-Ensaio-$Version.exe"

# -arch x64: sem ele o WiX instala em "Program Files (x86)".
wix build (Join-Path $repo "deploy/msi/painel.wxs") -arch x64 -d BinDir="$stage/painel" -d Version=$msiVersion `
  -ext WixToolset.Util.wixext -ext WixToolset.Firewall.wixext -o $painelMsi
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $painelMsi)) { throw "Falha ao gerar o MSI do painel." }
wix build (Join-Path $repo "deploy/msi/agente.wxs") -arch x64 -d BinDir="$stage/agente" -d Version=$msiVersion `
  -ext WixToolset.Util.wixext -o $agenteMsi
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $agenteMsi)) { throw "Falha ao gerar o MSI do agente." }
Copy-Item (Join-Path $stage "ensaio/RansomGuard-Ensaio.exe") $ensaioExe -Force
Get-ChildItem $out -Filter *.wixpdb | Remove-Item -Force   # simbolos do WiX: nao sao artefato da release

$sums = @()
foreach ($p in @($painelMsi, $agenteMsi, $ensaioExe)) {
  $name = Split-Path $p -Leaf
  $hash = (Get-FileHash $p -Algorithm SHA256).Hash.ToLowerInvariant()
  [IO.File]::WriteAllText("$p.sha256", "$hash  $name`n")
  $sums += "$hash  $name"
  Write-Host ("OK {0} ({1:N1} MB) {2}" -f $name, ((Get-Item $p).Length / 1MB), $hash) -ForegroundColor Green
}
[IO.File]::WriteAllText((Join-Path $out "SHA256SUMS.txt"), (($sums -join "`n") + "`n"))
Remove-Item $stage -Recurse -Force
Write-Host "Artefatos em $out" -ForegroundColor Green
