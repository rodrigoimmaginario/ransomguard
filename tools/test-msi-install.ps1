<#
.SYNOPSIS
  Instala os MSIs do painel e do agente de verdade e confere o resultado (A4, B2, D9, C4). Roda na CI; exige processo elevado.

.DESCRIPTION
  Publica o painel, monta o MSI, instala em modo silencioso e verifica, no proprio Windows:
    - o pacote nao leva chave, segredos, banco nem configuracao de desenvolvimento;
    - o servico existe, esta em execucao, inicia automaticamente e roda com a conta virtual;
    - o painel responde por HTTPS, com CSS e scripts (o MSI da RC 0.9.0 nao iniciava);
    - os dados ficam em ProgramData, em pasta restrita, e nada e gravado ao lado do executavel;
    - chave e segredos nao ficam legiveis em disco;
    - a conta de administrador e criada com o token do arquivo, e o arquivo some;
    - a identidade do painel e a mesma depois de reiniciar o servico;
    - as regras de firewall existem;
    - a desinstalacao remove servico, binarios e regras, e preserva os dados;
    - o administrador gera um token de enrolamento na tela Agentes; o agente e instalado com o comando que a tela
      mostra, se enrola com a propria chave, apaga o token do registro e APARECE NO PAINEL por HTTPS, com o
      certificado fixado e cada lote assinado (B1);
    - lote sem assinatura de agente enrolado e recusado pelo painel;
    - os canarios plantados numa pasta protegida tem nomes e conteudo proprios da instalacao (B4), e a
      desinstalacao os retira sem tocar no arquivo do cliente;
    - os dois produtos aparecem com o mesmo fabricante e sem "IPSEC" no registro;
    - o HTTP (5000) so atende na propria maquina;
    - o painel continua funcionando depois que o agente restringe a pasta de dados que os dois dividem.

  ALTERA A MAQUINA: instala e desinstala o produto e, ao final, apaga a pasta de dados que criou.
  Recusa rodar se ja houver um painel instalado ou uma pasta de dados existente.
#>
param([string]$WorkDir = "out/msi-test")

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$work = Join-Path $repo $WorkDir
$serviceName = "RansomGuardPanel"
$serviceSid = "S-1-5-80-2117528005-344204068-2938588982-2536083958-2915349141"
$installDir = Join-Path $env:ProgramFiles "RansomGuard\Painel"
$dataDir = Join-Path $env:ProgramData "RansomGuard\Painel"
$base = "https://localhost:5001"
$agentService = "RansomGuardAgent"
$agentName = "RGCI01"
$agentData = Join-Path $env:ProgramData "RansomGuard"
$agentDataExisted = Test-Path $agentData
$script:agentInstalled = $false
$protected = "C:\rg-ci-protegida"
$clientFile = Join-Path $protected "contrato do cliente.docx"

function Test-Port([string]$address, [int]$port) {
  $client = New-Object Net.Sockets.TcpClient
  try { $t = $client.ConnectAsync($address, $port); return ($t.Wait(3000) -and $client.Connected) } catch { return $false } finally { $client.Dispose() }
}
$script:failures = @()

function Check([string]$name, [bool]$ok, [string]$detail = "") {
  $mark = if ($ok) { "  OK " } else { "FALHA" }
  Write-Host "$mark  $name$(if ($detail) { " - $detail" })"
  if (-not $ok) { $script:failures += $name }
}

function Get-Page([string]$path, $session = $null) {
  $a = @{ Uri = "$base$path"; SkipCertificateCheck = $true; SkipHttpErrorCheck = $true; TimeoutSec = 15 }
  if ($session) { $a.WebSession = $session }
  Invoke-WebRequest @a
}

function Wait-Panel([int]$seconds = 90) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    try { $r = Get-Page "/api/identity"; if ($r.StatusCode -eq 200) { return $r.Content } } catch { }
    Start-Sleep -Seconds 2
  }
  return $null
}

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw "Este teste instala um servico: rode elevado." }
if ($PSVersionTable.PSVersion.Major -lt 7) { throw "Use o PowerShell 7 (pwsh)." }
if (Get-Service $serviceName -ErrorAction SilentlyContinue) { throw "Ja existe um servico $serviceName nesta maquina; o teste nao mexe em instalacao existente." }
if (Get-Service $agentService -ErrorAction SilentlyContinue) { throw "Ja existe um servico $agentService nesta maquina; o teste nao mexe em instalacao existente." }
if (Test-Path $dataDir) { throw "A pasta $dataDir ja existe; o teste nao mexe em dados existentes." }
if (Test-Path $protected) { throw "A pasta $protected ja existe; o teste nao mexe em dados existentes." }

# -- 1. Publicar e conferir o que vai no pacote --------------------------------------------------
if (Test-Path $work) { Remove-Item $work -Recurse -Force }
$bin = Join-Path $work "painel"
New-Item -ItemType Directory -Path $bin -Force | Out-Null
Write-Host "== Publicando o painel"
dotnet publish (Join-Path $repo "server/RansomGuard.Server/RansomGuard.Server.csproj") -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o $bin --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "Falha ao publicar o painel." }

$forbidden = Get-ChildItem $bin -Recurse -File | Where-Object {
  $_.Name -match '^(install-key|install-secrets)\.json$|^appsettings\.Development\.json$|\.db$|^token-de-setup\.txt$' -or $_.FullName -match '\\catalog-cache\\'
}
Check "pacote sem chave, segredos, banco, cache ou configuracao de desenvolvimento" (-not $forbidden) (($forbidden | ForEach-Object Name) -join ", ")
Check "pacote leva a biblioteca nativa do SQLite e o wwwroot" ((Test-Path "$bin/e_sqlite3.dll") -and (Test-Path "$bin/wwwroot/rg.css") -and (Test-Path "$bin/wwwroot/_framework/blazor.web.js"))

# -- 2. MSI --------------------------------------------------------------------------------------
if (-not (Get-Command wix -ErrorAction SilentlyContinue)) {
  Write-Host "== Instalando o WiX"
  dotnet tool install --global wix --version 5.0.2
  $env:PATH = "$env:USERPROFILE\.dotnet\tools;$env:PATH"
}
wix extension add -g WixToolset.Util.wixext/5.0.2
wix extension add -g WixToolset.Firewall.wixext/5.0.2
$msi = Join-Path $work "RansomGuard-Painel-teste.msi"
wix build (Join-Path $repo "deploy/msi/painel.wxs") -arch x64 -d BinDir=$bin -d Version=0.9.9 -ext WixToolset.Util.wixext -ext WixToolset.Firewall.wixext -o $msi
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $msi)) { throw "Falha ao montar o MSI." }
Write-Host ("MSI: {0:N1} MB" -f ((Get-Item $msi).Length / 1MB))

Write-Host "== Publicando o agente"
$agentBin = Join-Path $work "agente"
dotnet publish (Join-Path $repo "agent/RansomGuard.Agent.Service/RansomGuard.Agent.Service.csproj") -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o $agentBin --nologo -v q
if ($LASTEXITCODE -ne 0) { throw "Falha ao publicar o agente." }
$agentMsi = Join-Path $work "RansomGuard-Agente-teste.msi"
wix build (Join-Path $repo "deploy/msi/agente.wxs") -arch x64 -d BinDir=$agentBin -d Version=0.9.9 -ext WixToolset.Util.wixext -o $agentMsi
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $agentMsi)) { throw "Falha ao montar o MSI do agente." }


$sidNow = (sc.exe showsid $serviceName | Select-String "SERVICE SID").ToString() -replace '.*:\s*', ''
Check "SID do servico usado na permissao da pasta confere com o do Windows" ($sidNow -eq $serviceSid) $sidNow

# -- 3. Instalar ---------------------------------------------------------------------------------
$installLog = Join-Path $work "install.log"
Write-Host "== Instalando"
$p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart /l*v `"$installLog`"" -Wait -PassThru
if ($p.ExitCode -ne 0) {
  Get-Content $installLog -Tail 60 | Write-Host
  throw "msiexec /i terminou com $($p.ExitCode)."
}

try {
  # -- 4. Servico --------------------------------------------------------------------------------
  $svc = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
  Check "servico instalado" ($null -ne $svc)
  Check "servico em execucao" ($svc.State -eq "Running") $svc.State
  Check "inicio automatico" ($svc.StartMode -eq "Auto") $svc.StartMode
  Check "conta virtual, sem privilegio de administrador" ($svc.StartName -eq "NT SERVICE\$serviceName") $svc.StartName

  # -- 5. Painel respondendo ---------------------------------------------------------------------
  $identityBefore = Wait-Panel
  Check "painel responde por HTTPS em /api/identity" ($null -ne $identityBefore)
  if ($null -eq $identityBefore) {
    Get-WinEvent -FilterHashtable @{ LogName = "Application"; StartTime = (Get-Date).AddMinutes(-10) } -MaxEvents 15 -ErrorAction SilentlyContinue |
      Where-Object { $_.ProviderName -match "RansomGuard|\.NET Runtime|Application Error" } | ForEach-Object { Write-Host $_.Message }
    throw "O painel nao subiu."
  }
  foreach ($asset in "/rg.css", "/app.css", "/_framework/blazor.web.js") {
    Check "serve $asset" ((Get-Page $asset).StatusCode -eq 200)
  }
  $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
  $setup = Get-Page "/setup" $session
  Check "tela de setup abre e aponta o arquivo do token" ($setup.StatusCode -eq 200 -and $setup.Content -match "token-de-setup\.txt")

  # -- 6. Dados e permissoes ---------------------------------------------------------------------
  foreach ($f in "ransomguard.db", "install-key.json", "install-secrets.json", "token-de-setup.txt") {
    Check "dados: $f em ProgramData" (Test-Path (Join-Path $dataDir $f))
  }
  $stray = Get-ChildItem $installDir -Recurse -File | Where-Object { $_.Name -match '\.db|install-key|install-secrets|token-de-setup' -or $_.FullName -match '\\catalog-cache\\|\\keys\\' }
  Check "nada gravado ao lado do executavel" (-not $stray) (($stray | ForEach-Object Name) -join ", ")

  $allowed = @("S-1-5-18", "S-1-5-32-544", $serviceSid)
  $acl = Get-Acl $dataDir
  $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
  Check "pasta de dados nao herda a permissao de ProgramData" $acl.AreAccessRulesProtected
  Check "pasta de dados: so SYSTEM, administradores e o servico" (-not ($sids | Where-Object { $_ -notin $allowed })) ($sids -join ", ")
  $fileSids = @((Get-Acl (Join-Path $dataDir "install-key.json")).Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
  Check "arquivo da chave: so SYSTEM, administradores e o servico" (-not ($fileSids | Where-Object { $_ -notin $allowed })) ($fileSids -join ", ")

  foreach ($f in "install-key.json", "install-secrets.json") {
    $raw = Get-Content (Join-Path $dataDir $f) -Raw
    Check "$f protegido (sem texto legivel)" ($raw.StartsWith("RGP1:") -and $raw -notmatch "Seed|IngestSecret|CertificatePassword")
  }

  # -- 7. Firewall -------------------------------------------------------------------------------
  $rules = @(Get-NetFirewallRule -DisplayName "RansomGuard Panel HTTPS*" -ErrorAction SilentlyContinue)
  Check "duas regras de firewall (dominio e privado)" ($rules.Count -eq 2) "$($rules.Count)"
  foreach ($rule in $rules) {
    $port = ($rule | Get-NetFirewallPortFilter).LocalPort
    Check "regra '$($rule.DisplayName)': entrada, permitir, TCP 5001, ativa" ($rule.Enabled -eq "True" -and $rule.Direction -eq "Inbound" -and $rule.Action -eq "Allow" -and "$port" -eq "5001") "perfil=$($rule.Profile) porta=$port"
  }
  Check "nenhuma regra no perfil publico" (-not ($rules | Where-Object { "$($_.Profile)" -match "Public|Any" })) (($rules | ForEach-Object { "$($_.Profile)" }) -join ", ")

  # -- 8. Criar a conta com o token do arquivo ---------------------------------------------------
  $token = (Get-Content (Join-Path $dataDir "token-de-setup.txt") | Where-Object { $_.Trim() } | Select-Object -Last 1).Trim()
  $af = [regex]::Match($setup.Content, 'name="__RequestVerificationToken"[^>]*value="([^"]+)"').Groups[1].Value
  $body = @{ "__RequestVerificationToken" = $af; username = "admin"; password = "Senha-forte-de-teste-1"; token = $token }
  $created = Invoke-WebRequest -Uri "$base/auth/setup" -Method Post -Body $body -WebSession $session -SkipCertificateCheck -SkipHttpErrorCheck -TimeoutSec 30
  Check "conta criada com o token do arquivo (o servico grava no banco)" ($created.StatusCode -eq 200 -and $created.Content -match "Nenhum agente ainda") "status $($created.StatusCode)"
  Check "arquivo do token apagado depois da conta" (-not (Test-Path (Join-Path $dataDir "token-de-setup.txt")))

  # -- 8b. Rede: HTTPS escuta na rede, HTTP so na propria maquina --------------------------------
  $lan = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' } | Select-Object -First 1).IPAddress
  Check "HTTPS 5001 escuta no endereco de rede" (Test-Port $lan 5001) $lan
  Check "HTTP 5000 atende na propria maquina" (Test-Port "127.0.0.1" 5000)
  Check "HTTP 5000 nao escuta no endereco de rede" (-not (Test-Port $lan 5000)) $lan

  # -- 8c. Agente: token de enrolamento gerado na tela Agentes, instalado com o comando que ela mostra
  $unsigned = Invoke-WebRequest -Uri "$base/api/ingest" -Method Post -Body '{"server":"RGCI01","events":[]}' -ContentType "application/json" -SkipCertificateCheck -SkipHttpErrorCheck -TimeoutSec 15
  Check "lote sem assinatura de agente enrolado e recusado (401)" ($unsigned.StatusCode -eq 401) "status $($unsigned.StatusCode)"

  $agentsPage = Get-Page "/agentes" $session
  $af2 = [regex]::Match($agentsPage.Content, 'name="__RequestVerificationToken"[^>]*value="([^"]+)"').Groups[1].Value
  $tokenForm = @{ "_handler" = "novo-token"; "__RequestVerificationToken" = $af2; "Form.MaxUses" = "1"; "Form.Hours" = "1" }
  $issued = Invoke-WebRequest -Uri "$base/agentes" -Method Post -Body $tokenForm -WebSession $session -SkipCertificateCheck -SkipHttpErrorCheck -TimeoutSec 30
  $enroll = [regex]::Match($issued.Content, 'ENROLLTOKEN=([A-Za-z0-9_\-]+)').Groups[1].Value
  $pin = [regex]::Match($issued.Content, 'PANELCERT=([A-Fa-f0-9]+)').Groups[1].Value
  Check "tela Agentes gera o token e mostra o comando de instalacao, com o certificado" ($issued.StatusCode -eq 200 -and $enroll.Length -ge 30 -and $pin.Length -eq 64) "status $($issued.StatusCode)"
  Check "o comando nao carrega mais segredo compartilhado" ($issued.Content -notmatch "INGESTSECRET")
  New-Item -ItemType Directory -Path (Join-Path $protected "2024") -Force | Out-Null
  Set-Content -Path $clientFile -Value "arquivo do cliente" -Encoding utf8
  Write-Host "== Instalando o agente"
  # O token vai na linha de comando: vale uma vez, por uma hora, e a propriedade e oculta no log do instalador.
  $agentLog = Join-Path $work "agent-install.log"
  $a = Start-Process msiexec.exe -ArgumentList "/i `"$agentMsi`" /qn /norestart BACKENDURL=$base SERVERNAME=$agentName PROTECTEDPATHS=$protected ENROLLTOKEN=$enroll PANELCERT=$pin /liwea `"$agentLog`"" -Wait -PassThru
  if ($a.ExitCode -ne 0) {
    Get-Content $agentLog -Tail 40 | Write-Host
    throw "msiexec /i (agente) terminou com $($a.ExitCode)."
  }
  $script:agentInstalled = $true

  $asvc = Get-CimInstance Win32_Service -Filter "Name='$agentService'"
  Check "agente: servico em execucao, inicio automatico" ($asvc.State -eq "Running" -and $asvc.StartMode -eq "Auto") "$($asvc.State)/$($asvc.StartMode)"
  Check "agente: conta LocalSystem (padrao)" ($asvc.StartName -eq "LocalSystem") $asvc.StartName
  $reg = Get-ItemProperty "HKLM:\SOFTWARE\RansomGuard\Agent" -ErrorAction SilentlyContinue
  Check "agente: configuracao em SOFTWARE\RansomGuard\Agent, nascendo em Monitor" ($reg.BackendUrl -eq $base -and $reg.ServerName -eq $agentName -and $reg.Mode -eq "Monitor") "modo=$($reg.Mode)"
  Check "registro sem a chave antiga (IPSEC)" (-not (Test-Path "HKLM:\SOFTWARE\IPSEC\RansomGuard") -and -not (Test-Path "HKLM:\SOFTWARE\WOW6432Node\IPSEC\RansomGuard"))
  $arp = @(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "RansomGuard*" })
  Check "os dois produtos em Programas e Recursos, fabricante Rodrigo Immaginario" ($arp.Count -eq 2 -and -not ($arp | Where-Object { $_.Publisher -ne "Rodrigo Immaginario" })) (($arp | ForEach-Object { "$($_.DisplayName)=$($_.Publisher)" }) -join "; ")

  # O agente fala com o painel por HTTPS, com o certificado fixado, e o servidor aparece no painel.
  $seen = $false
  $deadline = (Get-Date).AddSeconds(180)
  while ((Get-Date) -lt $deadline -and -not $seen) {
    Start-Sleep -Seconds 5
    $front = Get-Page "/" $session
    $seen = $front.StatusCode -eq 200 -and $front.Content -match [regex]::Escape($agentName) -and $front.Content -notmatch "Nenhum agente ainda"
  }
  Check "agente aparece no painel (enrolado, lote assinado aceito por HTTPS com certificado fixado)" $seen
  if (-not $seen) {
    Get-WinEvent -FilterHashtable @{ LogName = "Application"; StartTime = (Get-Date).AddMinutes(-10) } -MaxEvents 40 -ErrorAction SilentlyContinue |
      Where-Object { $_.ProviderName -match "RansomGuard|\.NET Runtime" } | Select-Object -First 8 |
      ForEach-Object { Write-Host (($_.Message -split "`n" | Select-Object -First 6) -join "`n") }
  }
  Check "agente fixou a chave do painel no primeiro contato" (Test-Path (Join-Path $agentData "panel-key.pub"))

  # B1: identidade do agente
  $idFile = Join-Path $agentData "agent-identity.json"
  Check "chave do agente guardada protegida (sem texto legivel)" ((Test-Path $idFile) -and (Get-Content $idFile -Raw).StartsWith("RGP1:") -and (Get-Content $idFile -Raw) -notmatch "Seed")
  Check "agente marcou o enrolamento" (Test-Path (Join-Path $agentData "agent-enrolled.json"))
  $regAfter = Get-ItemProperty "HKLM:\SOFTWARE\RansomGuard\Agent" -ErrorAction SilentlyContinue
  Check "token de enrolamento apagado do registro depois de usado" ([string]::IsNullOrEmpty($regAfter.EnrollToken)) "valor presente: $(-not [string]::IsNullOrEmpty($regAfter.EnrollToken))"
  Check "registro do agente sem segredo de ingestao" ($null -eq $regAfter.IngestSecret)
  $listed = Get-Page "/agentes" $session
  Check "tela Agentes lista o servidor enrolado e nao repete o token" ($listed.Content -match [regex]::Escape($agentName) -and $listed.Content -notmatch [regex]::Escape($enroll))
  $again = Invoke-WebRequest -Uri "$base/api/enroll" -Method Post -Body (@{ token = $enroll; server = "OUTRO01"; publicKey = [Convert]::ToBase64String((New-Object byte[] 32)) } | ConvertTo-Json) -ContentType "application/json" -SkipCertificateCheck -SkipHttpErrorCheck -TimeoutSec 15
  Check "o token usado nao enrola um segundo servidor (401)" ($again.StatusCode -eq 401) "status $($again.StatusCode)"

  # B4: canarios com nomes e conteudo proprios da instalacao
  $inRoot = @(Get-ChildItem $protected -File -Force | Where-Object { $_.Name -ne "contrato do cliente.docx" })
  $inSub = @(Get-ChildItem (Join-Path $protected "2024") -File -Force)
  Check "canarios plantados na pasta protegida e na subpasta (9 em cada)" ($inRoot.Count -eq 9 -and $inSub.Count -eq 9) "raiz=$($inRoot.Count) subpasta=$($inSub.Count)"
  Check "nenhum nome de canario identifica o produto" (-not (@($inRoot + $inSub) | Where-Object { $_.Name -match "ransom|canary|canario" })) (($inRoot | Select-Object -First 2 | ForEach-Object Name) -join "; ")
  $leak = @($inRoot | Where-Object { [Text.Encoding]::ASCII.GetString([IO.File]::ReadAllBytes($_.FullName)) -match "RansomGuard" })
  Check "nenhum conteudo de canario identifica o produto" ($leak.Count -eq 0)
  Check "os mesmos nomes na raiz e na subpasta" (-not (Compare-Object ($inRoot | ForEach-Object Name) ($inSub | ForEach-Object Name)))
  $manifestFile = Join-Path $agentData "canary-manifest.json"
  Check "manifesto de canarios protegido (os nomes nao aparecem nele)" ((Test-Path $manifestFile) -and (Get-Content $manifestFile -Raw).StartsWith("RGP1:") -and -not ($inRoot | Where-Object { (Get-Content $manifestFile -Raw).Contains($_.Name) }))

  $aacl = Get-Acl $agentData
  $asids = @($aacl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
  Check "pasta de dados do agente: sem heranca, so SYSTEM e administradores" ($aacl.AreAccessRulesProtected -and -not ($asids | Where-Object { $_ -notin @("S-1-5-18", "S-1-5-32-544") })) ($asids -join ", ")


  # -- 9. Reinicio: mesma identidade -------------------------------------------------------------
  Restart-Service $serviceName
  $identityAfter = Wait-Panel
  Check "depois de reiniciar, o painel volta e a identidade e a mesma" ($null -ne $identityAfter -and $identityAfter -eq $identityBefore)
  $login = Get-Page "/login"
  Check "depois de reiniciar, a conta continua existindo (vai para o login, nao para o setup)" ($login.StatusCode -eq 200 -and $login.Content -match "/auth/login")
}
finally {
  # -- 10. Desinstalar ---------------------------------------------------------------------------
  if ($script:agentInstalled) {
    Write-Host "== Desinstalando o agente"
    $ua = Start-Process msiexec.exe -ArgumentList "/x `"$agentMsi`" /qn /norestart" -Wait -PassThru
    Check "agente: desinstalacao termina com sucesso" ($ua.ExitCode -eq 0) "exit $($ua.ExitCode)"
    Check "agente: servico removido" (-not (Get-Service $agentService -ErrorAction SilentlyContinue))
    Check "agente: chave de registro removida" (-not (Test-Path "HKLM:\SOFTWARE\RansomGuard\Agent"))
    $left = @(Get-ChildItem $protected -File -Force -Recurse -ErrorAction SilentlyContinue | ForEach-Object Name)
    Check "desinstalar retira os canarios e deixa o arquivo do cliente" ($left.Count -eq 1 -and $left[0] -eq "contrato do cliente.docx") ($left -join "; ")
    Check "arquivo do cliente intacto" ((Test-Path $clientFile) -and (Get-Content $clientFile -Raw).Trim() -eq "arquivo do cliente")
  }
  Write-Host "== Desinstalando"
  $u = Start-Process msiexec.exe -ArgumentList "/x `"$msi`" /qn /norestart /l*v `"$(Join-Path $work 'uninstall.log')`"" -Wait -PassThru
  Check "desinstalacao termina com sucesso" ($u.ExitCode -eq 0) "exit $($u.ExitCode)"
  Check "servico removido" (-not (Get-Service $serviceName -ErrorAction SilentlyContinue))
  Check "binarios removidos" (-not (Test-Path (Join-Path $installDir "RansomGuard.Server.exe")))
  Check "regras de firewall removidas" (@(Get-NetFirewallRule -DisplayName "RansomGuard Panel HTTPS*" -ErrorAction SilentlyContinue).Count -eq 0)
  Check "dados preservados na desinstalacao" (Test-Path (Join-Path $dataDir "ransomguard.db"))
  if (Test-Path $dataDir) { Remove-Item $dataDir -Recurse -Force -ErrorAction SilentlyContinue }
  if (-not $agentDataExisted -and (Test-Path $agentData)) { Remove-Item $agentData -Recurse -Force -ErrorAction SilentlyContinue }
  if (Test-Path $protected) { Remove-Item $protected -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ""
if ($script:failures.Count -gt 0) {
  Write-Host "VERMELHO - instalacao com desvio:" -ForegroundColor Red
  $script:failures | ForEach-Object { Write-Host "  x $_" }
  exit 1
}
Write-Host "VERDE - MSIs do painel e do agente instalados, verificados e desinstalados."
