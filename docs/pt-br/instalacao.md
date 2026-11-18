# Instalação

Ordem: painel primeiro, depois um agente por servidor de arquivos. Os dois instaladores são MSI x64 e não exigem
.NET instalado. Eles **não têm assinatura de código**: confira o SHA-256 e o atestado antes de instalar (ver
[README](../../README.md#conferir-o-download)).

## 1. Painel

Máquina central da sua rede: Windows Server ou Windows 10/11, x64.

```powershell
msiexec /i RansomGuard-Painel-1.0.0.msi
```

- Instala o serviço **RansomGuard Panel**, que roda com a conta virtual `NT SERVICE\RansomGuardPanel`.
- Dados em `C:\ProgramData\RansomGuard\Painel`, numa pasta acessível só ao serviço e aos administradores. Os
  segredos ficam protegidos pela DPAPI da máquina. Desinstalar **preserva** essa pasta.
- Abre a porta **5001/TCP** (HTTPS) no firewall, nos perfis de domínio e privado. Para não abrir:
  `msiexec /i ... OPENFIREWALL=0`. A porta 5000 (HTTP) só atende na própria máquina.

Abra `https://<painel>:5001`. O certificado é autoassinado, gerado na instalação; o navegador avisa na primeira
vez. A tela de configuração inicial pede o **token de primeira execução**, que está em
`C:\ProgramData\RansomGuard\Painel\token-de-setup.txt`. Só administradores abrem a pasta, e o arquivo é apagado
depois que a conta de administrador é criada.

## 2. Agente

Em cada servidor de arquivos: Windows Server com a função de servidor de arquivos, como administrador.

No painel, tela **Agentes → Novo token de enrolamento**. O painel mostra o comando pronto:

```powershell
msiexec /i RansomGuard-Agente-1.0.0.msi BACKENDURL=https://painel.empresa.local:5001 SERVERNAME=FS01 `
  PROTECTEDPATHS="D:\Shares\Financeiro;D:\Shares\Projetos" ENROLLTOKEN=<token> PANELCERT=<sha256 do certificado>
```

| Propriedade | O que é |
|---|---|
| `BACKENDURL` | Endereço do painel (HTTPS, porta 5001). |
| `ENROLLTOKEN` | Token de enrolamento, com prazo de até 7 dias e número de usos limitado (até 500). Usado uma vez: o agente apresenta ao painel a própria chave e apaga o token do registro. |
| `PANELCERT` | SHA-256 do certificado do painel: o agente só aceita esse certificado. |
| `PANELKEY` | (opcional) Chave pública do painel. Sem ela, o agente fixa a chave no primeiro contato. |
| `SERVERNAME` | Nome do servidor no painel. Vazio = nome da máquina. |
| `PROTECTEDPATHS` | Pastas onde o agente planta arquivos-canário (separadas por `;`). Vazio = nenhum canário: o produto nunca escolhe sozinho onde plantar. |
| `DECOYSHARES` | (opcional) Compartilhamentos-isca, em UNC, separados por `;`. Qualquer acesso a eles é incidente de alta confiança. |
| `CANARYNAMES` | (opcional) Nomes de canário escolhidos por você (mínimo três). Vazio = nomes gerados por instalação. |
| `MODE` | Modo inicial, `Monitor` por padrão. A política publicada pelo painel prevalece. |
| `FSRMBLOCKING` | `true` faz o file screen do FSRM bloquear a gravação (padrão: só registra). |
| `SERVICEACCOUNT` | `LocalSystem` por padrão. Aceita uma gMSA (`DOMINIO\conta$`). |

O agente roda como serviço **RansomGuard Agent** e guarda os dados em `C:\ProgramData\RansomGuard`, numa pasta só
para SYSTEM e administradores. Ao subir, ele:

- liga a auditoria de compartilhamento e de sistema de arquivos de que precisa, e a religa se alguém a desligar;
- planta os canários nas pastas protegidas, com regra de auditoria;
- aplica os file screens do FSRM, se o FSRM estiver instalado.

Em alguns minutos o servidor aparece no painel com a nota de risco.

### Instalação em massa

O MSI aceita as mesmas propriedades por GPO ou ferramenta de distribuição. Um token serve vários servidores
dentro do limite de usos e do prazo. Cada servidor gera a própria chave; um nome só aceita uma chave (revogue na
tela Agentes para reenrolar).

## 3. Primeiros passos

1. Fique em **Monitor** por alguns dias. Veja na tela **Incidentes** o que o seu ambiente gera de atividade
   legítima (backup, sincronização, antivírus).
2. Na tela **Política**, preencha a allowlist com as contas de serviço que atualizam muitos arquivos.
3. Configure um canal em **Notificações**.
4. Passe para **Block** num servidor de teste, rode o [ensaio controlado](ensaio.md) e confira a contenção e o
   **Desfazer**. Depois, estenda aos demais.

## Atualizar e desinstalar

- Atualizar: rode o MSI da versão nova. Identidade, enrolamento, política e canários são preservados.
- Desinstalar o agente retira os canários (só os arquivos que comprovadamente são dele, pelo conteúdo), os file
  screens e as regras de bloqueio.
- Desinstalar o painel preserva os dados.

## Backup do painel

Tela **Contas → Baixar backup**: um zip com o banco, a chave da instalação e os segredos, em forma portátil. É tão
sensível quanto a chave: guarde como tal. A restauração em outra máquina não foi exercitada no laboratório.
