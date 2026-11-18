# RansomGuard

Detecção e contenção de ransomware em servidores de arquivos Windows. Gratuito e de código aberto (MIT).

**Site:** https://www.ransomguard.com.br/ · **Baixar:** [v1.0.0](https://github.com/rodrigoimmaginario/ransomguard/releases/tag/v1.0.0) · **English:** [README.en.md](README.en.md)

## O que faz

O RansomGuard observa o que chega pela rede aos compartilhamentos de um servidor de arquivos Windows. Quando um
usuário, a partir de uma estação, começa a cifrar, regravar, renomear ou apagar arquivos em massa, o agente
atribui a atividade a **quem** (conta) e **de onde** (IP). Conforme a política que você definir, ele contém o
ataque: bloqueia o IP de origem no servidor, nega aquela conta no compartilhamento e derruba a sessão SMB. Por
último, cria uma cópia de sombra para a restauração. Cada ação tem **Desfazer** no painel.

São três peças, todas na sua rede:

- **Agente** — serviço do Windows em cada servidor de arquivos. Lê os eventos de auditoria do Windows, mantém
  arquivos-canário nas pastas que você indicar, aplica file screens do FSRM e executa a contenção localmente,
  mesmo com o painel fora do ar.
- **Painel** — serviço do Windows numa máquina central. Recebe os lotes assinados dos agentes, mostra incidentes,
  postura e nota de risco, distribui a política assinada e alerta (ntfy, Teams/Slack, Telegram, e-mail).
- **Catálogo** — extensões e notas de resgate conhecidas, assinado offline (minisign). O painel o busca neste
  repositório, verifica a assinatura e o repassa aos agentes.

Só metadado sai do servidor monitorado (conta, IP, compartilhamento, caminho, operação), nunca conteúdo de
arquivo. O agente fala apenas com o seu painel; o painel só acessa a internet para buscar o catálogo e enviar
as notificações que você configurar.

## Proteção e limites

O produto foi validado em laboratório, numa rede real com Active Directory e Windows Server 2022 e 2025. Os números
abaixo são observações de laboratório, não garantia. Leia [Proteção e limites](docs/pt-br/protecao-e-limites.md)
antes de usar em produção.

- Ataques que levam tempo por arquivo são contidos no meio do caminho. Exemplos:
  - regravação vinda de uma estação: 64 a 227 de 300 arquivos atingidos;
  - ataque lento: contido em cerca de 1 minuto;
  - ataque em rajadas: contido em 23 s.
- **Um ataque rápido sobre arquivos pequenos pode terminar antes da contenção.** Renomear ou apagar centenas de
  arquivos de poucos bytes leva 2–3 s.
- Leitura em massa e cópias grandes são registradas e alertadas (Média), mas **Média nunca contém**.
- O modo padrão é **Monitor**: só registra. Contenção exige mudar a política para Block, de propósito.

## Requisitos

- Agente: Windows Server com a função de servidor de arquivos (testado em 2022 e 2025), direito de administrador.
  O FSRM é opcional e acrescenta os file screens.
- Painel: Windows Server ou Windows 10/11, x64.
- Nenhum dos dois exige .NET instalado: os executáveis são autocontidos.

## Instalar

1. Instale `RansomGuard-Painel-<versão>.msi`, abra `https://<painel>:5001` e crie a conta de administrador com o
   token de primeira execução.
2. Na tela **Agentes**, gere um token de enrolamento: o painel mostra o comando de instalação do agente, pronto.
3. Rode o comando em cada servidor de arquivos, informando as pastas a proteger.
4. Comece em **Monitor**. Passe para Block só depois de ver o comportamento no seu ambiente e preencher a
   allowlist de contas de serviço.

Passo a passo: [instalação](docs/pt-br/instalacao.md) · [operação](docs/pt-br/operacao.md).

## Conferir o download

Os instaladores **não têm assinatura de código**: o Windows avisa na instalação. Cada release publica o SHA-256 de
cada arquivo e um atestado de proveniência que liga o arquivo ao workflow e ao commit que o gerou:

```powershell
Get-FileHash .\RansomGuard-Agente-1.0.0.msi -Algorithm SHA256
gh attestation verify .\RansomGuard-Agente-1.0.0.msi --repo rodrigoimmaginario/ransomguard
```

## Compilar e testar

```powershell
dotnet test RansomGuard.sln                                   # testes do núcleo, do agente e do painel
dotnet build agent/RansomGuard.Agent.Service                  # serviço do agente (net10.0-windows, fora da .sln)
pwsh tools/run-simulators.ps1                                 # simuladores (portões de regressão)
pwsh tools/build-release.ps1 -Version 1.0.0 -OutDir out/release   # MSIs, provocador e SHA-256 (exige WiX 5)
```

A CI roda também os testes do serviço do agente em Windows Server real (log de segurança, compartilhamento SMB,
FSRM) e instala os dois MSIs de verdade.

## Documentação

- [Instalação](docs/pt-br/instalacao.md)
- [Operação](docs/pt-br/operacao.md): modos, política, contenção, Desfazer, blocklist.
- [Proteção e limites](docs/pt-br/protecao-e-limites.md)
- [Modelo de segurança](docs/pt-br/seguranca.md)
- [Catálogo assinado](docs/pt-br/catalogo.md)
- [Ensaio de ataque controlado](docs/pt-br/ensaio.md)

## Segurança, contribuição e licença

- Vulnerabilidades: veja [SECURITY.md](SECURITY.md).
- Contribuições: veja [CONTRIBUTING.md](CONTRIBUTING.md).
- Licença [MIT](LICENSE). Mantido por Rodrigo Immaginario, de forma voluntária e sem SLA.
