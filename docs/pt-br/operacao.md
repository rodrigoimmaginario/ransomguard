# Operação

## Como o agente decide

O agente lê, a cada poucos segundos, os eventos de auditoria do Windows (acesso a arquivos por compartilhamento e
pelo sistema de arquivos), os eventos do FSRM e sinais do servidor (cópias de sombra, serviços, auditoria). Ele
agrupa a atividade por **ator**: conta + IP de origem + compartilhamento. Cada grupo recebe um nível:

| Nível | Exemplos de sinal |
|---|---|
| **Alta** | Arquivo-canário tocado; extensão de ransomware do catálogo; **regravação em massa de arquivos que já existiam** (criados mais de 2 minutos antes); compartilhamento-isca acessado; nota de resgate; remoção de cópias de sombra; adulteração do agente ou da auditoria; cópias de sombra diminuindo **enquanto** o mesmo ator grava, renomeia ou apaga em massa; dois sinais distintos de preparação no mesmo servidor (serviço novo, administrador novo, força bruta, ferramenta de recuperação, canário removido). |
| **Média** | Gravação, renomeação ou exclusão em volume sem os sinais acima; troca de extensão sem extensão do catálogo; leitura em massa (2000 arquivos em um minuto, a partir de outra máquina); um sinal de preparação isolado. |

O mesmo ator em até 10 minutos é o mesmo incidente; o painel alerta de novo quando o nível sobe.

## Modos

| Modo | O que faz |
|---|---|
| **Monitor** (padrão) | Registra. Não alerta nem contém. |
| **Alert** | Alerta e cria a cópia de sombra preventiva. Não contém. |
| **Block** | Contém incidentes de **Alta**. Média recebe a cópia de sombra preventiva e o alerta, nunca a contenção. |

A política é definida no painel (tela **Política**), para a rede toda ou por servidor, e chega aos agentes
assinada pela chave da instalação do painel. O agente recusa política sem essa assinatura. Ele também recusa
política mais antiga que a vigente.

## Contenção

Em Block, para um ataque vindo da rede, nesta ordem:

1. **Bloquear o IP de origem** no firewall do servidor. Barra conexões novas.
2. **Negar a conta naquele compartilhamento.** Funciona sem Active Directory, não afeta outros usuários e é
   reversível.
3. **Derrubar a sessão SMB** daquele cliente. Vem depois da negação: o cliente reconecta pelas conexões já
   abertas, que a regra de firewall não derruba, e a negação faz essa reconexão falhar.
4. **Cópia de sombra** do volume, para a restauração (respeita um teto diário e o espaço livre).

Degraus opcionais, desligados por padrão: **desabilitar a conta no AD** (exige delegação na OU) e **isolar o
compartilhamento** (afeta todos os usuários dele). O teto de degrau da política limita até onde a escada vai.

Cada passo confere o efeito: a regra existe, a negação aparece, a sessão sumiu. Passo que não se confirma é
registrado como falha, não como sucesso.

O agente **nunca bloqueia** os próprios endereços, o gateway, os servidores de nomes nem o painel. O painel nunca
põe na blocklist a si mesmo nem um agente enrolado.

Para um processo **do próprio servidor** que cifra arquivos (sessão RDP, serviço), a contenção é encerrar o
processo identificado pelo evento de auditoria. Processos protegidos do sistema não são encerrados, só alertados.
Esse caminho é coberto por testes, mas não foi exercitado no laboratório.

## Desfazer

Cada ação de contenção tem **Desfazer** no detalhe do incidente. No laboratório, o acesso voltou em menos de 48 s.

## Blocklist de rede

Um IP contido num servidor entra na blocklist do painel e é bloqueado também nos outros servidores, no lote
seguinte. **Liberar** na tela Política o tira de todos. O agente reafirma a blocklist a cada 10 minutos: uma regra
removida por fora volta.

Bloquear o IP afeta **a estação inteira** naquele servidor, não só a conta (por exemplo, todos os usuários de um
servidor de terminal).

## Allowlist e aprendizado

- Contas e IPs na allowlist só são contidos se tocarem um canário; fora isso, são alertados. Use para contas de
  serviço que gravam muito: backup, sincronização, antivírus, replicação.
- Um sincronizador que **atualiza** muitos arquivos existentes vira Alta e, em Block, seria contido. Ponha a conta
  dele na allowlist.
- O **modo de aprendizado**, em Block, cria a cópia de sombra preventiva e alerta, sem conter, enquanto você
  conhece o normal do ambiente.

## Painel fora do ar

O agente segue detectando e contendo com a última política assinada. Os lotes ficam numa fila no servidor, que
tem teto de tamanho e de idade, e chegam ao painel quando ele volta. Depois de uma falha de envio, o agente
espera de 15 s a 2 min antes de tentar de novo, para não prender a detecção.

## Notificações

Tela **Notificações**: ntfy (recomendado, pode ser auto-hospedado), Microsoft Teams/Slack por webhook, Telegram e
e-mail. Há também severidade mínima, janela anti-repetição e aviso de agente silencioso.

## Contas e auditoria

- Uma conta **admin** altera política, desfaz ações, gere contas e baixa o backup. Contas de **leitura** só
  consultam.
- A tela **Auditoria** registra quem fez o quê no painel.
- Retenção padrão: incidentes por 90 dias e postura por 30 dias.
