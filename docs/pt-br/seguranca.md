# Modelo de segurança

## O que roda e com que direito

| Peça | Conta | Dados |
|---|---|---|
| Agente | `LocalSystem` (ou gMSA) | `C:\ProgramData\RansomGuard`, pasta só para SYSTEM e administradores |
| Painel | conta virtual `NT SERVICE\RansomGuardPanel` | `C:\ProgramData\RansomGuard\Painel`, pasta só para o serviço e administradores; segredos protegidos pela DPAPI da máquina |

O agente precisa de direito de administrador. Com ele, lê o log de segurança, liga a auditoria, planta canários,
aplica file screens e executa a contenção (firewall, permissões do compartilhamento, sessões SMB, cópias de
sombra). Quem controla o painel controla o que os agentes fazem: proteja-o como sistema administrativo.

## Confiança entre as peças

- **Agente → painel.** Cada agente gera a própria chave Ed25519, que nunca sai do servidor, e assina cada lote
  (nome + instante + corpo). O painel aceita o lote se:
  - a assinatura confere com a chave enrolada para aquele nome;
  - o relógio está dentro de 5 minutos;
  - o lote não é uma reapresentação.
  Um nome só aceita uma chave. O enrolamento usa um token de prazo e usos limitados, apagado do registro depois de
  usado.
- **Painel → agente.** A política e os comandos (como o Desfazer) vão assinados pela chave da instalação do painel.
  O agente fixa essa chave no primeiro contato (ou recebe `PANELKEY` na instalação) e a usa daí em diante. Ele
  recusa política sem assinatura, de outro painel ou mais antiga que a vigente. O certificado TLS do painel também
  é fixado (`PANELCERT` ou primeiro contato).
- **Catálogo.** Assinado offline pelo mantenedor (minisign), verificado pelo painel e pelo agente contra a chave
  embutida. A versão nunca regride: catálogo adulterado, sem assinatura ou mais antigo é recusado, e o agente
  mantém o último bom.

## Painel

- HTTPS na porta 5001. A porta 5000 (HTTP) só atende na própria máquina.
- Contas de administrador e de leitura. Senhas com PBKDF2 (600 mil iterações), limite de tentativas de login e
  páginas que negam acesso por padrão.
- Trilha de auditoria de quem fez o quê.
- O backup (tela Contas) sai com a chave e os segredos em forma portátil: guarde como a própria chave.

## Guardas contra a própria contenção

- O agente nunca bloqueia os próprios endereços, o gateway, os servidores de nomes nem o painel.
- O painel nunca põe na blocklist a si mesmo nem um agente enrolado, e a blocklist tem teto de 200 entradas.
- Média nunca contém. O padrão de tudo é Monitor.
- Cópias de sombra preventivas têm teto diário por compartilhamento e por servidor, e respeitam o espaço livre.
- Canário só é removido se o conteúdo provar que é do agente: arquivo de cliente com o mesmo nome nunca é tocado.

## Dados e rede

- Só metadado sai do servidor monitorado (conta, IP, compartilhamento, caminho, operação), nunca conteúdo.
- O agente fala apenas com o painel.
- O painel acessa a internet para buscar o catálogo (`raw.githubusercontent.com`, este repositório) e para enviar
  as notificações que você configurar. Não há telemetria: o convite "registre seu uso" é só um link.

## O que fica fora deste modelo

- Um invasor com administrador no servidor monitorado pode parar o agente. O painel avisa sobre agente
  silencioso, mas não impede.
- Um invasor com administrador no painel controla a política.
- Os instaladores não têm assinatura de código. Confira o SHA-256 e o atestado de proveniência de cada release.
