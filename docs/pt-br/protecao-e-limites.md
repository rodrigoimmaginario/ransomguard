# Proteção e limites

O que o RansomGuard contém, em quanto tempo, e o que ele não cobre. Os números vêm de uma campanha de laboratório
em rede real (novembro de 2026). O ambiente:

- domínio Active Directory próprio, com controlador, painel e uma estação de ataque;
- dois servidores de arquivos, um Windows Server 2022 e um Windows Server 2025 (em inglês);
- a estação atacando os compartilhamentos pela rede, com a ferramenta de [ensaio controlado](ensaio.md);
- arquivos de teste pequenos (poucos bytes).

**Leia como observação, não como garantia.** Na maioria dos casos houve uma execução: o número é o que
aconteceu, não uma mediana. O seu ambiente (tamanho dos arquivos, latência, carga, antivírus) muda o resultado.

## Ataques pela rede, em modo Block

| Ataque | Resultado | Arquivos atingidos |
|---|---|---|
| Regrava arquivos e troca para extensão do catálogo | Contido; IP bloqueado 0,23 / 0,32 / 3,3 s após o início (3 execuções) | 64 / 96 / 227 de 300 |
| Grava o cifrado ao lado e apaga o original | Contido | 104 |
| Ataque lento (1 arquivo a cada 1,5 s), evitando os canários | Contido em 61 s | 42 de 80 |
| Ataque em rajadas (30 a cada 20 s), evitando os canários | Contido em 23 s | 60 de 180 |
| Nota de resgate em 6 pastas | Contido | 6 |
| Ataque a outro compartilhamento do mesmo servidor | Contido, no compartilhamento certo | 66 |
| Compartilhamento-isca | Contido | 5 |
| Renomeia 150 arquivos para extensão desconhecida | Contido, **depois** do fim | 150 de 150 |
| Regrava 150 arquivos no lugar | Contido, **depois** do fim | 150 de 150 |
| Regrava 300 arquivos em 2 s, evitando os canários (Server 2022 e 2025) | Contido, **depois** do fim | 300 de 300 |
| Só apaga 300 arquivos (3 s) | Contido, **depois** do fim | 300 de 300 |
| Lê 2600 arquivos (exfiltração) | Detectado como Média; não contido, por desenho | — |

Depois da contenção, o atacante não volta: a sessão SMB dele não se restabeleceu em nenhuma amostra, e ele parou
de gravar no momento da contenção (3 de 3 execuções).

## Uso legítimo, em modo Block

Nenhum destes foi contido:

- cópia de 2000 arquivos novos (registrada como Média);
- compactar e descompactar 2000 arquivos;
- renomear 2000 arquivos;
- uma usuária trabalhando no mesmo compartilhamento durante o ataque: nenhuma gravação dela falhou.

## Operação

| Situação | Resultado |
|---|---|
| Painel fora do ar durante o ataque | O agente conteve sozinho em 4 s (9 de 300 arquivos); o incidente chegou ao painel depois |
| Agente reiniciado no meio de um ataque lento | Contido 57 s depois do reinício |
| Blocklist entre servidores | O segundo servidor bloqueou a estação que só atacou o primeiro; liberar no painel desbloqueou em menos de 1 min |
| Invasor desliga a auditoria | Alta em cerca de 3 s; o agente religou a auditoria em cerca de 50 s |
| "Desfazer" pelo painel | Acesso de volta em menos de 48 s |
| Atualizar os instaladores | Identidade, enrolamento e política preservados (6 atualizações) |
| Desinstalar | Nada sobrou: canários, file screens, regras e serviço retirados |
| Usuário comum no servidor e no painel | Não lê chave, segredos, fila nem banco; não injeta lote |

## O que o RansomGuard não cobre

1. **Ataque rápido em arquivo pequeno termina antes da contenção.** Renomear, regravar ou apagar centenas de
   arquivos de poucos bytes leva 2–3 s; a contenção chega depois. O produto **reduz** o estrago de ataques que
   levam mais tempo por arquivo; não impede este. Com documentos reais, cada arquivo leva mais tempo, o que
   favorece a contenção, mas isso não foi medido.
2. **Ataque lento é visto em cerca de 1 minuto.**
3. **A regravação só conta para arquivos com mais de 2 minutos.** Um arquivo renomeado ou apagado antes da
   conferência não é marcado.
4. **Sincronizador que atualiza muitos arquivos existentes é tratado como ataque** (Alta). Ponha a conta dele na
   allowlist.
5. **Média nunca contém.** Leitura em massa (exfiltração) e cópias grandes são registradas e alertadas, sem
   contenção.
6. **Reiniciar o agente zera a contagem em memória**; o ataque é visto de novo, do zero.
7. **Com o painel inacessível**, a detecção pode atrasar até 10 s, no máximo uma vez a cada 2 minutos.
8. **Bloquear o IP bloqueia a estação inteira** naquele servidor, não só a conta.
9. **As conexões já abertas duram cerca de 75–80 s depois da contenção**, mas sem acesso: a negação no
   compartilhamento barra a reconexão.
10. **Não foram exercitados em rede real:**
    - ataque de dentro do próprio servidor (coberto por testes);
    - remoção de cópias de sombra (coberto por testes);
    - Windows em português;
    - convivência com backup que cria o próprio snapshot, espelhamento com purga e antivírus;
    - duas origens ao mesmo tempo;
    - conta da allowlist comprometida;
    - restauração do backup do painel em outra máquina.

Também não é antivírus nem EDR: não impede a execução do ransomware na estação, não protege a própria estação nem
servidores sem agente, e não substitui backup offline.

## Achados ainda abertos

- Um incidente separado de "canário removido" aparece em cada ataque, além do incidente principal.
- O pior caso de bloqueio (3,3 s) não tem causa conhecida.
- O primeiro file screen com o catálogo semente e o nome novo da renomeação vista de um cliente remoto ainda
  precisam de confirmação.
