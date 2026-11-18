# Ensaio de ataque controlado

`RansomGuard-Ensaio-<versão>.exe` simula, a partir de uma estação, os comportamentos de ransomware que o produto
precisa reconhecer. É assim que você confere, no seu ambiente, a atribuição (conta + IP), a contenção e o
Desfazer, **sem ransomware de verdade**.

## As cinco travas

1. Só age numa pasta de ensaio, criada pela própria ferramenta, com um arquivo marcador.
2. Recusa caminhos perigosos (raiz de disco, pastas do sistema) e extensões executáveis.
3. **Nunca cifra nada.** Os "cifrados" são arquivos de teste com outra extensão.
4. Sem `--confirmar`, só mostra o plano.
5. É reversível: `--ensaio-limpar` apaga a pasta de ensaio.

## Passo a passo

Num servidor de teste, com o agente instalado e a pasta do compartilhamento incluída em `PROTECTEDPATHS`:

```powershell
net use X: \\FS01\teste
RansomGuard-Ensaio-1.0.0.exe --ensaio-preparar X:\ensaio            # cria a pasta de ensaio
RansomGuard-Ensaio-1.0.0.exe --ensaio X:\ensaio                     # mostra o plano; não altera nada
RansomGuard-Ensaio-1.0.0.exe --ensaio X:\ensaio --confirmar         # executa
RansomGuard-Ensaio-1.0.0.exe --ensaio-limpar X:\ensaio              # limpa
```

Confira no painel o incidente com a sua conta e o IP da estação. Em Block, confira também a contenção (a estação
perde o acesso ao compartilhamento) e o **Desfazer**.

## Cenários e opções

`--cenario` escolhe o comportamento:

- `completo` (padrão)
- `reescrita`, `renomeacao`, `canario`, `bilhete`
- `copia-apaga`, `no-lugar`, `apagador`, `leitura`

| Opção | Efeito |
|---|---|
| `--arquivos N --subpastas N` | Tamanho da pasta de ensaio (em `--ensaio-preparar`) |
| `--quantidade N` | Quantos arquivos o ataque alcança (padrão 150) |
| `--extensao .abc` | Extensão dos "cifrados" (padrão `.locked`) |
| `--pular-ocultos` | Ignora arquivos ocultos e de sistema, como um ataque que evita canários |
| `--intervalo-ms N` | Pausa entre arquivos (ataque lento) |
| `--rajada N --pausa-ms M` | Pausa longa a cada N arquivos (ataque em rajadas) |
| `--relatorio arquivo.json` | Grava contagens e instantes da execução, em UTC |

Use só em servidor e compartilhamento de teste. Em Block, a estação de onde o ensaio roda é bloqueada naquele
servidor até o Desfazer.
