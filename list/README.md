# Catálogo de ransomware (assinado) / Ransomware catalog (signed)

A inteligência de detecção do RansomGuard mora aqui, não no código do agente. O agente só confia num catálogo
**assinado** pela chave do projeto e cuja versão **não regride**.

RansomGuard's detection intelligence lives here, not in the agent code. The agent trusts only a catalog **signed**
by the project key whose version **never goes back**.

## Arquivos / Files

- `catalog.json` — extensões, padrões de notas de resgate e parâmetros. O campo `version` sobe a cada mudança.
- `catalog.json.minisig` — assinatura minisign (Ed25519), feita offline pelo mantenedor.
- `catalog.pub` — chave pública (a mesma embutida no painel e no agente).
- `catalog.seed.json` — semente de desenvolvimento (não assinada), usada pelos testes e simuladores.

## Regras / Rules

1. Editar o catálogo quebra a assinatura. Reassinar é feito só pelo mantenedor, com a chave privada offline
   (`tools/ceremony.ps1`); nenhuma automação assina.
2. A `version` sobe a cada mudança: o produto recusa versão menor ou igual à última aceita.
3. A chave privada nunca entra no repositório.
4. Catálogo adulterado ou sem assinatura é recusado; vale o último bom.

## Verificar / Verify

```powershell
minisign -Vm list/catalog.json -p list/catalog.pub
```

Mais / more: [docs/pt-br/catalogo.md](../docs/pt-br/catalogo.md) · [docs/en/catalog.md](../docs/en/catalog.md).
