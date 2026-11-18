# Catálogo assinado

O catálogo (`list/catalog.json`) reúne extensões de ransomware e padrões de nomes de notas de resgate. É dele que
saem os file screens do FSRM e parte dos sinais de Alta. A inteligência fica no catálogo, não no código do agente:
atualizar a lista não exige versão nova do produto.

## Como chega aos servidores

1. O mantenedor edita o catálogo, sobe o campo `version` e o assina offline (minisign).
2. O painel busca `catalog.json` e `catalog.json.minisig` na pasta `list/` da branch `main` deste repositório.
   Para outra origem, use `Catalog:OriginUrl` na configuração do painel.
3. O painel verifica a assinatura com a chave pública embutida e repassa o catálogo aos agentes, que verificam de
   novo.
4. Catálogo sem assinatura válida, adulterado ou com `version` menor ou igual à vigente é recusado; vale o último
   bom. Sem nenhum catálogo válido, o agente usa uma semente conservadora embutida.

## Verificar você mesmo

```powershell
minisign -Vm list/catalog.json -p list/catalog.pub
```

`list/catalog.pub` é a mesma chave embutida no painel e no agente (`Catalog:PublicKeyBase64`).

## Propor mudanças

Abra uma issue ou pull request com as entradas e uma fonte pública. A assinatura é feita pelo mantenedor, com a
chave privada offline (`tools/ceremony.ps1`); nenhuma automação assina o catálogo.
