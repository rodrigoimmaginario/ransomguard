# Signed catalog

The catalog (`list/catalog.json`) holds ransomware extensions and ransom note name patterns. It drives the FSRM file
screens and part of the High signals. The intelligence lives in the catalog, not in the agent code: updating the
list needs no new product version.

## How it reaches the servers

1. The maintainer edits the catalog, bumps the `version` field and signs it offline (minisign).
2. The dashboard fetches `catalog.json` and `catalog.json.minisig` from the `list/` folder of this repository's
   `main` branch. For another origin, set `Catalog:OriginUrl` in the dashboard configuration.
3. The dashboard verifies the signature with the embedded public key and relays the catalog to the agents, which
   verify it again.
4. A catalog without a valid signature, tampered with, or with a `version` lower than or equal to the current one is
   refused; the last good one stays. With no valid catalog at all, the agent uses a conservative built-in seed.

## Verify it yourself

```powershell
minisign -Vm list/catalog.json -p list/catalog.pub
```

`list/catalog.pub` is the same key embedded in the dashboard and the agent (`Catalog:PublicKeyBase64`).

## Proposing changes

Open an issue or pull request with the entries and a public source. Signing is done by the maintainer with the
offline private key (`tools/ceremony.ps1`); no automation signs the catalog.
