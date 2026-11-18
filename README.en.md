# RansomGuard

Ransomware detection and containment for Windows file servers. Free and open source (MIT).

**Site:** https://www.ransomguard.com.br/ · **Download:** [v1.0.0](https://github.com/rodrigoimmaginario/ransomguard/releases/tag/v1.0.0) · **Português:** [README.md](README.md)

## What it does

RansomGuard watches what reaches the shares of a Windows file server over the network. When a user, from a
workstation, starts encrypting, overwriting, renaming or deleting files in bulk, the agent attributes the activity
to **who** (account) and **from where** (IP). Depending on the policy you set, it contains the attack: it blocks the
source IP on the server, denies that account on the share and drops the SMB session. Last, it takes a shadow copy
for the restore. Every action has **Undo** in the dashboard.

Three pieces, all inside your network:

- **Agent** — a Windows service on each file server. It reads Windows audit events, keeps canary files in the
  folders you choose, applies FSRM file screens and runs containment locally, even with the dashboard down.
- **Dashboard** — a Windows service on a central machine. It receives the agents' signed batches, shows incidents,
  posture and risk score, distributes the signed policy and alerts (ntfy, Teams/Slack, Telegram, e-mail). Its
  interface is in Portuguese.
- **Catalog** — known extensions and ransom notes, signed offline (minisign). The dashboard fetches it from this
  repository, verifies the signature and relays it to the agents.

Only metadata leaves the monitored server (account, IP, share, path, operation), never file content. The agent talks
only to your dashboard; the dashboard reaches the internet only to fetch the catalog and to send the notifications
you configure.

## Protection and limits

The product was validated in a lab, on a real network with Active Directory and Windows Server 2022 and 2025. The
numbers below are lab observations, not a guarantee. Read [Protection and limits](docs/en/protection-and-limits.md)
before using it in production.

- Attacks that take time per file are contained midway. Examples:
  - overwriting from a workstation: 64 to 227 of 300 files hit;
  - slow attack: contained in about a minute;
  - attack in bursts: contained in 23 s.
- **A fast attack on small files can finish before containment.** Renaming or deleting hundreds of few-byte files
  takes 2–3 s.
- Mass reads and large copies are recorded and alerted (Medium), but **Medium never contains**.
- The default mode is **Monitor**: it only records. Containment requires switching the policy to Block on purpose.

## Requirements

- Agent: Windows Server with the file server role (tested on 2022 and 2025), administrator rights. FSRM is optional
  and adds file screens.
- Dashboard: Windows Server or Windows 10/11, x64.
- Neither needs .NET installed: the executables are self-contained.

## Install

1. Install `RansomGuard-Painel-<version>.msi`, open `https://<dashboard>:5001` and create the administrator account
   with the first-run token.
2. On the **Agentes** page, generate an enrollment token: the dashboard shows the agent install command, ready.
3. Run the command on each file server, naming the folders to protect.
4. Start in **Monitor**. Switch to Block only after seeing the behavior in your environment and filling the
   service-account allowlist.

Step by step: [installation](docs/en/installation.md) · [operation](docs/en/operation.md).

## Verify the download

The installers are **not code-signed**: Windows warns during installation. Each release publishes the SHA-256 of
every file and a build provenance attestation that ties the file to the workflow and commit that produced it:

```powershell
Get-FileHash .\RansomGuard-Agente-1.0.0.msi -Algorithm SHA256
gh attestation verify .\RansomGuard-Agente-1.0.0.msi --repo rodrigoimmaginario/ransomguard
```

## Build and test

```powershell
dotnet test RansomGuard.sln                                   # core, agent and dashboard tests
dotnet build agent/RansomGuard.Agent.Service                  # agent service (net10.0-windows, outside the .sln)
pwsh tools/run-simulators.ps1                                 # simulators (regression gates)
pwsh tools/build-release.ps1 -Version 1.0.0 -OutDir out/release   # MSIs, drill tool and SHA-256 (needs WiX 5)
```

CI also runs the agent service tests on a real Windows Server (security log, SMB share, FSRM) and installs both
MSIs for real.

## Documentation

- [Installation](docs/en/installation.md)
- [Operation](docs/en/operation.md): modes, policy, containment, Undo, blocklist.
- [Protection and limits](docs/en/protection-and-limits.md)
- [Security model](docs/en/security.md)
- [Signed catalog](docs/en/catalog.md)
- [Controlled attack drill](docs/en/drill.md)

## Security, contributing and license

- Vulnerabilities: see [SECURITY.md](SECURITY.md).
- Contributions: see [CONTRIBUTING.md](CONTRIBUTING.md).
- [MIT](LICENSE) license. Maintained by Rodrigo Immaginario, on a voluntary basis, with no SLA.
