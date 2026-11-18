# Installation

Order: dashboard first, then one agent per file server. Both installers are x64 MSIs and need no .NET installed.
They are **not code-signed**: check the SHA-256 and the attestation before installing (see the
[README](../../README.en.md#verify-the-download)).

## 1. Dashboard

A central machine in your network: Windows Server or Windows 10/11, x64.

```powershell
msiexec /i RansomGuard-Painel-1.0.0.msi
```

- Installs the **RansomGuard Panel** service, running as the virtual account `NT SERVICE\RansomGuardPanel`.
- Data lives in `C:\ProgramData\RansomGuard\Painel`, a folder only the service and administrators can open.
  Secrets are protected with machine DPAPI. Uninstalling **keeps** this folder.
- Opens port **5001/TCP** (HTTPS) in the firewall, on domain and private profiles. To skip it:
  `msiexec /i ... OPENFIREWALL=0`. Port 5000 (HTTP) answers only on the machine itself.

Open `https://<dashboard>:5001`. The certificate is self-signed, generated at install; the browser warns the first
time. The initial setup page asks for the **first-run token**, in
`C:\ProgramData\RansomGuard\Painel\token-de-setup.txt`. Only administrators can open the folder, and the file is
deleted once the administrator account exists. The dashboard interface is in Portuguese.

## 2. Agent

On each file server: Windows Server with the file server role, as administrator.

In the dashboard, **Agentes → Novo token de enrolamento** (new enrollment token). The dashboard shows the command,
ready:

```powershell
msiexec /i RansomGuard-Agente-1.0.0.msi BACKENDURL=https://dashboard.corp.local:5001 SERVERNAME=FS01 `
  PROTECTEDPATHS="D:\Shares\Finance;D:\Shares\Projects" ENROLLTOKEN=<token> PANELCERT=<certificate sha256>
```

| Property | What it is |
|---|---|
| `BACKENDURL` | Dashboard address (HTTPS, port 5001). |
| `ENROLLTOKEN` | Enrollment token, valid up to 7 days with a limited number of uses (up to 500). Used once: the agent presents its own key to the dashboard and deletes the token from the registry. |
| `PANELCERT` | SHA-256 of the dashboard certificate: the agent accepts only that certificate. |
| `PANELKEY` | (optional) Dashboard public key. Without it, the agent pins the key on first contact. |
| `SERVERNAME` | Server name in the dashboard. Empty = machine name. |
| `PROTECTEDPATHS` | Folders where the agent plants canary files (`;`-separated). Empty = no canaries: the product never picks where to plant on its own. |
| `DECOYSHARES` | (optional) Decoy shares, UNC, `;`-separated. Any access is a high-confidence incident. |
| `CANARYNAMES` | (optional) Canary names you choose (at least three). Empty = names generated per install. |
| `MODE` | Initial mode, `Monitor` by default. The policy published by the dashboard prevails. |
| `FSRMBLOCKING` | `true` makes the FSRM file screen block the write (default: record only). |
| `SERVICEACCOUNT` | `LocalSystem` by default. Accepts a gMSA (`DOMAIN\account$`). |

The agent runs as the **RansomGuard Agent** service and keeps its data in `C:\ProgramData\RansomGuard`, a folder
for SYSTEM and administrators only. On start, it:

- turns on the share and file system auditing it needs, and turns it back on if someone turns it off;
- plants the canaries in the protected folders, with an audit rule;
- applies FSRM file screens, if FSRM is installed.

Within minutes the server shows up in the dashboard with its risk score.

### Mass deployment

The MSI takes the same properties through GPO or a deployment tool. One token serves several servers within its
use limit and lifetime. Each server generates its own key; a name accepts a single key (revoke it on the Agentes
page to re-enroll).

## 3. First steps

1. Stay in **Monitor** for a few days. On the **Incidentes** page, see what legitimate activity your environment
   generates (backup, sync, antivirus).
2. On the **Política** (policy) page, fill the allowlist with service accounts that update many files.
3. Set up a channel under **Notificações** (notifications).
4. Switch a test server to **Block**, run the [controlled drill](drill.md) and check containment and **Undo**
   (Desfazer). Then extend to the others.

## Upgrade and uninstall

- Upgrade: run the new version's MSI. Identity, enrollment, policy and canaries are kept.
- Uninstalling the agent removes the canaries (only files proven to be its own, by content), the file screens and
  the block rules.
- Uninstalling the dashboard keeps its data.

## Dashboard backup

**Contas → Baixar backup** (accounts → download backup): a zip with the database, installation key and secrets in
portable form. It is as sensitive as the key: store it accordingly. Restoring on another machine was not exercised
in the lab.
