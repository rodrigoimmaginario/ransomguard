# Security model

## What runs, and with which rights

| Piece | Account | Data |
|---|---|---|
| Agent | `LocalSystem` (or gMSA) | `C:\ProgramData\RansomGuard`, folder for SYSTEM and administrators only |
| Dashboard | virtual account `NT SERVICE\RansomGuardPanel` | `C:\ProgramData\RansomGuard\Painel`, folder for the service and administrators only; secrets protected with machine DPAPI |

The agent needs administrator rights. With them it reads the security log, turns on auditing, plants canaries,
applies file screens and runs containment (firewall, share permissions, SMB sessions, shadow copies). Whoever
controls the dashboard controls what agents do: protect it as an administrative system.

## Trust between the pieces

- **Agent → dashboard.** Each agent generates its own Ed25519 key, which never leaves the server, and signs every
  batch (name + time + body). The dashboard accepts the batch if:
  - the signature matches the key enrolled for that name;
  - the clock is within 5 minutes;
  - the batch is not a replay.
  A name accepts a single key. Enrollment uses a token with limited lifetime and uses, deleted from the registry
  once used.
- **Dashboard → agent.** Policy and commands (such as Undo) are signed with the dashboard installation key. The
  agent pins that key on first contact (or receives `PANELKEY` at install) and uses it from then on. It refuses
  policy that is unsigned, from another dashboard, or older than the current one. The dashboard TLS certificate is
  pinned as well (`PANELCERT` or first contact).
- **Catalog.** Signed offline by the maintainer (minisign), verified by the dashboard and by the agent against the
  embedded key. The version never goes back: a tampered, unsigned or older catalog is refused, and the agent keeps
  the last good one.

## Dashboard

- HTTPS on port 5001. Port 5000 (HTTP) answers only on the machine itself.
- Administrator and read-only accounts. Passwords with PBKDF2 (600,000 iterations), login attempt limits and pages
  that deny access by default.
- Audit trail of who did what.
- The backup (Contas page) carries the key and secrets in portable form: store it like the key itself.

## Guards against its own containment

- The agent never blocks its own addresses, the gateway, the name servers or the dashboard.
- The dashboard never puts itself or an enrolled agent on the blocklist, and the blocklist is capped at 200 entries.
- Medium never contains. The default for everything is Monitor.
- Preventive shadow copies have a daily ceiling per share and per server, and respect free space.
- A canary is removed only if its content proves it belongs to the agent: a customer file with the same name is
  never touched.

## Data and network

- Only metadata leaves the monitored server (account, IP, share, path, operation), never content.
- The agent talks only to the dashboard.
- The dashboard reaches the internet to fetch the catalog (`raw.githubusercontent.com`, this repository) and to send
  the notifications you configure. There is no telemetry: the "register your use" invitation is just a link.

## Outside this model

- An intruder with administrator rights on the monitored server can stop the agent. The dashboard warns about a
  silent agent, but cannot prevent it.
- An intruder with administrator rights on the dashboard controls the policy.
- The installers are not code-signed. Check the SHA-256 and the provenance attestation of each release.
