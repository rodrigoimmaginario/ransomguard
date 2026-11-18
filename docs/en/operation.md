# Operation

## How the agent decides

Every few seconds the agent reads Windows audit events (file access through shares and through the file system),
FSRM events and server signals (shadow copies, services, auditing). It groups activity by **actor**: account +
source IP + share. Each group gets a level:

| Level | Example signals |
|---|---|
| **High** | Canary file touched; ransomware extension from the catalog; **mass overwrite of files that already existed** (created more than 2 minutes earlier); decoy share accessed; ransom note; shadow copy deletion; tampering with the agent or with auditing; shadow copies shrinking **while** the same actor writes, renames or deletes in bulk; two distinct preparation signals on the same server (new service, new administrator, brute force, recovery tool, canary removed). |
| **Medium** | Bulk writing, renaming or deleting without the signals above; extension change without a catalog extension; mass read (2000 files within a minute, from another machine); a single preparation signal. |

The same actor within 10 minutes is the same incident; the dashboard alerts again when the level rises.

## Modes

| Mode | What it does |
|---|---|
| **Monitor** (default) | Records. No alert, no containment. |
| **Alert** | Alerts and takes the preventive shadow copy. No containment. |
| **Block** | Contains **High** incidents. Medium gets the preventive shadow copy and the alert, never containment. |

Policy is set in the dashboard (**Política** page), network-wide or per server, and reaches agents signed by the
dashboard installation key. The agent refuses policy without that signature. It also refuses policy older than the
current one.

## Containment

In Block, for an attack coming from the network, in this order:

1. **Block the source IP** in the server firewall. Stops new connections.
2. **Deny the account on that share.** Works without Active Directory, does not affect other users and is
   reversible.
3. **Drop that client's SMB session.** Comes after the deny: the client reconnects over the connections already
   open, which a firewall rule does not drop, and the deny makes that reconnection fail.
4. **Shadow copy** of the volume, for the restore (within a daily ceiling and the free space).

Optional steps, off by default: **disable the AD account** (needs delegation on the OU) and **isolate the share**
(affects all its users). The policy's step ceiling limits how far the ladder goes.

Each step verifies its effect: the rule exists, the deny shows up, the session is gone. A step that cannot be
confirmed is recorded as a failure, not as success.

The agent **never blocks** its own addresses, the gateway, the name servers or the dashboard. The dashboard never
puts itself or an enrolled agent on the blocklist.

For a process **on the server itself** encrypting files (RDP session, service), containment stops the process
identified by the audit event. Protected system processes are not stopped, only alerted. This path is covered by
tests but was not exercised in the lab.

## Undo

Each containment action has **Undo** (Desfazer) in the incident detail. In the lab, access came back in under 48 s.

## Network blocklist

An IP contained on one server goes on the dashboard blocklist and is blocked on the other servers too, on the next
batch. **Release** (Liberar) on the Política page removes it everywhere. The agent reasserts the blocklist every 10
minutes: a rule removed from outside comes back.

Blocking the IP affects **the whole workstation** on that server, not just the account (for example, every user of
a terminal server).

## Allowlist and learning

- Allowlisted accounts and IPs are contained only if they touch a canary; otherwise they are alerted. Use it for
  service accounts that write a lot: backup, sync, antivirus, replication.
- A sync job that **updates** many existing files becomes High and, in Block, would be contained. Allowlist its
  account.
- **Learning mode**, in Block, takes the preventive shadow copy and alerts, without containing, while you learn
  what is normal in the environment.

## Dashboard down

The agent keeps detecting and containing with the last signed policy. Batches wait in a queue on the server,
bounded in size and age, and reach the dashboard when it is back. After a failed send, the agent waits 15 s to
2 min before trying again, so the network does not hold up detection.

## Notifications

**Notificações** page: ntfy (recommended, can be self-hosted), Microsoft Teams/Slack by webhook, Telegram and
e-mail. There is also a minimum severity, an anti-repeat window and a silent-agent warning.

## Accounts and audit

- An **admin** account changes policy, undoes actions, manages accounts and downloads the backup. **Read-only**
  accounts can only look.
- The **Auditoria** page records who did what in the dashboard.
- Default retention: incidents for 90 days and posture for 30 days.
