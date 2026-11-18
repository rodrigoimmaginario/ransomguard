# Protection and limits

What RansomGuard contains, how fast, and what it does not cover. The numbers come from a lab campaign on a real
network (November 2026). The environment:

- its own Active Directory domain, with a domain controller, the dashboard and an attack workstation;
- two file servers, Windows Server 2022 and Windows Server 2025 (English);
- the workstation attacking the shares over the network, with the [controlled drill](drill.md) tool;
- small test files (a few bytes).

**Read these as observations, not as a guarantee.** Most cases ran once: the number is what happened, not a
median. Your environment (file size, latency, load, antivirus) changes the result.

## Network attacks, Block mode

| Attack | Result | Files hit |
|---|---|---|
| Overwrites files and switches to a catalog extension | Contained; IP blocked 0.23 / 0.32 / 3.3 s after start (3 runs) | 64 / 96 / 227 of 300 |
| Writes the encrypted copy alongside and deletes the original | Contained | 104 |
| Slow attack (1 file every 1.5 s), avoiding canaries | Contained in 61 s | 42 of 80 |
| Attack in bursts (30 every 20 s), avoiding canaries | Contained in 23 s | 60 of 180 |
| Ransom note in 6 folders | Contained | 6 |
| Attack on another share of the same server | Contained, on the right share | 66 |
| Decoy share | Contained | 5 |
| Renames 150 files to an unknown extension | Contained, **after** it finished | 150 of 150 |
| Overwrites 150 files in place | Contained, **after** it finished | 150 of 150 |
| Overwrites 300 files in 2 s, avoiding canaries (Server 2022 and 2025) | Contained, **after** it finished | 300 of 300 |
| Only deletes 300 files (3 s) | Contained, **after** it finished | 300 of 300 |
| Reads 2600 files (exfiltration) | Detected as Medium; not contained, by design | — |

After containment the attacker does not get back in: its SMB session did not come back in any sample, and it
stopped writing at the moment of containment (3 of 3 runs).

## Legitimate use, Block mode

None of these was contained:

- copying 2000 new files (recorded as Medium);
- zipping and unzipping 2000 files;
- renaming 2000 files;
- a user working on the same share during the attack: none of her writes failed.

## Operation

| Situation | Result |
|---|---|
| Dashboard down during the attack | The agent contained on its own in 4 s (9 of 300 files); the incident reached the dashboard later |
| Agent restarted in the middle of a slow attack | Contained 57 s after the restart |
| Blocklist across servers | The second server blocked the workstation that only attacked the first; releasing in the dashboard unblocked it in under 1 min |
| Intruder turns auditing off | High in about 3 s; the agent turned auditing back on in about 50 s |
| Undo from the dashboard | Access back in under 48 s |
| Upgrading the installers | Identity, enrollment and policy kept (6 upgrades) |
| Uninstall | Nothing left behind: canaries, file screens, rules and service removed |
| Standard user on the server and the dashboard | Cannot read the key, secrets, queue or database; cannot inject a batch |

## What RansomGuard does not cover

1. **A fast attack on small files finishes before containment.** Renaming, overwriting or deleting hundreds of
   few-byte files takes 2–3 s; containment arrives later. The product **reduces** the damage of attacks that take
   longer per file; it does not prevent this one. With real documents each file takes longer, which favors
   containment, but that was not measured.
2. **A slow attack is seen in about a minute.**
3. **Overwrite counts only for files older than 2 minutes.** A file renamed or deleted before the check is not
   marked.
4. **A sync job that updates many existing files is treated as an attack** (High). Allowlist its account.
5. **Medium never contains.** Mass reads (exfiltration) and large copies are recorded and alerted, without
   containment.
6. **Restarting the agent resets its in-memory counts**; the attack is seen again from zero.
7. **With the dashboard unreachable**, detection can be up to 10 s late, at most once every 2 minutes.
8. **Blocking the IP blocks the whole workstation** on that server, not just the account.
9. **Connections already open last about 75–80 s after containment**, but without access: the share deny stops the
   reconnection.
10. **Not exercised on a real network:**
    - attacks from inside the server itself (covered by tests);
    - shadow copy deletion (covered by tests);
    - Windows in Portuguese;
    - coexistence with backup that takes its own snapshot, mirroring with purge, and antivirus;
    - two sources at once;
    - a compromised allowlisted account;
    - restoring the dashboard backup on another machine.

It is not an antivirus or an EDR either: it does not stop ransomware from running on the workstation, does not
protect the workstation itself or servers without an agent, and does not replace offline backup.

## Open findings

- A separate "canary removed" incident shows up with each attack, besides the main incident.
- The worst blocking case (3.3 s) has no known cause.
- The first file screen with the seed catalog, and the new name of a rename seen from a remote client, still need
  confirmation.
