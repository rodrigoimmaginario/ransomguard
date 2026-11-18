# Controlled attack drill

`RansomGuard-Ensaio-<version>.exe` simulates, from a workstation, the ransomware behaviors the product has to
recognize. It is how you check, in your own environment, attribution (account + IP), containment and Undo,
**without real ransomware**. Its messages are in Portuguese.

## The five safeguards

1. It acts only on a drill folder, created by the tool itself, with a marker file.
2. It refuses dangerous paths (drive roots, system folders) and executable extensions.
3. **It never encrypts anything.** The "encrypted" files are test files with another extension.
4. Without `--confirmar`, it only shows the plan.
5. It is reversible: `--ensaio-limpar` deletes the drill folder.

## Step by step

On a test server, with the agent installed and the share folder included in `PROTECTEDPATHS`:

```powershell
net use X: \\FS01\test
RansomGuard-Ensaio-1.0.0.exe --ensaio-preparar X:\drill            # creates the drill folder
RansomGuard-Ensaio-1.0.0.exe --ensaio X:\drill                     # shows the plan; changes nothing
RansomGuard-Ensaio-1.0.0.exe --ensaio X:\drill --confirmar         # runs it
RansomGuard-Ensaio-1.0.0.exe --ensaio-limpar X:\drill              # cleans up
```

Check the incident in the dashboard, with your account and the workstation IP. In Block, also check containment
(the workstation loses access to the share) and **Undo**.

## Scenarios and options

`--cenario` picks the behavior:

- `completo` (full, default)
- `reescrita` (rewrite), `renomeacao` (rename), `canario` (canary), `bilhete` (ransom note)
- `copia-apaga` (copy then delete), `no-lugar` (in place), `apagador` (wiper), `leitura` (mass read)

| Option | Effect |
|---|---|
| `--arquivos N --subpastas N` | Size of the drill folder (with `--ensaio-preparar`) |
| `--quantidade N` | How many files the attack reaches (default 150) |
| `--extensao .abc` | Extension of the "encrypted" files (default `.locked`) |
| `--pular-ocultos` | Skips hidden and system files, like an attack that avoids canaries |
| `--intervalo-ms N` | Pause between files (slow attack) |
| `--rajada N --pausa-ms M` | Long pause every N files (burst attack) |
| `--relatorio file.json` | Writes the run's counts and timestamps, in UTC |

Use it only on a test server and share. In Block, the workstation running the drill is blocked on that server until
Undo.
