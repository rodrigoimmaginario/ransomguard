# Contributing / Contribuição

Maintainer / mantenedor: **Rodrigo Immaginario** ([@rodrigoimmaginario](https://github.com/rodrigoimmaginario)).

## Authorship / Autoria

- Every commit, tag, release, issue and document presents the GitHub user of its human author. Default authorship
  in this repository is `rodrigoimmaginario`.
- No attribution to code or text generation tools: no `Co-authored-by` trailers for automated tools, no mentions in
  commit messages, file headers, documentation or release notes. Tools are means of work; responsibility and credit
  belong to the author.
- Set your git identity before contributing:
  ```bash
  git config user.name "Rodrigo Immaginario"
  git config user.email "rodrigoimmaginario@users.noreply.github.com"
  ```
  Pull requests whose commits lack identifiable human authorship are rewritten or declined.

- Todo commit, tag, release, issue e documento apresenta o usuário GitHub do autor humano. Nenhuma atribuição a
  ferramentas de geração de código ou texto. Pull requests sem autoria humana identificável são reescritos ou
  recusados.

## Languages / Idiomas

- Documentation and site are **bilingual**: Brazilian Portuguese (default) and English. Every user-facing document
  ships in both languages in the same change (`docs/pt-br`, `docs/en`, `README.md` + `README.en.md`). The dashboard
  interface is in Portuguese.
- Documentação e site são **bilíngues**: português do Brasil (padrão) e inglês, nos dois idiomas na mesma mudança.
  A interface do painel é em português.

## Development routine / Rotina de desenvolvimento

1. **TDD**: write the failing test first, then the code, then refactor. A behavior that matters in production also
   gets a simulator (`spike/`) or, when it depends on Windows itself, a test that runs on the real Windows runner
   (`agent/RansomGuard.Agent.Service.Tests`, marked `[ElevatedFact]`).
2. Before a pull request: `dotnet test RansomGuard.sln`, `pwsh tools/run-simulators.ps1` and
   `node --test "tests/**/*.test.mjs"` green. CI also runs the real-Windows tests and installs both MSIs.
3. **Rules that decide when the product contains someone** (detection confidence, containment ladder, its order)
   change only with evidence: a test that fails before the change, and, when the change is about real-world
   behavior, a lab observation recorded in the pull request (expected × observed). A unit test alone does not prove
   network behavior.
4. **Medium never contains.** Containment is reserved for High confidence; the default mode is Monitor.
5. The controlled attack drill (`tools/RansomGuard.Ensaio`, `agent/RansomGuard.Agent/Drill`) keeps its five
   safeguards: marked folder only, refuses dangerous paths, never encrypts, requires `--confirmar`, reversible.
   Executable extensions are refused.
6. No secrets, keys, SAS links or credential files in the repository. No real third-party environment data.
   `node tools/export-public.mjs --check` scans for both.
7. The signed catalog (`list/catalog.json`) changes only through the maintainer's offline signing ceremony
   (`tools/ceremony.ps1`); a pull request may propose catalog entries, and the maintainer re-signs.

## Releases

A release is published by CI from a `vX.Y.Z` tag, with `docs/release-notes/X.Y.Z.md` (bilingual) required. Release
assets: both MSIs, the drill tool, a `.sha256` per file, `SHA256SUMS.txt` and a build provenance attestation.
Download links always point to a fixed tag, never to `releases/latest`.
