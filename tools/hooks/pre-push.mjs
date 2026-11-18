#!/usr/bin/env node
// Portão local antes do push: o repositório é público, então cada push publica. Nada sai daqui sem:
//   1. varredura estrita — segredos, nomes internos e arquivos versionados fora da lista de permissão;
//   2. testes Node (site, função de registro, exportador);
//   3. testes .NET da solução (núcleo, agente, painel).
// A CI pública repete tudo isso e mais (Windows real, MSIs, simuladores). Pular o portão (git push --no-verify) não
// pula a CI.
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const root = spawnSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).stdout.trim();
const perUserDotnet = join(homedir(), '.dotnet', process.platform === 'win32' ? 'dotnet.exe' : 'dotnet');
const dotnet = spawnSync('dotnet', ['--version'], { encoding: 'utf8' }).status === 0 ? 'dotnet' : (existsSync(perUserDotnet) ? perUserDotnet : null);

const steps = [
  ['varredura estrita', process.execPath, ['tools/export-public.mjs', '--check', '--strict']],
  ['testes Node', process.execPath, ['--test', 'tests/**/*.test.mjs']],
  ['testes .NET', dotnet, ['test', 'RansomGuard.sln', '--nologo', '-v', 'q']],
];
for (const [name, cmd, args] of steps) {
  if (!cmd) { console.error(`pre-push: ${name} — dotnet não encontrado (PATH ou ~/.dotnet). Push recusado.`); process.exit(1); }
  console.log(`pre-push: ${name}…`);
  const r = spawnSync(cmd, args, { cwd: root, stdio: 'inherit', env: { ...process.env, DOTNET_ROOT: process.env.DOTNET_ROOT || join(homedir(), '.dotnet') } });
  if (r.status !== 0) { console.error(`pre-push: ${name} falhou — push recusado.`); process.exit(1); }
}
console.log('pre-push: tudo verde.');
