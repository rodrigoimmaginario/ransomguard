#!/usr/bin/env node
// Monta a árvore do repositório público a partir deste repositório, por LISTA DE PERMISSÃO: só entra o que está
// listado abaixo (arquivo novo fora da lista não vaza por descuido). Depois de copiar, varre cada arquivo de texto
// atrás de segredos e de nomes internos. Qualquer achado fora das exceções declaradas faz a exportação falhar.
//
//   node tools/export-public.mjs --out out/public          exporta e varre
//   node tools/export-public.mjs --check                   só varre o que seria exportado (não copia)
//
// Só considera arquivos versionados (git ls-files): nada de bin/, obj/, out/ ou arquivo local.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Prefixos (pastas, com barra) e arquivos que vão para o repositório público. */
export const ALLOW = [
  'RansomGuard.sln', '.gitattributes', '.gitignore', 'vercel.json', '.vercelignore',
  'LICENSE', 'README.md', 'README.en.md', 'SECURITY.md', 'CONTRIBUTING.md', 'CHANGELOG.md',
  '.github/workflows/',
  'core/', 'agent/', 'server/', 'spike/', 'list/', 'site/', 'api/',
  'deploy/msi/',
  'docs/pt-br/', 'docs/en/', 'docs/release-notes/',
  'tests/api/', 'tests/site/', 'tests/export/',
  'tools/RansomGuard.Ensaio/',
  'tools/build-release.ps1', 'tools/ceremony.ps1', 'tools/sign-catalog.ps1', 'tools/coverage-gate.mjs',
  'tools/panel-layout-check.mjs', 'tools/run-simulators.ps1', 'tools/scan-mojibake.mjs', 'tools/site-layout-check.mjs',
  'tools/test-msi-install.ps1', 'tools/export-public.mjs', 'tools/export-public.allow.json',
];

/** Mesmo dentro de uma pasta permitida, nunca entra. */
export const DENY = [
  /(^|\/)(bin|obj)\//, /(^|\/)\.env/, /\.(key|pem|pfx|p12|snk)$/i, /(^|\/)appsettings\.Development\.json$/i,
  /^spike\/README-spikes-lab\.md$/,
];

// Regras montadas por partes: o texto deste arquivo não pode casar com as próprias regras.
const rx = (parts, flags = '') => new RegExp(parts.join(''), flags);

// O comando que apaga as cópias de sombra nunca aparece inteiro, nem aqui: montado por partes.
const SHADOW = ['vss', 'admin'].join('') + String.raw`(\.exe)?\s+delete\s+` + ['sha', 'dows'].join('');

/** Segredos: falha sempre, sem exceção possível. */
export const SECRETS = [
  ['chave privada PEM', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['chave secreta minisign', rx(['minisign encrypted', ' secret key'], 'i')],
  ['token do GitHub', /\b(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})/],
  ['chave da Resend', /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/],
  ['chave da AWS', /\bAKIA[0-9A-Z]{16}\b/],
  ['link SAS do Azure', /[?&]sig=[A-Za-z0-9%+/]{20,}/],
  ['chave de conta de armazenamento', /AccountKey=[A-Za-z0-9+/]{20,}/],
  ['comando contra a recuperação, inteiro', new RegExp(SHADOW, 'i')],
];

/** Nomes internos e comerciais: falham, salvo exceção declarada (arquivo + rótulo + motivo). */
export const INTERNAL = [
  ['pasta de governança interna', /\.ariad\//],
  ['pasta de documentos internos', /(^|[^A-Za-z])internal\//],
  ['e-mail pessoal', rx(['rodrigoi', '@hotmail'], 'i')],
  ['caminho da máquina do mantenedor', /C:[\\/]VSCode/i],
  ['assinatura do Azure do laboratório', rx(['12af0131', '-d174'], 'i')],
  ['projeto não publicado', /ShadowAI ?Guard/i],
  ['marca fora da identidade do projeto', rx(['Vig', 'la'], 'i')],
  ['empresa no lugar do autor', rx(['IPSEC', ' Tecnologia'], 'i')],
  ['licença comercial', rx(['software propriet[áa]rio|proprietary', ' software'], 'i')],
  ['documento interno de handoff', rx(['HANDOFF', '-LLM|PROMPT-NOVA', '-LLM|Ransonware', String.raw`\.txt`])],
];

const isText = (buf) => !buf.subarray(0, 8000).includes(0);

export function selectFiles(files) {
  return files.filter((f) => ALLOW.some((a) => (a.endsWith('/') ? f.startsWith(a) : f === a)) && !DENY.some((d) => d.test(f)));
}

export function scanText(file, text, allow = []) {
  const findings = [];
  const lines = text.split(/\r?\n/);
  for (const [label, re, internal] of [...SECRETS.map((s) => [...s, false]), ...INTERNAL.map((s) => [...s, true])]) {
    lines.forEach((line, i) => {
      if (!re.test(line)) return;
      if (internal && allow.some((a) => a.file === file && a.label === label)) return;
      findings.push({ file, line: i + 1, label, secret: !internal });
    });
  }
  return findings;
}

function gitFiles(root) {
  return execFileSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 })
    .split('\0').filter(Boolean).map((f) => f.replace(/\\/g, '/'));
}

export function exportTree({ root, out, check = false }) {
  const allowFile = join(root, 'tools', 'export-public.allow.json');
  const allow = existsSync(allowFile) ? JSON.parse(readFileSync(allowFile, 'utf8')) : [];
  const files = selectFiles(gitFiles(root)).filter((f) => existsSync(join(root, f)));
  const findings = [];
  if (!check) { rmSync(out, { recursive: true, force: true }); mkdirSync(out, { recursive: true }); }
  for (const f of files) {
    const buf = readFileSync(join(root, f));
    if (isText(buf)) findings.push(...scanText(f, buf.toString('utf8'), allow));
    if (!check) { mkdirSync(dirname(join(out, f)), { recursive: true }); writeFileSync(join(out, f), buf); }
  }
  // Exceção que não casa mais com nada é exceção esquecida: falha também, para a lista não apodrecer.
  const used = new Set(files.flatMap((f) => {
    const buf = readFileSync(join(root, f));
    if (!isText(buf)) return [];
    return scanText(f, buf.toString('utf8')).filter((x) => !x.secret).map((x) => `${x.file}|${x.label}`);
  }));
  const stale = allow.filter((a) => !used.has(`${a.file}|${a.label}`));
  return { files, findings, stale };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const args = process.argv.slice(2);
  const check = args.includes('--check');
  const outArg = args.includes('--out') ? args[args.indexOf('--out') + 1] : 'out/public';
  const rootArg = args.includes('--root') ? args[args.indexOf('--root') + 1] : resolve(dirname(fileURLToPath(import.meta.url)), '..');
  const root = resolve(rootArg);
  const { files, findings, stale } = exportTree({ root, out: resolve(root, outArg), check });
  for (const f of findings) console.log(`  ${f.secret ? 'SEGREDO' : 'interno'}  ${f.file}:${f.line}  ${f.label}`);
  for (const s of stale) console.log(`  exceção sem uso  ${s.file}  ${s.label}`);
  const ok = findings.length === 0 && stale.length === 0;
  console.log(`${ok ? 'OK' : 'FALHOU'} — ${files.length} arquivo(s) ${check ? 'seriam exportados' : `exportados para ${outArg}`}; ` +
    `${findings.length} achado(s); ${stale.length} exceção(ões) sem uso.`);
  process.exit(ok ? 0 : 1);
}
