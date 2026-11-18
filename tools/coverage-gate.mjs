#!/usr/bin/env node
// Portão de cobertura sobre relatórios Cobertura (coverlet collector). Uso:
//   node tools/coverage-gate.mjs <dir-ou-arquivo.xml> <minLine%> <minBranch%> [nome-do-módulo]
// Lê line-rate/branch-rate do <coverage> (ou do <package name=...> quando o módulo é informado) e sai 1 se abaixo.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const [target, minLine, minBranch, moduleName] = process.argv.slice(2);
if (!target || !minLine || !minBranch) { console.error('uso: coverage-gate <dir|xml> <minLine> <minBranch> [modulo]'); process.exit(2); }

function findXml(p) {
  if (statSync(p).isFile()) return [p];
  const out = [];
  for (const e of readdirSync(p)) { const f = join(p, e); if (statSync(f).isDirectory()) out.push(...findXml(f)); else if (/cobertura\.xml$/i.test(e)) out.push(f); }
  return out;
}
const files = findXml(target);
if (files.length === 0) { console.error(`nenhum coverage.cobertura.xml em ${target}`); process.exit(2); }
const xml = readFileSync(files.sort().at(-1), 'utf8');
let line, branch;
if (moduleName) {
  const m = xml.match(new RegExp(`<package[^>]*name="${moduleName.replace(/\./g, '\\.')}"[^>]*line-rate="([\\d.]+)"[^>]*branch-rate="([\\d.]+)"`));
  if (!m) { console.error(`módulo ${moduleName} não encontrado no relatório`); process.exit(2); }
  line = +m[1] * 100; branch = +m[2] * 100;
} else {
  const m = xml.match(/<coverage[^>]*line-rate="([\d.]+)"[^>]*branch-rate="([\d.]+)"/);
  if (!m) { console.error('relatório sem line-rate/branch-rate'); process.exit(2); }
  line = +m[1] * 100; branch = +m[2] * 100;
}
const okLine = line >= +minLine, okBranch = branch >= +minBranch;
console.log(`${moduleName ?? 'total'}: linha ${line.toFixed(1)}% (mín ${minLine}) · branch ${branch.toFixed(1)}% (mín ${minBranch}) → ${okLine && okBranch ? 'OK' : 'ABAIXO DO PISO'}`);
process.exit(okLine && okBranch ? 0 : 1);
