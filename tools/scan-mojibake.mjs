#!/usr/bin/env node
// Varre arquivos de texto do repositório por caracteres que não deveriam existir num projeto PT/EN
// (CJK, Hangul, área de uso privado) — sintoma de edição automatizada corrompida. Sai 1 se achar.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';

const exts = new Set(['.cs', '.razor', '.html', '.md', '.mjs', '.json', '.css', '.yml', '.ps1', '.wxs', '.txt', '.svg']);
const skip = /[\\/](node_modules|bin|obj|out|\.git|\.artifacts)[\\/]/;
const bad = /[\u1100-\u11FF\u3040-\u30FF\u3400-\u9FFF\uAC00-\uD7AF\uE000-\uF8FF\uFFFD]/g;
const hits = [];
function walk(d) {
  for (const name of readdirSync(d)) {
    const p = join(d, name);
    if (skip.test(p + '/')) continue;
    const st = statSync(p);
    if (st.isDirectory()) { walk(p); continue; }
    if (!exts.has(extname(name))) continue;
    const s = readFileSync(p, 'utf8');
    const m = [...s.matchAll(bad)];
    if (m.length) {
      const lines = [...new Set(m.map(x => s.slice(0, x.index).split('\n').length))].slice(0, 6);
      hits.push(`${p.replace(/\\/g, '/')}: linhas ${lines.join(', ')} (${m.map(x => x[0]).slice(0, 4).join(' ')})`);
    }
  }
}
walk(process.argv[2] ?? '.');
console.log(hits.length ? hits.join('\n') : 'OK — nenhum caractere suspeito');
process.exit(hits.length ? 1 : 0);
