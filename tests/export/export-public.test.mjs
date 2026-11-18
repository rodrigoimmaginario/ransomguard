import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { selectFiles, scanText } from '../../tools/export-public.mjs';

// Nomes de pastas internas montados por partes: este arquivo também vai para o repositório público.
const GOV = ['.ari', 'ad'].join('');
const INT = ['inter', 'nal'].join('');
const script = resolve(dirname(fileURLToPath(import.meta.url)), '../../tools/export-public.mjs');

function repoWith(files) {
  const root = mkdtempSync(join(tmpdir(), 'rg-export-'));
  for (const [path, body] of Object.entries(files)) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    writeFileSync(join(root, path), body);
  }
  execFileSync('git', ['init', '-q'], { cwd: root });
  execFileSync('git', ['add', '-A'], { cwd: root });
  return root;
}

test('só entra o que está na lista de permissão', () => {
  const picked = selectFiles(['core/A.cs', `${GOV}/plano.md`, `${INT}/x.md`, 'docs/GUIA-PILOTO-PARCEIRO.md',
    'docs/pt-br/instalacao.md', 'core/bin/Debug/A.dll', 'list/chave.key', 'lab/azure/Start-Lab.ps1', 'README.md']);
  assert.deepEqual(picked, ['core/A.cs', 'docs/pt-br/instalacao.md', 'README.md']);
});

test('segredo plantado é achado e não admite exceção', () => {
  const pem = ['-----BEGIN', 'PRIVATE KEY-----'].join(' ');
  const found = scanText('core/A.cs', `// ok\nvar k = "${pem}";`, [{ file: 'core/A.cs', label: 'chave privada PEM' }]);
  assert.equal(found.length, 1);
  assert.equal(found[0].secret, true);
  assert.equal(found[0].line, 2);
});

test('o comando contra a recuperação inteiro é achado; em partes, não', () => {
  const whole = ['vss', 'admin delete sha', 'dows /all'].join('');
  assert.equal(scanText('a.ps1', whole).length, 1);
  assert.equal(scanText('a.ps1', "$a = 'vss' + 'admin'").length, 0);
});

test('nome interno falha, salvo exceção declarada para aquele arquivo', () => {
  assert.equal(scanText("README.md", `veja ${GOV}/work`).length, 1);
  assert.equal(scanText(".vercelignore", `${GOV}/`, [{ file: '.vercelignore', label: 'pasta de governança interna' }]).length, 0);
});

test('a exportação copia só o permitido e falha com um segredo plantado', () => {
  const root = repoWith({
    'core/A.cs': 'class A {}',
    [`${GOV}/plano.md`]: 'interno',
    'lab/azure/Start-Lab.ps1': 'laboratório',
  });
  try {
    const out = join(root, 'pub');
    let r = spawnSync(process.execPath, [script, '--root', root, '--out', 'pub'], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stdout + r.stderr);
    assert.ok(existsSync(join(out, 'core/A.cs')));
    assert.ok(!existsSync(join(out, GOV)));
    assert.ok(!existsSync(join(out, 'lab')));

    writeFileSync(join(root, 'core/B.cs'), `// ${['ghp', 'A'.repeat(36)].join('_')}`);
    execFileSync('git', ['add', '-A'], { cwd: root });
    r = spawnSync(process.execPath, [script, '--root', root, '--out', 'pub'], { encoding: 'utf8' });
    assert.equal(r.status, 1);
    assert.match(r.stdout, /SEGREDO\s+core\/B\.cs:1\s+token do GitHub/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
