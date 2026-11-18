import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

const html = readFileSync(new URL('../../site/index.html', import.meta.url), 'utf8');
const og = readFileSync(new URL('../../site/og-image.svg', import.meta.url), 'utf8');
const version = JSON.parse(readFileSync(new URL('../../site/version.json', import.meta.url), 'utf8'));
const plain = (s) => s.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ');
const section = (id) => html.match(new RegExp(`<section id="${id}"[\\s\\S]*?</section>`))?.[0] ?? '';
const tag = `v${version.major}.${version.minor}.${version.patch}`;

test('hero keeps the approved Windows-server headline and leads to limits and download, not to a pilot', () => {
  assert.match(html, /Detecte e contenha ransomware em servidores Windows\./);
  assert.match(html, /Detect and contain ransomware on Windows servers\./);
  const hero = html.match(/<section class="hero">[\s\S]*?<\/section>/)[0];
  assert.match(hero, /href="#baixar"/);
  assert.match(hero, /href="#limites"/);
  assert.match(hero, /MIT/);
  assert.doesNotMatch(hero, /\d+(,\d+)? ?s\b|segundos|seconds/);
  assert.doesNotMatch(html, /piloto|\bpilot\b|Release Candidate/i);
});

test('scope stays on file shares and monitored folders, never every workload', () => {
  const scope = html.match(/<details class="qa" data-server-scope>[\s\S]*?<\/details>/)?.[0];
  assert.ok(scope, 'visible scope FAQ required');
  assert.match(scope, /compartilhamentos de arquivos e das pastas monitoradas/);
  assert.match(scope, /file shares and monitored folders/);
  assert.match(scope, /não significa proteção especializada/);
  assert.match(scope, /does not mean specialized protection/);
  assert.match(scope, /SQL Server, AD ou Hyper-V/);
  assert.doesNotMatch(plain(html), /\bqualquer servidor\b(?!\s*Windows\?)|\bevery workload/i);
});

test('real product image is labelled as demonstration data in PT and EN', () => {
  assert.match(html, /data-product-screenshot/);
  assert.match(html, /Captura real do painel · dados de demonstração/);
  assert.match(html, /Actual dashboard capture · demonstration data/);
  const images = [...html.matchAll(/<img[^>]+src="(\/screens\/[^" ]+)"/g)];
  assert.ok(images.length > 0);
  for (const [, path] of images) assert.ok(existsSync(new URL('../../site' + path, import.meta.url)), path);
});

test('timing numbers appear only in the limits section, labelled as lab observations, before the download', () => {
  const limits = section('limites');
  assert.ok(limits, 'limits section required');
  const outside = html.replace(limits, '');
  assert.doesNotMatch(plain(outside), /contido em \d|contained in \d|\d+(,\d+)? s após|after start/i);
  assert.match(plain(limits), /observações, a maioria de uma execução por caso, não garantia/);
  assert.match(plain(limits), /observations, most from a single run per case, not a guarantee/);
  for (const t of ['Contido depois do fim', 'Contained after it finished', 'Média nunca contém', 'Medium never contains',
    'Bloquear o IP bloqueia a estação inteira', 'Blocking the IP blocks the whole workstation', 'não substitui backup offline',
    'does not replace offline backup', 'Não exercitado em rede real', 'Not exercised on a real network']) {
    assert.ok(plain(limits).includes(t), t);
  }
  assert.match(limits, /docs\/pt-br\/protecao-e-limites\.md/);
  assert.match(limits, /docs\/en\/protection-and-limits\.md/);
  assert.ok(html.indexOf('id="limites"') < html.indexOf('id="baixar"'), 'limits come before the download');
});

test('editorial contract rejects unsupported guarantees across the page and the share image', () => {
  for (const forbidden of [
    /primeiro segundo|first second/i, /antes do dano|before the damage/i,
    /cont[eé]m em segundos|contenha em segundos|contains? in seconds/i,
    /tudo que ele faz é reversível|everything it does you can reverse/i,
    /nada sai (?:da sua rede|para a nuvem)|nothing (?:leaves your network|goes to the cloud)/i,
    /MSI assinado|signed (?:agent )?MSI|instalador assinado/i, /backup passa ileso|backups sail through/i,
    /servidor salvo|server saved/i, /garante (?:a )?prote|garantia total|(?<!não (?:é )?uma )garantia de prote|guaranteed protection/i,
    /bloqueia (?:qualquer|todo) ransomware|stops (?:any|every|all) ransomware/i
  ]) assert.doesNotMatch(html + plain(html) + og, forbidden);
});

test('downloads point to the fixed release tag, with SHA-256, attestation and the unsigned warning', () => {
  const dl = section('baixar');
  assert.doesNotMatch(html, /releases\/latest/);
  const links = [...dl.matchAll(/href="(https:\/\/github\.com\/rodrigoimmaginario\/ransomguard\/releases\/download\/[^"]+)"/g)].map((m) => m[1]);
  assert.equal(links.length, 4);
  for (const l of links) assert.ok(l.includes(`/download/${tag}/`), l);
  for (const f of ['RansomGuard-Painel-', 'RansomGuard-Agente-', 'RansomGuard-Ensaio-', 'SHA256SUMS.txt']) assert.ok(dl.includes(f), f);
  assert.match(dl, /Get-FileHash/);
  assert.match(dl, /gh attestation verify/);
  assert.match(plain(dl), /Sem assinatura de código/);
  assert.match(plain(dl), /Not code-signed/);
});

test('usage registration is optional, stores nothing and is the only data the project asks for', () => {
  const reg = section('registro');
  assert.match(reg, /data-register-form/);
  for (const f of ['organization', 'country', 'servers', 'email', 'usage']) assert.match(reg, new RegExp(`name="${f}"`));
  assert.doesNotMatch(reg, /\srequired[\s>]/);
  assert.match(plain(reg), /Todos os campos são opcionais/);
  assert.match(plain(reg), /Every field is optional/);
  assert.match(plain(reg), /não é guardado em banco/);
  assert.match(plain(reg), /is not stored in a database/);
  assert.match(html, /fetch\('\/api\/registro'/);
  assert.match(plain(section('seguranca')), /Sem telemetria/);
});

test('authorship, license, structured data and share image match the open-source release', () => {
  assert.match(html, /© 2026 Rodrigo Immaginario/);
  assert.match(html, /Licença MIT/);
  assert.doesNotMatch(html + og, /IPSEC|propriet[áa]ri|proprietary|licen[çc]a comercial|plano pago|paid plan/i);
  const graph = JSON.parse(html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)[1])['@graph'];
  const app = graph.find((n) => n['@type'] === 'SoftwareApplication');
  assert.equal(app.license, 'https://opensource.org/licenses/MIT');
  assert.equal(app.offers.price, '0');
  assert.equal(`v${app.softwareVersion}`, tag);
  assert.match(og, /em servidores Windows\./);
  assert.match(og, /Free and open source/);
  assert.match(og, new RegExp(tag.replace(/\./g, '\\.')));
  assert.doesNotMatch(og, /Piloto|pilot|Release Candidate/i);
});

test('a first-time visitor sees the purpose before the details: the problem, what it does, and the animated diagram', () => {
  const purpose = section('proposito');
  const product = section('produto');
  const how = section('como');
  assert.ok(purpose && product && how, 'purpose, product and how sections required');
  const order = ['class="hero"', 'id="proposito"', 'id="produto"', 'id="como"', 'id="limites"'].map((s) => html.indexOf(s));
  assert.deepEqual([...order].sort((a, b) => a - b), order, 'hero → purpose → product → how → limits');
  assert.match(purpose, /data-detection-compare/);
  assert.match(plain(purpose), /O ataque pode começar em outra máquina/);
  assert.match(plain(purpose), /The attack can start on another machine/);
  assert.match(plain(purpose), /não a substitui|does not replace it/);
  for (const t of ['Identificar riscos', 'Identify risks', 'Detectar', 'Detect', 'Conter', 'Contain']) assert.ok(plain(product).includes(t), t);
  const diagram = how.match(/<div class="rg-diagram"[\s\S]*?<\/svg>/)?.[0];
  assert.ok(diagram, 'animated diagram required in how it works');
  const steps = ['bloqueia IP', 'nega acesso', 'encerra sessão'].map((s) => diagram.indexOf(s));
  assert.ok(steps.every((i) => i > 0) && steps[0] < steps[1] && steps[1] < steps[2], 'diagram follows the containment order: IP, deny, session');
});
