#!/usr/bin/env node
/**
 * F37 — regressão visual do PAINEL (Blazor), sem dependência npm.
 *
 * Sobe o painel real (Development → DemoSeed: 3 servidores, 1 incidente com trilha de contenção e arquivos) num
 * diretório temporário, faz o setup com o token de primeira execução, loga e percorre as telas em três larguras:
 * nenhum elemento visível pode extrapolar o viewport. Com PANEL_SCREENSHOTS=1 grava as capturas em site/screens/
 * (as imagens reais do /doc).
 *
 * Pré-requisito: `dotnet build server/RansomGuard.Server` (a CI faz antes). Chrome/Edge local ou CHROME_PATH.
 */
import { spawn } from 'node:child_process';
import { mkdtemp, rm, readFile, mkdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

const port = 18790, debugPort = 19233;
const base = `http://127.0.0.1:${port}`;
let failures = 0;
const ok = (c, label, detail = '') => { console.log(`${c ? '  OK' : 'FALHA'}  ${label}${detail ? ` — ${detail}` : ''}`); if (!c) failures++; };
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ── painel ─────────────────────────────────────────────────────────────────────────────────
const work = await mkdtemp(join(tmpdir(), 'rg-panel-'));
const secretsPath = join(work, 'install-secrets.json');
const dotnet = process.env.DOTNET_ROOT ? join(process.env.DOTNET_ROOT, process.platform === 'win32' ? 'dotnet.exe' : 'dotnet') : 'dotnet';
const panel = spawn(dotnet, ['run', '--project', 'server/RansomGuard.Server', '--no-build', '--no-launch-profile'], {
  env: {
    ...process.env, ASPNETCORE_ENVIRONMENT: 'Development', ASPNETCORE_URLS: base,
    Database__Path: join(work, 'ransomguard.db'), InstallKey__Path: join(work, 'install-key.json'),
    InstallSecrets__Path: secretsPath, Panel__Https: 'false'
  },
  stdio: ['ignore', 'pipe', 'pipe']
});
let panelLog = '';
panel.stdout.on('data', d => { panelLog += d; });
panel.stderr.on('data', d => { panelLog += d; });

async function waitPanel() {
  for (let i = 0; i < 600; i++) {
    try { const r = await fetch(`${base}/login`); if (r.ok || r.status === 302) return true; } catch {}
    if (panel.exitCode !== null) break;
    await sleep(250);
  }
  return false;
}
if (!await waitPanel()) { console.error('Painel não subiu:\n' + panelLog.slice(-3000)); panel.kill(); process.exit(2); }
// Os segredos em disco são protegidos (B2); o token de primeira execução fica em arquivo próprio até a conta existir.
const secrets = { SetupToken: (await readFile(join(work, 'token-de-setup.txt'), 'utf8')).trim().split(/\r?\n/).pop().trim() };

// ── chrome ─────────────────────────────────────────────────────────────────────────────────
const candidates = process.platform === 'win32'
  ? ['C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe']
  : ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
const browser = process.env.CHROME_PATH || candidates.find(existsSync);
if (!browser) { console.error('Chrome/Edge não encontrado; defina CHROME_PATH.'); panel.kill(); process.exit(2); }
const profile = await mkdtemp(join(tmpdir(), 'rg-panel-chrome-'));
const chrome = spawn(browser, ['--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run', '--no-default-browser-check',
  ...(process.platform === 'win32' ? [] : ['--no-sandbox', '--disable-dev-shm-usage']),
  `--remote-debugging-port=${debugPort}`, `--user-data-dir=${profile}`, 'about:blank'], { stdio: 'ignore' });
async function waitJson(url, attempts = 300) { for (let i = 0; i < attempts; i++) { try { const r = await fetch(url); if (r.ok) return await r.json(); } catch {} await sleep(100); } throw new Error('DevTools indisponível'); }
await waitJson(`http://127.0.0.1:${debugPort}/json/version`);
const tab = await fetch(`http://127.0.0.1:${debugPort}/json/new?${encodeURIComponent(base + '/setup')}`, { method: 'PUT' }).then(r => r.json());
class Cdp {
  constructor(url) { this.ws = new WebSocket(url); this.id = 0; this.pending = new Map(); this.ready = new Promise((res, rej) => { this.ws.onopen = res; this.ws.onerror = rej; });
    this.ws.onmessage = ev => { const m = JSON.parse(ev.data); if (m.id && this.pending.has(m.id)) { const p = this.pending.get(m.id); this.pending.delete(m.id); m.error ? p.reject(new Error(m.error.message)) : p.resolve(m.result); } }; }
  async send(method, params = {}) { await this.ready; const id = ++this.id; return new Promise((resolve, reject) => { this.pending.set(id, { resolve, reject }); this.ws.send(JSON.stringify({ id, method, params })); }); }
  close() { this.ws.close(); }
}
const cdp = new Cdp(tab.webSocketDebuggerUrl);
await cdp.send('Page.enable'); await cdp.send('Runtime.enable');
async function evaluate(expression) { const r = await cdp.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }); if (r.exceptionDetails) throw new Error(r.exceptionDetails.text); return r.result.value; }
async function goto(path, width, theme = 'light') {
  await cdp.send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 600 });
  await cdp.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: theme }] });
  await cdp.send('Page.navigate', { url: base + path });
  for (let i = 0; i < 80; i++) { if ((await evaluate('document.readyState')) === 'complete') break; await sleep(50); }
  await sleep(250);
}
// Elemento dentro de um contêiner com rolagem horizontal própria (ex.: tabela larga em .rg-main) não é overflow do
// viewport — o contêiner é que precisa caber. Fora disso, nada visível pode extrapolar.
const geometry = `(()=>{const vw=document.documentElement.clientWidth;const off=[];const scrollHost=e=>{for(let a=e.parentElement;a&&a!==document.body;a=a.parentElement){const o=getComputedStyle(a).overflowX;if(o==='auto'||o==='scroll')return a;}return null;};for(const e of document.querySelectorAll('body *')){const s=getComputedStyle(e);if(s.display==='none'||s.visibility==='hidden')continue;const r=e.getBoundingClientRect();if(r.width<1||r.height<1)continue;if(r.left<-1||r.right>vw+1){const h=scrollHost(e);if(h){const hr=h.getBoundingClientRect();if(hr.left>=-1&&hr.right<=vw+1)continue;}off.push({tag:e.tagName.toLowerCase(),cls:String(e.className).slice(0,40),l:Math.round(r.left),r:Math.round(r.right)});}}return {vw,scroll:document.documentElement.scrollWidth,off:off.slice(0,6)}})()`;

// ── setup + login (token de primeira execução) ─────────────────────────────────────────────
console.log('RansomGuard painel — regressão visual F37');
await goto('/setup', 1200);
await evaluate(`(()=>{const f=document.querySelector('form[action="/auth/setup"]');f.username.value='admin';f.password.value='senha-forte-123';f.token.value=${JSON.stringify(secrets.SetupToken)};f.submit();})()`);
await sleep(1500);
for (let i = 0; i < 40; i++) { if ((await evaluate('document.readyState')) === 'complete' && !(await evaluate('location.pathname')).startsWith('/setup')) break; await sleep(100); }
ok(!(await evaluate('location.pathname')).startsWith('/setup') && !(await evaluate('location.pathname')).startsWith('/login'), 'setup com token de primeira execução loga no painel', await evaluate('location.pathname'));

// ── telas ──────────────────────────────────────────────────────────────────────────────────
const incidentHref = await (async () => { await goto('/incidentes', 1200); return await evaluate(`(document.querySelector('a[href^="/incidente/"]')||{}).getAttribute?.('href')||''`); })();
ok(incidentHref.length > 0, 'DemoSeed produz incidente com trilha (F32)', incidentHref);
const pages = [['/', 'home'], ['/incidentes', 'incidentes'], [incidentHref || '/incidentes', 'incidente'], ['/servidor/FS01', 'servidor'], ['/agentes', 'agentes'], ['/politica', 'politica'], ['/notificacoes', 'notificacoes'], ['/auditoria', 'auditoria'], ['/contas', 'contas']];
const shots = process.env.PANEL_SCREENSHOTS === '1';
if (shots) await mkdir(resolve('site/screens'), { recursive: true });
for (const [path, name] of pages) {
  for (const width of [390, 1024, 1440]) {
    await goto(path, width);
    const g = await evaluate(geometry);
    const title = await evaluate('document.title');
    ok(g.scroll <= g.vw + 1 && g.off.length === 0 && /RansomGuard/.test(title), `${name} sem overflow em ${width}px`, g.off.length ? JSON.stringify(g.off) : `scroll=${g.scroll}/${g.vw}`);
    if (shots && (width === 1440 || width === 390)) {
      const png = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false });
      await writeFile(resolve('site/screens', `painel-${name}-${width}.png`), Buffer.from(png.data, 'base64'));
    }
  }
}
// Tema escuro (preferência do sistema): fundo do conteúdo muda materialmente e nada vaza.
await goto('/', 1440, 'dark');
const darkBg = await evaluate(`getComputedStyle(document.querySelector('.rg-main')).backgroundColor`);
await goto('/', 1440, 'light');
const lightBg = await evaluate(`getComputedStyle(document.querySelector('.rg-main')).backgroundColor`);
ok(darkBg !== lightBg, 'painel responde ao tema escuro do sistema', `${lightBg} × ${darkBg}`);
const gDark = await (async () => { await goto('/incidentes', 390, 'dark'); return await evaluate(geometry); })();
ok(gDark.off.length === 0, 'incidentes em dark/390 sem overflow', gDark.off.length ? JSON.stringify(gDark.off) : 'ok');

// Conteúdo essencial do detalhe do incidente (a tela que o parceiro vai olhar primeiro).
await goto(incidentHref || '/incidentes', 1440);
const detail = await evaluate(`({trail:document.body.innerText.includes('Linha do tempo da resposta'),files:document.body.innerText.includes('Arquivos afetados'),fail:document.body.innerText.includes('falhou'),undo:[...document.querySelectorAll('button')].some(b=>b.textContent.includes('Desfazer'))})`);
ok(detail.trail && detail.files && detail.fail && detail.undo, 'detalhe do incidente mostra trilha, falha real, arquivos e Desfazer', JSON.stringify(detail));

// Editorial RC: recorte real da linha do tempo, sem alterar o DOM nem inventar métricas.
// DemoSeed usa executores simulados: a legenda do site deve explicitar dados de demonstração.
if (process.env.PANEL_HERO_SCREENSHOT === '1') {
  await mkdir(resolve('site/screens'), { recursive: true });
  for (const theme of ['light', 'dark']) {
    await goto(incidentHref, 1440, theme);
    const clip = await evaluate(`(()=>{
      const heading=[...document.querySelectorAll('h2,h3')].find(e=>e.textContent.includes('Linha do tempo'));
      if(!heading) throw new Error('Linha do tempo ausente');
      const table=heading.nextElementSibling;
      if(table.tagName!=='TABLE') throw new Error('Tabela de resposta ausente');
      const a=heading.getBoundingClientRect(), b=table.getBoundingClientRect();
      return {x:Math.floor(b.left),y:Math.floor(a.top+scrollY),width:Math.ceil(b.width),height:Math.ceil(b.bottom-a.top),scale:1};
    })()`);
    const png = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip });
    await writeFile(resolve('site/screens', `incidente-trilha-${theme}.png`), Buffer.from(png.data, 'base64'));
    // Hero mostra as quatro primeiras colunas em tamanho legível; link abre a tabela completa.
    const summaryWidth = await evaluate(`(()=>{
      const heading=[...document.querySelectorAll('h2,h3')].find(e=>e.textContent.includes('Linha do tempo'));
      const table=heading.nextElementSibling;
      return Math.ceil(table.querySelectorAll('th')[3].getBoundingClientRect().right-table.getBoundingClientRect().left);
    })()`);
    const summary = await cdp.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { ...clip, width: summaryWidth } });
    await writeFile(resolve('site/screens', `incidente-trilha-resumo-${theme}.png`), Buffer.from(summary.data, 'base64'));
  }
}

cdp.close(); chrome.kill(); panel.kill();
await Promise.race([new Promise(r => chrome.once('exit', r)), sleep(1500)]);
await Promise.race([new Promise(r => panel.once('exit', r)), sleep(3000)]);
await rm(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).catch(() => {});
await rm(work, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }).catch(() => {});
console.log(failures ? `\nVERMELHO — ${failures} regressão(ões).` : `\nVERDE — painel sem overflow em ${pages.length} telas × 3 larguras; fluxo de setup/login e detalhe do incidente aprovados.`);
process.exit(failures ? 1 : 0);
