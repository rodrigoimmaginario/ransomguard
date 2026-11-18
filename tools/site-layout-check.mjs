#!/usr/bin/env node
/**
 * F29 — regressão visual do site sem dependência npm.
 *
 * Sobe site/ em HTTP local, abre Chrome headless pelo DevTools Protocol e mede a geometria real em
 * seis viewports. Um simples `overflow-x:hidden` não engana o teste: ele procura qualquer elemento
 * visível que extrapole o viewport (salvo um componente explicitamente marcado data-allow-x-scroll).
 * Também congela PT/EN, light/dark, os endereços antigos, os downloads por tag fixa e o registro de uso.
 */
import { createServer } from 'node:http';
import { readFile, mkdtemp, rm, mkdir, writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { extname, join, normalize, resolve } from 'node:path';
import { tmpdir } from 'node:os';

const root = resolve('site');
const port = 18788;
const debugPort = 19231;
const mime = { '.html':'text/html; charset=utf-8', '.svg':'image/svg+xml', '.json':'application/json', '.png':'image/png', '.css':'text/css' };
let failures = 0;

function ok(condition, label, detail = '') {
  console.log(`${condition ? '  OK' : 'FALHA'}  ${label}${detail ? ` — ${detail}` : ''}`);
  if (!condition) failures++;
}
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

const server = createServer(async (req, res) => {
  try {
    const pathname = decodeURIComponent(new URL(req.url, `http://127.0.0.1:${port}`).pathname);
    const rel = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
    const file = normalize(join(root, rel));
    if (!file.startsWith(root)) throw new Error('path traversal');
    const bytes = await readFile(file);
    res.writeHead(200, { 'Content-Type': mime[extname(file)] || 'application/octet-stream', 'Cache-Control':'no-store' });
    res.end(bytes);
  } catch { res.writeHead(404); res.end('not found'); }
});
await new Promise(r => server.listen(port, '127.0.0.1', r));

const candidates = process.platform === 'win32'
  ? ['C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe']
  : ['/usr/bin/google-chrome', '/usr/bin/chromium', '/usr/bin/chromium-browser'];
const browser = process.env.CHROME_PATH || candidates.find(existsSync);
if (!browser) { console.error('Chrome/Edge não encontrado; defina CHROME_PATH.'); server.close(); process.exit(2); }

const profile = await mkdtemp(join(tmpdir(), 'ransomguard-site-'));
const chrome = spawn(browser, [
  '--headless=new', '--disable-gpu', '--hide-scrollbars', '--no-first-run', '--no-default-browser-check',
  ...(process.platform === 'win32' ? [] : ['--no-sandbox', '--disable-dev-shm-usage']),
  `--remote-debugging-port=${debugPort}`, `--user-data-dir=${profile}`, 'about:blank'
], { stdio:'ignore' });

async function waitJson(url, attempts=300) {   // até 30 s: runners de CI frios demoram para subir o Chrome
  for (let i=0;i<attempts;i++) { try { const r=await fetch(url); if (r.ok) return await r.json(); } catch {} await sleep(100); }
  throw new Error(`Chrome DevTools indisponível: ${url}`);
}
await waitJson(`http://127.0.0.1:${debugPort}/json/version`);
const tab = await fetch(`http://127.0.0.1:${debugPort}/json/new?${encodeURIComponent(`http://127.0.0.1:${port}/`)}`, { method:'PUT' }).then(r=>r.json());

class Cdp {
  constructor(url) {
    this.ws = new WebSocket(url); this.id=0; this.pending=new Map(); this.waiters=new Map();
    this.ready = new Promise((resolve,reject)=>{this.ws.onopen=resolve;this.ws.onerror=reject;});
    this.ws.onmessage = ev => {
      const m=JSON.parse(ev.data);
      if (m.id) { const p=this.pending.get(m.id); if(p){this.pending.delete(m.id); m.error?p.reject(new Error(m.error.message)):p.resolve(m.result);} }
      else if(m.method) { const list=this.waiters.get(m.method)||[]; this.waiters.set(m.method,[]); for(const f of list)f(m.params); }
    };
  }
  async send(method, params={}) { await this.ready; const id=++this.id; return new Promise((resolve,reject)=>{this.pending.set(id,{resolve,reject});this.ws.send(JSON.stringify({id,method,params}));}); }
  event(method) { return new Promise(resolve=>this.waiters.set(method,[...(this.waiters.get(method)||[]),resolve])); }
  close(){this.ws.close();}
}
const cdp = new Cdp(tab.webSocketDebuggerUrl);
await cdp.send('Page.enable'); await cdp.send('Runtime.enable');
// Hermético: o widget real do Turnstile nunca é baixado no teste; o cliente é simulado.
await cdp.send('Network.enable'); await cdp.send('Network.setBlockedURLs',{urls:['*challenges.cloudflare.com*']});

async function navigate(width, hash='#/', lang='pt', theme='light') {
  await cdp.send('Emulation.setDeviceMetricsOverride', { width, height:900, deviceScaleFactor:1, mobile:width<600 });
  const url=`http://127.0.0.1:${port}/${hash}`;
  // Mesma URL (só hash) seria navegação dentro do documento e preservaria estado mutado por um teste anterior.
  const current=await evaluate('location.href').catch(()=>'' );
  if(current===url) await cdp.send('Page.reload',{ignoreCache:true}); else await cdp.send('Page.navigate',{ url });
  for(let i=0;i<40;i++){
    const ready=await evaluate(`document.readyState`);
    if(ready==='complete')break;
    await sleep(50);
  }
  await evaluate(`(()=>{localStorage.setItem('rg-lang','${lang}');localStorage.setItem('rg-theme','${theme}');document.documentElement.setAttribute('data-theme','${theme}');if(typeof applyLang==='function')applyLang('${lang}');else document.documentElement.setAttribute('data-lang','${lang}');})()`);
  await sleep(180);
}
async function evaluate(expression) {
  const r=await cdp.send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
  if(r.exceptionDetails) throw new Error(r.exceptionDetails.text);
  return r.result.value;
}

const geometry = `(()=>{
  const vw=document.documentElement.clientWidth;
  const offenders=[];
  for(const e of document.querySelectorAll('body *')){
    if(e.closest('[data-allow-x-scroll]')) continue;
    const s=getComputedStyle(e); if(s.display==='none'||s.visibility==='hidden'||Number(s.opacity)===0)continue;
    const r=e.getBoundingClientRect(); if(r.width<1||r.height<1)continue;
    if(r.left < -1 || r.right > vw + 1) offenders.push({tag:e.tagName.toLowerCase(),cls:String(e.className).slice(0,50),left:Math.round(r.left),right:Math.round(r.right)});
  }
  return {vw,scroll:document.documentElement.scrollWidth,offenders:offenders.slice(0,8)};
})()`;

console.log('RansomGuard site — regressão visual, idiomas, temas, downloads e registro de uso (M4)');
for (const width of [320,375,390,768,1024,1440]) {
  for (const lang of ['pt','en']) for (const theme of ['light','dark']) {
    await navigate(width, '', lang, theme);
    const g=await evaluate(geometry);
    ok(g.scroll<=g.vw+1 && g.offenders.length===0, `página ${lang}/${theme} sem overflow em ${width}px`, g.offenders.length?JSON.stringify(g.offenders):`scroll=${g.scroll}/${g.vw}`);
    const capture=await evaluate(`(()=>{
      const f=document.querySelector('[data-product-screenshot]');
      const link=f&&[...f.querySelectorAll('a')].find(a=>getComputedStyle(a).display!=='none');
      const img=link?.querySelector('img');
      return {loaded:!!img&&img.complete&&img.naturalWidth>0,src:img?.getAttribute('src'),href:link?.getAttribute('href'),caption:f?.querySelector('figcaption')?.innerText||''};
    })()`);
    ok(capture.loaded && capture.href===capture.src?.replace('-resumo','') && capture.src?.includes(theme) && /demonstração|demonstration/.test(capture.caption), `captura real carregada, ampliável e identificada (${lang}/${theme}/${width})`);
  }
}

const paletteExpr=`(()=>{const c=s=>getComputedStyle(document.querySelector(s));return {hero:c('.hero').backgroundColor,panel:c('.screen').backgroundColor,alt:c('#limites').backgroundColor,table:c('.rtable-wrap').backgroundColor,form:c('.dl-card').backgroundColor};})()`;
await navigate(390, '', 'pt', 'light');
const lightPalette=await evaluate(paletteExpr);
await navigate(390, '', 'en', 'dark');
const darkPalette=await evaluate(paletteExpr);
const brightness=rgb=>{const n=(rgb.match(/\d+(?:\.\d+)?/g)||[]).slice(0,3).map(Number);return n.length===3?(n[0]*299+n[1]*587+n[2]*114)/1000:0;};
ok(brightness(lightPalette.hero)>brightness(darkPalette.hero)+80, 'hero diferencia light/dark materialmente', `${lightPalette.hero} × ${darkPalette.hero}`);
ok(['panel','alt','table','form'].every(k=>lightPalette[k]!==darkPalette[k]), 'captura, limites, tabela e downloads respondem ao tema', JSON.stringify({light:lightPalette,dark:darkPalette}));
let state=await evaluate(`({lang:document.documentElement.dataset.lang,theme:document.documentElement.dataset.theme,h1:document.querySelector('.hero h1[lang="en"]')?.innerText||'',nav:!!document.querySelector('[data-mobile-menu]')})`);
ok(state.lang==='en'&&state.theme==='dark'&&state.h1.length>10, 'EN + dark renderizam no mobile');
ok(state.nav, 'menu mobile acessível presente');
const head=await evaluate(`({title:document.title,og:document.querySelector('meta[property="og:title"]').content,twitter:document.querySelector('meta[name="twitter:title"]').content,description:document.querySelector('meta[name="description"]').content,ogDescription:document.querySelector('meta[property="og:description"]').content})`);
ok(head.title===head.og&&head.og===head.twitter&&head.description===head.ogDescription&&head.title.includes('Windows servers'), 'metadados acompanham o idioma EN');
await evaluate(`document.getElementById('langToggle').click()`);
const ptHead=await evaluate(`({title:document.title,og:document.querySelector('meta[property="og:title"]').content,pressed:document.getElementById('langToggle').getAttribute('aria-pressed')})`);
ok(ptHead.title===ptHead.og&&ptHead.title.includes('servidores Windows')&&ptHead.pressed==='false', 'toggle volta a PT com metadados e aria-pressed coerentes');
await evaluate(`document.querySelector('[data-mobile-menu] summary').click()`);
const openMenu=await evaluate(`({open:document.querySelector('[data-mobile-menu]').open,links:document.querySelectorAll('.mobile-panel a').length,g:${geometry}})`);
ok(openMenu.open&&openMenu.links>=7&&openMenu.g.offenders.length===0, 'menu mobile aberto cabe no viewport', openMenu.g.offenders.length?JSON.stringify(openMenu.g.offenders):`links=${openMenu.links}`);

// Endereços publicados antes (links externos, instaladores antigos) continuam chegando ao lugar certo.
for (const [old,want] of [['#/baixar','#baixar'],['#/doc','#baixar'],['#/#limites','#limites'],['#/faq','#faq']]) {
  await navigate(390, old, 'pt', 'light');
  await sleep(150);
  const at=await evaluate(`({hash:location.hash,g:${geometry}})`);
  ok(at.hash===want && at.g.offenders.length===0, `endereço antigo ${old} leva a ${want}`, at.hash);
}

await navigate(1440, '', 'pt', 'light');
const contract=await evaluate(`({
  downloads:[...document.querySelectorAll('#baixar a')].map(a=>a.getAttribute('href')).filter(h=>/releases\\/download\\//.test(h)),
  latest:document.documentElement.innerHTML.includes('releases/latest'),
  limitsFirst:document.querySelector('#limites').compareDocumentPosition(document.querySelector('#baixar'))===Node.DOCUMENT_POSITION_FOLLOWING,
  rows:document.querySelectorAll('#limites .rtable tbody tr').length,
  footer:!!document.querySelector('footer nav'),
  pt:document.querySelectorAll('[lang="pt"]').length,
  en:document.querySelectorAll('[lang="en"]').length
})`);
const version=JSON.parse(await readFile(join(root,'version.json'),'utf8'));
const tag=`v${version.major}.${version.minor}.${version.patch}`;
ok(contract.downloads.length===4 && contract.downloads.every(h=>h.includes(`/releases/download/${tag}/`)) && !contract.latest, `4 downloads pela tag fixa ${tag}, nunca releases/latest`, JSON.stringify(contract.downloads));
ok(contract.limitsFirst && contract.rows>=6, 'proteção e limites vêm antes do download, com a tabela do laboratório');
ok(contract.footer, 'rodapé navegável');
ok(contract.pt>40 && contract.en>40, 'texto em PT e EN', `pt=${contract.pt}, en=${contract.en}`);

// ---- Registro de uso: sem sitekey ou sem a função pronta, fica o e-mail; com as duas, o formulário protegido.
await navigate(390, '', 'pt', 'light');
const intake=await evaluate(`(()=>{
  document.querySelector('meta[name="rg-turnstile-sitekey"]').content='';initRegisterForm();
  const address=(document.querySelector('meta[name="rg-contact"]')||{}).content||'';
  const contacts=[...document.querySelectorAll('[data-contact]')];
  const vis=e=>!!e&&getComputedStyle(e).display!=='none';
  return {
    address, contacts:contacts.length,
    consistent:/^[^@\\s]+@[^@\\s]+$/.test(address)&&contacts.length>0&&contacts.every(a=>a.getAttribute('href').startsWith('mailto:'+address+'?')),
    fallbackVisible:vis(document.querySelector('[data-register-fallback]'))&&(document.querySelector('[data-register-fallback]')?.textContent||'').includes(address),
    formHidden:!vis(document.querySelector('[data-register-form]')),
    honeypot:!!document.querySelector('[data-register-form] input[name=website]'),
    turnstileSlot:!!document.querySelector('[data-register-form] [data-turnstile-slot]'),
    required:document.querySelectorAll('[data-register-form] [required]').length
  };
})()`);
ok(intake.consistent&&intake.fallbackVisible&&intake.formHidden, 'sem sitekey: contato por e-mail consistente com a fonte única; formulário oculto', JSON.stringify(intake));
ok(intake.honeypot&&intake.turnstileSlot&&intake.required===0, 'formulário tem honeypot, slot do Turnstile e nenhum campo obrigatório');

await navigate(390, '', 'en', 'dark');
const realKey=await evaluate(`(document.querySelector('meta[name="rg-turnstile-sitekey"]')||{}).content||''`);
ok(/^0x4A[0-9A-Za-z_-]{20,}$/.test(realKey), 'Site Key real do Turnstile presente na meta', realKey?realKey.slice(0,8)+'…':'vazia');
const formRun=await evaluate(`(async()=>{
  document.querySelector('meta[name="rg-turnstile-sitekey"]').content='0x-test';
  const log={render:null,posts:[],probes:0};
  window.turnstile={render:(el,o)=>{log.render=o;const i=document.createElement('input');i.type='hidden';i.name='cf-turnstile-response';i.value='tok-browser';el.appendChild(i);return 1;},reset:()=>{}};
  let next={status:200,body:{ok:true}};
  let probe=503;
  window.fetch=async(url,init)=>{if(!init||init.method==='GET'){log.probes++;return {status:probe,json:async()=>({})};}log.posts.push({url,body:JSON.parse(init.body)});const r=next;return {status:r.status,json:async()=>r.body};};
  const form=document.querySelector('[data-register-form]');
  const vis=e=>!!e&&getComputedStyle(e).display!=='none';
  initRegisterForm(); await new Promise(r=>setTimeout(r,30));
  const notReady={form:vis(form),fallback:vis(document.querySelector('[data-register-fallback]'))};
  probe=204; initRegisterForm(); await new Promise(r=>setTimeout(r,30));
  const visibleBefore={form:vis(form),fallback:vis(document.querySelector('[data-register-fallback]'))};
  form.requestSubmit(); await new Promise(r=>setTimeout(r,30));
  const emptyPosts=log.posts.length, emptyMsg=form.querySelector('[data-register-status]').textContent;
  form.country.value='Brasil';form.servers.value='3';
  form.requestSubmit(); await new Promise(r=>setTimeout(r,50));
  const afterOk={sent:vis(document.querySelector('[data-register-sent]')),form:vis(form)};
  next={status:503,body:{error:'not_configured'}};
  form.hidden=false;document.querySelector('[data-register-sent]').hidden=true;form.requestSubmit(); await new Promise(r=>setTimeout(r,50));
  const after503={form:vis(form),fallback:vis(document.querySelector('[data-register-fallback]'))};
  return {log,notReady,visibleBefore,emptyPosts,emptyMsg,afterOk,after503};
})()`);
ok(!formRun.notReady.form&&formRun.notReady.fallback&&formRun.log.probes>=1, 'sonda GET 503 → formulário não aparece mesmo com sitekey');
ok(formRun.visibleBefore.form&&!formRun.visibleBefore.fallback&&formRun.log.render?.sitekey==='0x-test'&&formRun.log.render?.theme==='dark'&&formRun.log.render?.language==='en', 'sonda GET 204 + sitekey: formulário visível, tema e idioma do widget');
ok(formRun.emptyPosts===0&&/at least one field/.test(formRun.emptyMsg), 'registro vazio nem sai do navegador', formRun.emptyMsg);
const p0=formRun.log.posts[0]||{};
ok(p0.url==='/api/registro'&&p0.body?.turnstile==='tok-browser'&&p0.body?.country==='Brasil'&&p0.body?.servers==='3'&&p0.body?.website===''&&typeof p0.body?.startedAt==='number'&&p0.body?.lang==='en', 'POST /api/registro leva token, campos, honeypot e idioma', JSON.stringify(p0.body||{}));
ok(formRun.afterOk.sent&&!formRun.afterOk.form, '200 → confirmação visível e formulário oculto');
ok(!formRun.after503.form&&formRun.after503.fallback, '503 (não configurado) → volta ao contato por e-mail');

if(process.env.SITE_SCREENSHOTS==='1') {
  await mkdir(resolve('.artifacts'),{recursive:true});
  for(const [w,name,lang,theme] of [[390,'mobile-light','pt','light'],[1440,'desktop-light','pt','light'],[390,'mobile-dark','en','dark'],[1440,'desktop-dark','en','dark']]) { await navigate(w,'',lang,theme); const shot=await cdp.send('Page.captureScreenshot',{format:'png'}); await writeFile(resolve('.artifacts',`site-${name}.png`),Buffer.from(shot.data,'base64')); }
  if(process.env.SITE_FULL_SCREENSHOT==='1'){
    for (const [lang,theme] of [['pt','light'],['en','dark']]) {
      await navigate(1440,'',lang,theme); const metrics=await cdp.send('Page.getLayoutMetrics'); const s=metrics.cssContentSize;
      const full=await cdp.send('Page.captureScreenshot',{format:'png',captureBeyondViewport:true,clip:{x:0,y:0,width:s.width,height:s.height,scale:1}});
      await writeFile(resolve('.artifacts',`site-full-${lang}-${theme}.png`),Buffer.from(full.data,'base64'));
    }
  }
}

cdp.close(); chrome.kill(); server.close();
await Promise.race([new Promise(r=>chrome.once('exit',r)),sleep(1200)]);
await rm(profile,{recursive:true,force:true,maxRetries:5,retryDelay:200}).catch(()=>{});
console.log(failures ? `\nVERMELHO — ${failures} regressão(ões).` : '\nVERDE — layout, idiomas, temas, downloads e registro de uso aprovados.');
process.exit(failures ? 1 : 0);
