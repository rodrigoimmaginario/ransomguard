// Registro voluntário de uso — função serverless (Vercel, Node 24, zero dependências).
//
// Quem usa o RansomGuard pode contar, se quiser, onde e como usa. Nada é guardado em banco: o registro vira um
// e-mail para o contato público do projeto. Não há telemetria no produto; o painel só mostra um link para cá.
//
// Camadas antispam, da mais barata para a mais cara:
//   1. honeypot (campo "website" oculto) → 200 silencioso, nada é enviado;
//   2. tempo mínimo de preenchimento (startedAt);
//   3. validação e saneamento (tamanho, e-mail quando informado, sem quebras em campos de cabeçalho);
//   4. limite por IP (melhor esforço: memória da instância);
//   5. Cloudflare Turnstile verificado no servidor (siteverify);
//   6. entrega via Resend.
// Sem TURNSTILE_SECRET_KEY e RESEND_API_KEY a função FALHA FECHADO (503) e o site mostra o contato por e-mail.
// O IP é usado só no limite e na verificação do Turnstile; não vai no e-mail.
//
// Variáveis (Vercel → Settings → Environment Variables):
//   TURNSTILE_SECRET_KEY  segredo do widget Turnstile
//   RESEND_API_KEY        chave da API do Resend
//   REGISTER_TO           destino (padrão: o contato público do projeto)
//   REGISTER_FROM         remetente (padrão: "RansomGuard <onboarding@resend.dev>")

const LIMITS = { organization: 120, country: 60, servers: 20, email: 120, usage: 1000, lang: 2 };
const MIN_FILL_MS = 3000;
const DEFAULT_TO = 'r.immaginario@gmail.com';
const DEFAULT_FROM = 'RansomGuard <onboarding@resend.dev>';
const TURNSTILE_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const RESEND_URL = 'https://api.resend.com/emails';

const clean = (v, max) => String(v ?? '').replace(/[\r\n\t]+/g, ' ').replace(/\s{2,}/g, ' ').trim().slice(0, max);
const cleanMultiline = (v, max) => String(v ?? '').replace(/\r\n?/g, '\n').replace(/[^\S\n]+/g, ' ').trim().slice(0, max);
const EMAIL = /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/;

export function validateSubmission(body, now = Date.now()) {
  const b = body && typeof body === 'object' ? body : {};
  if (clean(b.website, 200)) return { ok: false, reason: 'honeypot' };
  const startedAt = Number(b.startedAt);
  if (!Number.isFinite(startedAt) || now - startedAt < MIN_FILL_MS) return { ok: false, reason: 'too_fast' };
  const data = {
    organization: clean(b.organization, LIMITS.organization), country: clean(b.country, LIMITS.country),
    servers: clean(b.servers, LIMITS.servers), email: clean(b.email, LIMITS.email).toLowerCase(),
    usage: cleanMultiline(b.usage, LIMITS.usage), lang: clean(b.lang, LIMITS.lang) === 'en' ? 'en' : 'pt',
    turnstile: String(b.turnstile ?? '').trim().slice(0, 2048)
  };
  if (!data.organization && !data.country && !data.servers && !data.email && !data.usage) return { ok: false, reason: 'invalid:empty' };
  if (data.email && !EMAIL.test(data.email)) return { ok: false, reason: 'invalid:email' };
  if (!data.turnstile) return { ok: false, reason: 'invalid:turnstile' };
  return { ok: true, data };
}

export function buildEmail(d, { to, from, when = new Date() }) {
  const lines = [
    'Novo registro voluntário de uso do RansomGuard', '',
    `Organização: ${d.organization || '-'}`, `País: ${d.country || '-'}`, `Servidores: ${d.servers || '-'}`,
    `E-mail para contato: ${d.email || '-'}`, '', 'Como usa:', d.usage || '-', '',
    `Idioma: ${d.lang}`, `Recebido em: ${when.toISOString()}`
  ];
  const mail = { from, to: [to], subject: `[Registro de uso RansomGuard] ${d.organization || d.country || 'sem organização'}`, text: lines.join('\n') };
  if (d.email) mail.reply_to = d.email;
  return mail;
}

function clientIp(req) {
  const xff = req.headers?.['x-forwarded-for'];
  return (Array.isArray(xff) ? xff[0] : String(xff || '')).split(',')[0].trim() || req.socket?.remoteAddress || '';
}

async function readJson(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch { return null; } }
  let raw = ''; for await (const chunk of req) { raw += chunk; if (raw.length > 64_000) return null; }
  try { return JSON.parse(raw || '{}'); } catch { return null; }
}

export function createHandler({ env = process.env, fetch = globalThis.fetch, rateLimit = { max: 5, windowMs: 10 * 60_000 }, now = () => Date.now() } = {}) {
  const hits = new Map();
  const limited = (ip) => {
    const t = now(); const list = (hits.get(ip) || []).filter((x) => t - x < rateLimit.windowMs);
    if (list.length >= rateLimit.max) { hits.set(ip, list); return true; }
    list.push(t); hits.set(ip, list); if (hits.size > 5000) hits.clear(); return false;
  };

  return async function handler(req, res) {
    res.setHeader('Cache-Control', 'no-store');
    const secret = env.TURNSTILE_SECRET_KEY, apiKey = env.RESEND_API_KEY;
    const configured = Boolean(secret && apiKey);
    // GET = sonda de prontidão: o site só mostra o formulário se o canal estiver inteiro (Turnstile + entrega).
    if (req.method === 'GET') return configured ? res.status(204).end() : res.status(503).json({ error: 'not_configured' });
    if (req.method !== 'POST') { res.setHeader('Allow', 'GET, POST'); return res.status(405).json({ error: 'method' }); }
    if (!configured) return res.status(503).json({ error: 'not_configured' });

    const body = await readJson(req);
    if (!body) return res.status(400).json({ error: 'invalid:body' });
    const v = validateSubmission(body, now());
    if (!v.ok) {
      if (v.reason === 'honeypot') return res.status(200).json({ ok: true }); // não ensina o bot
      return res.status(400).json({ error: v.reason });
    }
    const ip = clientIp(req);
    if (limited(ip)) return res.status(429).json({ error: 'rate_limit' });

    let captcha;
    try {
      const r = await fetch(TURNSTILE_URL, {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ secret, response: v.data.turnstile, remoteip: ip }).toString()
      });
      captcha = await r.json();
    } catch { return res.status(502).json({ error: 'captcha_unavailable' }); }
    if (!captcha?.success) return res.status(403).json({ error: 'captcha' });

    const mail = buildEmail(v.data, { to: env.REGISTER_TO || DEFAULT_TO, from: env.REGISTER_FROM || DEFAULT_FROM, when: new Date(now()) });
    try {
      const r = await fetch(RESEND_URL, { method: 'POST', headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify(mail) });
      if (!r.ok) return res.status(502).json({ error: 'delivery' });
    } catch { return res.status(502).json({ error: 'delivery' }); }
    return res.status(200).json({ ok: true });
  };
}

export default createHandler();
