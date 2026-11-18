// Testes da função serverless de registro voluntário de uso (node --test tests/api/).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateSubmission, buildEmail, createHandler } from '../../api/registro.mjs';

const good = () => ({
  organization: 'ACME Ltda', country: 'Brasil', servers: '12', email: 'ana@acme.com.br',
  usage: 'Dois servidores de arquivos em Monitor, um em Block.', website: '', startedAt: Date.now() - 10_000,
  turnstile: 'tok-ok', lang: 'pt'
});

test('aceita um registro completo', () => {
  const r = validateSubmission(good(), Date.now());
  assert.equal(r.ok, true);
  assert.equal(r.data.email, 'ana@acme.com.br');
});

test('todos os campos são opcionais, mas o registro não pode vir vazio', () => {
  const vazio = { ...good(), organization: '', country: '', servers: '', email: '', usage: '' };
  assert.equal(validateSubmission(vazio, Date.now()).reason, 'invalid:empty');
  assert.equal(validateSubmission({ ...vazio, country: 'Portugal' }, Date.now()).ok, true);
});

test('e-mail é opcional, mas se vier precisa ser válido', () => {
  assert.equal(validateSubmission({ ...good(), email: '' }, Date.now()).ok, true);
  assert.equal(validateSubmission({ ...good(), email: 'nao-e-email' }, Date.now()).reason, 'invalid:email');
});

test('honeypot, envio rápido demais e falta do token são recusados', () => {
  assert.equal(validateSubmission({ ...good(), website: 'http://spam' }, Date.now()).reason, 'honeypot');
  assert.equal(validateSubmission({ ...good(), startedAt: Date.now() - 500 }, Date.now()).reason, 'too_fast');
  assert.equal(validateSubmission({ ...good(), turnstile: '' }, Date.now()).reason, 'invalid:turnstile');
});

test('trunca campos longos e remove quebras de linha dos campos de cabeçalho', () => {
  const r = validateSubmission({ ...good(), organization: 'X'.repeat(500), country: 'BR\r\nBcc: x@y' }, Date.now());
  assert.equal(r.ok, true);
  assert.equal(r.data.organization.length, 120);
  assert.equal(r.data.country.includes('\n'), false);
});

test('o e-mail do registro só leva Reply-To quando a pessoa deixou um endereço', () => {
  const com = buildEmail(validateSubmission(good(), Date.now()).data, { to: 'dest@example.com', from: 'RansomGuard <x@y>' });
  assert.equal(com.to[0], 'dest@example.com');
  assert.equal(com.reply_to, 'ana@acme.com.br');
  assert.match(com.subject, /Registro de uso/);
  assert.match(com.subject, /ACME Ltda/);
  assert.match(com.text, /Servidores: 12/);
  const sem = buildEmail(validateSubmission({ ...good(), email: '' }, Date.now()).data, { to: 'dest@example.com', from: 'x' });
  assert.equal('reply_to' in sem, false);
});

test('o e-mail não leva IP nem navegador de quem registrou', () => {
  const m = buildEmail(validateSubmission(good(), Date.now()).data, { to: 'd@e.com', from: 'x' });
  assert.doesNotMatch(m.text, /IP:|User-Agent/);
});

function fakeReq(body, { method = 'POST', ip = '198.51.100.7' } = {}) {
  return { method, headers: { 'content-type': 'application/json', 'x-forwarded-for': ip, 'user-agent': 'test' }, body };
}
function fakeRes() {
  const r = { statusCode: 200, headers: {}, body: null };
  r.setHeader = (k, v) => { r.headers[k] = v; };
  r.status = (c) => { r.statusCode = c; return r; };
  r.json = (o) => { r.body = o; return r; };
  r.end = () => r;
  return r;
}
const envOk = { TURNSTILE_SECRET_KEY: 'ts', RESEND_API_KEY: 'rk', REGISTER_TO: 'dest@example.com' };
const none = async () => { throw new Error('não deve chamar'); };

test('falha fechado (503) sem segredos; GET é a sonda de prontidão', async () => {
  const r0 = fakeRes(); await createHandler({ env: {}, fetch: none })(fakeReq(good()), r0);
  assert.equal(r0.statusCode, 503);
  const r1 = fakeRes(); await createHandler({ env: envOk, fetch: none })(fakeReq(null, { method: 'GET' }), r1);
  assert.equal(r1.statusCode, 204);
  const r2 = fakeRes(); await createHandler({ env: envOk, fetch: none })(fakeReq(good(), { method: 'PUT' }), r2);
  assert.equal(r2.statusCode, 405);
});

test('verifica o Turnstile e entrega pelo Resend', async () => {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    if (url.includes('turnstile')) return { ok: true, json: async () => ({ success: true }) };
    return { ok: true, status: 200, json: async () => ({ id: 'em_1' }) };
  };
  const res = fakeRes(); await createHandler({ env: envOk, fetch })(fakeReq(good()), res);
  assert.equal(res.statusCode, 200, JSON.stringify(res.body));
  assert.match(calls[0].init.body, /secret=ts/);
  assert.equal(calls[1].init.headers.Authorization, 'Bearer rk');
  assert.equal(JSON.parse(calls[1].init.body).to[0], 'dest@example.com');
});

test('Turnstile reprovado não envia e-mail; honeypot responde 200 sem chamar nada', async () => {
  let sent = false;
  const fetch = async (url) => url.includes('turnstile')
    ? { ok: true, json: async () => ({ success: false }) }
    : (sent = true, { ok: true, json: async () => ({}) });
  const r1 = fakeRes(); await createHandler({ env: envOk, fetch })(fakeReq(good()), r1);
  assert.equal(r1.statusCode, 403); assert.equal(sent, false);
  const r2 = fakeRes(); await createHandler({ env: envOk, fetch: none })(fakeReq({ ...good(), website: 'spam' }), r2);
  assert.equal(r2.statusCode, 200);
});

test('limita envios por IP e não vaza detalhes quando a entrega falha', async () => {
  const ok = async (url) => ({ ok: true, status: 200, json: async () => (url.includes('turnstile') ? { success: true } : { id: 'x' }) });
  const h = createHandler({ env: envOk, fetch: ok, rateLimit: { max: 2, windowMs: 60_000 } });
  for (let i = 0; i < 2; i++) { const r = fakeRes(); await h(fakeReq(good()), r); assert.equal(r.statusCode, 200); }
  const r3 = fakeRes(); await h(fakeReq(good()), r3); assert.equal(r3.statusCode, 429);
  const bad = async (url) => url.includes('turnstile') ? { ok: true, json: async () => ({ success: true }) } : { ok: false, status: 500, json: async () => ({ message: 'segredo interno' }) };
  const r4 = fakeRes(); await createHandler({ env: envOk, fetch: bad })(fakeReq(good()), r4);
  assert.equal(r4.statusCode, 502); assert.equal(JSON.stringify(r4.body).includes('segredo'), false);
});
