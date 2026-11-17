// The box as a process: the page its owner uses, one endpoint for devices, and one state file.
//   KEYKIN_DIR   where state.json lives (default ./box-data)
//   KEYKIN_ADDR  address to listen on (default 127.0.0.1; use the tailnet address to be reachable)
//   KEYKIN_PORT  port (default 7460)
//   KEYKIN_RELAYS  relays (comma separated, wss://) the box page uses for sign-in by a scanned code (QRST).
//                  Without any, the page falls back to its own scan-to-log-in.
// On its first start it prints the owner secret once. The owner logs in to the page with it.

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import { Box, type BoxState } from './box.ts';
import { loginPage, setupPage, devicesPage } from './page.ts';
import { randomBytes, bytesToHex, hexToBytes, sha, KeykinError } from '../src/bytes.ts';
import { verifyEvent } from 'nostr-tools/pure';
import { fileURLToPath } from 'node:url';

const SESSION_SECONDS = 12 * 3600, MAX_FAILS = 5, FAIL_WINDOW = 60;

export function startBox(o: { dir: string; addr?: string; port?: number; relays?: string[]; log?: (s: string) => void }) {
  const relays = (o.relays ?? []).filter(Boolean);
  const signinJs = join(fileURLToPath(new URL('.', import.meta.url)), 'static/signin.js');
  const log = o.log ?? console.log;
  mkdirSync(o.dir, { recursive: true, mode: 0o700 });
  const file = join(o.dir, 'state.json');
  const state: BoxState | null = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : null;
  const box = new Box(state);
  const save = (s: BoxState) => { writeFileSync(file + '.tmp', JSON.stringify(s, null, 2), { mode: 0o600 }); renameSync(file + '.tmp', file); };
  box.onChange = save;

  // The owner secret is shown once, here. Only its hash is kept.
  let ownerSecret: string | null = null;
  if (!box.state.owner) {
    ownerSecret = bytesToHex(randomBytes(16)).match(/.{4}/g)!.join('-');
    box.state.owner = bytesToHex(sha('keykin2-owner', ownerSecret));
    log(`keykin box: owner secret (shown once, keep it): ${ownerSecret}`);
  }
  if (!state || ownerSecret) save(box.state);

  const sessions = new Map<string, { until: number; csrf: string }>();
  let fails: number[] = [];
  // Logins waiting for a device to scan them: the code in the QR, tied to the browser that was shown it.
  const logins = new Map<string, { until: number; browser: string; approved: boolean }>();
  const LOGIN_SECONDS = 180;
  box.onLogin = (code, by) => {
    const l = logins.get(code);
    if (!l || l.until < nowS()) return false;
    l.approved = true; log(`keykin box: login approved by ${by}`);
    return true;
  };
  const newSession = (t: number) => { const token = bytesToHex(randomBytes(32)); sessions.set(token, { until: t + SESSION_SECONDS, csrf: bytesToHex(randomBytes(16)) }); return `kk=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_SECONDS}`; };
  const nowS = () => Math.floor(Date.now() / 1000);
  const where = () => `http://${o.addr ?? '127.0.0.1'}:${(server.address() as any).port}`;

  const session = (req: IncomingMessage) => {
    const m = /(?:^|;\s*)kk=([0-9a-f]{64})/.exec(req.headers.cookie ?? '');
    const s = m && sessions.get(m[1]);
    if (!s || !m) return null;
    if (s.until < nowS()) { sessions.delete(m[1]); return null; }
    return { token: m[1], ...s };
  };
  const readBody = (req: IncomingMessage, max = 256 * 1024) => new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = []; let size = 0;
    req.on('data', (c: Buffer) => { size += c.length; if (size > max) { reject(new Error('too big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
  // Challenges the account signs to log this browser in after a QRST sign-in: tied to the browser, used once.
  const challenges = new Map<string, { until: number; browser: string }>();
  const browserOf = (req: IncomingMessage) => /(?:^|;\s*)kkl=([0-9a-f]{32})/.exec(req.headers.cookie ?? '')?.[1];
  const html = (res: ServerResponse, status: number, body: string, nonce = '', cookie?: string) => {
    res.writeHead(status, {
      ...(cookie ? { 'set-cookie': cookie } : {}),
      'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer',
      'x-content-type-options': 'nosniff',
      'content-security-policy': `default-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'${relays.length ? ' wss: ws:' : ''}; form-action 'self'; base-uri 'none'${nonce === 'self' ? `; script-src 'self'` : nonce ? `; script-src 'nonce-${nonce}'` : ''}`,
    });
    res.end(body);
  };
  const json = (res: ServerResponse, status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' }); res.end(JSON.stringify(body)); };
  const go = (res: ServerResponse, to: string, cookie?: string) => { res.writeHead(303, { location: to, ...(cookie ? { 'set-cookie': cookie } : {}) }); res.end(); };

  async function route(req: IncomingMessage, res: ServerResponse) {
    const url = new URL(req.url ?? '/', 'http://box');
    const path = url.pathname, method = req.method ?? 'GET';

    // Devices.
    if (method === 'POST' && path === '/keykin') {
      let parsed: any;
      try { parsed = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: 'bad_json' }); }
      return json(res, 200, box.handle(parsed, nowS()));
    }

    // The owner's page.
    const s = session(req);
    if (method === 'GET' && path === '/') {
      if (!s) {
        const error = url.searchParams.has('e') ? (url.searchParams.get('e') === 'wait' ? 'Too many tries. Wait a minute.' : 'That is not the owner secret.') : undefined;
        if (!box.state.account) return html(res, 200, loginPage({ error }));
        if (relays.length && existsSync(signinJs)) {
          const browser = bytesToHex(randomBytes(16));
          return html(res, 200, loginPage({ error, relays }), 'self', `kkl=${browser}; HttpOnly; SameSite=Strict; Path=/login; Max-Age=900`);
        }
        // With an account, a device in it can log this browser in by scanning a code.
        const t = nowS();
        for (const [k, l] of logins) if (l.until < t) logins.delete(k);
        if (logins.size > 200) return html(res, 200, loginPage({ error }));
        const code = bytesToHex(randomBytes(16)), browser = bytesToHex(randomBytes(16)), nonce = bytesToHex(randomBytes(16));
        logins.set(code, { until: t + LOGIN_SECONDS, browser, approved: false });
        const addr = req.headers.host ? `http://${req.headers.host}` : where();
        const qrText = JSON.stringify({ keykin: 2, login: { addr, key: box.state.key, code } });
        return html(res, 200, loginPage({ error, qrText, code, nonce }), nonce, `kkl=${browser}; HttpOnly; SameSite=Strict; Path=/login; Max-Age=${LOGIN_SECONDS}`);
      }
      if (!box.state.account) {
        const nonce = bytesToHex(randomBytes(16));
        // The QR names the address the owner's browser used, since a device can likely reach that too.
        const addr = req.headers.host ? `http://${req.headers.host}` : where();
        return html(res, 200, setupPage({ qrText: box.qr(addr)!, csrf: s.csrf, nonce }), nonce);
      }
      return html(res, 200, devicesPage({ account: box.state.account, csrf: s.csrf, notice: url.searchParams.get('n') ?? undefined }));
    }
    if (method === 'GET' && path === '/signin.js' && existsSync(signinJs)) {
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
      return void res.end(readFileSync(signinJs));
    }
    if (method === 'POST' && path === '/login/challenge') {
      const browser = browserOf(req);
      if (!browser || !box.state.account) return json(res, 400, { error: 'no_browser' });
      const t = nowS();
      for (const [k, c] of challenges) if (c.until < t) challenges.delete(k);
      if (challenges.size > 500) return json(res, 429, { error: 'busy' });
      const challenge = bytesToHex(randomBytes(16));
      challenges.set(challenge, { until: t + 120, browser });
      return json(res, 200, { challenge });
    }
    if (method === 'POST' && path === '/login/nostr') {
      let ev: any; try { ev = JSON.parse(await readBody(req, 16 * 1024)).event; } catch { return json(res, 400, { error: 'bad_json' }); }
      const t = nowS(), tag = (n: string) => Array.isArray(ev?.tags) ? ev.tags.find((x: any) => Array.isArray(x) && x[0] === n)?.[1] : undefined;
      const c = challenges.get(String(tag('challenge')));
      // The account itself must have signed this box's own challenge, for this browser, just now.
      if (!c || c.until < t || c.browser !== browserOf(req)) return json(res, 403, { error: 'bad_challenge' });
      challenges.delete(String(tag('challenge')));
      if (ev.kind !== 22242 || typeof ev.created_at !== 'number' || Math.abs(t - ev.created_at) > 120 || !verifyEvent(ev)) return json(res, 403, { error: 'bad_event' });
      if (req.headers.origin && tag('relay') !== req.headers.origin) return json(res, 403, { error: 'bad_event' });
      if (ev.pubkey !== box.state.account?.npub) return json(res, 403, { error: 'wrong_account' });
      log('keykin box: login by the account, through its signer');
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store', 'set-cookie': newSession(t) });
      return void res.end(JSON.stringify({ ok: true }));
    }
    if (method === 'GET' && path === '/login/wait') {
      const l = logins.get(url.searchParams.get('code') ?? '');
      const browser = /(?:^|;\s*)kkl=([0-9a-f]{32})/.exec(req.headers.cookie ?? '')?.[1];
      if (!l || l.until < nowS() || l.browser !== browser) return json(res, 404, { error: 'gone' });
      if (!l.approved) return json(res, 200, { ok: false });
      logins.delete(url.searchParams.get('code')!);
      res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store', 'set-cookie': newSession(nowS()) });
      return void res.end(JSON.stringify({ ok: true }));
    }
    if (method === 'GET' && path === '/owner/state') return s ? json(res, 200, { account: !!box.state.account }) : json(res, 401, { error: 'login' });

    if (method === 'POST' && path === '/login') {
      const form = new URLSearchParams(await readBody(req, 4096));
      const t = nowS();
      fails = fails.filter((x) => t - x < FAIL_WINDOW);
      if (fails.length >= MAX_FAILS) return go(res, '/?e=wait');
      const given = sha('keykin2-owner', form.get('secret')?.trim() ?? '');
      if (!timingSafeEqual(given, hexToBytes(box.state.owner!))) { fails.push(t); return go(res, '/?e=1'); }
      return go(res, '/', newSession(t));
    }
    if (method === 'POST' && (path === '/logout' || path === '/owner/block' || path === '/owner/unblock')) {
      if (!s) return go(res, '/');
      const form = new URLSearchParams(await readBody(req, 4096));
      if (form.get('csrf') !== s.csrf) return html(res, 403, loginPage({ error: 'That page was out of date. Log in again.' }));
      if (path === '/logout') { sessions.delete(s.token); return go(res, '/', 'kk=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); }
      try {
        const key = form.get('key') ?? '';
        const name = box.state.account?.members.find((m) => m.key === key)?.name ?? 'Device';
        if (path === '/owner/block') { box.ownerBlock(key); log(`keykin box: owner blocked ${name}`); return go(res, `/?n=${encodeURIComponent(`${name} is blocked.`)}`); }
        box.ownerUnblock(key); log(`keykin box: owner unblocked ${name}`);
        return go(res, `/?n=${encodeURIComponent(`${name} is unblocked.`)}`);
      } catch (e) { if (e instanceof KeykinError) return go(res, `/?n=${encodeURIComponent('That did not work: ' + e.code)}`); throw e; }
    }
    res.writeHead(404, { 'content-type': 'text/plain' }); res.end('Not found\n');
  }

  const server = createServer((req, res) => {
    route(req, res).catch((e) => { log(`keykin box: ${String(e)}`); if (!res.headersSent) res.writeHead(500); res.end(); });
  });
  return new Promise<{ server: typeof server; box: Box; port: number; qr: () => string | null; ownerSecret: string | null }>((resolve) => {
    server.listen(o.port ?? 7460, o.addr ?? '127.0.0.1', () => {
      const port = (server.address() as any).port;
      log(`keykin box: page and devices on ${where()}`);
      resolve({ server, box, port, qr: () => box.qr(where()), ownerSecret });
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startBox({ dir: process.env.KEYKIN_DIR ?? './box-data', addr: process.env.KEYKIN_ADDR, port: Number(process.env.KEYKIN_PORT ?? 7460), relays: (process.env.KEYKIN_RELAYS ?? '').split(',').map((r) => r.trim()) });
}
