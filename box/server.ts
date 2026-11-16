// The box as a process: the page its owner uses, one endpoint for devices, and one state file.
//   KEYKIN_DIR   where state.json lives (default ./box-data)
//   KEYKIN_ADDR  address to listen on (default 127.0.0.1; use the tailnet address to be reachable)
//   KEYKIN_PORT  port (default 7460)
// On its first start it prints the owner secret once. The owner logs in to the page with it.

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import { Box, type BoxState } from './box.ts';
import { loginPage, setupPage, devicesPage } from './page.ts';
import { randomBytes, bytesToHex, hexToBytes, sha, KeykinError } from '../src/bytes.ts';

const SESSION_SECONDS = 12 * 3600, MAX_FAILS = 5, FAIL_WINDOW = 60;

export function startBox(o: { dir: string; addr?: string; port?: number; log?: (s: string) => void }) {
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
  const html = (res: ServerResponse, status: number, body: string, nonce = '') => {
    res.writeHead(status, {
      'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer',
      'x-content-type-options': 'nosniff',
      'content-security-policy': `default-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; form-action 'self'; base-uri 'none'${nonce ? `; script-src 'nonce-${nonce}'` : ''}`,
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
      if (!s) return html(res, 200, loginPage({ error: url.searchParams.has('e') ? (url.searchParams.get('e') === 'wait' ? 'Too many tries. Wait a minute.' : 'That is not the owner secret.') : undefined }));
      if (!box.state.account) {
        const nonce = bytesToHex(randomBytes(16));
        // The QR names the address the owner's browser used, since a device can likely reach that too.
        const addr = req.headers.host ? `http://${req.headers.host}` : where();
        return html(res, 200, setupPage({ qrText: box.qr(addr)!, csrf: s.csrf, nonce }), nonce);
      }
      return html(res, 200, devicesPage({ account: box.state.account, csrf: s.csrf, notice: url.searchParams.get('n') ?? undefined }));
    }
    if (method === 'GET' && path === '/owner/state') return s ? json(res, 200, { account: !!box.state.account }) : json(res, 401, { error: 'login' });

    if (method === 'POST' && path === '/login') {
      const form = new URLSearchParams(await readBody(req, 4096));
      const t = nowS();
      fails = fails.filter((x) => t - x < FAIL_WINDOW);
      if (fails.length >= MAX_FAILS) return go(res, '/?e=wait');
      const given = sha('keykin2-owner', form.get('secret')?.trim() ?? '');
      if (!timingSafeEqual(given, hexToBytes(box.state.owner!))) { fails.push(t); return go(res, '/?e=1'); }
      const token = bytesToHex(randomBytes(32));
      sessions.set(token, { until: t + SESSION_SECONDS, csrf: bytesToHex(randomBytes(16)) });
      return go(res, '/', `kk=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_SECONDS}`);
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
  startBox({ dir: process.env.KEYKIN_DIR ?? './box-data', addr: process.env.KEYKIN_ADDR, port: Number(process.env.KEYKIN_PORT ?? 7460) });
}
