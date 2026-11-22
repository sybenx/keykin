// Keykin Login: the public door. It serves the account page and passes two kinds of thing to the box,
// and nothing else: devices' signed requests (POST /keykin) and the account page's calls (POST /api).
// It holds no piece, no device list and no account data. Stopping it shuts the outside door; the box,
// the admin page and devices on the private network carry on.
//
//   KEYKIN_BOX          the box's side door, for example http://keykin-box_server_1:7461
//   KEYKIN_LOGIN_ADDR   address to listen on (default 127.0.0.1)
//   KEYKIN_LOGIN_PORT   port (default 7470)
//   KEYKIN_HOME_URL     the DMs home (bothy) this box is the back room of, for example https://home.example/.
//                       Unset: no Home section, and the page's headers are as before.
//   KEYKIN_STORAGE_URL  that home's file server (Keykin Storage), for example https://files.example. Optional. A
//                       second box's file server can follow after a comma.
//
// With a home set, the page calls the home and its file server itself, signed by the person's phone (the signer a
// scan leaves). This server only names those two hosts in the page's connect-src; it signs and passes on nothing.

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import qrcode from 'qrcode-generator';
import { npubEncode } from 'nostr-tools/nip19';

const STATIC = join(import.meta.dirname, 'static');
const FILES: Record<string, [string, string]> = {
  '/': ['account.html', 'text/html; charset=utf-8'],
  '/account.js': ['account.js', 'text/javascript; charset=utf-8'],
  '/rows.js': ['rows.js', 'text/javascript; charset=utf-8'],              // the Sites and apps detail line (SPEC 11.5)
  '/account.css': ['account.css', 'text/css; charset=utf-8'],
  '/signin.js': ['signin.js', 'text/javascript; charset=utf-8'],
  '/pointer.js': ['pointer.js', 'text/javascript; charset=utf-8'],         // the login-page pointer's rules (SPEC 11.1)          // sign-in by a scanned code, the same widget any site uses (site/signin.ts)
  '/home.js': ['home.js', 'text/javascript; charset=utf-8'],               // the Home section's calls and rules: the DMs home and its file server
};
// The only calls the page may make. A signed-in page has the person's authority (SPEC 11.6), but it still
// holds no piece: anything that needs a signature is left as a note for a device to do.
const NEED_SESSION = new Set(['me', 'block', 'unblock', 'revoke', 'limit', 'scopes', 'pw_set', 'pw_clear', 'logout', 'logout_all', 'logout_browser', 'note_put', 'note_get', 'protect', 'pk_add_start', 'pk_add', 'pk_remove']);
const OPEN = new Set(['pw_salt', 'pw_login', 'login_start', 'login_wait', 'signin_start', 'signin', 'pk_login_start', 'pk_login']);
/** Where the page and a phone meet for sign-in by a scanned code, unless KEYKIN_RELAYS says otherwise. */
const RELAYS = ['wss://syb.lol', 'wss://nos.lol', 'wss://relay.primal.net'];
// A passkey's session lasts 90 days from its last use, so its cookie is renewed whenever the page loads; a password's or a scan's lasts 12 hours (SPEC 11.6).
const SESSION_SECONDS = 12 * 3600, PASSKEY_SECONDS = 90 * 86400, LOGIN_SECONDS = 180;
const PER_MINUTE = 240;          // requests from one address, both paths together
// How long the box may take: a device's notes_wait is held up to 25 seconds, so devices get 35. Keep this
// under the reverse proxy's read timeout (often 60 seconds).
const DEVICE_MS = 35_000, PAGE_MS = 20_000;

/**
 * A home or file server address from the settings: https (or http on this machine, for tests), no user, query or
 * fragment. The home keeps its path with one trailing slash, since NIP-98's `u` must be that exact URL; the file
 * server is an origin plus an optional path, without the trailing slash. Throws on anything else, so a typo stops
 * the start instead of quietly leaving the page without its Home section.
 */
export function placeOf(raw: string | undefined, what: 'home' | 'storage'): { url: string; origin: string } | null {
  if (!raw?.trim()) return null;
  let u: URL;
  try { u = new URL(raw.trim()); } catch { throw new Error(`${what}: not a URL: ${raw}`); }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) throw new Error(`${what}: must be https: ${raw}`);
  if (u.username || u.password || u.search || u.hash) throw new Error(`${what}: no user, query or fragment: ${raw}`);
  const path = u.pathname.replace(/\/+$/, '');
  return { url: what === 'home' ? `${u.origin}${path}/` : `${u.origin}${path}`, origin: u.origin };
}

export function startLogin(o: { box: string; addr?: string; port?: number; relays?: string[]; home?: string; storage?: string; log?: (s: string) => void }) {
  const log = o.log ?? console.log;
  const relays = o.relays?.length ? o.relays : RELAYS;
  const home = placeOf(o.home, 'home');
  const files = home ? (o.storage ?? '').split(',').map((x) => placeOf(x, 'storage')).filter((x): x is { url: string; origin: string } => !!x) : [];
  // The extra hosts the page may call, and only with a home set: the home (its http side, for NIP-86) and its file servers.
  const homeHosts = [home?.origin, ...files.map((f) => f.origin)].filter((x): x is string => !!x && !relays.some((r) => r.replace(/^ws/, 'http').replace(/\/+$/, '') === x));
  // `storage` is the first file server, for pages that know only one; `files` is the list.
  const homeInfo = home ? { url: home.url, storage: files[0]?.url ?? null, files: [...new Set(files.map((f) => f.url))] } : null;
  const hits = new Map<string, number[]>();
  const tooFast = (req: IncomingMessage) => {
    const who = String(req.headers['cf-connecting-ip'] ?? req.headers['x-forwarded-for'] ?? req.socket.remoteAddress ?? '').split(',')[0].trim();
    const t = Date.now(), list = (hits.get(who) ?? []).filter((x) => t - x < 60_000);
    list.push(t); hits.set(who, list);
    if (hits.size > 5000) for (const [k, v] of hits) if (!v.length || t - v[v.length - 1] > 60_000) hits.delete(k);
    return list.length > PER_MINUTE;
  };
  const readBody = (req: IncomingMessage, max = 256 * 1024) => new Promise<string>((resolve, reject) => {
    const chunks: Buffer[] = []; let size = 0;
    req.on('data', (c: Buffer) => { size += c.length; if (size > max) { reject(new Error('too big')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
  // `from` tells the box which https origin this page was reached at. The box only shows it to its admin as a
  // suggestion for its login page address; it trusts nothing by it. A device's request may be a notes_wait, which
  // the box holds for up to 25 seconds (SPEC 11.6), so devices get longer than the page. `gone` ends the request
  // at the box when the device goes away first.
  const toBoxFrom = async (path: '/keykin' | '/page', body: unknown, from?: string, gone?: AbortSignal) => {
    const late = AbortSignal.timeout(path === '/keykin' ? DEVICE_MS : PAGE_MS);
    return (await fetch(o.box + path, { method: 'POST', body: JSON.stringify(body), headers: { 'content-type': 'application/json', connection: 'close', ...(from ? { 'x-keykin-origin': from } : {}) }, signal: gone ? AbortSignal.any([late, gone]) : late })).json() as Promise<any>;
  };
  const cookieOf = (req: IncomingMessage, name: string, len: number) => new RegExp(`(?:^|;\\s*)${name}=([0-9a-f]{${len}})(?:;|$)`).exec(req.headers.cookie ?? '')?.[1];
  const json = (res: ServerResponse, status: number, body: unknown, cookies: string[] = []) => {
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...(cookies.length ? { 'set-cookie': cookies } : {}) });
    res.end(JSON.stringify(body));
  };

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const path = new URL(req.url ?? '/', 'http://login').pathname, method = req.method ?? 'GET';
    // Cookies are marked Secure whenever the page was reached over https (through the reverse proxy).
    const https = req.headers['x-forwarded-proto'] === 'https' || (req.socket as any).encrypted;
    const cookie = (name: string, value: string, age: number) => `${name}=${value}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${age}${https ? '; Secure' : ''}`;
    // A passkey's relying party is this page's own host, taken from the request, never from the page.
    const origin = `${https ? 'https' : 'http'}://${req.headers.host ?? ''}`;
    const toBox = (path: '/keykin' | '/page', body: unknown, gone?: AbortSignal) => toBoxFrom(path, body, https ? origin : undefined, gone);
    // The browser as this door saw it, for the signed-in browsers list. Whatever the page sends is ignored.
    const agent = String(req.headers['user-agent'] ?? '').slice(0, 200);

    if (method === 'GET' && FILES[path]) {
      const [file, type] = FILES[path];
      // The page reaches its relays, and asks each what it is over http(s) first (NIP-11). Nothing else.
      const local = ' ' + relays.map((r) => r.replace(/^ws/, 'http').replace(/\/+$/, '')).join(' ') + (relays.some((r) => r.startsWith('ws://')) ? ' ws:' : '') + [...new Set(homeHosts)].map((h) => ' ' + h).join('');
      res.writeHead(200, {
        'content-type': type, 'cache-control': 'no-cache', 'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer',
        'content-security-policy': `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' wss:${local}; img-src 'self' data: https:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'`,
      });
      return void res.end(readFileSync(join(STATIC, file)));
    }
    if (method !== 'POST' || (path !== '/keykin' && path !== '/api')) { res.writeHead(404, { 'content-type': 'text/plain' }); return void res.end('Not found\n'); }
    if (tooFast(req)) return json(res, 429, { error: 'slow_down' });
    let body: any;
    try { body = JSON.parse(await readBody(req)); } catch { return json(res, 400, { error: 'bad_json' }); }

    // Devices: passed through untouched. The box checks every signature.
    if (path === '/keykin') {
      const gone = new AbortController(), away = () => gone.abort();
      res.on('close', away);
      try { return json(res, 200, await toBox('/keykin', body, gone.signal)); }
      catch { if (!res.destroyed) return json(res, 502, { error: 'no_box' }); }
      finally { res.off('close', away); }
      return;
    }

    // The account page. Only a page from this origin can send this header, so another site cannot make these calls for someone.
    if (req.headers['x-keykin'] !== '1') return json(res, 403, { error: 'forbidden' });
    const call = body?.call;
    if (!OPEN.has(call) && !NEED_SESSION.has(call)) return json(res, 400, { error: 'unknown_call' });
    try {
      if (call === 'pw_salt') return json(res, 200, await toBox('/page', { call, username: body.username }));
      if (call === 'pw_login') {
        const r = await toBox('/page', { call, username: body.username, verifier: body.verifier, agent });
        return r.session ? json(res, 200, { ok: true }, [cookie('ks', r.session, SESSION_SECONDS)]) : json(res, 200, r);
      }
      if (call === 'signin_start') {
        const r = await toBox('/page', { call });
        return json(res, 200, r.ok ? { ...r, relays } : r);
      }
      if (call === 'pk_login_start') return json(res, 200, await toBox('/page', { call, origin }));
      if (call === 'pk_login') {
        const r = await toBox('/page', { call, origin, response: body.response, session: cookieOf(req, 'ks', 64), agent });
        return r.session ? json(res, 200, { ok: true }, [cookie('ks', r.session, PASSKEY_SECONDS)]) : json(res, 200, r);
      }
      if (call === 'signin') {
        // A scan made while signed in with a password confirms that session: the box swaps it for a strong one.
        const r = await toBox('/page', { call, event: body.event, session: cookieOf(req, 'ks', 64), agent });
        return r.session ? json(res, 200, { ok: true }, [cookie('ks', r.session, SESSION_SECONDS)]) : json(res, 200, r);
      }
      if (call === 'login_start') {
        const browser = cookieOf(req, 'kl', 32) ?? randomBytes(16).toString('hex');
        const r = await toBox('/page', { call, browser });
        if (!r.ok) return json(res, 200, r);
        const qr = qrcode(0, 'M'); qr.addData(r.text); qr.make();
        return json(res, 200, { ok: true, code: r.code, text: r.text, svg: qr.createSvgTag({ cellSize: 4, margin: 0, scalable: true }) }, [cookie('kl', browser, LOGIN_SECONDS)]);
      }
      if (call === 'login_wait') {
        const r = await toBox('/page', { call, code: body.code, browser: cookieOf(req, 'kl', 32), agent });
        return r.session ? json(res, 200, { ok: true }, [cookie('ks', r.session, SESSION_SECONDS), cookie('kl', '', 0)]) : json(res, 200, r);
      }
      const session = cookieOf(req, 'ks', 64);
      if (!session) return json(res, 200, { error: 'login' });
      const { call: _c, session: _s, browser: _b, agent: _a, ...rest } = body;
      const r = await toBox('/page', { ...rest, call, session, ...(call.startsWith('pk_') ? { origin } : {}) });
      if (call === 'me' && r.ok) { r.npubText = npubEncode(r.npub); r.relays = relays; if (homeInfo && r.held !== false) r.home = homeInfo; }
      if (call === 'protect' && r.ok) { const qr = qrcode(0, 'M'); qr.addData(r.text); qr.make(); r.svg = qr.createSvgTag({ cellSize: 4, margin: 0, scalable: true }); }
      const gone = call === 'logout' || call === 'logout_all' || (call === 'logout_browser' && r.this === true) || r.error === 'login';
      const renew = call === 'me' && r.ok && r.how === 'passkey';
      return json(res, 200, r, gone ? [cookie('ks', '', 0)] : renew ? [cookie('ks', session, PASSKEY_SECONDS)] : []);
    } catch { return json(res, 502, { error: 'no_box' }); }
  }

  const server = createServer((req, res) => { route(req, res).catch((e) => { log(`keykin login: ${String(e)}`); if (!res.headersSent) res.writeHead(500); res.end(); }); });
  return new Promise<{ server: typeof server; port: number; close: () => Promise<void> }>((resolve) => {
    server.listen(o.port ?? 7470, o.addr ?? '127.0.0.1', () => {
      const port = (server.address() as any).port;
      log(`keykin login: account page on port ${port}, box at ${o.box}${home ? `, home ${home.url}${files.length ? `, file servers ${files.map((f) => f.url).join(' ')}` : ''}` : ''}`);
      resolve({ server, port, close: () => new Promise<void>((done) => { server.close(() => done()); server.closeAllConnections(); }) });
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const e = process.env;
  if (!e.KEYKIN_BOX) { console.error('Set KEYKIN_BOX to the box\'s side door, for example http://127.0.0.1:7461'); process.exit(1); }
  startLogin({ box: e.KEYKIN_BOX.replace(/\/+$/, ''), addr: e.KEYKIN_LOGIN_ADDR, port: Number(e.KEYKIN_LOGIN_PORT ?? 7470),
    relays: e.KEYKIN_RELAYS?.split(',').map((r) => r.trim()).filter(Boolean), home: e.KEYKIN_HOME_URL, storage: e.KEYKIN_STORAGE_URL });
}
