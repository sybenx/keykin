// The box as a process. One state file, and two doors:
//
//   the main port   the admin page, plus the two things devices and the account page need
//                   (POST /keykin and POST /page). Put it on a private network only.
//   the side port   only POST /keykin and POST /page. This is what Keykin Login talks to. The
//                   admin page does not exist on it.
//
//   KEYKIN_DIR           where state.json lives (default ./box-data)
//   KEYKIN_ADDR          address to listen on (default 127.0.0.1; use the tailnet address to be reachable)
//   KEYKIN_PORT          the main port (default 7460)
//   KEYKIN_SIDE_PORT     the side port (default: none)
//   KEYKIN_URL           the address devices reach this box at, for the codes its pages show. With Keykin
//                        Login in front, this is the public address. Otherwise the admin page uses the
//                        address the browser used.
//   KEYKIN_POLICY        JSON that overrides the account page's policy (SPEC 11.6), e.g.
//                        {"calls":{"note_put:invite":"any"},"weakSiteLimit":"posts"}
//   KEYKIN_LOGIN_URL     the login page's origin (https://, nothing after), when Keykin Login is in front. The box's
//                        codes carry it, so the device that scans one publishes the account's login-page pointer.
//                        Usually set on the admin page instead ("Your login page address"); this overrides that.
//   KEYKIN_OPEN          set to 1 to let anyone who signs in on the account page bring their account onto this
//                        box. Without it, a new account needs a code from the admin page or the admin's approval.
//   KEYKIN_BEHIND_LOGIN  set to 1 when something in front of the admin page already asks who you are (the
//                        Umbrel login, say). The page then asks for nothing itself and makes no owner
//                        secret. Use it only when the page cannot be reached any other way.
// On its first start it prints the owner secret once, and leaves it in owner-secret.txt beside the state.

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { timingSafeEqual } from 'node:crypto';
import { Box, loginOrigin, type BoxState } from './box.ts';
import { PageApi } from './pageapi.ts';
import { loginPage, codePage, adminPage } from './page.ts';
import { randomBytes, bytesToHex, hexToBytes, sha, KeykinError } from '../src/bytes.ts';

const SESSION_SECONDS = 12 * 3600, MAX_FAILS = 5, FAIL_WINDOW = 60;

export function startBox(o: { dir: string; addr?: string; port?: number; sidePort?: number; url?: string; behindLogin?: boolean; open?: boolean; login?: string; policy?: ConstructorParameters<typeof PageApi>[3]; log?: (s: string) => void }) {
  const log = o.log ?? console.log;
  mkdirSync(o.dir, { recursive: true, mode: 0o700 });
  const file = join(o.dir, 'state.json');
  const state: BoxState | null = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : null;
  const box = new Box(state);
  if (o.login !== undefined) { box.fixedLogin = loginOrigin(o.login) ?? undefined; if (!box.fixedLogin) throw new Error(`KEYKIN_LOGIN_URL must be https:// and a host, nothing after: ${o.login}`); }
  const save = (s: BoxState) => { writeFileSync(file + '.tmp', JSON.stringify(s, null, 2), { mode: 0o600 }); renameSync(file + '.tmp', file); };
  box.onChange = save;
  const nowS = () => Math.floor(Date.now() / 1000);
  const where = (): string => `http://${o.addr ?? '127.0.0.1'}:${(server.address() as any).port}`;
  const page = new PageApi(box, () => o.url || where(), () => !!o.open, o.policy ?? {});

  // The owner secret is shown once, here. Only its hash is kept.
  let ownerSecret: string | null = null;
  if (!box.state.owner && !o.behindLogin) {
    ownerSecret = bytesToHex(randomBytes(16)).match(/.{4}/g)!.join('-');
    box.state.owner = bytesToHex(sha('keykin2-owner', ownerSecret));
    log(`keykin box: owner secret (shown once, keep it): ${ownerSecret}`);
    // Also left in a file only the box's own user can read, for a box whose output is hard to get at
    // (a container). Delete it once the secret is kept somewhere else.
    writeFileSync(join(o.dir, 'owner-secret.txt'), ownerSecret + '\n', { mode: 0o600 });
  }
  save(box.state);          // also rewrites an older state file in today's shape

  const sessions = new Map<string, { until: number; csrf: string }>();
  let fails: number[] = [];
  // Behind someone else's login, whoever gets through is the admin. The form token still guards every button.
  const proxied = { token: 'behind-login', until: Infinity, csrf: bytesToHex(randomBytes(16)) };
  const session = (req: IncomingMessage) => {
    if (o.behindLogin) return proxied;
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
  const told = (res: ServerResponse, text: string) => go(res, `/?n=${encodeURIComponent(text)}`);

  // What both doors answer: devices' signed requests, and the account page's calls.
  let sideSeen = 0;      // when something last came in by the side door: Keykin Login is alive
  let sideOrigin: string | undefined;   // the https origin Keykin Login says it served, only ever a suggestion for the admin
  async function shared(req: IncomingMessage, res: ServerResponse, path: string): Promise<boolean> {
    if (req.method !== 'POST' || (path !== '/keykin' && path !== '/page')) return false;
    let parsed: any;
    try { parsed = JSON.parse(await readBody(req)); } catch { json(res, 400, { error: 'bad_json' }); return true; }
    json(res, 200, path === '/keykin' ? box.handle(parsed, nowS()) : await page.request(parsed, nowS()));
    return true;
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://box');
    const path = url.pathname, method = req.method ?? 'GET';
    if (await shared(req, res, path)) return;

    // The admin page.
    const s = session(req);
    const whereIs = { host: (req.headers.host ?? 'This box').replace(/:\d+$/, ''), behindLogin: !!o.behindLogin };
    const addr = (): string => o.url || (req.headers.host ? `http://${req.headers.host}` : where());
    // An address to suggest for the login page, never used until the admin saves it.
    const visited = req.headers['x-forwarded-proto'] === 'https' || (req.socket as any).encrypted ? loginOrigin(`https://${(req.headers.host ?? '').toLowerCase()}`) : null;
    const suggest = visited ? { addr: visited, from: 'here' as const } : sideOrigin ? { addr: sideOrigin, from: 'login' as const } : undefined;
    if (method === 'GET' && path === '/') {
      if (!s) return html(res, 200, loginPage({ error: url.searchParams.has('e') ? (url.searchParams.get('e') === 'wait' ? 'Too many tries. Wait a minute.' : 'That is not the owner secret.') : undefined }));
      const first = box.qr(addr());
      if (first) { const nonce = bytesToHex(randomBytes(16)); return html(res, 200, codePage({ qrText: first, csrf: s.csrf, nonce, logout: !o.behindLogin, first: true, count: 0, where: whereIs }), nonce); }
      return html(res, 200, adminPage({ accounts: box.accounts(), requests: Object.values(box.state.requests), boxKey: box.state.key, csrf: s.csrf, notice: url.searchParams.get('n') ?? undefined, logout: !o.behindLogin, where: whereIs,
        door: { url: o.url, seen: sideSeen, side: o.sidePort !== undefined }, now: nowS(),
        loginPage: { addr: box.login, fixed: !!box.fixedLogin, suggest: suggest?.addr === box.login ? undefined : suggest } }));
    }
    if (method === 'GET' && path === '/admin/state') return s ? json(res, 200, { accounts: box.accounts().length }) : json(res, 401, { error: 'login' });

    if (method === 'POST' && path === '/login') {
      if (o.behindLogin) return go(res, '/');
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
    if (method === 'POST' && (path === '/logout' || path.startsWith('/admin/'))) {
      if (!s) return go(res, '/');
      const form = new URLSearchParams(await readBody(req, 4096));
      if (form.get('csrf') !== s.csrf) return html(res, 403, loginPage({ error: 'That page was out of date. Open the box page again.' }));
      if (path === '/logout') { if (o.behindLogin) return go(res, '/'); sessions.delete(s.token); return go(res, '/', 'kk=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'); }
      try {
        const key = form.get('key') ?? '', account = form.get('account') ?? undefined, id = form.get('id') ?? '';
        const nameOf = () => box.accounts().flatMap((a) => a.members).find((m) => m.key === key)?.name ?? 'Device';
        switch (path) {
          case '/admin/block': { const n = nameOf(); box.ownerBlock(key, account); log(`keykin box: admin blocked ${n}`); return told(res, `${n} is blocked.`); }
          case '/admin/unblock': { const n = nameOf(); box.ownerUnblock(key, account); log(`keykin box: admin unblocked ${n}`); return told(res, `${n} is unblocked.`); }
          case '/admin/approve': { const n = box.state.requests[id]?.name ?? 'That device'; box.decide(id, true, nowS()); log(`keykin box: admin approved ${n}`); return told(res, `${n} may make its account now.`); }
          case '/admin/refuse': { const n = box.state.requests[id]?.name ?? 'That device'; box.decide(id, false, nowS()); return told(res, `${n} was refused.`); }
          case '/admin/remove': {
            if (form.get('sure') !== '1') return told(res, 'Tick the box to remove an account.');
            box.removeAccount(account ?? ''); log('keykin box: admin removed an account'); return told(res, 'The account is removed.');
          }
          case '/admin/loginpage': {
            if (box.fixedLogin) return told(res, 'The login page address is set by KEYKIN_LOGIN_URL on this box. Change it there.');
            if (form.get('do') === 'clear') { box.setLoginPage(null); log('keykin box: admin cleared the login page address'); return told(res, 'The login page address is cleared. New codes leave it out.'); }
            const a = loginOrigin(form.get('address'));
            if (!a) return told(res, 'That is not a login page address. It starts with https:// and has nothing after the host.');
            box.setLoginPage(a); log(`keykin box: admin set the login page address to ${a}`); return told(res, `New codes carry ${a}.`);
          }
          case '/admin/code': { const nonce = bytesToHex(randomBytes(16)); return html(res, 200, codePage({ qrText: box.newSetupCode(addr(), nowS()), csrf: s.csrf, nonce, logout: !o.behindLogin, first: false, count: box.accounts().length, where: whereIs }), nonce); }
        }
      } catch (e) { if (e instanceof KeykinError) return told(res, 'That did not work: ' + e.code); throw e; }
    }
    res.writeHead(404, { 'content-type': 'text/plain' }); res.end('Not found\n');
  }

  const guard = (fn: (req: IncomingMessage, res: ServerResponse) => Promise<unknown>) => (req: IncomingMessage, res: ServerResponse) => {
    fn(req, res).catch((e) => { log(`keykin box: ${String(e)}`); if (!res.headersSent) res.writeHead(500); res.end(); });
  };
  const server: ReturnType<typeof createServer> = createServer(guard(route));
  // The side door: nothing but the two shared paths.
  const side = o.sidePort === undefined ? null : createServer(guard(async (req, res) => {
    sideSeen = nowS();
    const said = loginOrigin(req.headers['x-keykin-origin']);
    if (said) sideOrigin = said;
    if (!(await shared(req, res, new URL(req.url ?? '/', 'http://box').pathname))) { res.writeHead(404, { 'content-type': 'text/plain' }); res.end('Not found\n'); }
  }));
  const listen = (srv: ReturnType<typeof createServer>, port: number) => new Promise<number>((ok) => srv.listen(port, o.addr ?? '127.0.0.1', () => ok((srv.address() as any).port)));
  return (async () => {
    const port = await listen(server, o.port ?? 7460);
    const sidePort = side ? await listen(side, o.sidePort!) : null;
    log(`keykin box: admin page and devices on ${where()}${sidePort ? `, side door on port ${sidePort}` : ''}`);
    const close = () => new Promise<void>((done) => { side?.close(); side?.closeAllConnections(); server.close(() => done()); server.closeAllConnections(); });
    return { server, box, page, port, sidePort, qr: () => box.qr(o.url || where()), ownerSecret, close };
  })();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const e = process.env;
  startBox({ dir: e.KEYKIN_DIR ?? './box-data', addr: e.KEYKIN_ADDR, port: Number(e.KEYKIN_PORT ?? 7460), sidePort: e.KEYKIN_SIDE_PORT ? Number(e.KEYKIN_SIDE_PORT) : undefined,
    url: e.KEYKIN_URL?.replace(/\/+$/, ''), behindLogin: e.KEYKIN_BEHIND_LOGIN === '1', open: e.KEYKIN_OPEN === '1', login: e.KEYKIN_LOGIN_URL?.replace(/\/+$/, ''),
    policy: e.KEYKIN_POLICY ? JSON.parse(e.KEYKIN_POLICY) : undefined });
}
