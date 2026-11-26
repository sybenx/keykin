// A headless Chromium and a page with the shared sign-in on it, for the sign-in's browser tests. Finds Chromium as
// test/signin-demo.test.ts does (KEYKIN_CHROMIUM, else Playwright's cache); serves signin/ from 127.0.0.1, plus a bare
// site page at /standin/ (?extension=on: it calls configure({ extension: true }) first). Nothing public is reached:
// every WebSocket but the given local relay is closed at once, every request off 127.0.0.1 is refused, and the page is
// told to send everything to the local relay (sessionStorage "marble.local", pool.js testRelay). Use:
//
//   import { chromiumPath, serveSignin, openPage } from './standins/browser.ts';
//   const exe = chromiumPath();
//   test('…', { skip: !exe && 'no Chromium found' }, async () => {
//     const site = await serveSignin();
//     const browser = await (await import('playwright-core')).chromium.launch({ executablePath: exe!, headless: true });
//     try {
//       const p = await openPage(browser, site.base, { relay, extension: 'on', before: (ctx) => fakeExtension(ctx) });
//       try { /* p.page, p.errors */ } finally { await p.close(); }
//     } finally { await browser.close(); await site.close(); }
//   });
//
// On the page, window.signin is me.js (current, sign, signOut, …) and openSignIn.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, normalize, extname } from 'node:path';
import { execFileSync } from 'node:child_process';
import type { AddressInfo } from 'node:net';

export function chromiumPath(): string | null {
  if (process.env.KEYKIN_CHROMIUM) return process.env.KEYKIN_CHROMIUM;
  const cache = join(homedir(), 'Library/Caches/ms-playwright');
  if (!existsSync(cache)) return null;
  for (const d of readdirSync(cache).filter((n) => /^chromium-\d+$/.test(n)).sort().reverse()) {
    try { const p = execFileSync('find', [join(cache, d), '-maxdepth', '5', '-type', 'f', '-perm', '+111', '-path', '*MacOS*'], { encoding: 'utf8' }).split('\n')[0]; if (p) return p; } catch {}
  }
  return null;
}

const root = join(import.meta.dirname, '../../signin');
const TYPES: Record<string, string> = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' };

// A bare site: the package's own default hooks, a Sign in button, and who is signed in.
const PAGE = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="application-name" content="Stand-in site"><title>Stand-in site</title>
<link rel="stylesheet" href="../signin.css">
<style>:root { --bg: #F7F3EC; --ink: #1F1B16; --muted: #6B6257; --accent: #2E4CB8; --accent-soft: #E3E8F9; --on-accent: #F7F3EC;
  --card: #FFFDF9; --line: #E6DFD4; --field: #FFFDF9; --field-line: #D6CDBF; } body { background: var(--bg); color: var(--ink); }</style>
</head><body>
<p id="who">Not signed in.</p><button type="button" data-sign-in>Sign in</button>
<script type="module">
  import { configure } from "../hooks.js";
  import { openSignIn } from "../dialog.js";
  import * as me from "../me.js";
  if (new URLSearchParams(location.search).get("extension") === "on") configure({ extension: true });
  const who = document.getElementById("who");
  const show = () => { who.textContent = me.current() ? "Signed in as " + me.current() : "Not signed in."; };
  me.onMe(show);
  show();
  window.signin = { ...me, openSignIn };
  document.querySelector("[data-sign-in]").addEventListener("click", () => openSignIn());
</script></body></html>`;

/** Serves signin/ and the bare site page from 127.0.0.1. */
export async function serveSignin() {
  const server = createServer(async (req, res) => {
    const path = normalize(decodeURIComponent(new URL(req.url!, 'http://x').pathname)).replace(/^(\.\.[/\\])+/, '');
    if (path === '/standin/' || path === '/standin/index.html') return void res.writeHead(200, { 'content-type': 'text/html' }).end(PAGE);
    try {
      const body = await readFile(join(root, path.endsWith('/') ? path + 'index.html' : path));
      res.writeHead(200, { 'content-type': TYPES[extname(path) || '.html'] ?? 'application/octet-stream' }).end(body);
    } catch { res.writeHead(404).end(); }
  });
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  return { base, close: () => new Promise<void>((ok) => { server.closeAllConnections(); server.close(() => ok()); }) };
}

export type PageOptions = {
  relay?: string;                         // the local relay; with none, every WebSocket is closed
  extension?: 'on' | 'off';               // configure({ extension: true }) on the site page
  before?: (context: any) => unknown;     // e.g. fakeExtension(context), page.clock: before the first page opens
  storage?: Record<string, string>;       // localStorage set once, before the site's own scripts run the first time
};

/** A fresh context and page on the bare site, opened. close() closes the context (and every page it opened). */
export async function openPage(browser: any, base: string, opts: PageOptions = {}) {
  const context = await browser.newContext();
  const sockets: string[] = [];
  await context.routeWebSocket(/.*/, (ws: any) => {
    const url = ws.url().replace(/\/$/, '');
    sockets.push(url);
    if (opts.relay && url === opts.relay) ws.connectToServer();
    else ws.close();                      // anything public: never reached
  });
  await context.route((u: URL) => u.hostname !== '127.0.0.1', (route: any) => route.abort());
  if (opts.relay) await context.addInitScript((r: string) => sessionStorage.setItem('marble.local', r), opts.relay);
  if (opts.storage) await context.addInitScript((s: Record<string, string>) => {
    if (sessionStorage.getItem('standin.stored')) return;
    sessionStorage.setItem('standin.stored', '1');
    for (const [k, v] of Object.entries(s)) localStorage.setItem(k, v);
  }, opts.storage);
  await opts.before?.(context);
  const page = await context.newPage();
  const errors: string[] = [];
  page.on('pageerror', (e: Error) => errors.push(e.message));
  page.on('dialog', (d: any) => { errors.push('dialog: ' + d.message()); d.dismiss(); });
  await page.goto(`${base}/standin/${opts.extension === 'on' ? '?extension=on' : ''}`);
  await page.waitForFunction(() => !!(window as any).signin);
  return { context, page, errors, sockets, close: () => context.close() };
}

/** The dialog's text, a line each. */
export const dialogLines = async (page: any): Promise<string[]> =>
  (await page.locator('dialog#signin').innerText()).split('\n').map((l: string) => l.trim()).filter(Boolean);
