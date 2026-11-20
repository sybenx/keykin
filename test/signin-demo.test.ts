// signin/ stands alone: the bare demo page, with the package's default hooks, in a headless Chromium. Served from a
// static server inside the test. No public relay or name server is reached: every WebSocket is answered here (the page
// is told to use a local test relay, as Marble Web's tests do, and the public ones are closed at once), and the one
// NIP-05 answer comes from the test. Skipped when no Chromium is at hand.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, normalize, extname } from 'node:path';
import { execFileSync } from 'node:child_process';
import type { AddressInfo } from 'node:net';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import * as nip19 from 'nostr-tools/nip19';

function chromium(): string | null {
  if (process.env.KEYKIN_CHROMIUM) return process.env.KEYKIN_CHROMIUM;
  const cache = join(homedir(), 'Library/Caches/ms-playwright');
  if (!existsSync(cache)) return null;
  for (const d of readdirSync(cache).filter((n) => /^chromium-\d+$/.test(n)).sort().reverse()) {
    try { const p = execFileSync('find', [join(cache, d), '-maxdepth', '5', '-type', 'f', '-perm', '+111', '-path', '*MacOS*'], { encoding: 'utf8' }).split('\n')[0]; if (p) return p; } catch {}
  }
  return null;
}
const exe = chromium();

const root = join(import.meta.dirname, '../signin');
const TYPES: Record<string, string> = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' };
const LOCAL_RELAY = 'ws://127.0.0.1:7777';

test('signin demo: the dialog opens on its own, and another signer app gets a nostrconnect code', { skip: !exe && 'no Chromium found', timeout: 60_000 }, async () => {
  const server = createServer(async (req, res) => {
    const path = normalize(decodeURIComponent(new URL(req.url!, 'http://x').pathname)).replace(/^(\.\.[/\\])+/, '');
    try {
      const body = await readFile(join(root, path.endsWith('/') ? path + 'index.html' : path));
      res.writeHead(200, { 'content-type': TYPES[extname(path) || '.html'] ?? 'application/octet-stream' }).end(body);
    } catch { res.writeHead(404).end(); }
  });
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

  // The account someone types: its NIP-05 answer and its login-page pointer, both from here.
  const sk = generateSecretKey(), pk = getPublicKey(sk);
  const pointer = finalizeEvent({ kind: 10046, created_at: Math.floor(Date.now() / 1000), tags: [['nostrconnect_url', 'https://login.example/#connect=<nostrconnect>']], content: '' }, sk);

  const { chromium: pw } = await import('playwright-core');
  let browser: any = null;
  try {
    browser = await pw.launch({ executablePath: exe!, headless: true });
    const page = await browser.newPage();
    const sockets: string[] = [], asked: any[] = [];
    await page.routeWebSocket(/.*/, (ws: any) => {
      const url = ws.url().replace(/\/$/, '');
      sockets.push(url);
      if (url !== LOCAL_RELAY) return ws.close();          // the public relays: not reached
      ws.onMessage((m: string) => {
        const msg = JSON.parse(m);
        if (msg[0] !== 'REQ') return;
        asked.push(msg);
        for (const f of msg.slice(2)) if (f.kinds?.includes(10046) && f.authors?.includes(pk)) ws.send(JSON.stringify(['EVENT', msg[1], pointer]));
        ws.send(JSON.stringify(['EOSE', msg[1]]));
      });
    });
    const fetched: string[] = [];
    await page.route((u: URL) => u.hostname !== '127.0.0.1', (route: any) => {
      const url = route.request().url();
      fetched.push(url);
      if (url === 'https://example.test/.well-known/nostr.json?name=alice') return route.fulfill({ status: 200, contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify({ names: { alice: pk } }) });
      return route.abort();
    });
    await page.addInitScript((r: string) => sessionStorage.setItem('marble.local', r), LOCAL_RELAY);
    const errors: string[] = [];
    page.on('pageerror', (e: Error) => errors.push(e.message));

    await page.goto(base + '/demo/');
    await page.click('[data-sign-in]');
    const dialog = page.locator('dialog#signin');
    assert.equal(await dialog.evaluate((d: HTMLDialogElement) => d.open), true);
    // The first screen, word for word as Marble Web's.
    const text = (await dialog.innerText()).split('\n').map((l: string) => l.trim()).filter(Boolean);
    assert.deepEqual(text, ['Sign in', 'Your Nostr address or npub', 'Continue', 'or', 'Sign in with your phone', 'Use a signer app', 'Here to manage your account? Your account page']);
    assert.equal(await page.getAttribute('#si-who', 'placeholder'), 'herbstmeister.com or npub1…');
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'si-who');

    // Another signer app: the plain nostrconnect code, drawn and ready to copy.
    await page.click('[data-si="signer"]');
    await page.waitForSelector('.si .qr svg');
    assert.equal(await page.textContent('#si-title'), 'Use a signer app');
    const code = (await page.getAttribute('[data-si="copy"]', 'data-code'))!;
    assert.match(code, /^nostrconnect:\/\/[0-9a-f]{64}\?/);
    const q = new URLSearchParams(code.slice(code.indexOf('?') + 1));
    assert.deepEqual(q.getAll('relay'), [LOCAL_RELAY]);
    assert.equal(q.get('name'), 'Sign-in demo');
    assert.equal(q.get('url'), base);
    assert.equal(q.get('perms'), 'sign_event:1,sign_event:7,sign_event:4811,sign_event:30811,sign_event:24242,nip44_decrypt,get_public_key');
    assert.match(q.get('secret')!, /^[0-9a-f]{16}$/);
    assert.ok(q.get('device'), 'the browser\'s label');
    assert.ok(!q.has('kk') && !q.has('kk_login'));
    // and the page waits for the answer on the local relay
    for (let i = 0; i < 50 && !asked.some((m) => m[2]?.kinds?.includes(24133)); i++) await new Promise((r) => setTimeout(r, 100));
    assert.ok(asked.some((m) => m[2]?.kinds?.includes(24133) && m[2]['#p']?.[0] === code.slice(15, 79)), 'listening for the signer\'s answer: ' + JSON.stringify({ sockets, asked }));

    // Back, then a name: looked up by NIP-05 and its pointer, through the default hooks.
    await page.click('[data-si="unsigner"]');
    await page.fill('#si-who', 'alice@example.test');
    await page.click('button[type="submit"]');
    await page.waitForSelector('a.si-open[data-si="away"]');
    assert.equal(await page.textContent('.acct-addr'), 'login.example');
    assert.equal(await page.textContent('a.si-open'), 'Sign in at login.example');
    const away = (await page.getAttribute('a.si-open', 'href'))!;
    assert.ok(away.startsWith('https://login.example/#connect=nostrconnect%3A%2F%2F'), away);
    assert.equal(await page.getAttribute('a.si-open', 'rel'), 'noopener');
    assert.equal(await page.textContent('.si-who .si-name'), nip19.npubEncode(pk).slice(0, 12) + '…');
    assert.ok(fetched.includes('https://example.test/.well-known/nostr.json?name=alice'));

    // Escape closes it.
    await page.keyboard.press('Escape');
    assert.equal(await dialog.evaluate((d: HTMLDialogElement) => d.open), false);

    assert.deepEqual(errors, []);
    assert.ok(sockets.includes(LOCAL_RELAY));
  } finally {
    await browser?.close();
    await new Promise((ok) => server.close(ok));
  }
});
