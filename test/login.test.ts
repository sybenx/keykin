// Keykin Login: the public door in front of the box, and the account page in a real browser.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { verifyEvent } from 'nostr-tools/pure';
import { startBox } from '../box/server.ts';
import { startLogin } from '../login/server.ts';
import { newMemberKey, softwareChip } from '../src/member.ts';
import * as D from '../src/device.ts';

const H = { connection: 'close' };
const device = (name: string): D.Me => ({ ...newMemberKey(), name, ...softwareChip() });
const note = (npub: string, content = 'hi') => ({ pubkey: npub, created_at: 1700000000, kind: 1, tags: [], content });

async function world() {
  const box = await startBox({ dir: mkdtempSync(join(tmpdir(), 'kk-box-')), port: 0, sidePort: 0, behindLogin: true, url: 'http://to-be-set', log: () => {} });
  const login = await startLogin({ box: `http://127.0.0.1:${box.sidePort}`, port: 0, log: () => {} });
  const base = `http://127.0.0.1:${login.port}`;
  const send: D.Send = async (r) => (await fetch(`${base}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: H })).json();
  const api = async (body: object, cookie = '', headers: Record<string, string> = { 'x-keykin': '1' }) => {
    const r = await fetch(`${base}/api`, { method: 'POST', body: JSON.stringify(body), headers: { ...H, 'content-type': 'application/json', cookie, ...headers } });
    return { status: r.status, body: await r.json() as any, cookies: r.headers.getSetCookie() };
  };
  return { box, login, base, send, api, close: async () => { await login.close(); await box.close(); } };
}

test('Keykin Login passes devices and the page\'s calls to the box, and nothing else', async () => {
  const w = await world();
  try {
    // Devices work through the public door exactly as they do at the box.
    const phone = device('Phone'), laptop = device('Laptop');
    const held = await D.createWithBox(phone, D.readQr(w.box.qr()!), w.send);
    await D.addMember(phone, held, { key: laptop.key, name: 'Laptop', kind: 'device', chip: laptop.chip }, w.send);
    const lh = await D.join(laptop, held.boxKey, held.npub, w.send);
    assert.ok(verifyEvent(await D.signEvent(phone, held, note(held.npub), w.send)));
    await D.passwordSet(phone, held, 'aaron', 'correct horse battery', w.send);

    // The admin page is not there, whatever is asked for.
    for (const [method, path] of [['GET', '/admin/state'], ['POST', '/admin/code'], ['POST', '/admin/remove'], ['POST', '/login'], ['POST', '/page'], ['GET', '/owner-secret.txt'], ['GET', '/../box/server.ts']])
      assert.equal((await fetch(w.base + path, { method, headers: H, body: method === 'POST' ? '{}' : undefined })).status, 404, path);
    const home = await fetch(w.base + '/', { headers: H });
    assert.match(await home.text(), /Your Keykin account/);
    assert.match(home.headers.get('content-security-policy')!, /default-src 'none'/);

    // Another site cannot make the page's calls: they need a header only this page can send.
    assert.equal((await w.api({ call: 'pw_salt', username: 'aaron' }, '', {})).status, 403);
    assert.deepEqual((await w.api({ call: 'unblock', key: laptop.key })).body, { error: 'unknown_call' });
    assert.deepEqual((await w.api({ call: 'me' })).body, { error: 'login' });

    // Password login: the session comes back as a cookie the page's script cannot read, never in the body.
    const { salt } = (await w.api({ call: 'pw_salt', username: 'aaron' })).body;
    const good = await D.passwordVerifier('correct horse battery', salt);
    assert.deepEqual((await w.api({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('nope', salt) })).body, { error: 'wrong' });
    const ok = await w.api({ call: 'pw_login', username: 'aaron', verifier: good });
    assert.deepEqual(ok.body, { ok: true });
    assert.match(ok.cookies[0], /^ks=[0-9a-f]{64}; HttpOnly; SameSite=Strict/);
    const cookie = ok.cookies[0].split(';')[0];
    // A session smuggled in the body is ignored: only the cookie counts.
    assert.deepEqual((await w.api({ call: 'me', session: cookie.slice(3) })).body, { error: 'login' });
    const me = (await w.api({ call: 'me' }, cookie)).body;
    assert.equal(me.npub, held.npub); assert.match(me.npubText, /^npub1/); assert.equal(me.username, 'aaron');

    // Block from the page; the device is refused through the same door.
    assert.deepEqual((await w.api({ call: 'block', key: laptop.key }, cookie)).body, { ok: true });
    await assert.rejects(D.signEvent(laptop, lh, note(held.npub), w.send), /blocked/);
    // Signing out clears the cookie and the session at the box.
    const out = await w.api({ call: 'logout' }, cookie);
    assert.match(out.cookies[0], /^ks=; .*Max-Age=0/);
    assert.deepEqual((await w.api({ call: 'me' }, cookie)).body, { error: 'login' });

    // Device login: the code is tied to the browser that asked for it.
    const start = await w.api({ call: 'login_start' });
    const kl = start.cookies[0].split(';')[0];
    assert.match(start.body.svg, /^<svg/);
    assert.deepEqual((await w.api({ call: 'login_wait', code: start.body.code }, kl)).body, { ok: true, waiting: true });
    await D.approveLogin(phone, held, start.body.text, w.send);
    assert.deepEqual((await w.api({ call: 'login_wait', code: start.body.code }, 'kl=' + 'a'.repeat(32))).body, { error: 'gone' });
    const done = await w.api({ call: 'login_wait', code: start.body.code }, kl);
    assert.deepEqual(done.body, { ok: true });
    assert.equal((await w.api({ call: 'me' }, done.cookies[0].split(';')[0])).body.npub, held.npub);
  } finally { await w.close(); }
});

test('with Keykin Login stopped, the box and private devices carry on', async () => {
  const w = await world();
  try {
    const direct: D.Send = async (r) => (await fetch(`http://127.0.0.1:${w.box.port}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: H })).json();
    const phone = device('Phone');
    const held = await D.createWithBox(phone, D.readQr(w.box.qr()!), w.send);
    await w.login.close();
    await assert.rejects(D.signEvent(phone, held, note(held.npub), w.send));
    assert.ok(verifyEvent(await D.signEvent(phone, held, note(held.npub), direct)));
    assert.equal((await fetch(`http://127.0.0.1:${w.box.port}/`, { headers: H })).status, 200);
  } finally { await w.box.close(); }
});

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

test('the account page in a browser: sign in, look around, block, end a sign-in, get a bunker link', { skip: !exe && 'no Chromium found', timeout: 120_000 }, async () => {
  const { chromium: pw } = await import('playwright-core');
  const w = await world();
  const browser = await pw.launch({ executablePath: exe!, args: ['--headless=new'] });
  try {
    const phone = device('Pixel 9a'), laptop = device('MacBook');
    const held = await D.createWithBox(phone, D.readQr(w.box.qr()!), w.send);
    await D.addMember(phone, held, { key: laptop.key, name: 'MacBook', kind: 'device', chip: laptop.chip }, w.send);
    const lh = await D.join(laptop, held.boxKey, held.npub, w.send);
    await D.passwordSet(phone, held, 'aaron', 'correct horse battery', w.send);
    const jumble = D.newGrant('site', 'https://jumble.social');
    await D.reportGrants(laptop, lh, [jumble], w.send);

    const page = await (await browser.newContext()).newPage();
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(String(e))); page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    await page.goto(w.base + '/');
    // Sign-in screen: a code for a device, and the password form.
    await page.waitForSelector('.qr svg');
    const loginText = await page.textContent('#logintext');
    assert.equal(JSON.parse(loginText!).login.key, w.box.box.state.key);
    await page.fill('#username', 'aaron'); await page.fill('#password', 'wrong one');
    await page.click('#pwgo');
    await page.waitForSelector('text=do not match');
    await page.fill('#password', 'correct horse battery');
    await page.click('#pwgo');
    await page.waitForSelector('text=Hello, aaron');
    assert.match((await page.textContent('#npub'))!, /^npub1/);

    // Devices: block the laptop, and see that the page offers no way to unblock.
    await page.click('nav >> text=Devices');
    await page.waitForSelector('text=Pixel 9a');
    page.once('dialog', (d) => d.accept());
    await page.click('button[aria-label="Block MacBook"]');
    await page.waitForSelector('text=MacBook is blocked.');
    assert.equal(await page.locator('button:has-text("Unblock")').count(), 0);
    await assert.rejects(D.signEvent(laptop, lh, note(held.npub), w.send), /blocked/);

    // Signed in: end the site's sign-in.
    await page.click('nav >> text=Signed in');
    await page.waitForSelector('text=https://jumble.social');
    await page.click('button[aria-label="End https://jumble.social"]');
    await page.waitForSelector('text=Nothing is signed in.');
    await assert.rejects(D.signEvent(phone, held, note(held.npub), w.send, undefined, jumble.id), /revoked/);

    // Sign in to a site: the page asks, a device answers, the page shows the link.
    await page.click('nav >> text=Sign in to a site');
    await page.click('text=Get a bunker link');
    await page.waitForSelector('text=Waiting for one of your devices');
    let waiting: D.Note[] = [];
    for (let k = 0; k < 20 && !waiting.length; k++) { waiting = await D.notes(phone, held, w.send); if (!waiting.length) await new Promise((r) => setTimeout(r, 200)); }
    assert.equal(waiting[0].kind, 'bunker');
    await D.noteDone(phone, held, waiting[0].id, 'bunker://abc123?relay=wss%3A%2F%2Frelay.example', w.send);
    await page.waitForSelector('#bunkerlink');
    assert.equal(await page.textContent('#bunkerlink'), 'bunker://abc123?relay=wss%3A%2F%2Frelay.example');

    // Sign out, then sign in again by a device instead of the password.
    await page.click('nav >> text=Security');
    await page.click('#signout');
    await page.waitForSelector('.qr svg');
    await D.approveLogin(phone, held, (await page.textContent('#logintext'))!, w.send);
    await page.waitForSelector('text=Hello, aaron');
    await page.setViewportSize({ width: 390, height: 800 });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'no sideways scroll on a phone');
    await page.screenshot({ path: join(tmpdir(), 'keykin-account-phone.png') });
    await page.setViewportSize({ width: 1200, height: 800 });
    await page.screenshot({ path: join(tmpdir(), 'keykin-account.png') });
    assert.deepEqual(errors.filter((e) => !/favicon/.test(e)), []);
  } finally { await browser.close(); await w.close(); }
});
