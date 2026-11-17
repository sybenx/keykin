// Keykin Login: the public door in front of the box, and the account page in a real browser.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, existsSync, readdirSync } from 'node:fs';
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
    assert.match(await home.text(), /Your account/);
    assert.match(home.headers.get('content-security-policy')!, /default-src 'none'/);

    // Another site cannot make the page's calls: they need a header only this page can send.
    assert.equal((await w.api({ call: 'pw_salt', username: 'aaron' }, '', {})).status, 403);
    assert.deepEqual((await w.api({ call: 'reveal', key: laptop.key })).body, { error: 'unknown_call' });
    assert.deepEqual((await w.api({ call: 'unblock', key: laptop.key })).body, { error: 'login' });
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

test('the account page in a browser: sign in, devices, sites and apps, security, activity', { skip: !exe && 'no Chromium found', timeout: 150_000 }, async () => {
  const { chromium: pw } = await import('playwright-core');
  const w = await world();
  const browser = await pw.launch({ executablePath: exe!, args: ['--headless=new'] });
  const shots = join(tmpdir(), 'keykin-shots'); mkdirSync(shots, { recursive: true });
  try {
    const phone = device('Pixel 9a'), laptop = device('MacBook');
    const held = await D.createWithBox(phone, D.readQr(w.box.qr()!), w.send);
    await D.addMember(phone, held, { key: laptop.key, name: 'MacBook', kind: 'device', chip: laptop.chip }, w.send);
    const lh = await D.join(laptop, held.boxKey, held.npub, w.send);
    await D.passwordSet(phone, held, 'aaron', 'correct horse battery', w.send);
    const jumble = D.newGrant('site', 'https://jumble.social'), amethyst = D.newGrant('app', 'Amethyst');
    await D.reportGrants(laptop, lh, [jumble], w.send);
    await D.reportGrants(phone, held, [amethyst], w.send);
    await D.signEvent(laptop, lh, note(held.npub), w.send, undefined, jumble.id);
    // The phone is somewhere else, online: it answers what the page asks with nobody touching it.
    const away = { ...phone, fp: undefined };
    const taps: string[] = [];
    const answer = (yes = true) => D.answerNotes(away, held, w.send, { addr: w.base, tap: async (t) => { taps.push(t); return yes; }, bunker: async () => 'bunker://abc123?relay=wss%3A%2F%2Frelay.example' });
    const answered = async (yes = true) => { for (let k = 0; k < 40; k++) { const did = await answer(yes); if (did.length) return did; await new Promise((r) => setTimeout(r, 150)); } return []; };

    const page = await (await browser.newContext({ viewport: { width: 1280, height: 860 } })).newPage();
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(String(e))); page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    const shot = (name: string) => page.screenshot({ path: join(shots, name + '.png') });
    await page.goto(w.base + '/');

    // Sign-in screen: a code for a device, and the password form.
    await page.waitForSelector('.qr svg');
    assert.equal(JSON.parse((await page.textContent('#logintext'))!).login.key, w.box.box.state.key);
    await shot('signin');
    await page.fill('#username', 'aaron'); await page.fill('#password', 'wrong one');
    await page.click('#pwgo');
    await page.waitForSelector('text=do not match');
    await page.fill('#password', 'correct horse battery');
    await page.click('#pwgo');
    await page.waitForSelector('text=Welcome, Aaron');
    assert.match((await page.textContent('#npub'))!, /^npub1/);
    assert.match((await page.textContent('.top'))!, /aaron · signed in with a password/);
    await page.waitForSelector('text=Everything looks fine.');
    await shot('home');

    // Devices: block, see it refused, unblock from the page.
    await page.click('nav >> text=Devices');
    await page.waitForSelector('text=Fingerprint key');
    await shot('devices');
    page.once('dialog', (d) => d.accept());
    await page.click('button[aria-label="Block MacBook"]');
    await page.waitForSelector('text=MacBook is blocked.');
    await assert.rejects(D.signEvent(laptop, lh, note(held.npub), w.send), /blocked/);
    await page.click('button[aria-label="Unblock MacBook"]');
    await page.waitForSelector('text=MacBook is unblocked.');
    assert.ok(verifyEvent(await D.signEvent(laptop, lh, note(held.npub), w.send)));

    // Add a device from the page: the phone, untouched, does it.
    const work = device('Work PC');
    await page.fill('input[aria-label="Invite from the new device"]', JSON.stringify({ keykin: 2, invite: { key: work.key, name: 'Work PC', chip: work.chip } }));
    await page.click('text=Send to phone');
    assert.deepEqual(await answered(), ['added Work PC']);
    await page.waitForSelector('#joincode');
    const jt = JSON.parse((await page.textContent('#joincode'))!).join;
    const wh = await D.join(work, jt.boxKey, jt.npub, w.send);
    assert.ok(verifyEvent(await D.signEvent(work, wh, note(held.npub), w.send)));
    assert.deepEqual(taps, []);

    // Remove a blocked device for good: that one asks for a Yes on a device.
    await page.click('nav >> text=Home'); await page.click('nav >> text=Devices');
    page.once('dialog', (d) => d.accept());
    await page.click('button[aria-label="Block MacBook"]');
    await page.waitForSelector('text=Remove 1 device');
    await page.click('text=Remove 1 device');
    await page.waitForSelector('text=Waiting for a Yes');
    assert.deepEqual(await answered(true), ['removed blocked devices']);
    assert.equal(taps.length, 1);
    await page.waitForSelector('text=Nothing to remove');
    assert.equal(await page.locator('text=MacBook').count(), 0);

    // Sites and apps: what is signed in, revoke, and a bunker link from the phone.
    await page.click('nav >> text=Sites and apps');
    await page.waitForSelector('text=App on Pixel 9a');
    await shot('sites');
    await page.click('button[aria-label="Revoke Amethyst"]');
    await page.waitForSelector('text=Amethyst is revoked.');
    await assert.rejects(D.signEvent(phone, held, note(held.npub), w.send, undefined, amethyst.id), /revoked/);
    await page.click('text=Ask my phone for a link');
    assert.deepEqual(await answered(), ['gave a bunker link']);
    await page.waitForSelector('#bunkerlink.has');
    assert.equal(await page.textContent('#bunkerlink'), 'bunker://abc123?relay=wss%3A%2F%2Frelay.example');

    // Security: change the password from the page; the new one signs in, the old one does not.
    await page.click('nav >> text=Security');
    await page.fill('#newpass', 'a brand new password');
    await page.click('#savepw');
    await page.waitForSelector('text=Password saved.');
    await shot('security');
    const salt = (await w.api({ call: 'pw_salt', username: 'aaron' })).body.salt;
    assert.deepEqual((await w.api({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('correct horse battery', salt) })).body, { error: 'wrong' });
    assert.deepEqual((await w.api({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('a brand new password', salt) })).body, { ok: true });

    // Recent activity lists what happened.
    await page.click('nav >> text=Recent activity');
    await page.waitForSelector('text=MacBook was blocked from the account page');
    await page.waitForSelector('text=The password was changed from the account page');
    await shot('activity');

    // Sign out, then sign in again by a device instead of the password.
    await page.click('nav >> text=Security');
    await page.click('#signout');
    await page.waitForSelector('.qr svg');
    await D.approveLogin(phone, held, (await page.textContent('#logintext'))!, w.send);
    await page.waitForSelector('text=Welcome, Aaron');
    assert.match((await page.textContent('.top'))!, /signed in with a device/);
    await page.setViewportSize({ width: 390, height: 800 });
    for (const s of ['Devices', 'Sites and apps', 'Security', 'Home']) {
      await page.click(`nav >> text=${s}`);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `no sideways scroll on a phone: ${s}`);
    }
    await shot('home-phone');
    assert.deepEqual(errors, []);
  } finally { await browser.close(); await w.close(); }
});
