// Keykin Login: the public door in front of the box, and the account page in a real browser.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, existsSync, readdirSync, readFileSync } from 'node:fs';
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

// QRST's own test relay, for the page's sign-in by a scanned code. Without it the page is given a relay that is not there.
const relayTool = process.env.QRST_REPO ? join(process.env.QRST_REPO, 'tools/test-relay.mjs') : join(homedir(), 'qr-secret-transfer/tools/test-relay.mjs');

async function world(o: { open?: boolean } = {}) {
  const testRelay = existsSync(relayTool) ? await (await import(relayTool)).startRelay({}) : null;
  const relay: string = testRelay?.url ?? 'ws://127.0.0.1:9';
  const box = await startBox({ dir: mkdtempSync(join(tmpdir(), 'kk-box-')), port: 0, sidePort: 0, behindLogin: true, url: 'http://to-be-set', open: o.open, log: () => {} });
  const login = await startLogin({ box: `http://127.0.0.1:${box.sidePort}`, port: 0, relays: [relay], log: () => {} });
  const base = `http://127.0.0.1:${login.port}`;
  const send: D.Send = async (r) => (await fetch(`${base}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: H })).json();
  const api = async (body: object, cookie = '', headers: Record<string, string> = { 'x-keykin': '1' }) => {
    const r = await fetch(`${base}/api`, { method: 'POST', body: JSON.stringify(body), headers: { ...H, 'content-type': 'application/json', cookie, ...headers } });
    return { status: r.status, body: await r.json() as any, cookies: r.headers.getSetCookie() };
  };
  return { box, login, base, send, api, relay, hasRelay: !!testRelay, closeRelay: async () => { await testRelay?.close?.(); }, close: async () => { await login.close(); await box.close(); await testRelay?.close?.(); } };
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

    // The browser in the signed-in list is the one Keykin Login saw, cut to 200 characters; what the page says is ignored.
    const ua = 'Mozilla/5.0 (Windows NT 10.0) Chrome/131.0 ' + 'y'.repeat(300);
    const other = await w.api({ call: 'pw_login', username: 'aaron', verifier: good, agent: 'I am a liar' }, '', { 'x-keykin': '1', 'user-agent': ua });
    const otherCookie = other.cookies[0].split(';')[0];
    assert.match(other.cookies[0], /Max-Age=43200/);
    const browsers = (await w.api({ call: 'me', agent: 'also ignored' }, cookie)).body.browsers;
    assert.deepEqual(browsers.map((b: any) => [b.how, b.this]).sort(), [['password', false], ['password', true]]);
    assert.equal(browsers.find((b: any) => !b.this).agent, ua.slice(0, 200));
    // Signing out another browser leaves this one's cookie; signing out this one clears it.
    const theirs = browsers.find((b: any) => !b.this).id;
    const out1 = await w.api({ call: 'logout_browser', id: theirs }, cookie);
    assert.deepEqual(out1.body, { ok: true, this: false }); assert.deepEqual(out1.cookies, []);
    assert.deepEqual((await w.api({ call: 'me' }, otherCookie)).body, { error: 'login' });
    const again = await w.api({ call: 'pw_login', username: 'aaron', verifier: good });
    const againCookie = again.cookies[0].split(';')[0];
    const out2 = await w.api({ call: 'logout_browser', id: (await w.api({ call: 'me' }, againCookie)).body.browsers.find((b: any) => b.this).id }, againCookie);
    assert.deepEqual(out2.body, { ok: true, this: true }); assert.match(out2.cookies[0], /^ks=; .*Max-Age=0/);

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
  } finally { await w.box.close(); await w.closeRelay(); }
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
    // A second box holds a piece too, as a backup. It collects its piece the way a box does, signing its own request.
    const backup = newMemberKey();
    await D.addMember(phone, held, { key: backup.key, name: 'Backup box', kind: 'box' }, w.send);
    const { seal } = await import('../src/member.ts');
    assert.equal((await w.send(await seal({ op: 'welcome', account: held.npub }, backup.sk, Math.floor(Date.now() / 1000)))).ok, true);
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
    if (w.hasRelay) { await page.waitForSelector('#scan .kk-qr svg'); assert.match((await page.textContent('#kk-uri'))!, /&kk=account$/); }
    await page.waitForSelector('#username');
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
    // Every row has a button except the box this page belongs to.
    assert.equal(await page.locator('button[aria-label="Block Backup box"]').count(), 1);
    assert.equal(await page.locator('button[aria-label="Block Box"]').count(), 0);
    await page.waitForSelector('text=Another box');
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
    // Posts only: the site may still post, and nothing else.
    await page.check('input[aria-label="Posts only for https://jumble.social"]');
    await page.waitForSelector('text=jumble.social can only post now.');
    assert.ok(await page.isChecked('input[aria-label="Posts only for https://jumble.social"]'));
    const follows = { pubkey: held.npub, created_at: 1700000000, kind: 3, tags: [['p', 'a'.repeat(64)]], content: '' };
    await assert.rejects(D.signEvent(work, wh, follows, w.send, undefined, jumble.id), /not_allowed/);
    assert.ok(verifyEvent(await D.signEvent(work, wh, note(held.npub), w.send, undefined, jumble.id)));
    await page.uncheck('input[aria-label="Posts only for https://jumble.social"]');
    await page.waitForSelector('text=jumble.social can do everything again.');
    assert.ok(verifyEvent(await D.signEvent(work, wh, follows, w.send, undefined, jumble.id)));
    await page.click('button[aria-label="Revoke Amethyst"]');
    await page.waitForSelector('text=Amethyst is revoked.');
    await assert.rejects(D.signEvent(phone, held, note(held.npub), w.send, undefined, amethyst.id), /revoked/);
    await page.click('text=Ask my phone for a link');
    assert.deepEqual(await answered(), ['gave a bunker link']);
    await page.waitForSelector('#bunkerlink.has');
    assert.equal(await page.textContent('#bunkerlink'), 'bunker://abc123?relay=wss%3A%2F%2Frelay.example');
    // The page checks the account every 15 seconds and redraws. The link must still be there after that.
    await new Promise((r) => setTimeout(r, 16_000));
    assert.equal(await page.textContent('#bunkerlink'), 'bunker://abc123?relay=wss%3A%2F%2Frelay.example');
    assert.equal(await page.locator('#bunkerlink.has').count(), 1);
    await page.click('nav >> text=Devices'); await page.click('nav >> text=Sites and apps');
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

    // Sign out, and the sign-in screen is back. (Signing in by a scanned code is tried on an emulator: it needs a signer app.)
    await page.click('nav >> text=Security');
    await page.click('#signout');
    await page.waitForSelector('#username');
    if (w.hasRelay) await page.waitForSelector('#scan .kk-qr svg');
    await page.fill('#username', 'aaron'); await page.fill('#password', 'a brand new password');
    await page.click('#pwgo');
    await page.waitForSelector('text=Welcome, Aaron');

    // A phone's camera followed the code's link here: the page offers the app, and signs nobody in.
    const phonePage = await (await browser.newContext({ viewport: { width: 390, height: 800 }, userAgent: 'Mozilla/5.0 (Linux; Android 15; Pixel 9a) Chrome/130 Mobile' })).newPage();
    await phonePage.goto(w.base + '/#v=1&mode=offer&p=signer-ticket&npub=npub1vrue0xcv6vqfq3y2257epkxajfw8l52v5r5lanygnn0w0rdvg8ls978669&check=none&token=839a8c191794cd858d79c60457c48261&relay=wss://syb.lol&origin=' + w.base);
    await phonePage.waitForSelector('#openapp');
    assert.match((await phonePage.getAttribute('#openapp', 'href'))!, /^intent:\/\/npub1vrue0xcv6vqfq3y2257epkxajfw8l52v5r5lanygnn0w0rdvg8ls978669\?v=1&mode=offer&p=signer-ticket.*#Intent;scheme=qrst;/);
    assert.equal(await phonePage.locator('#username').count(), 0);
    await phonePage.click('#here');
    await phonePage.waitForSelector('#username');
    // On a phone there is no code to scan: a button opens the app on this phone (a nostrconnect link, NIP-46).
    await phonePage.waitForSelector('#withapp');
    const tap = new URL((await phonePage.getAttribute('#withapp', 'href'))!);
    assert.equal(tap.protocol, 'nostrconnect:'); assert.match(tap.host, /^[0-9a-f]{64}$/);
    assert.equal(tap.searchParams.get('kk'), 'account');          // an account page says so: a signer uses the main account there
    assert.deepEqual(tap.searchParams.getAll('relay'), [w.relay]); assert.match(tap.searchParams.get('secret')!, /^[0-9a-f]{32}$/);
    assert.equal(await phonePage.locator('.kk-qr').count(), 0);
    await page.setViewportSize({ width: 390, height: 800 });
    for (const s of ['Devices', 'Sites and apps', 'Security', 'Home']) {
      await page.click(`nav >> text=${s}`);
      assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `no sideways scroll on a phone: ${s}`);
    }
    await shot('home-phone');
    assert.deepEqual(errors, []);
  } finally { await browser.close(); await w.close(); }
});

test('signing in to the account page the way any site does: a signed challenge, with or without the box holding the account', async () => {
  const { finalizeEvent, generateSecretKey, getPublicKey } = await import('nostr-tools/pure');
  const { bytesToHex } = await import('../src/bytes.ts');
  const now = () => Math.floor(Date.now() / 1000);
  const proof = (sk: Uint8Array, challenge: string, more: object = {}) => finalizeEvent({ kind: 22242, created_at: now(), tags: [['relay', 'http://page'], ['challenge', challenge]], content: '', ...more }, sk);
  const ks = (cookies: string[]) => cookies.find((c) => c.startsWith('ks='))!.split(';')[0];

  // A box that lets nobody in by the page.
  const shut = await world();
  try {
    const sk = generateSecretKey(), pub = getPublicKey(sk);
    const c = (await shut.api({ call: 'signin_start' })).body;
    assert.match(c.challenge, /^[0-9a-f]{32}$/); assert.deepEqual(c.relays, [shut.relay]);
    // Not a login event, a challenge the box never gave, a broken signature: all refused.
    assert.equal((await shut.api({ call: 'signin', event: proof(sk, c.challenge, { kind: 1 }) })).body.error, 'bad_request');
    assert.equal((await shut.api({ call: 'signin', event: proof(sk, 'f'.repeat(32)) })).body.error, 'gone');
    const bent = proof(sk, c.challenge); bent.sig = bent.sig.replace(/.$/, (x) => (x === '0' ? '1' : '0'));
    assert.equal((await shut.api({ call: 'signin', event: bent })).body.error, 'wrong');
    const good = proof(sk, c.challenge);
    const done = await shut.api({ call: 'signin', event: good });
    assert.equal(done.body.ok, true);
    assert.equal((await shut.api({ call: 'signin', event: good })).body.error, 'gone');            // a challenge works once
    const cookie = ks(done.cookies);
    const me = (await shut.api({ call: 'me' }, cookie)).body;
    assert.equal(me.held, false); assert.equal(me.npub, pub); assert.equal(me.open, false); assert.match(me.npubText, /^npub1/);
    assert.equal((await shut.api({ call: 'protect' }, cookie)).body.error, 'not_open');
    assert.equal((await shut.api({ call: 'note_put', kind: 'bunker', text: '' }, cookie)).body.error, 'not_here');
    assert.equal((await shut.api({ call: 'logout' }, cookie)).body.ok, true);
    assert.equal((await shut.api({ call: 'me' }, cookie)).body.error, 'login');
  } finally { await shut.close(); }

  // An open box: the signed-in account comes in with the code the page shows, and no other account can use that code.
  const open = await world({ open: true });
  try {
    const sk = generateSecretKey(), pub = getPublicKey(sk);
    const c = (await open.api({ call: 'signin_start' })).body;
    const cookie = ks((await open.api({ call: 'signin', event: proof(sk, c.challenge) })).cookies);
    assert.equal((await open.api({ call: 'me' }, cookie)).body.open, true);
    const p = (await open.api({ call: 'protect' }, cookie)).body;
    assert.match(p.svg, /^<svg/);
    const qr = D.readQr(p.text);
    await assert.rejects(D.importWithBox(device('Thief'), qr, bytesToHex(generateSecretKey()), open.send), /bad_code/);
    await assert.rejects(D.createWithBox(device('Thief'), qr, open.send), /bad_code/);
    const phone = device('Pixel 9a');
    const held = await D.importWithBox(phone, qr, bytesToHex(sk), open.send);
    assert.equal(held.npub, pub);
    // The same session now sees the whole account page.
    const me = (await open.api({ call: 'me' }, cookie)).body;
    assert.equal(me.held, true); assert.deepEqual(me.devices.map((d: any) => d.name), ['Pixel 9a', 'Box']);
    assert.ok(verifyEvent(await D.signEvent(phone, held, note(pub), open.send)));
  } finally { await open.close(); }
});

// A site (Marble) sends the person here with its nostrconnect:// code in the fragment. They sign in,
// and the command-line device (`keykin agent`) answers the note with nobody at it: the site is signed in.
async function nakRelay() {
  const { spawn } = await import('node:child_process');
  const port = 20000 + Math.floor(Math.random() * 20000);
  const proc = spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', String(port)], { stdio: 'ignore' });
  const url = `ws://127.0.0.1:${port}`;
  for (let k = 0; k < 50; k++) {
    try { const w = new WebSocket(url); await new Promise((ok, no) => { w.onopen = ok; w.onerror = no; }); w.close(); break; }
    catch { await new Promise((r) => setTimeout(r, 100)); }
  }
  return { url, kill: () => proc.kill() };
}
const freePort = async () => { const { createServer } = await import('node:net'); const s = createServer(); await new Promise<void>((r) => s.listen(0, '127.0.0.1', r)); const p = (s.address() as any).port; await new Promise((r) => s.close(r)); return p; };
let hasNak = false; try { execFileSync('which', ['nak']); hasNak = true; } catch {}

test('a site sends you here with its code: scan, save a passkey, sign in with it or a password, and a click signs the site in', { skip: (!exe && 'no Chromium found') || (!hasNak && 'nak is not installed'), timeout: 180_000 }, async () => {
  const { chromium: pw } = await import('playwright-core');
  const { createServer } = await import('node:http');
  const { main } = await import('../cli/keykin.ts');
  const { BunkerSigner, createNostrConnectURI } = await import('nostr-tools/nip46');
  const { generateSecretKey, getPublicKey } = await import('nostr-tools/pure');
  const cli = async (home: string, ...argv: string[]) => { const lines: string[] = []; const r = await main(argv, (s) => lines.push(s), home); return { text: lines.join('\n'), run: r as any }; };
  const relay = await nakRelay();
  const port = await freePort(), base = `http://127.0.0.1:${port}`;
  const boxDir = mkdtempSync(join(tmpdir(), 'kk-box-'));
  const box = await startBox({ dir: boxDir, port: 0, sidePort: 0, behindLogin: true, url: base, log: () => {} });
  const login = await startLogin({ box: `http://127.0.0.1:${box.sidePort}`, port, relays: [relay.url], log: () => {} });
  // The site that sends people to the login page: a page of its own, so the browser gives its origin as the referrer.
  const siteServer = createServer((_req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!doctype html><title>Marble</title><p>Marble</p>'); });
  await new Promise<void>((r) => siteServer.listen(0, '127.0.0.1', r));
  const siteOrigin = `http://127.0.0.1:${(siteServer.address() as any).port}`;
  const browser = await pw.launch({ executablePath: exe!, args: ['--headless=new'] });
  const sites: Awaited<ReturnType<typeof BunkerSigner.fromURI>>[] = [];
  let agent: any;
  try {
    const home = mkdtempSync(join(tmpdir(), 'kk-mac-'));
    const npub = /([0-9a-f]{64})/.exec((await cli(home, 'create', box.qr()!, 'MacBook')).text)![1];
    agent = (await cli(home, 'agent', relay.url)).run;
    const now = () => Math.floor(Date.now() / 1000);
    const publish = async (event: object) => {
      const signed = JSON.parse((await cli(home, 'sign', JSON.stringify(event))).text);
      await new Promise<void>((ok, no) => { const ws = new WebSocket(relay.url); ws.onopen = () => ws.send(JSON.stringify(['EVENT', signed])); ws.onmessage = (m) => { ws.close(); JSON.parse(String(m.data))[2] ? ok() : no(new Error(String(m.data))); }; });
    };
    // The account's name and picture, which the sign-in card shows.
    await publish({ kind: 0, created_at: now(), tags: [], content: JSON.stringify({ name: 'Aaron', picture: 'https://pics.example/aaron.png' }) });
    const code = (name: string, url = siteOrigin + '/') => {
      const key = generateSecretKey();
      return { key, uri: createNostrConnectURI({ clientPubkey: getPublicKey(key), relays: [relay.url], secret: 'c0ffee' + Math.random().toString(16).slice(2, 8), name, url }) };
    };
    const site = async (name: string, url?: string) => { const c = code(name, url); return { uri: c.uri, waiting: BunkerSigner.fromURI(c.key, c.uri, {}, 30_000) }; };
    const tickUntil = async (page: any, sel: string) => { for (let k = 0; k < 60; k++) { await agent.tick(); if (await page.locator(sel).count()) return; await new Promise((r) => setTimeout(r, 250)); } throw new Error('no answer: ' + sel); };
    const errors: string[] = [];
    // Every call the page makes, to see that nothing goes to a device before a click.
    const calls: any[] = [];
    const watch = (p: any) => {
      p.on('pageerror', (e: any) => errors.push(String(e))); p.on('console', (m: any) => { if (m.type() === 'error') errors.push(m.text()); });
      p.on('request', (r: any) => { if (r.url().endsWith('/api') && r.method() === 'POST') { try { calls.push(JSON.parse(r.postData())); } catch {} } });
    };
    const puts = () => calls.filter((c) => c.call === 'note_put');
    const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');
    const context = async () => { const ctx = await browser.newContext(); await ctx.route('https://pics.example/**', (r) => r.fulfill({ contentType: 'image/png', body: png })); return ctx; };
    // Opens the login page the way a site does: from the site's own page, so the referrer is the site.
    const fromSite = async (page: any, target: string) => { await page.goto(siteOrigin + '/'); await page.evaluate((t: string) => { location.href = t; }, target); await page.waitForURL((u: URL) => u.port === String(port)); };

    // A code that is not a nostrconnect:// code is left alone, and said so.
    const odd = await (await context()).newPage(); watch(odd);
    await odd.goto(base + '/#connect=' + encodeURIComponent('bunker://nope'));
    await odd.waitForSelector('#asking[role=alert]');
    assert.equal(new URL(odd.url()).hash, '');

    // A raw code after `connect=` is taken as it is (its own & and = do not split it); an encoded one is decoded once.
    const raw = code('Marble');
    for (const tail of [raw.uri, encodeURIComponent(raw.uri)]) {
      const p = await (await context()).newPage(); watch(p);
      await fromSite(p, base + '/#x=1&connect=' + tail);
      await p.waitForSelector('#askname');
      assert.equal(await p.textContent('#askname'), 'Marble');
      assert.match((await p.textContent('#askrelay'))!, new RegExp(relay.url));
      assert.deepEqual(JSON.parse((await p.evaluate(() => sessionStorage.getItem('kk-connect')))!), { uri: raw.uri, from: siteOrigin });
      assert.equal(new URL(p.url()).hash, '#x=1', 'other fragment parameters stay');
      await p.context().close();
    }

    // 1. Signed in by a device, no password yet: the page offers a passkey, then asks before signing the site in.
    const ctx = await context(); const page = await ctx.newPage(); watch(page);
    const c = (await (await fetch(base + '/api', { method: 'POST', headers: { 'content-type': 'application/json', 'x-keykin': '1', connection: 'close' }, body: JSON.stringify({ call: 'signin_start' }) })).json()) as any;
    const proof = JSON.parse((await cli(home, 'sign', JSON.stringify({ kind: 22242, created_at: now(), tags: [['relay', base], ['challenge', c.challenge]], content: '' }))).text);
    const signed = await fetch(base + '/api', { method: 'POST', headers: { 'content-type': 'application/json', 'x-keykin': '1', connection: 'close' }, body: JSON.stringify({ call: 'signin', event: proof }) });
    const ks = signed.headers.getSetCookie().find((x) => x.startsWith('ks='))!.split(';')[0].slice(3);
    await ctx.addCookies([{ name: 'ks', value: ks, url: base }]);
    // A passkey needs a host name, not an address: the browser comes in by localhost.
    const page0 = base.replace('127.0.0.1', 'localhost');
    await ctx.addCookies([{ name: 'ks', value: ks, url: page0 }]);
    const cdp = await ctx.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    const first = await site('Marble');
    await fromSite(page, page0 + '/#connect=' + encodeURIComponent(first.uri));
    await page.waitForSelector('text=Save a passkey so next time it’s one tap');
    assert.equal(new URL(page.url()).hash, '', 'the code is gone from the address bar');
    assert.equal(JSON.parse((await page.evaluate(() => sessionStorage.getItem('kk-connect')))!).uri, first.uri);
    assert.equal(await page.textContent('#askname'), 'Marble');
    assert.match((await page.textContent('#asking'))!, /127\.0\.0\.1/);
    assert.match((await page.textContent('#askrelay'))!, new RegExp(relay.url));
    await page.reload();                                             // it lives through a reload, sender and all
    await page.waitForSelector('#savepk');
    await page.click('#savepk');
    // The card: the site (the sender, which matches the code), the account's name and picture, and the relay.
    await page.waitForSelector('#connectcard');
    const host = new URL(siteOrigin).host;
    assert.equal(await page.textContent('#connecttitle'), `Sign in to ${host} as Aaron?`);
    assert.equal(await page.getAttribute('#connectcard img.avatar', 'src'), 'https://pics.example/aaron.png');
    assert.match((await page.textContent('#askfrom'))!, new RegExp(siteOrigin));
    assert.equal(await page.locator('#connectwarn').count(), 0);
    assert.equal(await page.textContent('#connectgo'), 'Sign in');
    await new Promise((r) => setTimeout(r, 800));
    assert.deepEqual(puts(), [], 'nothing goes to a device before the click');
    // No pointer yet, and no signer here to sign one: the page says so plainly.
    await page.waitForSelector('text=does not name a sign-in page yet');
    assert.equal(await page.locator('#publishpointer').count(), 0);
    await page.click('#connectgo');
    await page.waitForSelector('text=Waiting for one of your devices…');
    await tickUntil(page, '#backto');
    assert.deepEqual(puts().map((x) => [x.text, x.from, x.as]), [[first.uri, siteOrigin, 'main']]);
    assert.equal(await page.textContent('#handoff'), 'Done. Go back to Marble');
    assert.equal(await page.getAttribute('#backto', 'href'), siteOrigin + '/');
    assert.equal(await page.evaluate(() => sessionStorage.getItem('kk-connect')), null);
    const s1 = await first.waiting; sites.push(s1);
    assert.equal(await s1.getPublicKey(), npub);
    const held = JSON.parse(readFileSync(join(boxDir, 'state.json'), 'utf8')).accounts[npub];
    assert.equal(held.passkeys.length, 1); assert.equal(held.passkeys[0].rpId, 'localhost');

    // Signed out, the passkey is the first way in, and after a click it signs in the next site too.
    await ctx.clearCookies();
    const again = await site('Marble');
    await page.goto('about:blank');
    await fromSite(page, page0 + '/#connect=' + encodeURIComponent(again.uri));
    await page.waitForSelector('#pkgo');
    assert.ok(await page.evaluate(() => { const pk = document.getElementById('pkcard')!, panel = document.querySelector('.panel')!; return !!(pk.compareDocumentPosition(panel) & Node.DOCUMENT_POSITION_FOLLOWING); }), 'the passkey comes before the scan and the password');
    await page.click('#pkgo');
    await page.waitForSelector('#connectgo');
    // A passkey's session lasts 90 days, so its cookie does too.
    assert.ok((await ctx.cookies()).some((k) => k.name === 'ks' && k.expires > Date.now() / 1000 + 80 * 86400));
    await page.click('#connectgo');
    await tickUntil(page, '#backto');
    sites.push(await again.waiting);
    await page.click('#toaccount');
    await page.waitForSelector('text=signed in with a passkey');

    // The regression: a browser already signed in here must not sign a site in without a click. Opening the
    // page with a code shows the card at once, and nothing goes to a device until "Sign in".
    calls.length = 0;
    const third = await site('Marble');
    await fromSite(page, page0 + '/#connect=' + encodeURIComponent(third.uri));
    await page.waitForSelector('#connectcard');
    await new Promise((r) => setTimeout(r, 1500));
    assert.deepEqual(puts(), [], 'an already signed-in page leaves no note before the click');
    assert.equal(await page.locator('#handoff').count(), 0);
    // A separate account for this site: the same click, with `as: "site"`.
    await page.click('#connectsite');
    await tickUntil(page, '#backto');
    assert.deepEqual(puts().map((x) => [x.from, x.as]), [[siteOrigin, 'site']]);
    sites.push(await third.waiting);

    // No referrer: the card says it could not tell, and signing in needs a second yes.
    calls.length = 0;
    const blind = await site('Marble');
    await page.goto('about:blank');
    await page.goto(page0 + '/#connect=' + encodeURIComponent(blind.uri));
    await page.waitForSelector('#connectwarn');
    assert.equal(await page.textContent('#connecttitle'), 'Sign in to a site as Aaron?');
    assert.match((await page.textContent('#connectwarn'))!, /This page could not tell which site sent you here\. It calls itself Marble\./);
    assert.equal(await page.textContent('#connectgo'), 'Sign in anyway');
    page.once('dialog', (d) => d.dismiss());
    await page.click('#connectgo');
    await new Promise((r) => setTimeout(r, 500));
    assert.deepEqual(puts(), [], 'a No on the second question sends nothing');
    page.once('dialog', (d) => d.accept());
    await page.click('#connectgo');
    await tickUntil(page, '#handoff');
    assert.deepEqual(puts().map((x) => [x.from, x.as]), [[null, 'main']]);
    await tickUntil(page, 'text=Done. Go back to the site.');
    sites.push(await blind.waiting);

    // A sender that is not the site the code names: said in plain words, and Not now sends nothing.
    calls.length = 0;
    const liar = code('Marble', 'https://marble.example/');
    await fromSite(page, page0 + '/#connect=' + encodeURIComponent(liar.uri));
    await page.waitForSelector('#connectwarn');
    assert.equal(await page.textContent('#connecttitle'), `Sign in to ${host} as Aaron?`);
    assert.match((await page.textContent('#connectwarn'))!, new RegExp(`This request came from ${host.replace(/\./g, '\\.')}, but says it is marble\\.example\\.`));
    assert.equal(await page.textContent('#connectgo'), 'Sign in anyway');
    await page.click('#connectno');
    await page.waitForSelector('#notsigned');
    assert.deepEqual(puts(), []);
    assert.equal(await page.evaluate(() => sessionStorage.getItem('kk-connect')), null);

    // The Security section lists the signed-in browsers, with Sign out on each.
    await page.click('#toaccount');
    await page.click('nav >> text=Security');
    await page.waitForSelector('#browsers');
    assert.match((await page.textContent('#browsers'))!, /This browser/);
    assert.match((await page.textContent('#browsers'))!, /passkey · signed in .* · last used today/);
    // A password is still a full way in: set one here.
    await page.fill('#newuser', 'aaron'); await page.fill('#newpass', 'correct horse battery');
    await page.click('#savepw');
    await page.waitForSelector('text=Password saved.');

    // The account names this page in the old kind only (from before the move): read as a fallback, so the page offers nothing.
    await publish({ kind: 30078, created_at: now(), tags: [['d', 'keykin/login'], ['url', base]], content: '' });

    // 2. Next time, from a fresh browser: the site shows above the sign-in card, and the password signs in.
    const second = await site('Marble');
    const p2 = await (await context()).newPage(); watch(p2);
    await fromSite(p2, base + '/#connect=' + encodeURIComponent(second.uri));
    await p2.waitForSelector('#username');
    assert.equal(await p2.textContent('#askname'), 'Marble');
    await p2.fill('#username', 'aaron'); await p2.fill('#password', 'correct horse battery');
    await p2.click('#pwgo');
    await p2.waitForSelector('#connectgo');
    assert.equal(await p2.locator('#savepk').count(), 0, 'a password sign-in is not pushed to a passkey');
    assert.equal(await p2.locator('#pointerline').count(), 0, 'the account names its page: nothing to offer');
    await p2.click('#connectgo');
    await tickUntil(p2, '#backto');
    const s2 = await second.waiting; sites.push(s2);
    assert.equal(await s2.getPublicKey(), npub);
    await p2.click('#toaccount');
    await p2.waitForSelector('text=Welcome, Aaron');

    // A newer 10046 with no template is a removal, and the old kind is not read then: the page says so.
    await publish({ kind: 10046, created_at: now() + 1, tags: [], content: '' });
    const fourth = await site('Marble');
    await fromSite(p2, base + '/#connect=' + encodeURIComponent(fourth.uri));
    await p2.waitForSelector('#connectgo');
    assert.match((await p2.textContent('#pointersub'))!, /sign-in page was removed/);
    await p2.click('#connectgo');
    await tickUntil(p2, '#backto');
    sites.push(await fourth.waiting);
    // The 10046 path: the newest names this page, so there is nothing to offer.
    await publish({ kind: 10046, created_at: now() + 2, tags: [['nostrconnect_url', base + '/#connect=<nostrconnect>']], content: '' });
    const fifth = await site('Marble');
    await fromSite(p2, base + '/#connect=' + encodeURIComponent(fifth.uri));
    await p2.waitForSelector('#connectgo');
    assert.equal(await p2.locator('#pointerline').count(), 0);
    await p2.click('#connectgo');
    await tickUntil(p2, '#backto');
    sites.push(await fifth.waiting);
    // The first browser sees the second in its list, and signs it out.
    await page.click('nav >> text=Home'); await page.click('nav >> text=Security');
    await page.waitForSelector('#browsers .row >> nth=1');
    await page.locator('#browsers .row', { hasText: 'password ·' }).locator('button').click();
    await page.waitForSelector('text=Chrome on macOS is signed out.');
    assert.equal(await page.locator('#browsers .row', { hasText: 'password ·' }).count(), 0);
    await p2.reload();
    await p2.waitForSelector('#username');
    assert.deepEqual(errors, []);
  } finally { for (const s of sites) await s.close().catch(() => {}); agent?.close(); await browser.close(); await login.close(); await box.close(); relay.kill(); siteServer.close(); }
});

// An app (Marble on a Mac, through Marble Web) sends the person here with its own invite: #relay=…&secret=…&add=<invite>.
// They sign in (or already are), press Add on a card, one of their devices adds it, and the page sends the join code
// back to the invite's key on that relay, NIP-44 from a throwaway key, with the secret beside it.
test('an app sends you here to add it as a device: #add=, a click, and the join code back to the app on its relay', { skip: (!exe && 'no Chromium found') || (!existsSync(relayTool) && 'no test relay'), timeout: 120_000 }, async () => {
  const { chromium: pw } = await import('playwright-core');
  const nip44 = await import('nostr-tools/nip44');
  const w = await world();
  const browser = await pw.launch({ executablePath: exe!, args: ['--headless=new'] });
  const shots = process.env.KEYKIN_SHOTS ?? join(tmpdir(), 'keykin-shots'); mkdirSync(shots, { recursive: true });
  try {
    const phone = device('Pixel 9a');
    const held = await D.createWithBox(phone, D.readQr(w.box.qr()!), w.send);
    await D.passwordSet(phone, held, 'aaron', 'correct horse battery', w.send);
    // The account's name and picture, on the page's relay, for the card.
    const ev = await D.signEvent(phone, held, { pubkey: held.npub, created_at: Math.floor(Date.now() / 1000), kind: 0, tags: [], content: JSON.stringify({ name: 'Aaron', picture: 'https://pics.example/aaron.png' }) }, w.send);
    await new Promise<void>((ok, no) => { const ws = new WebSocket(w.relay); ws.onopen = () => ws.send(JSON.stringify(['EVENT', ev])); ws.onmessage = (m) => { ws.close(); JSON.parse(String(m.data))[2] ? ok() : no(new Error(String(m.data))); }; ws.onerror = no; });
    const away = { ...phone, fp: undefined };
    const answered = async () => { for (let k = 0; k < 40; k++) { const did = await D.answerNotes(away, held, w.send, { addr: w.base, tap: async () => false }); if (did.length) return did; await new Promise((r) => setTimeout(r, 150)); } return []; };
    const mac = device('Marble on Mac');
    const invite = JSON.stringify({ keykin: 2, invite: { key: mac.key, name: 'Marble on Mac' } });
    const secret = 'c0ffee'.repeat(4);
    const ask = (inv = invite, relay: string | null = w.relay) => (relay ? `relay=${encodeURIComponent(relay)}&secret=${secret}&` : '') + 'add=' + encodeURIComponent(inv);
    // The app's side: listening on its relay for kind 24133 to the invite's key.
    const listen = (key: string) => {
      const got: any[] = [];
      const ws = new WebSocket(w.relay);
      const ready = new Promise<void>((ok) => { ws.onopen = () => { ws.send(JSON.stringify(['REQ', 'mac', { kinds: [24133], '#p': [key] }])); ok(); }; });
      ws.onmessage = (m) => { const d = JSON.parse(String(m.data)); if (d[0] === 'EVENT') got.push(d[2]); };
      return { got, ready, close: () => ws.close() };
    };

    const errors: string[] = [], calls: any[] = [];
    const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');
    const context = async () => { const ctx = await browser.newContext({ viewport: { width: 1100, height: 820 } }); await ctx.route('https://pics.example/**', (r) => r.fulfill({ contentType: 'image/png', body: png })); return ctx; };
    const watch = (p: any) => {
      p.on('pageerror', (e: any) => errors.push(String(e))); p.on('console', (m: any) => { if (m.type() === 'error') errors.push(m.text()); });
      p.on('request', (r: any) => { if (r.url().endsWith('/api') && r.method() === 'POST') { try { calls.push(JSON.parse(r.postData())); } catch {} } });
    };
    const puts = () => calls.filter((c) => c.call === 'note_put');
    const kept = (p: any) => p.evaluate(() => JSON.parse(sessionStorage.getItem('kk-add') ?? 'null'));

    // Not a Keykin invite (not JSON, a short key, encoded twice): said plainly and left alone, and the address bar is cleared.
    for (const bad of [encodeURIComponent('not an invite'), encodeURIComponent(JSON.stringify({ keykin: 2, invite: { key: 'ab12', name: 'x' } })), encodeURIComponent(encodeURIComponent(invite))]) {
      const p = await (await context()).newPage(); watch(p);
      await p.goto(w.base + '/#add=' + bad);
      await p.waitForSelector('#addasking[role=alert]');
      assert.match((await p.textContent('#addasking'))!, /not a Keykin invite, so it was left alone/);
      assert.equal(new URL(p.url()).hash, '');
      assert.equal(await kept(p), null);
      await p.context().close();
    }

    // Raw or encoded once, after other parameters: read, kept for this tab with the relay and secret, and gone from the address bar.
    for (const tail of [invite, encodeURIComponent(invite)]) {
      const p = await (await context()).newPage(); watch(p);
      await p.goto(w.base + `/#x=1&relay=${encodeURIComponent(w.relay)}&secret=${secret}&add=` + tail);
      await p.waitForSelector('#addname');
      assert.equal(await p.textContent('#addname'), 'Marble on Mac');
      assert.equal(new URL(p.url()).hash, '#x=1', 'other fragment parameters stay; relay, secret and add go');
      assert.deepEqual(await kept(p), { invite, relay: w.relay, secret });
      await p.context().close();
    }

    // Signed out: the request shows above the sign-in, lives through a reload, and after the password the card asks.
    const ctx = await context(); const page = await ctx.newPage(); watch(page);
    await page.goto(w.base + '/#' + ask());
    await page.waitForSelector('#username');
    assert.match((await page.textContent('#addasking'))!, /A device is asking to be added to your account/);
    await page.reload();
    await page.waitForSelector('#addname');
    await page.fill('#username', 'aaron'); await page.fill('#password', 'correct horse battery');
    await page.click('#pwgo');
    await page.waitForSelector('#addcard');
    assert.equal(await page.textContent('#addtitle'), 'Add Marble on Mac to your account?');
    assert.equal(await page.textContent('#addwho'), 'Aaron');
    assert.equal(await page.getAttribute('#addcard img.avatar', 'src'), 'https://pics.example/aaron.png');
    assert.equal(await page.textContent('#adddevice'), 'New device: Marble on Mac');
    assert.match((await page.textContent('#addwarn'))!, /Only say yes if you just pressed Sign in on this computer/);
    assert.deepEqual([await page.textContent('#addgo'), await page.textContent('#addno')], ['Add', 'Not now']);
    await new Promise((r) => setTimeout(r, 1000));
    assert.deepEqual(puts(), [], 'nothing goes to a device before the click');
    await page.screenshot({ path: join(shots, 'add-card.png') });

    // Add: the same invite note as Devices, Add a device; a device adds it; the join code goes back on the app's relay.
    const app = listen(mac.key); await app.ready;
    await page.click('#addgo');
    await page.waitForSelector('text=Waiting for one of your devices…');
    await page.waitForFunction(() => sessionStorage.getItem('kk-add') === null);   // the box holds it now: a reload does not add it twice
    assert.deepEqual(puts().map((x) => [x.kind, x.text]), [['invite', invite]]);
    assert.deepEqual(await answered(), ['added Marble on Mac']);
    await page.waitForSelector('text=Done. Marble on Mac is signed in.');
    await page.screenshot({ path: join(shots, 'add-done.png') });
    for (let k = 0; k < 40 && !app.got.length; k++) await new Promise((r) => setTimeout(r, 100));
    app.close();
    assert.equal(app.got.length, 1);
    const back = app.got[0];
    assert.ok(verifyEvent(back)); assert.equal(back.kind, 24133); assert.deepEqual(back.tags, [['p', mac.key]]);
    assert.notEqual(back.pubkey, held.npub, 'from a throwaway key');
    const opened = JSON.parse(nip44.decrypt(back.content, nip44.getConversationKey(Buffer.from(mac.sk, 'hex'), back.pubkey)));
    assert.deepEqual(opened, { keykin: 2, join: { addr: w.base, boxKey: held.boxKey, npub: held.npub }, secret });
    assert.equal(await page.textContent('#joincode'), JSON.stringify({ keykin: 2, join: { addr: w.base, boxKey: held.boxKey, npub: held.npub } }), 'and shown, folded, to paste by hand');
    // The join code it sent really joins the new device.
    const mh = await D.join(mac, held.boxKey, held.npub, w.send);
    assert.ok(verifyEvent(await D.signEvent(mac, mh, note(held.npub), w.send)));

    // Already signed in: the card at once, and still nothing without a click. Not now sends nothing.
    calls.length = 0;
    const other = device('Marble on Mac');
    await page.goto('about:blank');
    await page.goto(w.base + '/#' + ask(JSON.stringify({ keykin: 2, invite: { key: other.key, name: 'Marble on Mac' } })));
    await page.waitForSelector('#addcard');
    await new Promise((r) => setTimeout(r, 1500));
    assert.deepEqual(puts(), [], 'an already signed-in page leaves no note before the click');
    await page.click('#addno');
    await page.waitForSelector('#notadded');
    assert.equal(await page.textContent('#notadded'), 'Marble on Mac was not added.');
    assert.equal(await kept(page), null);
    await new Promise((r) => setTimeout(r, 500));
    assert.deepEqual(puts(), []);

    // No relay given (an older app): the join code is shown to paste.
    const third = device('Laptop');
    await page.goto('about:blank');
    await page.goto(w.base + '/#' + ask(JSON.stringify({ keykin: 2, invite: { key: third.key, name: 'Laptop' } }), null));
    await page.click('#addgo');
    assert.deepEqual(await answered(), ['added Laptop']);
    await page.waitForSelector('text=Done. Paste this join code into Laptop:');
    assert.ok(await page.locator('#addcode[open]').count());
    assert.deepEqual(errors, []);
  } finally { await browser.close(); await w.close(); }
});

test('sign-in strength: one session for every way in today, and tiers a box owner can switch on', async () => {
  const { allowedBy } = await import('../box/box.ts');
  const now = () => Math.floor(Date.now() / 1000);
  for (const policy of [undefined, { calls: { 'note_put:invite': 'strong' as const, 'limit:none': 'strong' as const }, weakSiteLimit: 'dms' as const }]) {
    const box = await startBox({ dir: mkdtempSync(join(tmpdir(), 'kk-box-')), port: 0, url: 'http://box', policy, log: () => {} });
    try {
      const send: D.Send = async (r) => box.box.handle(r as any, now());
      const phone = device('Phone');
      const held = await D.createWithBox(phone, D.readQr(box.qr()!), send);
      await D.passwordSet(phone, held, 'aaron', 'correct horse battery', send);
      const { salt } = box.page.call({ call: 'pw_salt', username: 'aaron' }, now());
      const session = box.page.call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('correct horse battery', salt) }, now()).session;
      assert.equal(box.page.call({ call: 'me', session }, now()).how, 'password');
      const invite = box.page.call({ call: 'note_put', session, kind: 'invite', text: '{}' }, now());
      const put = box.page.call({ call: 'note_put', session, kind: 'nostrconnect', text: 'nostrconnect://' + 'a'.repeat(64) + '?relay=wss://r&secret=s' }, now());
      await D.answerNotes({ ...phone, fp: undefined }, held, send, { addr: 'http://box', tap: async () => true, connect: async () => true });
      const grant = D.newGrant('site', 'https://site.example');
      await D.reportGrants(phone, held, [grant], send);
      const limit = box.page.call({ call: 'me', session }, now()).grants[0].limit;
      const lift = box.page.call({ call: 'limit', session, grant: grant.id, to: null }, now());
      if (!policy) {
        // Today: a password is a full session. Nothing is refused and nothing is limited.
        assert.equal(invite.ok, true); assert.equal(put.limit, undefined); assert.equal(limit, null); assert.equal(lift.ok, true);
      } else {
        assert.deepEqual(invite, { error: 'need_strong' }); assert.equal(put.limit, 'dms'); assert.equal(limit, 'dms'); assert.deepEqual(lift, { error: 'need_strong' });
      }
    } finally { await box.close(); }
  }
  // The `dms` limit: posts and direct messages with other people's keys, but not the account's own key (private lists).
  const me = 'b'.repeat(64);
  assert.equal(allowedBy('dms', 'sign', 1, undefined, me), true); assert.equal(allowedBy('dms', 'sign', 1059, undefined, me), true);
  assert.equal(allowedBy('dms', 'sign', 30000, undefined, me), false); assert.equal(allowedBy('dms', 'ecdh', undefined, 'c'.repeat(64), me), true);
  assert.equal(allowedBy('dms', 'ecdh', undefined, '02' + me, me), false); assert.equal(allowedBy('posts', 'ecdh', undefined, 'c'.repeat(64), me), false);
  assert.equal(allowedBy('posts', 'sign', 4, undefined, me), false); assert.equal(allowedBy(undefined, 'sign', 30000, undefined, me), true);
});
