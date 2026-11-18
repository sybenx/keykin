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
