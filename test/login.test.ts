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

async function world(o: { open?: boolean; noRelay?: boolean } = {}) {
  const testRelay = !o.noRelay && existsSync(relayTool) ? await (await import(relayTool)).startRelay({}) : null;
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
    // Home: "Sign in to an app" first (under an alert, if there is one), and a status line only when no alert is up.
    await page.waitForSelector('#signinapp');
    assert.equal(await page.evaluate(() => { const m = document.querySelector('main')!; return Array.from(m.children).find((c) => !['pointeralert', 'pointernote', 'status'].includes(c.id))?.id; }), 'signinapp');
    assert.equal(await page.textContent('#signinapp h2'), 'Sign in to an app');
    await page.waitForFunction(() => !!document.querySelector('#pointeralert, #pointernote'));
    if (await page.locator('#pointeralert').count()) assert.equal(await page.locator('#statusline').count(), 0, 'no status line under an alert');
    else assert.match((await page.textContent('#statusline'))!, /^Everything looks fine\. 2 devices and 2 boxes can sign, nothing is blocked\.$/);
    // Two devices and a backup box: backed up, by both.
    assert.equal(await page.textContent('#backupsub'), 'Backed up by a second device and another box (Backup box). If one device is lost, the others still sign.');
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
    // Added from the page: its piece waits for the six digits the page shows with the join code (SPEC 11.6).
    await assert.rejects(D.join(work, jt.boxKey, jt.npub, w.send), /not_approved|wrong_code/);
    const digits = /(\d{3}) (\d{3})/.exec((await page.textContent('#pastecode'))!)!;
    const wh = await D.join(work, jt.boxKey, jt.npub, w.send, undefined, { code: digits[1] + digits[2] });
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
    // A site with the phone's two switches: DMs turned on here waits for the phone, which picks it up when it reports.
    const chat: D.Grant = { ...D.newGrant('site', 'https://chat.nostr.com'), lists: false, dms: false, via: 'bunker' };
    await D.reportGrants(phone, held, [amethyst, chat], w.send);
    await page.click('nav >> text=Devices'); await page.click('nav >> text=Sites and apps');
    const dms = 'input[aria-label="DMs for https://chat.nostr.com"]', lists = 'input[aria-label="Private lists for https://chat.nostr.com"]';
    assert.equal(await page.locator('input[aria-label="DMs for https://jumble.social"]').count(), 0);
    await page.check(dms);
    await page.waitForSelector('text=chat.nostr.com can read and send DMs once Pixel 9a picks it up.');
    assert.ok(await page.isChecked(dms)); assert.ok(!(await page.isChecked(lists)));
    await page.waitForSelector('text=waiting for Pixel 9a');
    await shot('sites-switches');
    const got = await D.syncGrants(phone, held, [amethyst, chat], w.send);
    assert.deepEqual(got.scopes, { [chat.id]: { dms: true } });
    await D.reportGrants(phone, held, [amethyst, { ...chat, dms: true }], w.send);
    await page.check('input[aria-label="Posts only for https://chat.nostr.com"]');
    await page.waitForSelector('text=chat.nostr.com can only post now.');
    assert.ok(await page.isDisabled(dms)); assert.ok(await page.isDisabled(lists));
    assert.equal(await page.locator('text=waiting for Pixel 9a').count(), 0);
    await page.click('button[aria-label="Revoke Amethyst"]');
    await page.waitForSelector('text=Amethyst is revoked.');
    await assert.rejects(D.signEvent(phone, held, note(held.npub), w.send, undefined, amethyst.id), /revoked/);
    // The card is on Home now, and the sites page links there.
    assert.equal(await page.locator('#signinapp').count(), 0);
    await page.click('text=Sign in to another app');
    await page.click('text=Get a bunker link');
    assert.deepEqual(await answered(), ['gave a bunker link']);
    await page.waitForSelector('#bunkerlink.has');
    assert.equal(await page.textContent('#bunkerlink'), 'bunker://abc123?relay=wss%3A%2F%2Frelay.example');
    // The page checks the account every 15 seconds and redraws. The link must still be there after that.
    await new Promise((r) => setTimeout(r, 16_000));
    assert.equal(await page.textContent('#bunkerlink'), 'bunker://abc123?relay=wss%3A%2F%2Frelay.example');
    assert.equal(await page.locator('#bunkerlink.has').count(), 1);
    await page.click('nav >> text=Devices'); await page.click('nav >> text=Home');
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

test('the account page says at the top when sites cannot find you by name, and nothing once they can', { skip: !exe && 'no Chromium found', timeout: 90_000 }, async () => {
  const { chromium: pw } = await import('playwright-core');
  const browser = await pw.launch({ executablePath: exe!, args: ['--headless=new'] });
  const shots = process.env.KEYKIN_SHOTS;
  const signIn = async (w: Awaited<ReturnType<typeof world>>, dark = false) => {
    const page = await (await browser.newContext({ viewport: { width: 1280, height: 860 }, colorScheme: dark ? 'dark' : 'light' })).newPage();
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(String(e)));
    await page.goto(w.base + '/');
    await page.fill('#username', 'aaron'); await page.fill('#password', 'correct horse battery');
    await page.click('#pwgo');
    await page.waitForSelector('text=Welcome, Aaron');
    return { page, errors };
  };
  const shot = async (page: any, name: string) => { if (shots) { mkdirSync(shots, { recursive: true }); await page.screenshot({ path: join(shots, name + '.png'), fullPage: true }); } };
  try {
    // The relays cannot be reached: a quiet note, not an alert.
    const off = await world({ noRelay: true });
    try {
      const phone = device('Phone');
      const held = await D.createWithBox(phone, D.readQr(off.box.qr()!), off.send);
      await D.passwordSet(phone, held, 'aaron', 'correct horse battery', off.send);
      for (const dark of [false, true]) {
        const { page, errors } = await signIn(off, dark);
        await page.waitForSelector('#pointernote');
        assert.match((await page.textContent('#pointernote'))!, /could not check whether sites can find you by your name/);
        assert.equal(await page.locator('#pointeralert').count(), 0);
        await shot(page, `account-unknown${dark ? '-dark' : ''}`);
        assert.deepEqual(errors, []);
        await page.context().close();
      }
    } finally { await off.close(); }

    const w = await world();
    if (!w.hasRelay) { await w.close(); return; }
    try {
      const phone = device('Phone');
      const held = await D.createWithBox(phone, D.readQr(w.box.qr()!), w.send);
      await D.passwordSet(phone, held, 'aaron', 'correct horse battery', w.send);
      let at = Math.floor(Date.now() / 1000);
      const publish = async (e: { kind: number; tags: string[][] }) => {
        const signed = await D.signEvent(phone, held, { pubkey: held.npub, created_at: ++at, content: '', ...e }, w.send);
        await new Promise<void>((ok, no) => { const ws = new WebSocket(w.relay); ws.onopen = () => ws.send(JSON.stringify(['EVENT', signed])); ws.onmessage = (m) => { ws.close(); JSON.parse(String(m.data))[2] ? ok() : no(new Error(String(m.data))); }; });
      };
      // Nothing published: the alert, first on the page, then "Sign in to an app", and no status line. After a
      // password there is no signer here, so the alert asks the phone instead.
      for (const dark of [false, true]) {
        const { page, errors } = await signIn(w, dark);
        await page.waitForSelector('#pointeralert');
        assert.equal(await page.textContent('#pointertitle'), 'Sites can’t find you by name yet');
        assert.deepEqual(await page.evaluate(() => Array.from(document.querySelector('main')!.children).slice(0, 3).map((c) => c.id || c.className)), ['pointeralert', 'signinapp', 'hello']);
        assert.equal(await page.locator('#statusline').count(), 0, 'no status line while an alert shows');
        assert.equal(await page.locator('#publishpointer').count(), 0, 'no signer after a password');
        assert.equal(await page.textContent('#pointerphone'), 'Publish it from my phone');
        assert.equal(await page.textContent('#pointerline'), 'Your phone asks you first, then signs it.');
        assert.equal(await page.locator('#pointerscan').count(), 0);
        // One device and the box: no backup, and the box alone cannot bring the account back.
        assert.match((await page.textContent('#backupsub'))!, /^No backup yet/);
        await shot(page, `account-missing${dark ? '-dark' : ''}`);
        assert.deepEqual(errors, []);
        await page.context().close();
      }
      // Another page named.
      await publish({ kind: 10046, tags: [['nostrconnect_url', 'https://other.example/#connect=<nostrconnect>']] });
      for (const dark of [false, true]) {
        const { page, errors } = await signIn(w, dark);
        await page.waitForSelector('#pointeralert');
        assert.equal(await page.textContent('#pointertitle'), 'Sites send you to other.example, not here');
        await shot(page, `account-other${dark ? '-dark' : ''}`);
        assert.deepEqual(errors, []);
        await page.context().close();
      }
      // This page named: no alert, and the card lower down.
      await publish({ kind: 10046, tags: [['nostrconnect_url', w.base + '/#connect=<nostrconnect>']] });
      const { page, errors } = await signIn(w);
      await page.waitForSelector('#pointersub');
      assert.match((await page.textContent('#pointersub'))!, new RegExp(`names ${w.base.replace(/[.]/g, '\\.')} as its sign-in page`));
      assert.equal(await page.locator('#pointeralert').count(), 0); assert.equal(await page.locator('#pointernote').count(), 0);
      await shot(page, 'account-here');
      assert.deepEqual(errors, []);
    } finally { await w.close(); }
  } finally { await browser.close(); }
});

test('the account page asks the phone to publish the sign-in page after a password: no address, No, no answer, Cancel, Yes', { skip: !exe && 'no Chromium found', timeout: 120_000 }, async () => {
  const { chromium: pw } = await import('playwright-core');
  const w = await world();
  if (!w.hasRelay) { await w.close(); return; }
  const browser = await pw.launch({ executablePath: exe!, args: ['--headless=new'] });
  const shots = process.env.KEYKIN_SHOTS;
  const shot = async (page: any, name: string) => { if (shots) { mkdirSync(shots, { recursive: true }); await page.screenshot({ path: join(shots, name + '.png'), fullPage: true }); } };
  const P: any = (() => { const g: any = {}; new Function('globalThis', readFileSync(join(import.meta.dirname, '../login/static/pointer.js'), 'utf8'))(g); return g.KeykinPointer; })();
  try {
    const phone = device('Pixel 9a');
    const held = await D.createWithBox(phone, D.readQr(w.box.qr()!), w.send);
    await D.passwordSet(phone, held, 'aaron', 'correct horse battery', w.send);
    let at = Math.floor(Date.now() / 1000);
    const toRelay = (signed: any) => new Promise<void>((ok, no) => { const ws = new WebSocket(w.relay); ws.onopen = () => ws.send(JSON.stringify(['EVENT', signed])); ws.onmessage = (m) => { ws.close(); JSON.parse(String(m.data))[2] ? ok() : no(new Error(String(m.data))); }; });
    // The phone, somewhere else: asks Yes or No, then signs both kinds and sends them to the relay.
    const taps: string[] = [], named: string[] = [];
    const can = (yes: boolean) => ({ addr: w.base, tap: async (t: string) => { taps.push(t); return yes; }, pointer: async (origin: string) => {
      named.push(origin);
      for (const e of P.pointerEvents(origin, ++at)) await toRelay(await D.signEvent(phone, held, { pubkey: held.npub, ...e }, w.send));
      return true;
    } });
    const answered = async (yes: boolean) => { for (let k = 0; k < 40; k++) { const did = await D.answerNotes({ ...phone, fp: undefined }, held, w.send, can(yes)); if (did.length) return did; await new Promise((r) => setTimeout(r, 150)); } return []; };

    const page = await (await browser.newContext({ viewport: { width: 1280, height: 860 } })).newPage();
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(String(e)));
    const signIn = async () => {
      await page.goto(w.base + '/');
      await page.fill('#username', 'aaron'); await page.fill('#password', 'correct horse battery');
      await page.click('#pwgo');
      await page.waitForSelector('#pointerphone');
    };
    // The box has no login page address yet: it refuses, and the page says why.
    await signIn();
    await page.click('#pointerphone');
    await page.waitForSelector('text=This box has no login page address set yet');
    assert.equal(await page.locator('#pointerphone').count(), 0);
    await shot(page, 'phone-no-address');

    // Now it has one, and not the address this test page is at (http://127.0.0.1): the page counts a pointer
    // naming the box's address as here, so no alert comes back after the phone publishes it.
    w.box.box.setLoginPage('https://account.example');
    await page.reload(); await page.waitForSelector('#pointerphone');
    await page.click('#pointerphone');
    await page.waitForSelector('#pointercancel');
    assert.equal(await page.textContent('#pointerline'), 'Approve on your phone…');
    await shot(page, 'phone-waiting');
    // At a phone's width, dark: nothing scrolls sideways.
    await page.setViewportSize({ width: 390, height: 844 }); await page.emulateMedia({ colorScheme: 'dark' });
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), 'no sideways scroll on a phone');
    await shot(page, 'phone-waiting-narrow-dark');
    await page.emulateMedia({ colorScheme: 'light' }); await shot(page, 'phone-waiting-narrow');
    await page.setViewportSize({ width: 1280, height: 860 }); await page.emulateMedia({ colorScheme: 'dark' }); await shot(page, 'phone-waiting-dark');
    await page.emulateMedia({ colorScheme: 'light' });
    // The page redraws every 15 seconds; the waiting state stays.
    await page.click('nav >> text=Devices'); await page.click('nav >> text=Home');
    await page.waitForSelector('text=Approve on your phone…');
    // The phone said No.
    assert.deepEqual(await answered(false), ['said No to the sign-in page']);
    assert.deepEqual(taps, ['Make account.example your sign-in page?']);
    await page.waitForSelector('text=Your phone said no.');
    assert.equal(await page.locator('#pointerphone').count(), 1, 'it can be asked again');
    await shot(page, 'phone-declined');

    // No answer in the note's time: the box says the note is gone.
    await page.route('**/api', async (r) => {
      if (JSON.parse(r.request().postData() ?? '{}').call === 'note_get') return r.fulfill({ contentType: 'application/json', body: JSON.stringify({ ok: true, state: 'gone' }) });
      return r.fallback();
    });
    await page.click('#pointerphone');
    await page.waitForSelector('text=No device answered in time. Is one of them online?');
    await page.unroute('**/api');
    await shot(page, 'phone-gone');

    // Cancel: the page stops waiting and offers the button again.
    await page.click('#pointerphone');
    await page.waitForSelector('#pointercancel');
    await page.click('#pointercancel');
    await page.waitForSelector('#pointerphone');
    assert.equal(await page.textContent('#pointerline'), 'Your phone asks you first, then signs it.');

    // Yes: the phone publishes it naming the box's address, and the page checks again and says so.
    await page.click('#pointerphone');
    await page.waitForSelector('#pointercancel');
    const did = await answered(true);
    assert.ok(did.includes('published https://account.example as the sign-in page'), String(did));
    assert.ok(named.every((o) => o === 'https://account.example'));
    await page.waitForSelector('#status');
    assert.equal(await page.textContent('#status'), 'Published. Sites send you to account.example.');
    assert.equal(await page.locator('#pointeralert').count(), 0, 'the box\'s address counts as here');
    assert.match((await page.textContent('#pointersub'))!, /names https:\/\/account\.example as its sign-in page/);
    // It stays that way after a reload, when the page asks the relays afresh.
    await page.reload(); await page.waitForSelector('#pointersub');
    assert.equal(await page.locator('#pointeralert').count(), 0);
    // No alert now, so the status line is back, and it says what is left: one device.
    assert.equal(await page.textContent('#statusline'), 'One thing to look at. You have one device. If Pixel 9a is lost, the account goes with it.');
    await shot(page, 'phone-published');
    await page.emulateMedia({ colorScheme: 'dark' }); await shot(page, 'phone-published-dark'); await page.emulateMedia({ colorScheme: 'light' });

    // A backup box: two boxes and the phone. Losing the phone no longer loses the account.
    const backup = newMemberKey();
    await D.addMember(phone, held, { key: backup.key, name: 'Backup box', kind: 'box' }, w.send);
    const { seal } = await import('../src/member.ts');
    assert.equal((await w.send(await seal({ op: 'welcome', account: held.npub }, backup.sk, Math.floor(Date.now() / 1000)))).ok, true);
    await page.reload(); await page.waitForSelector('#statusline');
    assert.equal(await page.textContent('#statusline'), 'Everything looks fine. 1 device and 2 boxes can sign, nothing is blocked.');
    assert.equal(await page.textContent('#backupsub'), 'Backed up by another box (Backup box). If one device is lost, the others still sign.');
    assert.equal(await page.locator('text=goes with it').count(), 0);
    await shot(page, 'home-backup-box');
    assert.deepEqual(errors, []);
  } finally { await browser.close(); await w.close(); }
});

test('a pointer note: the box puts in its own login page address, ignores any from the page, and refuses without one', async () => {
  const now = () => Math.floor(Date.now() / 1000);
  const box = await startBox({ dir: mkdtempSync(join(tmpdir(), 'kk-box-')), port: 0, url: 'http://box', log: () => {} });
  try {
    const send: D.Send = async (r) => box.box.handle(r as any, now());
    const phone = device('Phone');
    const held = await D.createWithBox(phone, D.readQr(box.qr()!), send);
    await D.passwordSet(phone, held, 'aaron', 'correct horse battery', send);
    const { salt } = box.page.call({ call: 'pw_salt', username: 'aaron' }, now());
    const session = box.page.call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('correct horse battery', salt) }, now()).session;
    // No address set: refused, and nothing waits for a device. `me` says there is none.
    assert.equal(box.page.call({ call: 'me', session }, now()).loginPage, null);
    assert.deepEqual(box.page.call({ call: 'note_put', session, kind: 'pointer' }, now()), { error: 'no_login_page' });
    assert.deepEqual(box.page.call({ call: 'note_put', session, kind: 'pointer', text: 'https://evil.example' }, now()), { error: 'no_login_page' });
    assert.deepEqual(await D.notes(phone, held, send), []);
    // The admin's setting, and a password session is enough (the same tier as `bunker`).
    box.box.setLoginPage('https://account.example');
    assert.equal(box.page.call({ call: 'me', session }, now()).loginPage, 'https://account.example');
    const put = box.page.call({ call: 'note_put', session, kind: 'pointer', text: 'https://evil.example' }, now());
    assert.equal(put.ok, true); assert.equal(put.url, 'https://account.example');
    const [n] = await D.notes(phone, held, send);
    assert.deepEqual([n.kind, n.text, n.tap], ['pointer', 'https://account.example', true]);
    // KEYKIN_LOGIN_URL wins over the setting.
    box.box.fixedLogin = 'https://fixed.example';
    assert.equal(box.page.call({ call: 'note_put', session, kind: 'pointer' }, now()).url, 'https://fixed.example');
    // The device asks, and answers `ok` or `declined`; the page reads that with note_get. A No leaves the session alone.
    let yes = false;
    const did = await D.answerNotes({ ...phone, fp: undefined }, held, send, { addr: 'http://box', tap: async () => (yes = !yes), pointer: async () => true });
    assert.deepEqual(did, ['published https://account.example as the sign-in page', 'said No to the sign-in page']);
    assert.deepEqual(box.page.call({ call: 'note_get', session, note: put.note }, now()), { ok: true, state: 'done', result: 'ok' });
    assert.equal(box.page.call({ call: 'me', session }, now()).ok, true);
    assert.match(box.page.call({ call: 'me', session }, now()).log.map((l: any) => l.text).join('\n'), /Publishing the sign-in page was asked for from the account page/);
  } finally { await box.close(); }
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

// An app (Marble on a Mac, through Marble Web) sends the person here with its own invite, as an app signs in with OAuth
// (RFC 8252 with PKCE): #challenge=…&return=http://127.0.0.1:<port>/done&state=…&add=<invite>. They sign in (or already
// are) and press Add; a device adds it; the box holds its piece; this page gets an approval code and sends it, with the
// state and the join text, to the return address on this computer, and shows six digits to type as the fallback.
test('an app sends you here to add it as a device: #add=, a click, and the approval back to this computer', { skip: !exe && 'no Chromium found', timeout: 120_000 }, async () => {
  const { chromium: pw } = await import('playwright-core');
  const { createServer } = await import('node:http');
  const { createHash, randomBytes: rb } = await import('node:crypto');
  const w = await world();
  const browser = await pw.launch({ executablePath: exe!, args: ['--headless=new'] });
  const shots = process.env.KEYKIN_SHOTS ?? join(tmpdir(), 'keykin-shots'); mkdirSync(shots, { recursive: true });
  // The app's loopback listener (RFC 8252 7.3): what reaches it.
  const back: URL[] = [];
  const app = createServer((req, res) => { back.push(new URL(req.url!, 'http://127.0.0.1')); res.writeHead(200, { 'content-type': 'text/html' }); res.end('<!doctype html><title>Marble</title><p>Done. Marble on Mac is signed in.'); });
  await new Promise<void>((r) => app.listen(0, '127.0.0.1', r));
  const ret = `http://127.0.0.1:${(app.address() as any).port}/done`;
  try {
    const phone = device('Pixel 9a');
    const held = await D.createWithBox(phone, D.readQr(w.box.qr()!), w.send);
    await D.passwordSet(phone, held, 'aaron', 'correct horse battery', w.send);
    if (w.hasRelay) {
      const ev = await D.signEvent(phone, held, { pubkey: held.npub, created_at: Math.floor(Date.now() / 1000), kind: 0, tags: [], content: JSON.stringify({ name: 'Aaron', picture: 'https://pics.example/aaron.png' }) }, w.send);
      await new Promise<void>((ok, no) => { const ws = new WebSocket(w.relay); ws.onopen = () => ws.send(JSON.stringify(['EVENT', ev])); ws.onmessage = (m) => { ws.close(); JSON.parse(String(m.data))[2] ? ok() : no(new Error(String(m.data))); }; ws.onerror = no; });
    }
    const who = w.hasRelay ? 'Aaron' : 'aaron';
    const away = { ...phone, fp: undefined };
    const answered = async () => { for (let k = 0; k < 40; k++) { const did = await D.answerNotes(away, held, w.send, { addr: w.base, tap: async () => false }); if (did.length) return did; await new Promise((r) => setTimeout(r, 150)); } return []; };
    const pkce = () => { const verifier = rb(32).toString('base64url'); return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') }; };
    const inviteOf = (m: D.Me) => JSON.stringify({ keykin: 2, invite: { key: m.key, name: m.name } });
    const link = (inv: string, p: { challenge: string }, state = 'st4te-' + Math.random().toString(36).slice(2), r = ret) => `challenge=${p.challenge}&return=${encodeURIComponent(r)}&state=${state}&add=${encodeURIComponent(inv)}`;

    const errors: string[] = [], calls: any[] = [];
    const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64');
    const context = async () => { const ctx = await browser.newContext({ viewport: { width: 1100, height: 820 } }); await ctx.route('https://pics.example/**', (r) => r.fulfill({ contentType: 'image/png', body: png })); return ctx; };
    const watch = (p: any) => {
      p.on('pageerror', (e: any) => errors.push(String(e))); p.on('console', (m: any) => { if (m.type() === 'error') errors.push(m.text()); });
      p.on('request', (r: any) => { if (r.url().endsWith('/api') && r.method() === 'POST') { try { calls.push(JSON.parse(r.postData())); } catch {} } });
    };
    const puts = () => calls.filter((c) => c.call === 'note_put');
    const kept = (p: any) => p.evaluate(() => JSON.parse(sessionStorage.getItem('kk-add') ?? 'null'));
    const mac = device('Marble on Mac'), mp = pkce(), invite = inviteOf(mac);

    // Left alone, and said why: not an invite; an invite whose approval would go to another computer; one missing its challenge.
    for (const [bad, why] of [
      ['add=' + encodeURIComponent('not an invite'), /not a Keykin invite/],
      ['add=' + encodeURIComponent(encodeURIComponent(invite)), /not a Keykin invite/],
      [link(invite, mp, 'st4te-evil1', 'https://evil.example/done'), /send the approval to evil\.example, which is not this computer/],
      [link(invite, mp, 'st4te-evil2', 'http://192.168.1.5:8080/done'), /which is not this computer/],
      [link(invite, mp, 'st4te-evil3', 'http://127.0.0.1/done'), /which is not this computer/],
      [`return=${encodeURIComponent(ret)}&state=st4te-xxxx&add=${encodeURIComponent(invite)}`, /not complete/],
    ] as const) {
      const p = await (await context()).newPage(); watch(p);
      await p.goto(w.base + '/#' + bad);
      await p.waitForSelector('#addasking[role=alert]');
      assert.match((await p.textContent('#addasking'))!, why);
      assert.equal(new URL(p.url()).hash, '');
      assert.equal(await kept(p), null);
      await p.context().close();
    }

    // Read, kept for this tab, and gone from the address bar (other fragment parameters stay).
    {
      const p = await (await context()).newPage(); watch(p);
      await p.goto(w.base + '/#x=1&' + link(invite, mp, 'st4te-abcdefgh'));
      await p.waitForSelector('#addname');
      assert.equal(await p.textContent('#addname'), 'Marble on Mac');
      assert.equal(new URL(p.url()).hash, '#x=1');
      assert.deepEqual(await kept(p), { invite, challenge: mp.challenge, ret, state: 'st4te-abcdefgh' });
      await p.context().close();
    }

    // Signed out: the request shows above the sign-in, lives through a reload, and after the password the card asks.
    const ctx = await context(); const page = await ctx.newPage(); watch(page);
    await page.goto(w.base + '/#' + link(invite, mp, 'st4te-mac00001'));
    await page.waitForSelector('#username');
    assert.match((await page.textContent('#addasking'))!, /A device is asking to be added to your account/);
    await page.reload();
    await page.waitForSelector('#addname');
    await page.fill('#username', 'aaron'); await page.fill('#password', 'correct horse battery');
    await page.click('#pwgo');
    await page.waitForSelector('#addcard');
    assert.equal(await page.textContent('#addtitle'), 'Add Marble on Mac to your account?');
    assert.equal(await page.textContent('#addwho'), who);
    if (w.hasRelay) assert.equal(await page.getAttribute('#addcard img.avatar', 'src'), 'https://pics.example/aaron.png');
    assert.equal(await page.textContent('#adddevice'), 'New device: Marble on Mac');
    assert.match((await page.textContent('#addwarn'))!, /^Add it only if you just pressed Sign in on Marble on Mac\.$/);
    // The six digits must not show on the way back to the app (they flashed before 0.1.14).
    let sawCode = false;
    await page.exposeFunction('kkSawCode', () => { sawCode = true; });
    await page.evaluate(() => new MutationObserver(() => { if (document.getElementById('shortcode')) (window as any).kkSawCode(); }).observe(document.body, { childList: true, subtree: true }));
    assert.deepEqual([await page.textContent('#addgo'), await page.textContent('#addno')], ['Add', 'Not now']);
    await new Promise((r) => setTimeout(r, 1000));
    assert.deepEqual(puts(), [], 'nothing goes to a device before the click');
    await page.screenshot({ path: join(shots, 'add-card.png') });

    // Add: the invite note carries the challenge; a device adds it; the approval goes to the app on this computer.
    await page.click('#addgo');
    await page.waitForSelector('text=Waiting for one of your devices…');
    await page.waitForFunction(() => sessionStorage.getItem('kk-add') === null);   // the box holds it now: a reload does not add it twice
    assert.deepEqual(puts().map((x) => [x.kind, x.text, x.challenge]), [['invite', invite, mp.challenge]]);
    // Until the app shows the code, the new device gets nothing, even with its own verifier.
    assert.deepEqual(await answered(), ['added Marble on Mac']);
    await assert.rejects(D.join(mac, held.boxKey, held.npub, w.send, undefined, { code: 'x'.repeat(24), verifier: mp.verifier }), /not_approved|wrong_code/);
    await page.waitForURL((u: URL) => u.href.startsWith(ret));
    assert.match((await page.textContent('body'))!, /Done/);
    assert.equal(sawCode, false, 'no six digits on the way back');
    assert.equal(back.length, 1);
    const got = back[0];
    assert.equal(got.pathname, '/done'); assert.equal(got.searchParams.get('state'), 'st4te-mac00001');
    assert.deepEqual(JSON.parse(got.searchParams.get('join')!), { keykin: 2, join: { addr: w.base, boxKey: held.boxKey, npub: held.npub } });
    const code = got.searchParams.get('code')!;
    assert.ok(code.length >= 22);
    // The code with the wrong verifier is refused; with the app's own, the piece comes.
    await assert.rejects(D.join(mac, held.boxKey, held.npub, w.send, undefined, { code, verifier: pkce().verifier }), /wrong_code/);
    const mh = await D.join(mac, held.boxKey, held.npub, w.send, undefined, { code, verifier: mp.verifier });
    assert.ok(verifyEvent(await D.signEvent(mac, mh, note(held.npub), w.send)));
    // Back in the account page's tab (as when the way to the app failed): the six digits are still there to type.
    await page.goBack();
    await page.waitForSelector('#shortcode');
    assert.match((await page.textContent('#shortcode'))!, /^\d{3} \d{3}$/);
    assert.match((await page.textContent('#addcard, .card'))!, /type this only into Marble on Mac on this computer/);
    assert.match((await page.textContent('#shortwhere'))!, new RegExp(`Your account page: ${new URL(w.base).host.replace(/\./g, '\\.')}`));
    await page.screenshot({ path: join(shots, 'add-done.png') });
    await page.click('#toaccount');
    await page.waitForSelector('text=Welcome, Aaron');

    // A stranger's link: their invite, their challenge. Pressed Add on the real page, a device adds it, but the
    // approval goes to a return on THIS computer, and without it the stranger's device gets nothing.
    calls.length = 0; back.length = 0;
    const stranger = device('Marble on Mac'), sp = pkce();
    await page.goto('about:blank');
    await page.goto(w.base + '/#' + link(inviteOf(stranger), sp, 'st4te-strange1'));
    await page.waitForSelector('#addcard');
    await new Promise((r) => setTimeout(r, 1500));
    assert.deepEqual(puts(), [], 'an already signed-in page leaves no note before the click');
    await page.click('#addgo');
    assert.deepEqual(await answered(), ['added Marble on Mac']);
    await page.waitForURL((u: URL) => u.href.startsWith(ret));
    for (const guess of ['000000', '123456', 'x'.repeat(24)]) await assert.rejects(D.join(stranger, held.boxKey, held.npub, w.send, undefined, { code: guess, verifier: sp.verifier }), /wrong_code/);
    assert.equal(back.length, 1, 'the code went to this computer only');

    // Not now sends nothing.
    calls.length = 0;
    await page.goto('about:blank');
    await page.goto(w.base + '/#' + link(inviteOf(device('Marble on Mac')), pkce(), 'st4te-notnow01'));
    await page.waitForSelector('#addno');
    await page.click('#addno');
    await page.waitForSelector('#notadded');
    assert.equal(await page.textContent('#notadded'), 'Marble on Mac was not added.');
    assert.equal(await kept(page), null);
    await new Promise((r) => setTimeout(r, 500));
    assert.deepEqual(puts(), []);
    assert.deepEqual(errors.filter((e) => !/ERR_CONNECTION|Failed to load resource/.test(e)), []);
  } finally { await browser.close(); await w.close(); app.close(); }
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
