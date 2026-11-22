// The Shared home section in a real browser: signed in by password, the page asks for a scan, a stand-in phone
// answers (NIP-46 over a local relay, signing as the account through the box, like Marble), and the page manages
// a stand-in home and file server that check every NIP-98 signature.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';
import { npubEncode } from 'nostr-tools/nip19';
import { startBox } from '../box/server.ts';
import { startLogin } from '../login/server.ts';
import { fakeBothy, fakeStorage } from './home-fakes.ts';

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
let hasNak = false; try { execFileSync('which', ['nak']); hasNak = true; } catch {}

async function nakRelay() {
  const port = 20000 + Math.floor(Math.random() * 20000);
  const proc = spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', String(port)], { stdio: 'ignore' });
  const url = `ws://127.0.0.1:${port}`;
  for (let k = 0; k < 50; k++) {
    try { const w = new WebSocket(url); await new Promise((ok, no) => { w.onopen = ok; w.onerror = no; }); w.close(); break; }
    catch { await new Promise((r) => setTimeout(r, 100)); }
  }
  return { url, port, kill: () => proc.kill() };
}
const freePort = async () => { const { createServer } = await import('node:net'); const srv = createServer(); await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r)); const p = (srv.address() as any).port; await new Promise((r) => srv.close(r)); return p; };
const toRelay = (relay: string, ev: object) => new Promise<void>((ok, no) => { const ws = new WebSocket(relay); ws.onopen = () => ws.send(JSON.stringify(['EVENT', ev])); ws.onmessage = (m) => { ws.close(); JSON.parse(String(m.data))[2] ? ok() : no(new Error(String(m.data))); }; ws.onerror = no; });

/**
 * A phone answering a nostrconnect:// code the way Marble does: it says the code's secret back, then signs what the
 * page asks with `sign` (here the account, through the box). Returns what it was asked to sign, by kind.
 */
function phone(uri: string, account: string, sign: (e: object) => Promise<object>) {
  const u = new URL(uri.replace(/^nostrconnect:\/\//, 'http://'));
  const client = u.hostname, relay = u.searchParams.get('relay')!, secret = u.searchParams.get('secret')!;
  const sk = generateSecretKey(), me = getPublicKey(sk);
  const kinds: number[] = [];
  const reply = (to: string, j: object) => finalizeEvent({ kind: 24133, created_at: Math.floor(Date.now() / 1000), tags: [['p', to]], content: nip44.v2.encrypt(JSON.stringify(j), nip44.v2.utils.getConversationKey(sk, to)) }, sk);
  const ws = new WebSocket(relay);
  // Kind 24133 is ephemeral: a relay passes it on live and keeps nothing. So the hello is said again each second
  // until the page asks something, in case the page was not listening yet (a real phone is seconds behind anyway).
  let heard = false, again: ReturnType<typeof setInterval> | undefined;
  ws.onopen = () => {
    ws.send(JSON.stringify(['REQ', 'p', { kinds: [24133], '#p': [me], since: Math.floor(Date.now() / 1000) - 5 }]));
    const hello = () => { if (!heard && ws.readyState === 1) ws.send(JSON.stringify(['EVENT', reply(client, { id: 'hello', result: secret })])); else clearInterval(again); };
    hello(); again = setInterval(hello, 1000);
  };
  ws.onmessage = async (m) => {
    const d = JSON.parse(String(m.data));
    if (d[0] !== 'EVENT' || d[1] !== 'p') return;
    const e = d[2];
    let q: any; try { q = JSON.parse(nip44.v2.decrypt(e.content, nip44.v2.utils.getConversationKey(sk, e.pubkey))); } catch { return; }
    heard = true;
    let result: string;
    if (q.method === 'get_public_key') result = account;
    else if (q.method === 'sign_event') { const t = JSON.parse(q.params[0]); kinds.push(t.kind); result = JSON.stringify(await sign(t)); }
    else if (q.method === 'ping') result = 'pong';
    else result = 'ack';
    ws.send(JSON.stringify(['EVENT', reply(e.pubkey, { id: q.id, result })]));
  };
  return { kinds, close: () => { clearInterval(again); ws.close(); } };
}

test('the Shared home section: a scan, the invite tree, the photo switch, removal, the bin and the file server link', { skip: (!exe && 'no Chromium found') || (!hasNak && 'nak is not installed'), timeout: 150_000 }, async () => {
  const { chromium: pw } = await import('playwright-core');
  const { main } = await import('../cli/keykin.ts');
  const cli = async (home: string, ...argv: string[]) => { if (argv[0] === 'create') argv.push('--username', 'macbook', '--password', 'long enough pw'); const lines: string[] = []; const r = await main(argv, (s) => lines.push(s), home); return { text: lines.join('\n'), run: r as any }; };
  const shut: (() => unknown)[] = [];
  try {
  const relay = await nakRelay(); shut.push(relay.kill);
  const homeRelay = await nakRelay(); shut.push(homeRelay.kill);       // the home's own relay; `relay` is the account's
  const port = await freePort();
  const box = await startBox({ dir: mkdtempSync(join(tmpdir(), 'kk-box-')), port: 0, sidePort: 0, behindLogin: true, url: `http://127.0.0.1:${port}`, log: () => {} }); shut.push(() => box.close());
  const mac = mkdtempSync(join(tmpdir(), 'kk-mac-'));
  // The account is made through the public door first; the door is then started again with the home set.
  const first = await startLogin({ box: `http://127.0.0.1:${box.sidePort}`, port, relays: [relay.url], log: () => {} });
  const account = /([0-9a-f]{64})/.exec((await cli(mac, 'create', box.qr()!, 'MacBook')).text)![1];
  const sign = async (e: object) => JSON.parse((await cli(mac, 'sign', JSON.stringify(e))).text);
  await first.close();

  // The home: Ana (an admin) let in Ben, Ben let in Cleo and Dev; Eve came in by the owner. Each has a name on the home.
  // From before the invite tree (no inviter): Finn, whose name is only on the account's relays, and one with no name anywhere.
  const people = Object.fromEntries(['ana', 'ben', 'cleo', 'dev', 'eve', 'finn', 'nameless'].map((n) => { const sk = generateSecretKey(); return [n, { sk, pk: getPublicKey(sk) }]; }));
  const P = (n: string) => people[n].pk;
  const home = await fakeBothy({ owner: account, name: 'The Herbst home', relayPort: homeRelay.port, members: [
    { pubkey: P('ana'), role: 'admin' }, { pubkey: P('ben'), invitedBy: P('ana'), source: 'member' }, { pubkey: P('cleo'), invitedBy: P('ben'), close: false, source: 'member' },
    { pubkey: P('dev'), invitedBy: P('ben'), close: false, source: 'request' }, { pubkey: P('eve'), source: 'owner' },
    { pubkey: P('finn'), invitedBy: null, source: 'owner', joinedAt: 1_700_000_000 }, { pubkey: P('nameless'), invitedBy: null, source: 'owner', joinedAt: 1_700_000_001 }] }); shut.push(() => home.close());
  for (const n of ['ana', 'ben', 'cleo', 'dev', 'eve']) await toRelay(homeRelay.url, finalizeEvent({ kind: 0, created_at: Math.floor(Date.now() / 1000), tags: [], content: JSON.stringify({ name: n[0].toUpperCase() + n.slice(1) }) }, people[n].sk));
  await toRelay(relay.url, finalizeEvent({ kind: 0, created_at: Math.floor(Date.now() / 1000), tags: [], content: JSON.stringify({ name: 'Finn' }) }, people.finn.sk));
  const files = await fakeStorage({ owner: account, admins: [P('ana')], home: home.url, blobs: [
    { sha256: 'a1'.repeat(32), size: 120e6, owner: P('ana'), binned: true }, { sha256: 'a2'.repeat(32), size: 100e6, owner: P('ana'), binned: true },
    { sha256: 'b1'.repeat(32), size: 2e9, owner: P('ben') }, { sha256: 'c1'.repeat(32), size: 50e6, owner: P('cleo'), binned: true }] }); shut.push(() => files.close());
  const login = await startLogin({ box: `http://127.0.0.1:${box.sidePort}`, port, relays: [relay.url], home: home.url, storage: files.url, log: () => {} }); shut.push(() => login.close());
  const base = `http://127.0.0.1:${login.port}`;
  const browser = await pw.launch({ executablePath: exe!, args: ['--headless=new'] }); shut.push(() => browser.close());
  let ph: ReturnType<typeof phone> | null = null;
  shut.push(() => ph?.close());
  {
    const ctx = await browser.newContext({ viewport: { width: 390, height: 860 }, userAgent: 'Mozilla/5.0 (Linux; Android 15; Pixel 9a) Chrome/130 Mobile' });
    const page = await ctx.newPage();
    const errors: string[] = [];
    page.on('pageerror', (e) => errors.push(String(e)));
    // The sign-in widget (signin.js, KeykinSignIn.link) closes its relay pool once the phone has answered, and Chrome
    // logs a CLOSE sent on the closing socket. That is the widget's, from before this section, and harmless.
    page.on('console', (m) => { if (m.type() === 'error' && !(m.text() === 'WebSocket is already in CLOSING or CLOSED state.' && m.location().url.endsWith('/signin.js'))) errors.push(m.text() + ' @ ' + JSON.stringify(m.location())); });
    page.on('dialog', (d) => d.accept());

    // Signed in by password: no signer here, so the section asks for the phone, in one plain line.
    await page.goto(base + '/');
    await page.fill('#username', 'macbook'); await page.fill('#password', 'long enough pw'); await page.click('#pwgo');
    await page.waitForSelector('nav');
    await page.click('nav >> text=Shared home');
    await page.waitForSelector('#housewithapp');
    assert.match((await page.textContent('main'))!, /Changes here are signed by your phone, so this page asks for a scan each visit\./);
    const uri = (await page.getAttribute('#housewithapp', 'href'))!;
    assert.match(uri, /^nostrconnect:\/\/[0-9a-f]{64}\?.*&kk=account$/);
    ph = phone(uri, account, sign);

    // The phone answers: the home loads. The owner, then each person under whoever let them in, with their names.
    await page.waitForSelector('#housepeople .row.person >> text=Cleo', { timeout: 30_000 }).catch(async (x) => { throw new Error(`${x.message}\npage: ${await page.textContent('main')}\nerrors: ${errors.join('; ')}\nphone signed: ${ph!.kinds}`); });
    await page.waitForSelector('#housepeople .row.person >> text=Finn');
    const rows = await page.$$eval('#housepeople .row.person', (rs) => rs.map((r) => [r.querySelector('.name')!.textContent, parseInt((r as HTMLElement).style.paddingLeft) / 24]));
    const tail = P('nameless').slice(-6);
    assert.deepEqual(rows, [['You', 0], ['AnaAdmin', 1], ['Ben', 2], ['Cleo', 3], ['Dev', 3], ['Eve', 1], ['Finn', 1], ['Someone' + tail, 1]]);
    // Rows from before the invite tree sit apart, under their own heading, after the tree.
    assert.match((await page.textContent('#houseold'))!, /Added before invites/);
    const detail = async (name: string) => (await page.locator('#housepeople .row.person', { hasText: name }).first().locator('.grow > .detail').first().textContent())!;
    assert.match(await detail('Cleo'), /^Invited by Ben · joined .* · 50 MB stored$/);
    assert.match(await detail('Dev'), /^Asked to join, let in by Ben · joined .* · Nothing stored$/);
    assert.match(await detail('Eve'), /^Added by you · joined /);
    assert.match(await detail(tail), /^Added by hand · joined Nov 14, 2023 · Nothing stored$/);
    assert.match((await page.textContent('h1'))!, /The Herbst home/);
    // KEYKIN_SHOTS=<folder> saves what the section looks like, for a person to look at.
    const shot = async (name: string, width = 390) => { if (!process.env.KEYKIN_SHOTS) return; await page.setViewportSize({ width, height: 860 }); await page.screenshot({ path: join(process.env.KEYKIN_SHOTS, `${name}-${width}.png`), fullPage: true }); await page.setViewportSize({ width: 390, height: 860 }); };
    await shot('home'); await shot('home', 1280);
    assert.match((await page.textContent('.head .dim'))!, /8 people · 2\.3 GB of photos and files/);
    // Plain words only: nothing technical until Advanced.
    const plain = (await page.textContent('main'))!;
    for (const word of ['npub', 'pubkey', 'relay', 'blob', 'NIP', 'sha256', '—']) assert.ok(!plain.includes(word), word);
    assert.deepEqual(new Set(home.calls.map((c) => c.method)), new Set(['listmembers', 'getstorage']));
    assert.ok(home.calls.every((c) => c.by === account));

    // The photo location switch: Cleo was off, now on.
    assert.equal(await page.isChecked('[aria-label="Cleo sees where photos were taken"]'), false);
    await page.click('[aria-label="Cleo sees where photos were taken"]');
    await page.waitForSelector('#status >> text=Cleo now sees where photos were taken.');
    assert.equal(home.members.get(P('cleo'))!.close, true);

    // Remove Ben, who invited two: both choices with the count and names, neither styled as the dangerous one.
    await page.click('[aria-label="Remove Ben"]');
    await page.waitForSelector('#houseask');
    await shot('remove');
    assert.match((await page.textContent('#houseask'))!, /Ben invited 2 people\. What happens to them\?Cleo, Dev/);
    assert.equal(await page.textContent('#houseremovekeep'), 'Keep the 2 people they invited');
    assert.equal(await page.textContent('#houseremoveall'), 'Remove them too');
    assert.deepEqual(await page.$$eval('#houseask button', (bs) => bs.map((b) => b.className)), ['btn', 'btn', 'btn']);
    await page.click('#houseremovekeep');
    await page.waitForSelector('#status >> text=Ben is no longer in the home. 2 people they invited stay.');
    assert.deepEqual(home.calls.filter((c) => c.method === 'unallowpubkey').map((c) => c.params), [[P('ben'), { invitees: 'keep' }]]);
    assert.ok(!home.members.has(P('ben')));
    await page.waitForSelector('#houseremoved >> text=Ben');
    await page.click('[aria-label="Let Ben back in"]');
    await page.waitForSelector('#status >> text=Ben is back in the home.');
    assert.ok(home.members.has(P('ben')));

    // Space and the bin, by person. Restore Ana's files; erase Cleo's (owner only, after a confirm).
    assert.match((await page.textContent('#housespace'))!, /40 GB used, 960 GB free on your box\./);
    assert.match((await page.textContent('#housebin'))!, /Ana2 files, 220 MB, erased on/);
    await page.click('[aria-label="Restore Ana\'s files"]');
    await page.waitForSelector('#status >> text=2 files restored.');
    assert.equal(files.blobs.get('a1'.repeat(32))!.binnedAt, null);
    await page.click('[aria-label="Erase Cleo\'s files now"]');
    await page.waitForSelector('#status >> text=1 file erased.');
    assert.ok(!files.blobs.has('c1'.repeat(32)));
    await page.waitForSelector('#housebinempty');

    // The file server: its key is shown before anything is signed, then linked.
    await page.click('#houselink');
    await page.waitForSelector('#housekey');
    await shot('link', 1280);
    assert.equal(await page.textContent('#housekey'), npubEncode(files.key));
    assert.equal(home.storage, null, 'nothing signed before Link');
    await page.click('#houselinkgo');
    await page.waitForSelector('#houselinked');
    assert.deepEqual(home.storage, { url: files.url, pubkey: files.key });

    // Advanced: the technical detail, and unlinking.
    await page.click('#houseadv');
    await page.waitForSelector('#houseaddr');
    await shot('advanced', 1280);
    assert.match((await page.textContent('#housepeople'))!, new RegExp(npubEncode(P('ana'))));
    await page.click('#houseunlink');
    await page.waitForSelector('#houselink');
    assert.equal(home.storage, null);

    // Linked before this page existed, the way the live home was (setstorage with a trailing slash): it reads as linked.
    home.storage = { url: files.url + '/', pubkey: files.key };
    await page.click('#houseadv');
    await page.click('nav >> text=Devices'); await page.click('nav >> text=Shared home');
    await page.waitForSelector('#houselinked');
    assert.equal(await page.textContent('#houselinked'), 'Photos and files are kept on your box.');
    assert.equal(await page.locator('#houselink, #houselinkask, #housewronghome').count(), 0);

    // Everything was signed by the phone, as the account: NIP-98 only (no NIP-42 needed on this home).
    assert.ok(ph.kinds.length >= 10 && ph.kinds.every((k) => k === 27235), String(ph.kinds));
    assert.ok(files.calls.every((c) => c.by === account));
    assert.deepEqual(errors, []);

    // Signing out forgets the signer: signed in again, the section asks for the phone again.
    await page.click('text=Sign out');
    await page.waitForSelector('#pwgo');
    await page.fill('#username', 'macbook'); await page.fill('#password', 'long enough pw'); await page.click('#pwgo');
    await page.waitForSelector('nav');
    await page.click('nav >> text=Shared home');
    await page.waitForSelector('#housewithapp');
  }
  } finally { for (const f of shut.reverse()) await Promise.resolve().then(f).catch(() => {}); }
});

test('the Shared home section: an admin sees the tree, and a box with no home has no such section', { skip: (!exe && 'no Chromium found') || (!hasNak && 'nak is not installed'), timeout: 120_000 }, async () => {
  const { chromium: pw } = await import('playwright-core');
  const { main } = await import('../cli/keykin.ts');
  const cli = async (home: string, ...argv: string[]) => { if (argv[0] === 'create') argv.push('--username', 'ana', '--password', 'long enough pw'); const lines: string[] = []; const r = await main(argv, (s) => lines.push(s), home); return { text: lines.join('\n'), run: r as any }; };
  const shut: (() => unknown)[] = [];
  try {
  const relay = await nakRelay(); shut.push(relay.kill);
  const port = await freePort();
  const box = await startBox({ dir: mkdtempSync(join(tmpdir(), 'kk-box-')), port: 0, sidePort: 0, behindLogin: true, url: `http://127.0.0.1:${port}`, log: () => {} }); shut.push(() => box.close());
  const mac = mkdtempSync(join(tmpdir(), 'kk-mac-'));
  // The account is made through the public door first; the door is then started again with the home set.
  const first = await startLogin({ box: `http://127.0.0.1:${box.sidePort}`, port, relays: [relay.url], log: () => {} });
  const ana = /([0-9a-f]{64})/.exec((await cli(mac, 'create', box.qr()!, 'MacBook')).text)![1];
  const sign = async (e: object) => JSON.parse((await cli(mac, 'sign', JSON.stringify(e))).text);
  await first.close();
  const owner = getPublicKey(generateSecretKey()), other = getPublicKey(generateSecretKey()), admin2 = getPublicKey(generateSecretKey());
  const home = await fakeBothy({ owner, relayPort: relay.port, members: [{ pubkey: ana, role: 'admin' }, { pubkey: other, invitedBy: ana }, { pubkey: admin2, role: 'admin' }] }); shut.push(() => home.close());
  // The file server does not know the admins yet (bothy's memberkeys.admins not shipped): it says no to Ana.
  const files = await fakeStorage({ owner, admins: [], home: home.url }); shut.push(() => files.close());
  const login = await startLogin({ box: `http://127.0.0.1:${box.sidePort}`, port, relays: [relay.url], home: home.url, storage: files.url, log: () => {} }); shut.push(() => login.close());
  const plainLogin = await startLogin({ box: `http://127.0.0.1:${box.sidePort}`, port: 0, relays: [relay.url], log: () => {} }); shut.push(() => plainLogin.close());
  const browser = await pw.launch({ executablePath: exe!, args: ['--headless=new'] }); shut.push(() => browser.close());
  let ph: ReturnType<typeof phone> | null = null;
  shut.push(() => ph?.close());
  {
    const ctx = await browser.newContext({ viewport: { width: 1280, height: 860 }, userAgent: 'Mozilla/5.0 (Linux; Android 15; Pixel 9a) Chrome/130 Mobile' });
    const first = await ctx.newPage();
    const errors: string[] = [];
    first.on('pageerror', (e) => errors.push(String(e)));
    // No home set: no section.
    await first.goto(`http://127.0.0.1:${plainLogin.port}/`);
    await first.fill('#username', 'ana'); await first.fill('#password', 'long enough pw'); await first.click('#pwgo');
    await first.waitForSelector('nav');
    assert.equal(await first.locator('nav >> text=Shared home').count(), 0);
    // With the home set, Ana is an admin there. (A new browser: cookies do not tell ports apart.)
    await ctx.close();
    const ctx2 = await browser.newContext({ viewport: { width: 1280, height: 860 }, userAgent: 'Mozilla/5.0 (Linux; Android 15; Pixel 9a) Chrome/130 Mobile' });
    const page = await ctx2.newPage(); page.on('pageerror', (e) => errors.push(String(e)));
    await page.goto(`http://127.0.0.1:${login.port}/`);
    await page.fill('#username', 'ana'); await page.fill('#password', 'long enough pw'); await page.click('#pwgo');
    await page.waitForSelector('nav');
    await page.click('nav >> text=Shared home');
    await page.waitForSelector('#housewithapp');
    ph = phone((await page.getAttribute('#housewithapp', 'href'))!, ana, sign);
    await page.waitForSelector('#housepeople', { timeout: 30_000 });
    assert.deepEqual(home.calls.map((c) => c.method).sort(), ['listmembers', 'myrole']);
    // The other admin has no Remove for her, with the reason; the owner none at all; her own row none.
    assert.equal(await page.locator(`[aria-label^="Remove"]`).count(), 1);
    assert.match((await page.textContent('#housepeople'))!, /Only the owner can remove an admin\./);
    assert.match((await page.textContent('#housestoragenote'))!, /Space and the bin show here for the owner\. The file server does not know the admins yet\./);
    assert.equal(await page.locator('#houselink').count(), 0, 'linking is for the owner');
    assert.deepEqual(errors, []);
  }
  } finally { for (const f of shut.reverse()) await Promise.resolve().then(f).catch(() => {}); }
});
