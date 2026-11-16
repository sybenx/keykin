// The browser extension in a real Chromium, against a real box. Skipped when no Chromium is at hand.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { verifyEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { v2 as nip44 } from 'nostr-tools/nip44';
import * as nip19 from 'nostr-tools/nip19';
import { startBox } from '../box/server.ts';
import { newMemberKey, softwareChip } from '../src/member.ts';
import * as D from '../src/device.ts';

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
// The window Keykin opens to ask about a site. A new window has no address yet when it first appears.
const approval = async (ctx: any) => { const p = await ctx.waitForEvent('page'); await p.waitForURL(/approve\.html/); return p; };

test('the extension: set up with the box, a site signs in, signs and encrypts, then is signed out', { skip: !exe && 'no Chromium found', timeout: 90_000 }, async () => {
  execFileSync('node', ['ext/build.mjs'], { stdio: 'ignore' });
  const { chromium: pw } = await import('playwright-core');
  const b = await startBox({ dir: mkdtempSync(join(tmpdir(), 'kk-box-')), port: 0, log: () => {} });
  const ext = join(import.meta.dirname, '../ext/dist');
  const ctx = await pw.launchPersistentContext(mkdtempSync(join(tmpdir(), 'kk-chrome-')), {
    executablePath: exe!, headless: false, args: ['--headless=new', `--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  try {
    const sw = ctx.serviceWorkers()[0] ?? await ctx.waitForEvent('serviceworker');
    const id = new URL(sw.url()).host;
    const base = `http://127.0.0.1:${b.port}`;

    // Set up: paste the box's code into the extension's window.
    const popup = await ctx.newPage();
    await popup.goto(`chrome-extension://${id}/popup.html`);
    await popup.fill('#code', b.qr()!);
    await popup.click('#create');
    const npubText = await popup.textContent('#npub');
    const npub = nip19.decode(npubText!).data as string;
    assert.equal(npub, b.box.state.account!.npub);
    assert.match((await popup.textContent('#app'))!, /Browser \(this browser\)/);

    // A site asks to sign in. The first time, Keykin asks; nothing is answered before Allow.
    const site = await ctx.newPage();
    await site.goto(base + '/');                      // any web page will do: the box's own login page
    assert.equal(await site.evaluate(() => typeof (window as any).nostr?.signEvent), 'function');
    const asked = approval(ctx);
    const pending = site.evaluate(() => (window as any).nostr.getPublicKey());
    const approve = await asked;
    assert.match((await approve.textContent('#what'))!, new RegExp(`Let ${base} sign in`));
    await approve.click('#allow');
    assert.equal(await pending, npub);

    // From then on, no questions: sign and encrypt.
    const ev = await site.evaluate(() => (window as any).nostr.signEvent({ kind: 1, created_at: 1700000000, tags: [['t', 'keykin']], content: 'signed in a browser' }));
    assert.ok(verifyEvent(ev)); assert.equal(ev.pubkey, npub);
    const friendSk = generateSecretKey(), friend = getPublicKey(friendSk), friendKey = nip44.utils.getConversationKey(friendSk, npub);
    const sealed = await site.evaluate((f) => (window as any).nostr.nip44.encrypt(f, 'hello from a page'), friend);
    assert.equal(nip44.decrypt(sealed, friendKey), 'hello from a page');
    assert.equal(await site.evaluate(([f, c]) => (window as any).nostr.nip44.decrypt(f, c), [friend, nip44.encrypt('and back', friendKey)]), 'and back');

    // Another site is asked about separately, and Deny means no.
    const other = await ctx.newPage();
    await other.goto(`http://localhost:${b.port}/`);
    const asked2 = approval(ctx);
    const refused = other.evaluate(() => (window as any).nostr.getPublicKey().then(() => 'answered', (e: Error) => e.message));
    await (await asked2).click('#deny');
    assert.equal(await refused, 'Not allowed.');

    // Signing the site out in the extension's window: it has to ask again.
    await popup.reload();
    await popup.click(`button[aria-label="Sign out ${base}"]`);
    await popup.waitForSelector('text=None yet');
    const asked3 = approval(ctx);
    const again = site.evaluate(() => (window as any).nostr.getPublicKey().then(() => 'answered', (e: Error) => e.message));
    await (await asked3).click('#deny');
    assert.equal(await again, 'Not allowed.');

    // Blocked from another device: the browser can no longer sign. (Allow the site again first.)
    const asked4 = approval(ctx);
    const back = site.evaluate(() => (window as any).nostr.getPublicKey());
    await (await asked4).click('#allow'); await back;
    b.box.ownerBlock(b.box.state.account!.members.find((m) => m.name === 'Browser')!.key);
    assert.equal(await site.evaluate(() => (window as any).nostr.signEvent({ kind: 1, content: 'x' }).then(() => 'signed', (e: Error) => e.message)), 'This browser is blocked.');
  } finally {
    await ctx.close();
    await new Promise((done) => { b.server.close(done); b.server.closeAllConnections(); });
  }
});

test('the extension joins an account a phone made', { skip: !exe && 'no Chromium found', timeout: 90_000 }, async () => {
  const { chromium: pw } = await import('playwright-core');
  const b = await startBox({ dir: mkdtempSync(join(tmpdir(), 'kk-box-')), port: 0, log: () => {} });
  const ext = join(import.meta.dirname, '../ext/dist');
  const ctx = await pw.launchPersistentContext(mkdtempSync(join(tmpdir(), 'kk-chrome-')), {
    executablePath: exe!, headless: false, args: ['--headless=new', `--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  try {
    const qr = D.readQr(b.qr()!);
    const send: D.Send = async (r) => (await fetch(`${qr.addr}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: { connection: 'close' } })).json();
    const phone: D.Me = { ...newMemberKey(), name: 'Phone', ...softwareChip() };
    const held = await D.createWithBox(phone, qr, send);

    const sw = ctx.serviceWorkers()[0] ?? await ctx.waitForEvent('serviceworker');
    const popup = await ctx.newPage();
    await popup.goto(`chrome-extension://${new URL(sw.url()).host}/popup.html`);
    const invite = JSON.parse((await popup.textContent('#invite'))!).invite;
    await D.addMember(phone, held, { key: invite.key, name: invite.name, kind: 'device' }, send);
    await popup.fill('#jointext', JSON.stringify({ keykin: 2, join: { addr: qr.addr, boxKey: held.boxKey, npub: held.npub } }));
    await popup.click('#join');
    assert.equal(nip19.decode((await popup.textContent('#npub'))!).data, held.npub);
    assert.match((await popup.textContent('#app'))!, /Phone/);

    // The phone cycles the keys while the browser is idle; the browser catches up when a site next asks.
    await D.cycle(phone, held, send);
    const site = await ctx.newPage();
    await site.goto(qr.addr + '/');
    const asked = approval(ctx);
    const signed = site.evaluate(() => (window as any).nostr.signEvent({ kind: 1, created_at: 1700000000, tags: [], content: 'after a cycle' }));
    await (await asked).click('#allow');
    const ev = await signed;
    assert.ok(verifyEvent(ev)); assert.equal(ev.pubkey, held.npub);
    // The browser has no fingerprint key, so the box does not let it make account changes.
    assert.equal(b.box.state.account!.members.find((m) => m.name === 'Browser')!.chip, undefined);
  } finally {
    await ctx.close();
    await new Promise((done) => { b.server.close(done); b.server.closeAllConnections(); });
  }
});
