// signin/: signing in with the browser extension (NIP-07), which a site turns on with configure({ extension: true }).
// Off (the default) everything is as before: no row, and a sign-in the extension made is signed out once, with its
// toast. In headless Chromium with the stand-in extension (test/standins/extension.ts); no relay or public server is
// reached (test/standins/browser.ts closes every WebSocket). Skipped when no Chromium is at hand.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { verifyEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import { chromiumPath, serveSignin, openPage, dialogLines } from './standins/browser.ts';
import { fakeExtension, type FakeExtension } from './standins/extension.ts';

const exe = chromiumPath();
const skip = !exe && 'no Chromium found';
const FIRST = ['Sign in', 'Your Nostr address or npub', 'Continue', 'or', 'Sign in with your phone', 'Use a signer app', 'Here to manage your account? Your account page'];
const ROW = 'Continue with your browser extension';
// new screen text says none of these
const PROTOCOL = /nostr|relay|npub|nsec|\bnip|\bkeys?\b/i;
const OLD_TOAST = "Marble doesn't use the browser extension any more, so you're signed out. Sign in again.";

let site: Awaited<ReturnType<typeof serveSignin>>, browser: any;
before(async () => {
  if (skip) return;
  site = await serveSignin();
  browser = await (await import('playwright-core')).chromium.launch({ executablePath: exe!, headless: true });
});
after(async () => { await browser?.close(); await site?.close(); });

const signedIn = (page: any) => page.evaluate(() => (window as any).signin.current());
const stored = (page: any) => page.evaluate(() => localStorage.getItem('marble.me'));
const open = async (page: any) => { await page.click('[data-sign-in]'); await page.waitForSelector('dialog#signin[open] #si-title'); };
const toastText = (page: any) => page.evaluate(() => { const t = document.getElementById('toast'); return t && !t.hidden ? t.textContent : ''; });
async function withPage(opts: Parameters<typeof openPage>[2] & { ext?: Parameters<typeof fakeExtension>[1] | false }, fn: (p: Awaited<ReturnType<typeof openPage>>, ext: FakeExtension | null) => Promise<void>) {
  let ext: FakeExtension | null = null;
  const p = await openPage(browser, site.base, { ...opts, before: opts.ext === false ? undefined : async (c: any) => { ext = await fakeExtension(c, opts.ext || {}); } });
  try { await fn(p, ext); assert.deepEqual(p.errors, []); } finally { await p.close(); }
}

test('signin extension: configure takes extension as true or false, beside the hooks', async () => {
  const { configure, options } = await import(new URL('../signin/hooks.js', import.meta.url).href) as any;
  assert.equal(options.extension, false, 'off unless a site turns it on');
  assert.throws(() => configure({ extension: 'yes' }), /option extension must be true or false/);
  try {
    configure({ extension: true });
    assert.equal(options.extension, true);
  } finally { configure({ extension: false }); }
  assert.throws(() => configure({ extensions: true }), /no hook named extensions/);
});

test('signin extension: off (the default), no row even with an extension, and nothing asks it', { skip }, async () => {
  await withPage({}, async ({ page }, ext) => {
    await open(page);
    assert.deepEqual(await dialogLines(page), FIRST, 'the first screen, as before');
    assert.equal(await page.locator('[data-si="extension"]').count(), 0);
    assert.deepEqual(ext!.calls, []);
  });
});

test('signin extension: off, a sign-in the extension made is signed out once, with its toast (both kept forms)', { skip }, async () => {
  const pk = getPublicKey(generateSecretKey());
  for (const kept of [JSON.stringify({ pubkey: pk, method: 'extension' }), pk]) {
    await withPage({ storage: { 'marble.me': kept } }, async ({ page }, ext) => {
      assert.equal(await signedIn(page), null);
      assert.equal(await stored(page), null, 'forgotten');
      await page.waitForFunction(() => !!document.getElementById('toast') && !document.getElementById('toast')!.hidden, null, { timeout: 3000 });
      assert.equal(await toastText(page), OLD_TOAST);
      await page.reload();
      await page.waitForFunction(() => !!(window as any).signin);
      await page.waitForTimeout(600);
      assert.equal(await toastText(page), '', 'said once');
      assert.deepEqual(ext!.calls, []);
    });
  }
});

test('signin extension: on, but no extension in this browser: no row', { skip }, async () => {
  await withPage({ extension: 'on', ext: false }, async ({ page }) => {
    await open(page);
    assert.deepEqual(await dialogLines(page), FIRST);
  });
});

test('signin extension: on, the row comes first, signs in, signs and encrypts through it, survives a reload, and sign-out forgets it', { skip }, async () => {
  await withPage({ extension: 'on' }, async ({ page }, ext) => {
    assert.deepEqual(ext!.calls, [], 'nothing asked on load');
    await open(page);
    const lines = await dialogLines(page);
    assert.deepEqual(lines, ['Sign in', ROW, 'or', ...FIRST.slice(1)], lines.join(' | '));
    assert.equal(await page.evaluate(() => document.activeElement?.id), 'si-who', 'the name field still has the focus');
    await page.click('[data-si="extension"]');
    await page.waitForFunction(() => !(document.getElementById('signin') as HTMLDialogElement).open);
    assert.equal(await signedIn(page), ext!.pubkey);
    assert.equal(await page.evaluate(() => (window as any).signin.method()), 'extension');
    assert.equal(await toastText(page), 'Signed in');
    assert.deepEqual(JSON.parse(await stored(page)), { pubkey: ext!.pubkey, method: 'extension' });

    const signed = await page.evaluate(() => (window as any).signin.sign({ kind: 1, content: 'hello' }));
    assert.equal(signed.pubkey, ext!.pubkey);
    assert.equal(signed.content, 'hello');
    assert.ok(verifyEvent(signed));
    const back = await page.evaluate(async (me: string) => {
      const s = (window as any).signin;
      return s.nip44DecryptFrom(me, await s.nip44EncryptTo(me, 'for later'));
    }, ext!.pubkey);
    assert.equal(back, 'for later');

    ext!.calls.length = 0;
    await page.reload();
    await page.waitForFunction(() => !!(window as any).signin);
    await page.waitForTimeout(500);
    assert.equal(await signedIn(page), ext!.pubkey, 'still signed in after a reload');
    assert.equal(await toastText(page), '', 'and not told it was signed out');
    assert.deepEqual(ext!.calls, [], 'nothing signed or decrypted in the background on load');
    assert.ok(verifyEvent(await page.evaluate(() => (window as any).signin.sign({ kind: 1, content: 'again' }))));

    await page.evaluate(() => (window as any).signin.signOut());
    assert.equal(await signedIn(page), null);
    assert.equal(await stored(page), null);
    await page.reload();
    await page.waitForFunction(() => !!(window as any).signin);
    assert.equal(await signedIn(page), null, 'still signed out after a reload');
    await assert.rejects(page.evaluate(() => (window as any).signin.sign({ kind: 1 })), /read-only/);
  });
});

test('signin extension: on, a sign-in the extension made earlier is kept (and the first version\'s form too), with no toast', { skip }, async () => {
  const pk = getPublicKey(generateSecretKey());
  for (const kept of [JSON.stringify({ pubkey: pk, method: 'extension' }), pk]) {
    await withPage({ extension: 'on', storage: { 'marble.me': kept } }, async ({ page }, ext) => {
      assert.equal(await signedIn(page), pk);
      assert.deepEqual(JSON.parse(await stored(page)), { pubkey: pk, method: 'extension' });
      await page.waitForTimeout(600);
      assert.equal(await toastText(page), '');
      assert.deepEqual(ext!.calls, []);
    });
  }
});

test('signin extension: a slow extension shows it is waiting and can be cancelled; its late answer counts for nothing', { skip }, async () => {
  await withPage({ extension: 'on', ext: { mode: 'slow', delay: 1500 } }, async ({ page }) => {
    await open(page);
    await page.click('[data-si="extension"]');
    await page.waitForSelector('.si-wait');
    const waiting = await dialogLines(page);
    assert.deepEqual(waiting, ['Sign in', 'Waiting for your browser extension…', 'Cancel']);
    assert.ok(!PROTOCOL.test(waiting.join(' ')));
    await page.click('[data-si="retype"]');
    assert.equal((await dialogLines(page))[1], ROW, 'back to the first screen');
    await page.waitForTimeout(2000);
    assert.equal(await signedIn(page), null, 'the late answer signed no one in');
  });
});

test('signin extension: a locked extension says how to get on after a moment; Cancel, then Escape, still work', { skip }, async () => {
  await withPage({ extension: 'on', ext: { mode: 'locked' } }, async ({ page }, ext) => {
    await open(page);
    await page.click('[data-si="extension"]');
    await page.waitForSelector('[data-ext-help]:not([hidden])', { timeout: 5000 });
    assert.ok((await dialogLines(page)).includes('Open your browser extension to approve.'));
    await page.click('[data-si="retype"]');
    await page.click('[data-si="extension"]');
    await page.keyboard.press('Escape');
    assert.equal(await page.evaluate(() => (document.getElementById('signin') as HTMLDialogElement).open), false);
    ext!.unlock();
    await page.waitForTimeout(300);
    assert.equal(await signedIn(page), null);
  });
});

test('signin extension: a refusal goes back to the dialog with a plain line, and trying again works', { skip }, async () => {
  await withPage({ extension: 'on', ext: { mode: 'refuse' } }, async ({ page }, ext) => {
    await open(page);
    await page.click('[data-si="extension"]');
    await page.waitForSelector('.si-said');
    const lines = await dialogLines(page);
    assert.deepEqual(lines.slice(0, 2), ['Sign in', ROW]);
    assert.ok(lines.includes("Your browser extension didn't sign you in. Try again, or sign in another way."), lines.join(' | '));
    assert.ok(!PROTOCOL.test(lines.find((l) => l.startsWith('Your browser extension'))!));
    assert.equal(await signedIn(page), null);
    ext!.setMode('ready');
    await page.click('[data-si="extension"]');
    await page.waitForFunction(() => !!(window as any).signin.current());
    assert.equal(await signedIn(page), ext!.pubkey);
  });
});

test('signin extension: an extension without nip44 signs, and encrypting says plainly it can\'t', { skip }, async () => {
  await withPage({ extension: 'on', ext: { nip44: false } }, async ({ page }, ext) => {
    await open(page);
    await page.click('[data-si="extension"]');
    await page.waitForFunction(() => !!(window as any).signin.current());
    assert.ok(verifyEvent(await page.evaluate(() => (window as any).signin.sign({ kind: 1, content: 'x' }))));
    await assert.rejects(page.evaluate((me: string) => (window as any).signin.nip44EncryptTo(me, 'x'), ext!.pubkey), /unsupported: your browser extension can't do this/);
    await assert.rejects(page.evaluate((me: string) => (window as any).signin.nip44DecryptFrom(me, 'x'), ext!.pubkey), /unsupported: your browser extension can't do this/);
  });
});
