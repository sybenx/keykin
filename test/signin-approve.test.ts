// signin/: signer apps that ask you to approve at a web page first (NIP-46 auth_url), and ones that refuse or stay
// silent. The stand-in phone (test/standins/phone.ts) answers over a local relay (nak serve) and runs its approval
// page on 127.0.0.1; the page reaches nothing else (test/standins/browser.ts). Skipped with no Chromium or no nak.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { verifyEvent } from 'nostr-tools/pure';
import { chromiumPath, serveSignin, openPage, dialogLines } from './standins/browser.ts';
import { standInPhone, type StandInPhone } from './standins/phone.ts';
import { hasNak, startRelay, type LocalRelay } from './standins/relay.ts';

const exe = chromiumPath();
const skip = (!exe && 'no Chromium found') || (!hasNak && 'nak is not installed');

let site: Awaited<ReturnType<typeof serveSignin>>, browser: any, relay: LocalRelay;
before(async () => {
  if (skip) return;
  relay = await startRelay();
  site = await serveSignin();
  browser = await (await import('playwright-core')).chromium.launch({ executablePath: exe!, headless: true });
});
after(async () => { await browser?.close(); await site?.close(); await relay?.stop(); });

const signedIn = (page: any) => page.evaluate(() => (window as any).signin.current());
const isOpen = (page: any) => page.evaluate(() => (document.getElementById('signin') as HTMLDialogElement).open);
/** The page and a stand-in phone, both closed after, also on failure. */
async function withPhone(opts: Parameters<typeof standInPhone>[0], fn: (p: Awaited<ReturnType<typeof openPage>>, phone: StandInPhone) => Promise<void>, pageOpts: Parameters<typeof openPage>[2] = {}) {
  const phone = standInPhone(opts);
  const p = await openPage(browser, site.base, { relay: relay.url, ...pageOpts });
  try {
    await fn(p, phone);
    assert.deepEqual(p.errors, []);
    assert.ok(p.sockets.every((u) => u === relay.url || !/^wss?:\/\/(127\.0\.0\.1|localhost)/.test(u)), 'only the local relay is connected to');
  } finally { await p.close(); await phone.stop(); }
}
async function pasteBunker(page: any, link: string) {
  await page.click('[data-sign-in]');
  await page.click('[data-si="signer"]');
  await page.fill('#si-bunker', link);
  await page.click('form[data-form="bunker"] button[type="submit"]');
}

test('signin approve: the pure rule takes http and https pages only, and shows the host', async () => {
  const { approvalPage } = await import(new URL('../signin/pure.js', import.meta.url).href) as any;
  assert.deepEqual(approvalPage('https://signer.example/approve?id=1'), { href: 'https://signer.example/approve?id=1', host: 'signer.example' });
  assert.deepEqual(approvalPage('http://127.0.0.1:8080/a'), { href: 'http://127.0.0.1:8080/a', host: '127.0.0.1:8080' });
  for (const bad of ['javascript:alert(1)', 'data:text/html,hi', 'ftp://x.example/', 'https://u:p@x.example/', 'nostrconnect://x', 'https://x.example/ a', '', null, 42, 'https://' + 'a'.repeat(2000) + '.example/'])
    assert.equal(approvalPage(bad), null, String(bad).slice(0, 40));
});

test('signin approve: a bunker that asks to approve at a page shows "Continue at <host>", a click opens it in a new tab, and sign-in completes', { skip }, async () => {
  await withPhone({ approveFirst: true }, async ({ page, context }, phone) => {
    await pasteBunker(page, await phone.bunker(relay.url));
    const button = page.locator('a[data-si="approve"]');
    await button.waitFor({ timeout: 10000 });
    const host = new URL(phone.approvalUrl!).host;
    assert.equal(await button.textContent(), `Continue at ${host}`);
    assert.ok((await button.getAttribute('href'))!.startsWith(phone.approvalUrl!));
    assert.equal(await button.getAttribute('target'), '_blank');
    assert.equal(await button.getAttribute('rel'), 'noopener');
    const lines = await dialogLines(page);
    assert.ok(lines.includes(`Your sign-in app asks you to approve this at ${host} first.`), lines.join(' | '));
    assert.equal(await signedIn(page), null, 'not before you approve');
    const [tab] = await Promise.all([context.waitForEvent('page'), button.click()]);
    await tab.waitForLoadState();
    assert.match(await tab.textContent('body'), /Approved/);
    await page.waitForFunction(() => !!(window as any).signin.current(), null, { timeout: 10000 });
    assert.equal(await signedIn(page), phone.pubkey);
    assert.equal(await isOpen(page), false);
    assert.deepEqual(phone.asked.slice(0, 2), ['connect', 'get_public_key']);
    // and it signs through the bunker from then on
    const signed = await page.evaluate(() => (window as any).signin.sign({ kind: 1, content: 'hi' }));
    assert.ok(verifyEvent(signed) && signed.pubkey === phone.pubkey);
  });
});

test('signin approve: once the signer asks you to approve, the request waits longer than its own timeout', { skip }, async () => {
  await withPhone({ approveFirst: true }, async ({ page, context }, phone) => {
    await pasteBunker(page, await phone.bunker(relay.url));
    const button = page.locator('a[data-si="approve"]');
    await button.waitFor({ timeout: 10000 });
    await page.clock.fastForward(91_000); // past the connect request's own 90 s
    await page.waitForTimeout(300);
    assert.doesNotMatch((await page.textContent('[data-bunker-note]'))!, /didn't answer/);
    assert.equal(await button.isVisible(), true, 'still waiting for you');
    const [tab] = await Promise.all([context.waitForEvent('page'), button.click()]);
    await tab.waitForLoadState();
    await page.waitForFunction(() => !!(window as any).signin.current(), null, { timeout: 10000 });
    assert.equal(await signedIn(page), phone.pubkey);
  }, { before: (c: any) => c.clock.install({ time: Date.now() - 91_000 }) });
});

test('signin approve: a code answered by a signer that asks to approve at a page, under the code', { skip }, async () => {
  await withPhone({ approveFirst: true }, async ({ page, context }, phone) => {
    await page.click('[data-sign-in]');
    await page.click('[data-si="signer"]');
    await page.waitForSelector('.si .qr svg');
    await phone.answerCode((await page.getAttribute('[data-si="copy"]', 'data-code'))!);
    const button = page.locator('a[data-si="approve"]');
    await button.waitFor({ timeout: 10000 });
    assert.equal(await button.textContent(), `Continue at ${new URL(phone.approvalUrl!).host}`);
    assert.equal(await page.locator('.si .qr svg').count(), 1, 'the code stays');
    const [tab] = await Promise.all([context.waitForEvent('page'), button.click()]);
    await tab.waitForLoadState();
    await page.waitForFunction(() => !!(window as any).signin.current(), null, { timeout: 10000 });
    assert.equal(await signedIn(page), phone.pubkey);
    assert.equal(await page.evaluate(() => (window as any).signin.method()), 'phone');
  });
});

test('signin approve: an auth_url that is not a web page is ignored, and the real answer still signs in', { skip }, async () => {
  for (const url of ['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>']) {
    await withPhone({ approveFirst: { url, answerAfter: 1500 } }, async ({ page, context }, phone) => {
      let tabs = 0;
      context.on('page', () => tabs++);
      await pasteBunker(page, await phone.bunker(relay.url));
      await page.waitForFunction(() => !!(window as any).signin.current(), null, { timeout: 10000 });
      assert.equal(await signedIn(page), phone.pubkey);
      assert.equal(await page.locator('[data-approve]').count(), 0, 'no button');
      assert.equal(tabs, 0, 'nothing opened');
    });
  }
});

test('signin approve: a signer that stays silent times out, says so, and the dialog still works', { skip }, async () => {
  const later = standInPhone();
  try {
    await withPhone({ silent: true }, async ({ page }, phone) => {
      await pasteBunker(page, await phone.bunker(relay.url));
      await page.waitForSelector('[data-bunker-note]:not([hidden])');
      assert.match((await page.textContent('[data-bunker-note]'))!, /Connecting/);
      for (let i = 0; i < 50 && !phone.asked.length; i++) await page.waitForTimeout(100);
      assert.deepEqual(phone.asked, ['connect'], 'it was asked, and said nothing');
      await page.clock.fastForward(91_000); // past the connect request's 90 s
      await page.waitForFunction(() => /didn't answer/.test(document.querySelector('[data-bunker-note]')?.textContent || ''), null, { timeout: 5000 });
      assert.equal(await page.textContent('[data-bunker-note]'), "Your signer app didn't answer.");
      assert.equal(await page.isEnabled('form[data-form="bunker"] button[type="submit"]'), true);
      assert.equal(await isOpen(page), true);
      // the same dialog, another link: signs in
      await page.fill('#si-bunker', await later.bunker(relay.url));
      await page.click('form[data-form="bunker"] button[type="submit"]');
      await page.waitForFunction(() => !!(window as any).signin.current(), null, { timeout: 10000 });
      assert.equal(await signedIn(page), later.pubkey);
      // (the clock starts as far behind as it is moved on, so after the jump the page's time is the relay's again)
    }, { before: (c: any) => c.clock.install({ time: Date.now() - 91_000 }) });
  } finally { await later.stop(); }
});

test('signin approve: a signer that refuses: the bunker form says why, and a code says the sign-in didn\'t finish', { skip }, async () => {
  await withPhone({ refuse: 'Not now' }, async ({ page }, phone) => {
    await pasteBunker(page, await phone.bunker(relay.url));
    await page.waitForFunction(() => /Not now/.test(document.querySelector('[data-bunker-note]')?.textContent || ''), null, { timeout: 10000 });
    assert.equal(await signedIn(page), null);
    await page.click('[data-si="unsigner"]');
    await page.click('[data-si="signer"]');
    await page.waitForSelector('.si .qr svg');
    await phone.answerCode((await page.getAttribute('[data-si="copy"]', 'data-code'))!);
    await page.waitForFunction(() => document.getElementById('si-title')?.textContent === "Sign-in didn't finish", null, { timeout: 10000 });
    assert.ok((await dialogLines(page)).includes('Not now'));
    assert.equal(await signedIn(page), null);
  });
});
