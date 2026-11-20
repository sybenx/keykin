// signin/: a site's own sign-in code and the login page's link (SPEC 11.6): no kk=account on a site's code, `connect=`
// last in the fragment and URL-encoded once, and the link opened with no noreferrer. Ported from Marble Web's
// tools/site-codes.test.mjs; its last check (Marble's account menu shows the short key) stays in Marble.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const at = (p: string) => new URL(`../signin/${p}`, import.meta.url);
const { siteCode, loginLink, deviceLabel, shortKey }: any = await import(at('connect.js').href);

const pk = 'a'.repeat(64), perms = 'sign_event:1,nip44_decrypt,get_public_key';
const base = { pk, relays: ['wss://syb.lol', 'wss://relay.damus.io'], secret: '0123456789abcdef', name: 'Marble', url: 'https://marble.syb.lol', perms };
const params = (code: string) => new URLSearchParams(code.slice(code.indexOf('?') + 1));

test('signin: a site\'s code carries key, relays, secret, name, url and perms, and no kk=account', () => {
  const code = siteCode(base);
  assert.ok(code.startsWith(`nostrconnect://${pk}?relay=wss%3A%2F%2Fsyb.lol&relay=wss%3A%2F%2Frelay.damus.io&secret=0123456789abcdef`), 'key, relays, secret');
  const q = params(code);
  assert.ok(q.get('name') === 'Marble' && q.get('url') === 'https://marble.syb.lol' && q.get('perms') === perms, 'name, url, perms');
  assert.ok(!q.has('kk') && !/kk=account/.test(code), 'no kk=account on a site\'s code');
  const missing = siteCode({ ...base, extra: '&kk_login=missing' });
  assert.ok(params(missing).get('kk_login') === 'missing' && !/kk=account/.test(missing), 'kk_login=missing alone');
});

test('signin: the login page\'s link has connect= last, encoded once, and no noreferrer', () => {
  const code = siteCode(base);
  const link = loginLink('https://account.syb.lol/#connect=<nostrconnect>', code);
  assert.ok(link.startsWith('https://account.syb.lol/#connect=nostrconnect%3A%2F%2F'), 'connect= in the fragment, encoded once');
  const frag = link.slice(link.indexOf('#') + 1);
  assert.ok(frag.indexOf('connect=') === 0 && !frag.slice(8).includes('&') && !frag.slice(8).includes('#'), 'connect= last, nothing after it');
  assert.equal(decodeURIComponent(frag.slice(8)), code, 'decodes back to the code');

  // the link to the login page sends the referrer (the page checks the sender by it)
  const dialog = readFileSync(at('dialog.js'), 'utf8');
  const away = dialog.split('\n').filter((l) => l.includes('loginLink(') && l.includes('<a '));
  assert.ok(away.length >= 1 && away.every((l) => !/noreferrer/.test(l)), 'login link has no noreferrer');
  assert.ok(!/kk=account/.test(readFileSync(at('connect.js'), 'utf8').replace(/^\s*(\*|\/\/).*$/gm, '')), 'connect.js code adds no kk=account');
});

test('signin: device= names this browser, at most 60 characters', () => {
  const labelled = params(siteCode({ ...base, device: 'Chrome on Windows', extra: '&kk_login=missing' }));
  assert.ok(labelled.get('device') === 'Chrome on Windows' && labelled.get('kk_login') === 'missing', 'device= on the code, extra after it');
  assert.ok(!siteCode(base).includes('device='), 'no device= when there is no label');
  assert.equal(params(siteCode({ ...base, device: 'x'.repeat(90) })).get('device')!.length, 60, 'device= at most 60');
  const win = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
  assert.equal(deviceLabel({ userAgent: win }), 'Chrome on Windows', 'Chrome on Windows from userAgent');
  assert.equal(deviceLabel({ userAgent: win, userAgentData: { brands: [{ brand: 'Microsoft Edge' }, { brand: 'Chromium' }], platform: 'Windows' } }), 'Edge on Windows', 'userAgentData first');
  assert.equal(deviceLabel({ userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1' }), 'Safari on iPhone', 'Safari on iPhone');
  assert.equal(deviceLabel({ userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0' }), 'Firefox on Linux', 'Firefox on Linux');
  assert.equal(deviceLabel({}), '', 'nothing known: no label');
  assert.match(readFileSync(at('connect.js'), 'utf8'), /device: deviceLabel\(\)/, 'the phone sign-in code carries this browser\'s label');
});

test('signin: the short key is the client key\'s first 4 hex', async () => {
  assert.equal(await shortKey('nothex'), null, 'no key, no short key');
  const sk = '1'.repeat(64);
  const { schnorr }: any = await import(at('vendor/sign.js').href);
  const hex = [...schnorr.getPublicKey(Uint8Array.from(sk.match(/../g)!, (h) => parseInt(h, 16)))].map((b: number) => b.toString(16).padStart(2, '0')).join('');
  assert.equal(await shortKey(sk), hex.slice(0, 4));
});
