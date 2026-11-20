// signin/: the login-page pointer (SPEC 11.1): kind 10046 and its nostrconnect_url template, the old kind 30078 only
// when there's no 10046 at all, removal, and the link built from it. Ported from Marble Web's tools/login-pointer.test.mjs.
import { test } from 'node:test';
import assert from 'node:assert/strict';

const at = (p: string) => new URL(`../signin/${p}`, import.meta.url).href;
const { schnorr, sha256 }: any = await import(at('vendor/noble.js'));
const { toHex, fromHex }: any = await import(at('ids.js'));
const { loginTemplate, legacyTemplate, loginLink }: any = await import(at('connect.js'));
const { pointerOf, POINTER }: any = await import(at('pointer.js'));

const sk = schnorr.utils.randomSecretKey(), pk = toHex(schnorr.getPublicKey(sk));
const other = schnorr.utils.randomSecretKey();
function signed(kind: number, tags: string[][], at: number, key = sk) {
  const t = { kind, pubkey: toHex(schnorr.getPublicKey(key)), created_at: at, tags, content: '' };
  const id = toHex(sha256(new TextEncoder().encode(JSON.stringify([0, t.pubkey, t.created_at, t.kind, t.tags, t.content]))));
  return { ...t, id, sig: toHex(schnorr.sign(fromHex(id), key)) };
}
const T = 'https://account.syb.lol/#connect=<nostrconnect>';

test('signin: login page templates', () => {
  assert.ok(loginTemplate(T)?.origin === 'https://account.syb.lol' && loginTemplate(T).template === T, 'Keykin\'s template');
  assert.equal(loginTemplate('https://login.example.org/signin?code=<nostrconnect>')?.origin, 'https://login.example.org', 'another shape, placeholder at the end');
  assert.equal(loginTemplate('https://a.example:8443/#connect=<nostrconnect>')?.origin, 'https://a.example:8443', 'a port');
  for (const [t, why] of [
    ['http://account.syb.lol/#connect=<nostrconnect>', 'not https'],
    ['http://localhost:8080/#connect=<nostrconnect>', 'http localhost when this isn\'t localhost'],
    ['https://me:pw@account.syb.lol/#connect=<nostrconnect>', 'user and password'],
    ['https://me@account.syb.lol/#connect=<nostrconnect>', 'user'],
    ['https://account.syb.lol/#connect=', 'no placeholder'],
    ['https://account.syb.lol/#connect=<nostrconnect>&x=1', 'placeholder not at the end'],
    ['https://account.syb.lol/<nostrconnect>#connect=<nostrconnect>', 'two placeholders'],
    ['javascript:alert(1)//<nostrconnect>', 'not a web address'],
    ['<nostrconnect>', 'only the placeholder'],
    [42, 'not a string'],
    [undefined, 'missing'],
  ] as [unknown, string][]) assert.equal(loginTemplate(t), null, 'refused: ' + why);
});

test('signin: the link from a template', () => {
  const code = 'nostrconnect://' + 'a'.repeat(64) + '?relay=wss%3A%2F%2Fsyb.lol&secret=s1&name=Marble&url=https%3A%2F%2Fmarble.syb.lol';
  const link = loginLink(T, code);
  assert.equal(link, 'https://account.syb.lol/#connect=' + encodeURIComponent(code), 'placeholder replaced by the code, encoded once');
  assert.ok(!link.includes('<nostrconnect>') && decodeURIComponent(link.split('#connect=')[1]) === code, 'decodes back to the code');
  assert.equal(loginLink(legacyTemplate('https://old.example'), code), 'https://old.example/#connect=' + encodeURIComponent(code), 'old origin as the template');
});

test('signin: the lookup\'s decision', () => {
  const p10046 = (tpl: string | null, at: number) => signed(POINTER, tpl === null ? [['relays', 'wss://syb.lol']] : [['nostrconnect_url', tpl]], at);
  const p30078 = (url: string | null, at: number) => signed(30078, [['d', 'keykin/login'], ...(url ? [['url', url]] : [])], at);
  let r = pointerOf([p10046(T, 100)], pk);
  assert.ok(r.url === 'https://account.syb.lol' && r.template === T && !r.legacy, '10046 found');
  r = pointerOf([p10046('https://old.example/#connect=<nostrconnect>', 100), p10046(T, 200)], pk);
  assert.equal(r.template, T, 'newest 10046 wins');
  r = pointerOf([p10046(T, 100), p30078('https://old.example', 500)], pk);
  assert.equal(r.template, T, 'a 10046 wins over a newer 30078');
  r = pointerOf([p30078('https://old.example', 100)], pk);
  assert.ok(r.legacy && r.url === 'https://old.example' && r.template === 'https://old.example/#connect=<nostrconnect>', 'no 10046 at all: the old kind, as the template');
  r = pointerOf([p10046(null, 300), p30078('https://old.example', 100)], pk);
  assert.ok(r.none && r.removed && !r.template, 'newest 10046 without nostrconnect_url: removed, no falling back');
  r = pointerOf([p10046(T, 100), p10046(null, 300)], pk);
  assert.ok(r.none && r.removed, 'removed after an older good one');
  r = pointerOf([p10046('http://evil.example/#connect=<nostrconnect>', 300), p30078('https://old.example', 100)], pk);
  assert.ok(r.none && !r.template, 'newest 10046 with a bad template: nothing, no falling back');
  r = pointerOf([p30078(null, 100)], pk);
  assert.ok(r.none && r.removed, 'old kind with no url: removed');
  assert.ok(pointerOf([], pk).none && !pointerOf([], pk).removed, 'nothing found');
  // only the account's own, signed as they are
  assert.ok(pointerOf([signed(POINTER, [['nostrconnect_url', T]], 100, other)], pk).none, 'someone else\'s 10046 doesn\'t count');
  const forged = { ...p10046(T, 100) }; forged.tags = [['nostrconnect_url', 'https://evil.example/#connect=<nostrconnect>']];
  assert.ok(pointerOf([forged], pk).none, 'a changed 10046 doesn\'t count');
  assert.ok(pointerOf([forged, p30078('https://old.example', 50)], pk).legacy, 'a forged 10046 is no 10046: the old kind is read');
});
