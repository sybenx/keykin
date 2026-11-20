// signin/pure.js: the pure rules a page or a server uses on its own (typed names, templates, origins, NIP-05 answers),
// and the explicit "local pages count" answer a server passes per request instead of the page's location. Imported
// with its types (pure.d.ts, pointer.d.ts), so the typecheck holds those to how a TypeScript site calls them.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loginTemplate, originOnly, typedName, bech32Key, nip05Key, loginLink, legacyTemplate, PLACEHOLDER } from '../signin/pure.js';
import { pointerOf, pageFrom } from '../signin/pointer.js';
import * as pointer from '../signin/pointer.js';

const at = (p: string) => new URL(`../signin/${p}`, import.meta.url).href;
const connect: any = await import(at('connect.js')), rules: any = await import(at('rules.js'));
const { schnorr, sha256 }: any = await import(at('vendor/noble.js'));
const { toHex, fromHex, npub }: any = await import(at('ids.js'));

const sk = fromHex('33'.repeat(32)), pk: string = toHex(schnorr.getPublicKey(sk));
function signed(kind: number, tags: string[][], at: number) {
  const t = { kind, pubkey: pk, created_at: at, tags, content: '' };
  const id: string = toHex(sha256(new TextEncoder().encode(JSON.stringify([0, t.pubkey, t.created_at, t.kind, t.tags, t.content]))));
  return { ...t, id, sig: toHex(schnorr.sign(fromHex(id), sk)) as string };
}
function hereIs<T>(host: string, fn: () => T): T {
  (globalThis as any).location = { hostname: host };
  try { return fn(); } finally { delete (globalThis as any).location; }
}

test('signin pure: the same functions wherever they are imported from', () => {
  for (const m of [connect, rules]) assert.equal(m.loginTemplate, loginTemplate);
  for (const m of [pointer, rules]) assert.equal(m.originOnly, originOnly);
  assert.equal(rules.typedName, typedName);
  assert.equal(rules.nip05Key, nip05Key);
  assert.equal(PLACEHOLDER, '<nostrconnect>');
});

test('signin pure: local pages count when told so, whatever the location says', () => {
  const L = 'http://localhost:7070/#connect=<nostrconnect>';
  assert.equal(loginTemplate(L), null, 'no location: not local');
  assert.equal(loginTemplate(L, true)?.origin, 'http://localhost:7070');
  assert.equal(hereIs('localhost', () => loginTemplate(L))?.origin, 'http://localhost:7070', 'left out: the location decides, as before');
  assert.equal(hereIs('localhost', () => loginTemplate(L, false)), null, 'told no on localhost');
  assert.equal(hereIs('marble.example', () => loginTemplate(L, true))?.origin, 'http://localhost:7070', 'told yes elsewhere');
  assert.equal(loginTemplate('http://example.com/#connect=<nostrconnect>', true), null, 'only this machine, never plain http');
  assert.equal(originOnly('http://127.0.0.1:7070', true), 'http://127.0.0.1:7070');
  assert.equal(hereIs('localhost', () => originOnly('http://127.0.0.1:7070', false)), null);
  const p46 = signed(10046, [['nostrconnect_url', L]], 100);
  const found = pointerOf([p46], pk, true);
  assert.equal('url' in found && found.url, 'http://localhost:7070');
  assert.ok('none' in hereIs('localhost', () => pointerOf([p46], pk, false)));
  const p78 = signed(30078, [['d', 'keykin/login'], ['url', 'http://localhost:7070']], 100);
  assert.equal(pageFrom(p78, pk, true), 'http://localhost:7070');
  assert.equal(pageFrom(p78, pk), null);
});

test('signin pure: a template is written as its origin, and the code never reaches the host', () => {
  for (const t of ['https:account.syb.lol/#connect=<nostrconnect>', 'https://account.syb.lol:<nostrconnect>', 'https://account.syb.lol:8<nostrconnect>',
    'https://account.syb.lol/<b><nostrconnect>', 'https://account.syb.lol/#\u0000<nostrconnect>', 'https://account.syb.lol/#c=\t<nostrconnect>'])
    assert.equal(loginTemplate(t), null, t);
  assert.equal(loginTemplate('https://account.syb.lol?<nostrconnect>')?.origin, 'https://account.syb.lol', 'in the query is fine');
  const code = 'nostrconnect://' + 'a'.repeat(64) + '?relay=wss%3A%2F%2Fsyb.lol&secret=1';
  assert.equal(new URL(loginLink('https://a.example/#c=<nostrconnect>', code)).origin, 'https://a.example');
  assert.equal(legacyTemplate('https://old.example'), 'https://old.example/#connect=<nostrconnect>');
});

test('signin pure: typed names and keys', () => {
  const KEY = '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d';
  const n: string = npub(KEY);
  assert.deepEqual(typedName('nostr:' + n.toUpperCase()), { pubkey: KEY });
  assert.deepEqual(typedName('Nostr:aaron@example.com'), { name: 'aaron', domain: 'example.com' });
  assert.equal(typedName(undefined), null);
  assert.equal(bech32Key(n), KEY);
  assert.equal(bech32Key(n.toUpperCase()), KEY);
  assert.equal(bech32Key(n.slice(0, 10) + n.slice(10).toUpperCase()), null, 'mixed case');
  assert.equal(bech32Key('note1' + n.slice(5)), null, 'not a profile');
  assert.equal(bech32Key(42), null);
});

test('signin pure: the key in a NIP-05 answer', () => {
  const KEY = 'ab'.repeat(32);
  assert.equal(nip05Key({ names: { aaron: KEY.toUpperCase() } }, 'aaron'), KEY);
  assert.equal(nip05Key({ names: { Aaron: KEY, aaron: 'cd'.repeat(32) } }, 'aaron'), 'cd'.repeat(32), 'the name as written first');
  assert.equal(nip05Key({ names: { AARON: KEY } }, 'Aaron'), KEY);
  for (const body of [null, 'x', [], { names: null }, { names: { aaron: 5 } }, { names: { aaron: KEY + 'a' } }]) assert.equal(nip05Key(body, 'aaron'), null);
  assert.equal(nip05Key({ names: {} }, '__proto__'), null);
  assert.equal(nip05Key({ names: {} }, 'constructor'), null);
});
