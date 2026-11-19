// The login-page pointer's rules (SPEC 11.1): kind 10046 first, kind 30078 during the move.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const box: any = {};
new Function('globalThis', readFileSync(join(import.meta.dirname, '../login/static/pointer.js'), 'utf8'))(box);        // the same file the page loads
const P = box.KeykinPointer;
let n = 0;
const ev = (kind: number, tags: string[][], at: number) => ({ id: String(++n).padStart(64, '0'), kind, created_at: at, tags, content: '', pubkey: 'a'.repeat(64) });
const fresh = (origin: string, at: number) => ev(10046, [['nostrconnect_url', `${origin}/#connect=<nostrconnect>`], ['relays', 'wss://r']], at);
const old = (origin: string | null, at: number) => ev(30078, origin ? [['d', 'keykin/login'], ['url', origin]] : [['d', 'keykin/login']], at);

test('the pointer: 10046 first, 30078 only when there is no 10046, and a 10046 without a template is a removal', () => {
  const here = 'marble.example';
  assert.deepEqual(P.read([], here), { state: 'none' });
  // Only the old kind: read as the template <url>/#connect=<nostrconnect>.
  assert.equal(P.read([old('https://old.example', 5)], here).origin, 'https://old.example');
  assert.equal(P.read([old('https://old.example', 5)], here).kind, 30078);
  assert.equal(P.read([old(null, 5)], here).state, 'removed');
  assert.equal(P.read([ev(30078, [['d', 'other'], ['url', 'https://x.example']], 9)], here).state, 'none');        // another app's 30078
  // A 10046 wins over any 30078, even a newer one.
  const both = P.read([old('https://old.example', 9), fresh('https://account.syb.lol', 5)], here);
  assert.deepEqual([both.state, both.origin, both.kind], ['found', 'https://account.syb.lol', 10046]);
  // Newest 10046 wins; one with no template is a removal, and the old kind is not read then.
  assert.equal(P.read([fresh('https://a.example', 1), fresh('https://b.example', 2)], here).origin, 'https://b.example');
  assert.equal(P.read([fresh('https://a.example', 1), ev(10046, [], 2), old('https://old.example', 3)], here).state, 'removed');
});

test('the pointer: template checks', () => {
  const ok = (t: string, here = 'marble.example') => P.checkTemplate(t, here);
  assert.equal(ok('https://account.syb.lol/#connect=<nostrconnect>'), 'https://account.syb.lol');
  assert.equal(ok('https://signer.example/connect?uri=<nostrconnect>'), 'https://signer.example');
  for (const bad of ['http://account.syb.lol/#connect=<nostrconnect>', 'https://u:p@account.syb.lol/#connect=<nostrconnect>', 'https://account.syb.lol/#connect=',
    'https://account.syb.lol/#a=<nostrconnect>&b=<nostrconnect>', 'https://account.syb.lol/<nostrconnect>/x', 'javascript:alert(1)//<nostrconnect>', 7 as any])
    assert.equal(ok(bad), null, String(bad));
  // A local http page only for a reader running locally.
  assert.equal(ok('http://127.0.0.1:7470/#connect=<nostrconnect>', 'localhost'), 'http://127.0.0.1:7470');
  assert.equal(ok('http://127.0.0.1:7470/#connect=<nostrconnect>'), null);
  assert.equal(P.read([fresh('http://evil.example', 1)], 'marble.example').state, 'bad');
});

test('the pointer: a new one is signed as both kinds, a removal removes both, and a missing copy goes again as it is', async () => {
  const [a, b] = P.pointerEvents('https://account.syb.lol', 100);
  assert.deepEqual([a.kind, a.tags], [10046, [['nostrconnect_url', 'https://account.syb.lol/#connect=<nostrconnect>']]]);
  assert.deepEqual([b.kind, b.tags], [30078, [['d', 'keykin/login'], ['url', 'https://account.syb.lol']]]);
  assert.equal(P.read([a, b], 'x').origin, 'https://account.syb.lol');
  const gone = P.removalEvents(200);
  assert.deepEqual(gone.map((e: any) => [e.kind, e.tags]), [[10046, []], [30078, [['d', 'keykin/login']]]]);
  assert.equal(P.read([{ ...a, id: '1' }, { ...b, id: '2' }, ...gone.map((e: any, i: number) => ({ ...e, id: 'g' + i }))], 'x').state, 'removed');

  // publish: every event signed, each sent to every relay; true once each kind reached a relay.
  const signedKinds: number[] = [], sent: [string, number][] = [];
  const signer = { signEvent: async (e: any) => { signedKinds.push(e.kind); return { ...e, id: 'id' + e.kind, sig: 's' }; } };
  assert.equal(await P.publish(signer, ['wss://1', 'wss://2'], P.pointerEvents('https://account.syb.lol', 1), async (r: string, e: any) => { sent.push([r, e.kind]); return r === 'wss://2'; }), true);
  assert.deepEqual(signedKinds, [10046, 30078]);
  assert.deepEqual(sent.sort(), [['wss://1', 10046], ['wss://1', 30078], ['wss://2', 10046], ['wss://2', 30078]]);
  assert.equal(await P.publish(signer, ['wss://1'], P.removalEvents(2), async (_r: string, e: any) => e.kind === 10046), false);

  // Missing copies: the newest of each kind, sent as it is to the relays that answered without it.
  const n1 = fresh('https://account.syb.lol', 5), o1 = old('https://account.syb.lol', 5);
  const copies = P.missingCopies({ 'wss://1': [n1, o1], 'wss://2': [o1], 'wss://3': [] }, 'https://account.syb.lol', 'account.syb.lol');
  assert.deepEqual(copies.map((c: any) => [c.relay, c.event.kind, c.event.id]).sort(), [['wss://2', 10046, n1.id], ['wss://3', 10046, n1.id], ['wss://3', 30078, o1.id]]);
  // Nothing when the pointer names another page, or was removed.
  assert.deepEqual(P.missingCopies({ 'wss://1': [n1], 'wss://2': [] }, 'https://other.example', 'other.example'), []);
  assert.deepEqual(P.missingCopies({ 'wss://1': [n1, ev(10046, [], 9)], 'wss://2': [] }, 'https://account.syb.lol', 'account.syb.lol'), []);
  // An old copy naming another page is not sent about.
  assert.deepEqual(P.missingCopies({ 'wss://1': [n1, old('https://elsewhere.example', 9)], 'wss://2': [n1] }, 'https://account.syb.lol', 'account.syb.lol'), []);
});
