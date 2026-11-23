// The account page's Home section: its rules and its signed calls (login/static/home.js, the same file the page
// loads), against stand-ins for the home (bothy) and its file server that check NIP-98 the way the contracts say.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateSecretKey, getPublicKey, finalizeEvent } from 'nostr-tools/pure';
import { npubEncode } from 'nostr-tools/nip19';
import { fakeBothy, fakeStorage } from './home-fakes.ts';
import { placeOf, startLogin } from '../login/server.ts';

const box: any = {};
new Function('globalThis', readFileSync(join(import.meta.dirname, '../login/static/home.js'), 'utf8'))(box);
const K = box.KeykinHome;
const person = () => { const sk = generateSecretKey(); return { sk, pk: getPublicKey(sk), signer: { signEvent: async (t: any) => finalizeEvent(t, sk) } }; };
const pk = (c: string) => c.repeat(64);

test('npub and sizes read the way the rest of Keykin writes them', () => {
  for (let i = 0; i < 5; i++) { const p = getPublicKey(generateSecretKey()); assert.equal(K.npub(p), npubEncode(p)); }
  assert.equal(K.size(0), '0 B'); assert.equal(K.size(4096), '4.1 KB'); assert.equal(K.size(220e6), '220 MB'); assert.equal(K.size(3.4e9), '3.4 GB');
  assert.deepEqual(K.chunks([1, 2, 3, 4, 5], 2), [[1, 2], [3, 4], [5]]);
  assert.ok(K.sameHome('https://h.example', 'https://h.example/')); assert.ok(!K.sameHome('https://h.example/', 'https://other.example/'));
});

test('the invite tree: the owner on top, each person under whoever let them in, rows with no inviter apart, every key once', () => {
  const O = pk('0'), A = pk('a'), B = pk('b'), C = pk('c'), D = pk('d'), E = pk('e'), F = pk('f'), G = pk('1');
  const t = K.tree(O, { members: [
    { pubkey: B, invitedBy: A, joinedAt: 3, role: 'member' }, { pubkey: A, invitedBy: O, joinedAt: 1, role: 'admin' },
    { pubkey: C, invitedBy: B, joinedAt: 4 }, { pubkey: D, invitedBy: null, joinedAt: 2 },          // from before the invite tree: apart
    { pubkey: E, invitedBy: pk('9'), joinedAt: 5 },                                               // inviter not listed: apart
    { pubkey: A, invitedBy: O, joinedAt: 9 },                                                     // listed twice: once
    { pubkey: F, invitedBy: F, joinedAt: 6 },                                                     // its own inviter: apart
    { pubkey: G, invitedBy: D, joinedAt: 7 },                                                     // invited by an old row: under it
    { pubkey: pk('2'), invitedBy: O, inviterUnknown: true, joinedAt: 8 },                       // bothy v0.29: the owner named, but not known
    { pubkey: O, invitedBy: null }] });                                                           // the owner in the list: only at the root
  assert.deepEqual(K.flat(t).map((r: any) => [r.node.pubkey[0], r.depth]), [['0', 0], ['a', 1], ['b', 2], ['c', 3]]);
  assert.deepEqual(t.old.flatMap((n: any) => K.flat(n, 1)).map((r: any) => [r.node.pubkey[0], r.depth]), [['d', 1], ['1', 2], ['e', 1], ['f', 1], ['2', 1]]);
  assert.deepEqual(t.old.map((n: any) => n.legacy), [true, true, true, true]);
  assert.equal(K.find(t, G).legacy, undefined);
  assert.deepEqual(K.below(K.find(t, A)).map((n: any) => n.pubkey[0]), ['b', 'c']);
  assert.equal(K.find(t, G).pubkey, G);
  assert.equal(K.everyone(t).length, 8);
  // A loop never comes from bothy, but if it did each row still shows once.
  const loop = K.tree(O, { members: [{ pubkey: A, invitedBy: B }, { pubkey: B, invitedBy: A }] });
  assert.equal(K.everyone(loop).length, 2);
});

test('how someone came in, in plain words, and the end of their key', () => {
  assert.equal(K.howCame({ role: 'owner' }, null), 'Owner');
  assert.equal(K.howCame({ source: 'owner' }, 'you'), 'Added by you');
  assert.equal(K.howCame({ source: 'member' }, 'Robin'), 'Invited by Robin');
  assert.equal(K.howCame({ source: 'invite' }, 'Robin'), 'Invited by Robin');
  assert.equal(K.howCame({ source: 'request' }, 'you'), 'Asked to join, let in by you');
  assert.equal(K.howCame({ source: 'owner' }, null), 'Added by hand');
  assert.equal(K.howCame({ source: 'request' }, null), 'Asked to join');
  assert.equal(K.howCame({ source: 'member' }, null), 'Came with an invite');
  assert.equal(K.howCame({ source: 'invite', legacy: true }, 'you'), null);
  assert.equal(K.tail('ab'.repeat(29) + 'c0ffee'), 'c0ffee');
});

test('last here: bothy v0.29 lastSeen is a UTC day number, shown as that UTC day', () => {
  assert.equal(K.seenWords({ lastSeen: 20779 }), 'Last here Nov 22, 2026');                                // 2026-11-22
  assert.equal(K.seenWords({ lastSeen: 20778 }), 'Last here Nov 21, 2026');
  assert.equal(K.seenWords({ lastSeen: 20779 * 86400 + 5000 }), 'Last here Nov 22, 2026', 'seconds by mistake: still that day, never the year 50000');
  assert.equal(K.seenWords({ lastSeen: null, joinedAt: 1_756_000_000 }), 'No sign-in since Nov 21, 2026'); // joined before bothy kept days
  assert.equal(K.seenWords({ lastSeen: null, joinedAt: 20779 * 86400 }), 'Never signed in');
  assert.equal(K.seenWords({ lastSeen: null }), 'Never signed in');
  assert.equal(K.seenWords({}), null);                                                                     // an older bothy says nothing
  for (const odd of ['2026-11-22', -1, NaN, true]) assert.equal(K.seenWords({ lastSeen: odd }), null, String(odd));
});

test('removal: the page offers only what bothy takes', () => {
  const O = pk('0'), A = pk('a'), B = pk('b'), C = pk('c'), M = pk('d');
  const t = K.tree(O, { members: [{ pubkey: A, invitedBy: O, role: 'admin' }, { pubkey: B, invitedBy: O, role: 'member' }, { pubkey: C, invitedBy: B, role: 'admin' }, { pubkey: M, invitedBy: A, role: 'member' }] });
  const n = (p: string) => K.find(t, p);
  assert.deepEqual(K.removal(n(O), O, 'owner'), { remove: false, branch: false, why: null });       // not the owner
  assert.deepEqual(K.removal(n(A), O, 'owner'), { remove: true, branch: true, why: null });         // the owner can remove an admin
  assert.equal(K.removal(n(A), A, 'admin').remove, false);                                          // not yourself
  assert.equal(K.removal(n(C), A, 'admin').remove, false);                                          // an admin cannot remove an admin
  assert.deepEqual(K.removal(n(B), A, 'admin'), { remove: true, branch: false, why: 'Someone they invited is an admin, so only the owner can remove them all.' });
  assert.deepEqual(K.removal(n(M), A, 'admin'), { remove: true, branch: true, why: null });
  // Both choices, with the count, and neither marked as the dangerous one.
  assert.deepEqual(K.removeWords('Ana', [{}, {}, {}]), { ask: 'Ana invited 3 people. What happens to them?', keep: 'Keep the 3 people they invited', branch: 'Remove them too' });
  assert.deepEqual(K.removeWords('Ana', [{}]).keep, 'Keep the person they invited');
  assert.deepEqual(K.removeWords('Ana', []), { ask: 'Remove Ana from the home?', keep: 'Remove', branch: null });
});

test('names and photos: the newest kind 0, only an https picture', () => {
  const A = pk('a');
  const p = K.profiles([
    { kind: 0, pubkey: A, created_at: 1, content: JSON.stringify({ name: 'Old' }) },
    { kind: 0, pubkey: A, created_at: 2, content: JSON.stringify({ name: 'ana', display_name: ' Ana ', picture: 'javascript:alert(1)' }) },
    { kind: 0, pubkey: pk('b'), created_at: 1, content: '{nope' },
    { kind: 1, pubkey: pk('c'), created_at: 1, content: '{}' }]);
  assert.deepEqual(p, { [A]: { name: 'Ana', picture: null }, [pk('b')]: { name: null, picture: null } });
});

test('the bin by person, largest first, with the soonest erase date', () => {
  const A = pk('a'), B = pk('b');
  const g = K.binByPerson({ items: [
    { sha256: pk('1'), size: 10, charged: A, erasesAt: 50 }, { sha256: pk('2'), size: 5, charged: B, erasesAt: 40 },
    { sha256: pk('3'), size: 20, charged: B, erasesAt: 30 }, { sha256: pk('4'), size: 1, charged: null }, { sha256: 'bad', size: 99, charged: A }] });
  assert.deepEqual(g.map((x: any) => [x.pubkey?.[0] ?? null, x.items.length, x.bytes, x.erasesAt ?? null]), [['b', 2, 25, 30], ['a', 1, 10, 50], [null, 1, 1, null]]);
});

test('signed calls: bothy and the file server take them from the owner and an admin, and say no in their own words', async () => {
  const owner = person(), admin = person(), friend = person(), stranger = person();
  const home = await fakeBothy({ owner: owner.pk, members: [{ pubkey: admin.pk, role: 'admin' }, { pubkey: friend.pk, invitedBy: admin.pk, close: false }] });
  const files = await fakeStorage({ owner: owner.pk, admins: [admin.pk], home: home.url, blobs: [{ sha256: pk('1'), size: 1000, owner: friend.pk, binned: true }, { sha256: pk('2'), size: 5000, owner: friend.pk }] });
  try {
    const info = await K.homeInfo(home.url);
    assert.equal(info.pubkey, owner.pk);
    assert.equal((await K.call(admin.signer, home.url, 'myrole', [])).role, 'admin');
    assert.equal((await K.call(stranger.signer, home.url, 'myrole', [])).role, 'none');
    const list = await K.call(admin.signer, home.url, 'listmembers', []);
    assert.equal(list.members.length, 2);
    assert.equal(await K.call(admin.signer, home.url, 'setclose', [friend.pk, true]), true);
    assert.equal(home.members.get(friend.pk)!.close, true);
    await assert.rejects(K.call(admin.signer, home.url, 'setclose', [owner.pk, false]), { message: 'setclose: the owner always sees where photos were taken', status: 200 });
    await assert.rejects(K.call(friend.signer, home.url, 'listmembers', []), { status: 401 });
    // A body changed after signing is refused: the signature covers the payload.
    const auth = await admin.signer.signEvent(await K.authEvent(home.url, JSON.stringify({ method: 'listmembers', params: [] })));
    const r = await fetch(home.url, { method: 'POST', headers: { authorization: 'Nostr ' + Buffer.from(JSON.stringify(auth)).toString('base64') }, body: JSON.stringify({ method: 'setclose', params: [friend.pk, false] }) });
    assert.equal(r.status, 401);
    // The file server: its key and home unsigned, the rest signed, erase for the owner only.
    assert.deepEqual(await K.storageInfo(files.url), { pubkey: files.key, home: home.url });
    const m = K.manageUrl(files.url);
    const usage = await K.call(admin.signer, m, 'usage', []);
    assert.deepEqual(K.usedBy(usage)[friend.pk].blobs, 2);
    assert.equal((await K.call(admin.signer, m, 'bin', [])).items.length, 1);
    await assert.rejects(K.call(admin.signer, m, 'erase', [[pk('1')]]), { message: 'this key may not manage this box', status: 401 });
    assert.deepEqual(await K.call(admin.signer, m, 'restore', [[pk('1')]]), { restored: 1 });
    assert.deepEqual(await K.call(owner.signer, m, 'erase', [[pk('2')]]), { erased: 1 });
    await assert.rejects(K.call(friend.signer, m, 'usage', []), { status: 401 });
    // Nobody there: said plainly.
    await assert.rejects(K.call(owner.signer, 'http://127.0.0.1:9/', 'myrole', []), { message: 'no answer', status: 0 });
  } finally { await home.close(); await files.close(); }
});

test('Keykin Login: the home settings, and the page may reach exactly those two hosts', async () => {
  assert.equal(placeOf('', 'home'), null);
  assert.deepEqual(placeOf('https://home.example', 'home'), { url: 'https://home.example/', origin: 'https://home.example' });
  assert.deepEqual(placeOf('https://files.example/box/', 'storage'), { url: 'https://files.example/box', origin: 'https://files.example' });
  for (const bad of ['http://home.example', 'https://u:p@home.example', 'https://home.example/?x=1', 'home.example', 'ftp://home.example'])
    assert.throws(() => placeOf(bad, 'home'), bad);
  assert.deepEqual(placeOf('http://127.0.0.1:8080', 'home'), { url: 'http://127.0.0.1:8080/', origin: 'http://127.0.0.1:8080' });

  const csp = async (o: { home?: string; storage?: string }) => {
    const l = await startLogin({ box: 'http://127.0.0.1:9', port: 0, relays: ['wss://relay.example'], log: () => {}, ...o });
    try { return (await fetch(`http://127.0.0.1:${l.port}/`, { headers: { connection: 'close' } })).headers.get('content-security-policy')!; } finally { await l.close(); }
  };
  const plain = await csp({});
  assert.match(plain, /connect-src 'self' wss: https:\/\/relay\.example;/);
  const both = await csp({ home: 'https://home.example', storage: 'https://files.example' });
  assert.match(both, /connect-src 'self' wss: https:\/\/relay\.example https:\/\/home\.example https:\/\/files\.example;/);
  assert.doesNotMatch(both, /connect-src[^;]* https:[ ;]/, 'never all of https');
  // A second box's file server after a comma: both named, nothing else.
  const two = await csp({ home: 'https://home.example', storage: 'https://files.example, https://files2.example/' });
  assert.match(two, /connect-src 'self' wss: https:\/\/relay\.example https:\/\/home\.example https:\/\/files\.example https:\/\/files2\.example;/);
  // A file server without a home is no Home section, and no extra host.
  assert.equal(await csp({ storage: 'https://files.example' }), plain);
  // home.js is served beside the page's other scripts.
  const l = await startLogin({ box: 'http://127.0.0.1:9', port: 0, log: () => {} });
  try { const r = await fetch(`http://127.0.0.1:${l.port}/home.js`, { headers: { connection: 'close' } }); assert.equal(r.status, 200); assert.match(await r.text(), /KeykinHome/); } finally { await l.close(); }
});

test('private profiles: names come from the home, signed in, asked with an own-mail filter so the home asks for AUTH', async () => {
  const me = pk('a'), A = pk('b');
  const sent: any[] = [];
  const real = (globalThis as any).WebSocket;
  class FakeWs {
    onopen: any; onmessage: any; onerror: any; url: string;
    constructor(url: string) { this.url = url; setTimeout(() => this.onopen?.(), 0); }
    send(text: string) {
      const d = JSON.parse(text); sent.push(d);
      const reply = (x: any) => setTimeout(() => this.onmessage?.({ data: JSON.stringify(x) }), 0);
      if (d[0] === 'REQ' && sent.filter((s) => s[0] === 'AUTH').length === 0) { reply(['AUTH', 'ch']); reply(['CLOSED', 'kk-names', 'auth-required: sign in']); }
      else if (d[0] === 'AUTH') reply(['OK', d[1].id ?? 'x', true, '']);
      else if (d[0] === 'REQ') { reply(['EVENT', 'kk-names', { kind: 0, pubkey: A, created_at: 1, content: '{"name":"Ana"}' }]); reply(['EOSE', 'kk-names']); }
    }
    close() {}
  }
  (globalThis as any).WebSocket = FakeWs;
  try {
    const got = await K.readProfiles('wss://home.example', [A], async (ch: string) => ({ id: 'auth', challenge: ch }), 2000, me);
    assert.deepEqual(got.map((e: any) => e.pubkey), [A]);
    const req = sent.find((s) => s[0] === 'REQ');
    assert.deepEqual(req[2], { kinds: [0], authors: [A] });
    assert.deepEqual([req[3].kinds, req[3]['#p'], req[3].limit], [[1059], [me], 1]);
  } finally { (globalThis as any).WebSocket = real; }
});

test('private profiles: a sealed photo opens from the home by its hash, as a data: picture; no name reads "No name shared"', async () => {
  const plain = new Uint8Array([0xff, 0xd8, 0xff, 1, 2, 3, 4]);
  const key = crypto.getRandomValues(new Uint8Array(32)), iv = crypto.getRandomValues(new Uint8Array(12));
  const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const sealed = new Uint8Array([...iv, ...new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, plain))]);
  const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const sha = hex(new Uint8Array(await crypto.subtle.digest('SHA-256', sealed)));
  const picture = `https://blossom.primal.net/${sha}#k=${hex(key)}`;
  assert.equal(K.sealedKey(picture), hex(key));
  assert.equal(K.sealedKey('https://x.example/a.jpg'), null);
  const asked: string[] = [];
  const fetch = async (u: string) => { asked.push(u); return new Response(u.startsWith('https://home.example/') ? sealed : null, { status: u.startsWith('https://home.example/') ? 200 : 404 }); };
  const url = await K.sealedPicture(picture, 'https://home.example/', { fetch });
  assert.deepEqual(asked, [`https://home.example/${sha}`]);
  assert.equal(url, 'data:image/jpeg;base64,' + Buffer.from(plain).toString('base64'));
  assert.equal(await K.sealedPicture(picture.replace(/k=.*/, 'k=' + '0'.repeat(64)), 'https://home.example', { fetch }), null);
  assert.equal(K.noName(pk('a').slice(0, 58) + 'abc123'), 'No name shared abc123');
});
