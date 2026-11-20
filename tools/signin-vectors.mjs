#!/usr/bin/env node
// Writes signin/vectors/pointer.json: shared cases for the login-page pointer (SPEC 11.1) and name-first sign-in,
// gathered from the tests of the four readers (Marble Web, Keykin Login's pointer.js, Tube, Marble Android).
//
//   node tools/signin-vectors.mjs
//
// The events are signed here with two fixed test keys, so the file is plain data any implementation can read.
// `expect` is the rule. `differs` names an implementation that answers otherwise today, with what it gives
// (test/signin-vectors.test.ts holds signin/ and login/static/pointer.js to both).
import { writeFileSync } from 'node:fs';
import { schnorr, sha256 } from '../signin/vendor/noble.js';
import { toHex, fromHex, npub } from '../signin/ids.js';

const SK = '11'.repeat(32), OTHER = '22'.repeat(32);
const pkOf = (sk) => toHex(schnorr.getPublicKey(fromHex(sk)));
const ME = pkOf(SK), THEM = pkOf(OTHER);
const idOf = (t) => toHex(sha256(new TextEncoder().encode(JSON.stringify([0, t.pubkey, t.created_at, t.kind, t.tags, t.content]))));
function signed(kind, tags, at, sk = SK) {
  const t = { kind, pubkey: pkOf(sk), created_at: at, tags, content: '' };
  const id = idOf(t);
  return { id, ...t, sig: toHex(schnorr.sign(fromHex(id), fromHex(sk), new Uint8Array(32))) };
}
const T = 'https://account.syb.lol/#connect=<nostrconnect>';
const p46 = (tpl, at = 100, sk = SK, extra = []) => signed(10046, tpl === null ? [...extra] : [['nostrconnect_url', tpl], ...extra], at, sk);
const p78 = (url, at = 100, sk = SK, d = 'keykin/login') => signed(30078, [['d', d], ...(url === null ? [] : [['url', url]])], at, sk);
const found = (origin, template = `${origin}/#connect=<nostrconnect>`, kind = 10046) => ({ state: 'found', origin, template, kind });
const old = (origin) => found(origin, `${origin}/#connect=<nostrconnect>`, 30078);
const REMOVED = { state: 'removed' }, NONE = { state: 'none' };
const KL = 'keykin-login'; // login/static/pointer.js, read as the account page calls it (author checked, no signature check)

// ── Templates (nostrconnect_url): the origin a reader shows and sends people to, or null ──
const templates = [
  { template: T, origin: 'https://account.syb.lol', from: 'all' },
  { template: 'https://login.example.org/signin?code=<nostrconnect>', origin: 'https://login.example.org', from: 'marble-web' },
  { template: 'https://a.example:8443/#connect=<nostrconnect>', origin: 'https://a.example:8443', from: 'marble-web' },
  { template: 'https://signer.example/connect?uri=<nostrconnect>', origin: 'https://signer.example', from: KL },
  { template: 'https://signer.example.com:8443/<nostrconnect>', origin: 'https://signer.example.com:8443', from: 'tube' },
  { template: 'https://Account.syb.lol:443/x#connect=<nostrconnect>', origin: 'https://account.syb.lol', from: 'marble-android' },
  { template: 'http://127.0.0.1:7470/#connect=<nostrconnect>', here: 'localhost', origin: 'http://127.0.0.1:7470', from: KL, why: 'a local page, for a reader running locally' },
  { template: 'http://localhost:7070/#connect=<nostrconnect>', here: 'localhost', origin: 'http://localhost:7070', from: 'tube' },
  ...[
    ['http://account.syb.lol/#connect=<nostrconnect>', 'not https'],
    ['http://localhost:8080/#connect=<nostrconnect>', 'http localhost when the reader is not on localhost'],
    ['http://127.0.0.1:7470/#connect=<nostrconnect>', 'http 127.0.0.1 when the reader is not local'],
    ['https://me:pw@account.syb.lol/#connect=<nostrconnect>', 'user and password'],
    ['https://me@account.syb.lol/#connect=<nostrconnect>', 'user'],
    ['https://account.syb.lol/#connect=', 'no placeholder'],
    ['https://account.syb.lol/#connect=<nostrconnect>&x=1', 'placeholder not at the end'],
    ['https://account.syb.lol/<nostrconnect>#connect=<nostrconnect>', 'two placeholders'],
    ['https://account.syb.lol/#a=<nostrconnect>&b=<nostrconnect>', 'two placeholders'],
    ['https://account.syb.lol/<nostrconnect>/x', 'placeholder not at the end'],
    ['javascript:alert(1)//<nostrconnect>', 'not a web address'],
    ['<nostrconnect>', 'only the placeholder'],
    ['/#connect=<nostrconnect>', 'no origin'],
    ['', 'empty'],
    [42, 'not a string'],
    [null, 'missing'],
  ].map(([template, why]) => ({ template, origin: null, why })),
  { template: 'https://<nostrconnect>', origin: null, from: 'tube', why: 'the code would go into the host',
    differs: { signin: 'https://x', [KL]: 'https://x' } },
  { template: 'https://account.syb.lol<nostrconnect>', origin: null, from: 'tube', why: 'the code would go into the host: the origin shown is not where the link goes',
    differs: { signin: 'https://account.syb.lolx', [KL]: 'https://account.syb.lolx' } },
  { template: 'https://account.syb.lol.<nostrconnect>', origin: null, from: 'tube', why: 'the code would go into the host',
    differs: { signin: 'https://account.syb.lol.x', [KL]: 'https://account.syb.lol.x' } },
  { template: 'https://account.syb.lol/ #connect=<nostrconnect>', origin: null, from: 'tube', why: 'white space', differs: { [KL]: 'https://account.syb.lol' } },
  { template: ' https://account.syb.lol/#connect=<nostrconnect>', origin: null, why: 'white space before it', differs: { [KL]: 'https://account.syb.lol' } },
  { template: 'https://account.syb.lol/' + 'a'.repeat(500) + '<nostrconnect>', origin: null, from: 'tube', why: 'longer than 500', differs: { [KL]: 'https://account.syb.lol' } },
];

// ── The old kind's url: an https origin and nothing else ──
const origins = [
  { url: 'https://account.syb.lol', origin: 'https://account.syb.lol' },
  { url: 'https://account.syb.lol/', origin: 'https://account.syb.lol' },
  { url: 'https://account.syb.lol:8443', origin: 'https://account.syb.lol:8443' },
  { url: 'http://localhost:7070', here: 'localhost', origin: 'http://localhost:7070' },
  { url: 'http://127.0.0.1:7070', here: 'localhost', origin: 'http://127.0.0.1:7070' },
  ...['http://account.syb.lol', 'ftp://account.syb.lol', 'javascript:alert(1)', 'https://account.syb.lol/login', 'https://account.syb.lol/?x=1',
    'https://account.syb.lol/#x', 'https://me:pw@account.syb.lol', 'account.syb.lol', '', 'http://localhost:7070', 42, null]
    .map((url) => ({ url, origin: null })),
  { url: 'http://example.com', here: 'localhost', origin: null },
  { url: 'https://ACCOUNT.syb.lol', origin: null, why: 'not written as its origin', differs: { [KL]: 'https://account.syb.lol' } },
  { url: 'https://account.syb.lol:443', origin: null, why: 'not written as its origin', differs: { [KL]: 'https://account.syb.lol' } },
  { url: ' https://account.syb.lol', origin: null, why: 'white space before it', differs: { [KL]: 'https://account.syb.lol' } },
  { url: 'https://' + 'a'.repeat(200) + '.com', origin: null, why: 'longer than 200', differs: { [KL]: 'https://' + 'a'.repeat(200) + '.com' } },
];

// ── Links: the template with its placeholder replaced by encodeURIComponent(code) ──
const code = 'nostrconnect://' + 'a'.repeat(64) + '?relay=wss%3A%2F%2Fsyb.lol&secret=s1&name=Marble&url=https%3A%2F%2Fmarble.syb.lol';
const odd = 'nostrconnect://x?a=$&b=<nostrconnect>';
const links = [
  { template: T, code, link: 'https://account.syb.lol/#connect=' + encodeURIComponent(code) },
  { template: 'https://signer.example.com/c?uri=<nostrconnect>', code, link: 'https://signer.example.com/c?uri=' + encodeURIComponent(code) },
  { template: 'https://a.example/#c=<nostrconnect>', code: odd, link: 'https://a.example/#c=' + encodeURIComponent(odd), why: '$ patterns and a placeholder in the code are put in as they are, encoded' },
];
// The old kind's origin as a template
const legacy = [
  { origin: 'https://old.example', template: 'https://old.example/#connect=<nostrconnect>' },
  { origin: 'https://old.example/', template: 'https://old.example/#connect=<nostrconnect>', differs: { [KL]: 'https://old.example//#connect=<nostrconnect>' }, why: 'readers only ever pass URL.origin, so harmless' },
];

// ── What the pointers found say ──
const tie = [p46('https://a.example/#connect=<nostrconnect>', 300), p46('https://b.example/#connect=<nostrconnect>', 300)];
const [lo, hi] = [...tie].sort((a, b) => (a.id < b.id ? -1 : 1));
const loOrigin = new URL(lo.tags[0][1].replace('<nostrconnect>', '')).origin, hiOrigin = new URL(hi.tags[0][1].replace('<nostrconnect>', '')).origin;
const forged46 = { ...p46(T, 100) }; forged46.tags = [['nostrconnect_url', 'https://evil.example/#connect=<nostrconnect>']];
const good78 = p78('https://account.syb.lol', 100);
const badSig = { ...good78, sig: good78.sig.slice(0, -2) + (good78.sig.endsWith('00') ? '11' : '00') };
const swapped = { ...good78, tags: [['d', 'keykin/login'], ['url', 'https://evil.example']] };
const forgedNewer = { ...p78('https://evil.example', 200), sig: good78.sig };
const pointers = [
  { why: 'nothing found', events: [], expect: NONE },
  { why: 'a good 10046 (with a relays tag)', events: [p46(T, 100, SK, [['relays', 'wss://syb.lol']])], expect: found('https://account.syb.lol') },
  { why: 'the newest 10046 wins', events: [p46('https://old.example/#connect=<nostrconnect>', 100), p46(T, 200)], expect: found('https://account.syb.lol') },
  { why: 'a 10046 wins over a newer 30078', events: [p46(T, 100), p78('https://old.example', 500)], expect: found('https://account.syb.lol') },
  { why: 'no 10046 at all: the 30078, as <url>/#connect=<nostrconnect>', events: [p78('https://old.example', 100)], expect: old('https://old.example') },
  { why: 'the newest 10046 has no nostrconnect_url: removed, no falling back', events: [p46(null, 300, SK, [['relays', 'wss://syb.lol']]), p78('https://old.example', 100)], expect: REMOVED },
  { why: 'removed after an older good one, and a newer 30078 does not bring it back', events: [p46(T, 100), p46(null, 300), p78('https://account.syb.lol', 900)], expect: REMOVED },
  { why: 'the newest 10046 has a bad template: removed (keykin-login calls it bad), no falling back', events: [p46('http://evil.example/#connect=<nostrconnect>', 300), p78('https://old.example', 100)], expect: REMOVED },
  { why: 'an empty template', events: [p46('', 300)], expect: REMOVED },
  { why: 'a 30078 with no url: removed', events: [p78(null, 100)], expect: REMOVED },
  { why: 'the newest 30078 removed it', events: [p78('https://account.syb.lol', 100), p78(null, 500)], expect: REMOVED },
  { why: 'the newest 30078 removed it, given in the other order', events: [p78(null, 500), p78('https://account.syb.lol', 100)], expect: REMOVED },
  { why: 'a newer address wins over a removal', events: [p78(null, 500), p78('https://new.syb.lol', 1000)], expect: old('https://new.syb.lol') },
  { why: 'a 30078 naming http, or a path: removed', events: [p78('http://account.syb.lol', 100)], expect: REMOVED },
  { why: 'a 30078 naming a path: removed', events: [p78('https://account.syb.lol/path', 100)], expect: REMOVED },
  { why: 'a 30078 not written as its origin: removed', events: [p78('https://ACCOUNT.syb.lol', 100)], expect: REMOVED, differs: { [KL]: old('https://account.syb.lol') } },
  { why: 'another app\'s 30078 (another d)', events: [p78('https://x.example', 100, SK, 'other')], expect: NONE },
  { why: 'a kind 1 with the same tags', events: [signed(1, [['d', 'keykin/login'], ['url', 'https://evil.example']], 100)], expect: NONE },
  { why: 'someone else\'s 10046 and 30078', events: [p46(T, 100, OTHER), p78('https://evil.example', 100, OTHER)], expect: NONE },
  { why: 'junk', events: [null, 1, 'x', {}], expect: NONE },
  { why: 'a changed 10046 (the id no longer matches)', events: [forged46], expect: NONE,
    differs: { [KL]: found('https://evil.example') } },
  { why: 'a changed 10046 is no 10046: the 30078 is read', events: [forged46, p78('https://old.example', 50)], expect: old('https://old.example'),
    differs: { [KL]: found('https://evil.example') } },
  { why: 'a bad signature', events: [badSig], expect: NONE, differs: { [KL]: old('https://account.syb.lol') } },
  { why: 'the same id with another address', events: [swapped], expect: NONE, differs: { [KL]: old('https://evil.example') } },
  { why: 'a forged newer one does not hide the real one', events: [good78, forgedNewer], expect: old('https://account.syb.lol'), differs: { [KL]: old('https://evil.example') } },
  { why: 'a local template, for a reader on localhost', here: 'localhost', events: [p46('http://127.0.0.1:7470/#connect=<nostrconnect>')], expect: found('http://127.0.0.1:7470', 'http://127.0.0.1:7470/#connect=<nostrconnect>') },
  { why: 'a local template, for a reader that is not local', events: [p46('http://127.0.0.1:7470/#connect=<nostrconnect>')], expect: REMOVED },
  { why: 'a template with white space', events: [p46('https://account.syb.lol/ #connect=<nostrconnect>')], expect: REMOVED, differs: { [KL]: found('https://account.syb.lol', 'https://account.syb.lol/ #connect=<nostrconnect>') } },
  { why: 'two 10046 at the same second: the lower id wins (NIP-01), given higher id first', events: [hi, lo], expect: found(loOrigin, lo.tags[0][1]),
    differs: { signin: found(hiOrigin, hi.tags[0][1]), [KL]: found(hiOrigin, hi.tags[0][1]) } },
  { why: 'a 30078 whose first d is another app\'s: its address is that one (NIP-01), so it is not the pointer', events: [signed(30078, [['d', 'other'], ['d', 'keykin/login'], ['url', 'https://x.example']], 100)], expect: NONE,
    differs: { signin: old('https://x.example') } },
];

// ── Typed names: { pubkey } for a key, { name, domain } to look up by NIP-05 (a bare domain is _), or null ──
const KEY = '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d';
const n = npub(KEY);
const words = (bytes) => { const out = []; let acc = 0, bits = 0; for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; out.push((acc >> bits) & 31); } } if (bits) out.push((acc << (5 - bits)) & 31); return out; };
const CH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l', GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const poly = (v) => { let c = 1; for (const x of v) { const t = c >> 25; c = ((c & 0x1ffffff) << 5) ^ x; for (let i = 0; i < 5; i++) if ((t >> i) & 1) c ^= GEN[i]; } return c; };
const bech = (hrp, bytes) => { const w = words(bytes), ex = [...hrp].map((c) => c.charCodeAt(0) >> 5).concat(0, [...hrp].map((c) => c.charCodeAt(0) & 31)); const m = poly(ex.concat(w, [0, 0, 0, 0, 0, 0])) ^ 1; return hrp + '1' + w.concat([0, 1, 2, 3, 4, 5].map((i) => (m >> (5 * (5 - i))) & 31)).map((x) => CH[x]).join(''); };
const relayFirst = bech('nprofile', [1, 23, ...new TextEncoder().encode('wss://relay.example.com'), 0, 32, ...fromHex(KEY)]);
const flipped = n.slice(0, -1) + (n.endsWith('q') ? 'p' : 'q');
const typed = [
  { typed: 'Aaron@Herbstmeister.com', expect: { name: 'aaron', domain: 'herbstmeister.com' } },
  { typed: '  a.b_c-d@sub.example.org ', expect: { name: 'a.b_c-d', domain: 'sub.example.org' } },
  { typed: 'herbstmeister.com', expect: { name: '_', domain: 'herbstmeister.com' } },
  { typed: '_@herbstmeister.com', expect: { name: '_', domain: 'herbstmeister.com' } },
  { typed: n, expect: { pubkey: KEY } },
  { typed: 'nostr:' + n, expect: { pubkey: KEY } },
  { typed: relayFirst, expect: { pubkey: KEY }, why: 'an nprofile with its relay before its key' },
  { typed: KEY, expect: { pubkey: KEY } },
  { typed: KEY.toUpperCase(), expect: { pubkey: KEY } },
  { typed: n.toUpperCase(), expect: { pubkey: KEY }, why: 'bech32 may be all upper case', differs: { signin: null } },
  { typed: 'NOSTR:' + n, expect: { pubkey: KEY }, differs: { signin: null } },
  { typed: n.slice(0, 10) + n.slice(10).toUpperCase(), expect: null, why: 'mixed case is not bech32', differs: { signin: { pubkey: KEY } } },
  { typed: flipped, expect: null, why: 'a bad checksum' },
  { typed: KEY.slice(1), expect: null, why: '63 hex' },
  { typed: bech('npub', new Uint8Array(31)), expect: null, why: '31 bytes' },
  { typed: bech('nsec', new Uint8Array(32).fill(1)), expect: null, why: 'never a secret key' },
  { typed: 'aaron+tag@example.com', expect: null, why: 'NIP-05 names are a-z0-9-_.', differs: { signin: { name: 'aaron+tag', domain: 'example.com' } } },
  { typed: 'a'.repeat(401) + '.com', expect: null, why: 'longer than 400', differs: { signin: { name: '_', domain: 'a'.repeat(401) + '.com' } } },
  ...['', '   ', 'aaron', 'aaron@', '@herbstmeister.com', 'a b@c.com', 'https://herbstmeister.com', 'x@y', null].map((t) => ({ typed: t, expect: null })),
];

// ── NIP-05 answers: what https://<domain>/.well-known/nostr.json?name=<name> said, and the key it gives ──
const nip05 = [
  { name: 'aaron', domain: 'herbstmeister.com', status: 200, body: { names: { aaron: KEY } }, expect: KEY },
  { name: 'aaron', domain: 'x.com', status: 200, body: { names: { Aaron: KEY } }, expect: KEY, why: 'a name in another case still matches' },
  { name: 'aaron', domain: 'x.com', status: 200, body: { names: { Aaron: KEY.toUpperCase() } }, expect: KEY, why: 'an upper case key, lowercased', differs: { signin: null } },
  { name: 'aaron', domain: 'x.com', status: 200, body: { names: {} }, expect: null },
  { name: 'aaron', domain: 'x.com', status: 200, body: { names: { aaron: 'npub1xyz' } }, expect: null },
  { name: 'aaron', domain: 'x.com', status: 404, body: {}, expect: null },
  { name: 'aaron', domain: 'x.com', status: 500, body: {}, expect: null },
  { name: 'aaron', domain: 'x.com', status: 200, body: '<html>', expect: null },
  { name: '__proto__', domain: 'x.com', status: 200, body: { names: {} }, expect: null },
];

const out = {
  about: 'Shared cases for the login-page pointer (Keykin SPEC 11.1) and name-first sign-in. Made by tools/signin-vectors.mjs; run by test/signin-vectors.test.ts. `expect` is the rule; `differs` names an implementation that answers otherwise today, and what it gives. `here` is the reader\'s own hostname (default marble.example). Pointer states: found (origin, template, kind), removed (keykin-login says bad for a bad one), none.',
  account: ME, other: THEM, here: 'marble.example',
  templates, origins, links, legacy, pointers, typed, nip05,
};
writeFileSync(new URL('../signin/vectors/pointer.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
console.log(`signin/vectors/pointer.json: ${templates.length} templates, ${origins.length} origins, ${links.length + legacy.length} links, ${pointers.length} pointer cases, ${typed.length} typed, ${nip05.length} NIP-05`);
