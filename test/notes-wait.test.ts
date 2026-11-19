// notes_wait (SPEC 11.6): a device's request the box holds until the account page leaves a note, so the
// phone hears of it at once instead of on its next 30-second check.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startBox } from '../box/server.ts';
import { startLogin } from '../login/server.ts';
import { HOLD, WAITS_PER_ACCOUNT } from '../box/box.ts';
import { newMemberKey, softwareChip, seal } from '../src/member.ts';
import * as D from '../src/device.ts';

const H = { connection: 'close' };
const device = (name: string): D.Me => ({ ...newMemberKey(), name, ...softwareChip() });
const now = () => Math.floor(Date.now() / 1000);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const timed = async <T>(p: Promise<T>) => { const t = Date.now(); const v = await p; return { v, ms: Date.now() - t }; };

async function world() {
  const b = await startBox({ dir: mkdtempSync(join(tmpdir(), 'kk-wait-')), port: 0, sidePort: 0, log: () => {} });
  const addr = `http://127.0.0.1:${b.port}`;
  const send = (signal?: AbortSignal): D.Send => async (r) => (await fetch(`${addr}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: H, signal })).json();
  const phone = device('Phone');
  const held = await D.createWithBox(phone, D.readQr(b.qr()!), send());
  await D.passwordSet(phone, held, 'aaron', 'pw pw pw pw', send());
  const { salt } = b.page.call({ call: 'pw_salt', username: 'aaron' }, now());
  const session = b.page.call({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw pw', salt) }, now()).session;
  const put = (kind = 'bunker') => b.page.call({ call: 'note_put', session, kind, text: '' }, now()).note as string;
  return { b, addr, send, phone, held, session, put };
}

test('notes_wait: answers at once when a note waits, holds until one comes, and answers empty when the wait runs out', async () => {
  const w = await world();
  try {
    const { phone, held } = w;
    // Nothing waiting and a short wait: the empty answer, after the wait.
    const empty = await timed(D.notesWait(phone, held, w.send(), 1));
    assert.deepEqual(empty.v, []);
    assert.ok(empty.ms >= 980 && empty.ms < 2000, `held ${empty.ms} ms`);
    assert.equal(w.b.box.waitsFor(held.npub), 0);

    // A note already waiting: at once, in the same shape as `notes`.
    const id = w.put();
    const now1 = await timed(D.notesWait(phone, held, w.send(), 5));
    assert.ok(now1.ms < 500, `took ${now1.ms} ms`);
    assert.deepEqual(now1.v, await D.notes(phone, held, w.send()));
    assert.deepEqual(now1.v.map((n) => [n.id, n.kind]), [[id, 'bunker']]);

    // A note this device already has (one waiting for a Yes or No, say) does not answer at once; a new one does.
    const held1 = D.notesWait(phone, held, w.send(), 5, [id]);
    await sleep(300);
    assert.equal(w.b.box.waitsFor(held.npub), 1);
    const id2 = w.put('cycle');
    const woke = await timed(held1);
    assert.ok(woke.ms < 1000, `woke after ${woke.ms} ms`);
    assert.deepEqual(woke.v.map((n) => n.id), [id, id2]);
    assert.equal(woke.v[1].tap, true);
    assert.equal(w.b.box.waitsFor(held.npub), 0);

    // Answered notes are gone from the list; with only seen ones left it holds, then answers with them.
    await D.noteDone(phone, held, id, 'bunker://x', w.send());
    const left = await timed(D.notesWait(phone, held, w.send(), 1, [id2]));
    assert.ok(left.ms >= 980, `held ${left.ms} ms`);
    assert.deepEqual(left.v.map((n) => n.id), [id2]);

    // The old-style call still works.
    assert.deepEqual((await D.notes(phone, held, w.send())).map((n) => n.id), [id2]);
  } finally { await w.b.close(); }
});

test('notes_wait: a note put while it waits answers within a second; the wait is capped and checked', async () => {
  const w = await world();
  try {
    const { phone, held } = w;
    const start = Date.now();
    const waiting = D.notesWait(phone, held, w.send(), 10);
    await sleep(400);
    const id = w.put();
    const got = await waiting;
    const after = Date.now() - start - 400;
    assert.ok(after < 1000, `answered ${after} ms after the note`);
    assert.deepEqual(got.map((n) => n.id), [id]);

    // The box holds a request 25 seconds at most, whatever it asks for; a bad wait is refused.
    const req = (body: any) => seal({ account: held.npub, ...body }, phone.sk, now());
    assert.equal(w.b.box.handle(await req({ op: 'notes_wait', wait: 9999, seen: [id] }), now())[HOLD].seconds, 25);
    assert.equal(w.b.box.handle(await req({ op: 'notes_wait', wait: 3, seen: [id] }), now())[HOLD].seconds, 3);
    assert.equal(w.b.box.handle(await req({ op: 'notes_wait', wait: 3 }), now())[HOLD], undefined);          // a note waits: at once
    for (const wait of [-1, '5', null, undefined]) assert.deepEqual(w.b.box.handle(await req({ op: 'notes_wait', wait }), now()), { error: 'bad_request' }, String(wait));
    assert.deepEqual(w.b.box.handle(await req({ op: 'notes_wait', wait: 1, seen: 'x' }), now()), { error: 'bad_request' });
    // What the device receives has no trace of the hold.
    assert.deepEqual(JSON.parse(JSON.stringify(w.b.box.handle(await req({ op: 'notes_wait', wait: 3, seen: [id] }), now()))), { ok: true, notes: got });
  } finally { await w.b.close(); }
});

test('notes_wait: a few held at once per account, a device that goes away is let go, a blocked one hears nothing', async () => {
  const w = await world();
  try {
    const { phone, held } = w;
    // One more than the limit: the oldest answers early, empty, and the rest stay held.
    const all = Array.from({ length: WAITS_PER_ACCOUNT + 1 }, () => D.notesWait(phone, held, w.send(), 10));
    const first = await timed(all[0]);
    assert.deepEqual(first.v, []);
    assert.ok(first.ms < 2000);
    await sleep(100);
    assert.equal(w.b.box.waitsFor(held.npub), WAITS_PER_ACCOUNT);
    w.put();
    for (const n of await Promise.all(all.slice(1))) assert.equal(n.length, 1);
    assert.equal(w.b.box.waitsFor(held.npub), 0);
    await D.noteDone(phone, held, (await D.notes(phone, held, w.send()))[0].id, 'bunker://x', w.send());

    // The device hangs up: its wait ends at the box too.
    const ac = new AbortController();
    const gone = D.notesWait(phone, held, w.send(ac.signal), 10).catch(() => 'aborted');
    await sleep(200);
    assert.equal(w.b.box.waitsFor(held.npub), 1);
    ac.abort();
    assert.equal(await gone, 'aborted');
    await sleep(200);
    assert.equal(w.b.box.waitsFor(held.npub), 0);

    // Blocked while waiting: the note is not handed over.
    const laptop = device('Laptop');
    await D.addMember(phone, held, { key: laptop.key, name: 'Laptop', kind: 'device', chip: laptop.chip }, w.send());
    const lh = await D.join(laptop, held.boxKey, held.npub, w.send());
    const blocked = D.notesWait(laptop, lh, w.send(), 10);
    await sleep(200);
    await D.block(phone, laptop.key, w.send(), now(), held.npub);
    w.put();
    await assert.rejects(blocked, /blocked/);
  } finally { await w.b.close(); }
});

test('notes_wait through Keykin Login: held past the page\'s 20 seconds, woken by a note from the account page', { timeout: 60_000 }, async () => {
  const b = await startBox({ dir: mkdtempSync(join(tmpdir(), 'kk-wait-')), port: 0, sidePort: 0, behindLogin: true, url: 'http://to-be-set', log: () => {} });
  const login = await startLogin({ box: `http://127.0.0.1:${b.sidePort}`, port: 0, log: () => {} });
  const base = `http://127.0.0.1:${login.port}`;
  try {
    const send = (signal?: AbortSignal): D.Send => async (r) => (await fetch(`${base}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: H, signal })).json();
    const api = async (body: object, cookie = '') => {
      const r = await fetch(`${base}/api`, { method: 'POST', body: JSON.stringify(body), headers: { ...H, 'content-type': 'application/json', 'x-keykin': '1', cookie } });
      return { body: await r.json() as any, cookies: r.headers.getSetCookie() };
    };
    const phone = device('Phone');
    const held = await D.createWithBox(phone, D.readQr(b.qr()!), send());
    await D.passwordSet(phone, held, 'aaron', 'pw pw pw pw', send());
    const { salt } = (await api({ call: 'pw_salt', username: 'aaron' })).body;
    const cookie = (await api({ call: 'pw_login', username: 'aaron', verifier: await D.passwordVerifier('pw pw pw pw', salt) })).cookies[0].split(';')[0];

    // The account page asks while the phone waits: the phone has it within a second.
    const waiting = D.notesWait(phone, held, send(), 10);
    await sleep(400);
    const put = await api({ call: 'note_put', kind: 'bunker', text: '' }, cookie);
    const t = Date.now();
    const got = await waiting;
    assert.ok(Date.now() - t < 1000);
    assert.deepEqual(got.map((n) => n.id), [put.body.note]);
    // The phone answers, and the page reads the link.
    await D.noteDone(phone, held, put.body.note, 'bunker://abc', send());
    assert.equal((await api({ call: 'note_get', note: put.body.note }, cookie)).body.result, 'bunker://abc');

    // A device that hangs up on Keykin Login is let go at the box too.
    const ac = new AbortController();
    const gone = D.notesWait(phone, held, send(ac.signal), 10).catch(() => 'aborted');
    await sleep(300);
    assert.equal(b.box.waitsFor(held.npub), 1);
    ac.abort(); await gone; await sleep(300);
    assert.equal(b.box.waitsFor(held.npub), 0);

    // Longer than the 20 seconds the page's calls get: still an answer, not no_box.
    const long = await timed(D.notesWait(phone, held, send(), 21));
    assert.deepEqual(long.v, []);
    assert.ok(long.ms >= 20_900, `held ${long.ms} ms`);
    // The old-style call works through the door too.
    assert.deepEqual(await D.notes(phone, held, send()), []);
  } finally { await login.close(); await b.close(); }
});
