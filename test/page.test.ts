// The box's admin page, over real HTTP.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startBox } from '../box/server.ts';
import { newMemberKey, softwareChip } from '../src/member.ts';
import * as D from '../src/device.ts';

const H = { connection: 'close' };
const dir = () => mkdtempSync(join(tmpdir(), 'keykin-page-'));
const device = (name: string): D.Me => ({ ...newMemberKey(), name, ...softwareChip() });
const text = (page: string, id: string) => new RegExp(`id="${id}"[^>]*>([^<]+)<`).exec(page)![1].replaceAll('&quot;', '"').replaceAll('&#39;', "'");

function client(base: string, cookie = '') {
  const get = (path: string, c = cookie) => fetch(base + path, { headers: { ...H, cookie: c }, redirect: 'manual' });
  const post = (path: string, form: Record<string, string>, c = cookie) => fetch(base + path, { method: 'POST', body: new URLSearchParams(form), headers: { ...H, cookie: c }, redirect: 'manual' });
  const send: D.Send = async (r) => (await fetch(`${base}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: H })).json();
  return { get, post, send };
}

test('the admin page: owner login, first setup, a second account, block, unblock, remove', async () => {
  const b = await startBox({ dir: dir(), port: 0, log: () => {} });
  const base = `http://127.0.0.1:${b.port}`;
  const anon = client(base);
  try {
    assert.ok(b.ownerSecret);
    // Not logged in: the login form, and nothing else.
    let page = await (await anon.get('/')).text();
    assert.match(page, /Owner secret/); assert.doesNotMatch(page, /<svg/);
    assert.equal((await anon.get('/admin/state')).status, 401);
    const bad = await anon.post('/login', { secret: 'nope' });
    assert.equal(bad.headers.get('location'), '/?e=1'); assert.equal(bad.headers.get('set-cookie'), null);
    const ok = await anon.post('/login', { secret: b.ownerSecret! });
    assert.match(ok.headers.get('set-cookie')!, /HttpOnly; SameSite=Strict/);
    const admin = client(base, ok.headers.get('set-cookie')!.split(';')[0]);

    // An empty box goes straight to the first setup code.
    page = await (await admin.get('/')).text();
    assert.match(page, /Scan to start/); assert.match(page, /<svg/);
    assert.deepEqual(await (await admin.get('/admin/state')).json(), { accounts: 0 });
    const phone = device('Phone <b>');
    const held = await D.createWithBox(phone, D.readQr(text(page, 'qrtext')), anon.send);
    const laptop = device('Laptop');
    await D.addMember(phone, held, { key: laptop.key, name: 'Laptop', kind: 'device', chip: laptop.chip }, anon.send);
    const lh = await D.join(laptop, held.boxKey, held.npub, anon.send);
    const ev = { pubkey: held.npub, created_at: 1, kind: 1, tags: [], content: 'x' };

    // Now it lists the account and its devices, with names escaped.
    page = await (await admin.get('/')).text();
    assert.match(page, /Phone &lt;b&gt;/); assert.doesNotMatch(page, /Phone <b>/); assert.match(page, /npub1/); assert.match(page, /this box/);
    const csrf = /name="csrf" value="([0-9a-f]+)"/.exec(page)![1];

    // Every button needs the session and the page's token.
    assert.equal((await anon.post('/admin/block', { key: phone.key, csrf })).headers.get('location'), '/');
    assert.equal((await admin.post('/admin/block', { key: phone.key, csrf: 'wrong' })).status, 403);
    await D.signEvent(phone, held, ev, anon.send);
    assert.match(decodeURIComponent((await admin.post('/admin/block', { key: phone.key, account: held.npub, csrf })).headers.get('location')!), /is blocked/);
    await assert.rejects(D.signEvent(phone, held, ev, anon.send), /blocked/);
    assert.match(await (await admin.get('/')).text(), /class="tag bad"/);
    await admin.post('/admin/unblock', { key: phone.key, account: held.npub, csrf });      // needs no device: the admin's own power
    await D.signEvent(phone, held, ev, anon.send);

    // A second account, from a code the admin makes.
    const codePage = await (await admin.post('/admin/code', { csrf })).text();
    assert.match(codePage, /Scan to make a new account/);
    const other = device('Other phone');
    const oh = await D.createWithBox(other, D.readQr(text(codePage, 'qrtext')), anon.send);
    assert.deepEqual(await (await admin.get('/admin/state')).json(), { accounts: 2 });
    await D.signEvent(other, oh, { ...ev, pubkey: oh.npub }, anon.send);
    await D.signEvent(laptop, lh, ev, anon.send);

    // Removing an account needs the tick, and leaves the other alone.
    await admin.post('/admin/remove', { account: oh.npub, csrf });
    assert.deepEqual(await (await admin.get('/admin/state')).json(), { accounts: 2 });
    await admin.post('/admin/remove', { account: oh.npub, csrf, sure: '1' });
    await assert.rejects(D.signEvent(other, oh, { ...ev, pubkey: oh.npub }, anon.send), /unknown_account/);
    await D.signEvent(laptop, lh, ev, anon.send);

    // Logging out ends the session, and too many wrong tries are slowed down.
    await admin.post('/logout', { csrf });
    assert.match(await (await admin.get('/')).text(), /Owner secret/);
    for (let k = 0; k < 5; k++) await anon.post('/login', { secret: 'x' + k });
    assert.equal((await anon.post('/login', { secret: b.ownerSecret! })).headers.get('location'), '/?e=wait');
  } finally { await b.close(); }
});

test('the admin page: someone asks for an account, the admin approves', async () => {
  const b = await startBox({ dir: dir(), port: 0, behindLogin: true, log: () => {} });
  const base = `http://127.0.0.1:${b.port}`;
  const c = client(base);
  try {
    await D.createWithBox(device('First'), D.readQr(b.qr()!), c.send);
    const carol = device('Carol phone');
    const id = await D.askBox(carol, 'make', "Aaron's sister <3", c.send);
    let page = await (await c.get('/')).text();
    assert.match(page, /Waiting for your answer/); assert.match(page, /Carol phone/); assert.match(page, /Aaron&#39;s sister &lt;3/); assert.match(page, /new account/);
    assert.match(page, new RegExp(`device ${carol.key.slice(0, 8)}`));
    const csrf = /name="csrf" value="([0-9a-f]+)"/.exec(page)![1];
    assert.match(decodeURIComponent((await c.post('/admin/approve', { id, csrf })).headers.get('location')!), /Carol phone may make its account now/);
    assert.equal(await D.asked(carol, id, c.send), 'approved');
    const held = await D.createWithBox(carol, { key: b.box.state.key, code: id }, c.send);
    page = await (await c.get('/')).text();
    assert.match(page, /Nobody is asking for an account/);
    assert.match(page, /Carol phone/); assert.equal(b.box.accounts().length, 2); assert.ok(held.npub);
    // A refusal.
    const dave = device('Dave');
    const id2 = await D.askBox(dave, 'make', '', c.send);
    await c.post('/admin/refuse', { id: id2, csrf });
    assert.equal(await D.asked(dave, id2, c.send), 'refused');
  } finally { await b.close(); }
});

test('behind another login, the admin page asks for nothing and makes no owner secret', async () => {
  const d = dir();
  const b = await startBox({ dir: d, port: 0, behindLogin: true, url: 'http://box.example:8711', log: () => {} });
  const c = client(`http://127.0.0.1:${b.port}`);
  try {
    assert.equal(b.ownerSecret, null); assert.equal(b.box.state.owner, undefined);
    assert.equal(existsSync(join(d, 'owner-secret.txt')), false);
    const page = await (await c.get('/')).text();
    assert.match(page, /Scan to start/); assert.doesNotMatch(page, /Log out/); assert.doesNotMatch(page, /Owner secret/);
    assert.equal(D.readQr(text(page, 'qrtext')).addr, 'http://box.example:8711');     // the outside address, not the one the browser used
  } finally { await b.close(); }
});

test('the side door answers devices and the account page, and has no admin page', async () => {
  const b = await startBox({ dir: dir(), port: 0, sidePort: 0, behindLogin: true, log: () => {} });
  const side = `http://127.0.0.1:${b.sidePort}`;
  try {
    const send: D.Send = async (r) => (await fetch(`${side}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: H })).json();
    const held = await D.createWithBox(device('Phone'), D.readQr(b.qr()!), send);
    assert.ok(held.npub);
    const r = await (await fetch(`${side}/page`, { method: 'POST', body: JSON.stringify({ call: 'pw_salt', username: 'x' }), headers: H })).json();
    assert.match(r.salt, /^[0-9a-f]{32}$/);
    for (const [method, path] of [['GET', '/'], ['GET', '/admin/state'], ['POST', '/admin/code'], ['POST', '/admin/remove'], ['POST', '/login']])
      assert.equal((await fetch(side + path, { method, headers: H, body: method === 'POST' ? 'csrf=x' : undefined })).status, 404);
  } finally { await b.close(); }
});
