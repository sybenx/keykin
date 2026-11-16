import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startBox } from '../box/server.ts';
import { newMemberKey, softwareChip } from '../src/member.ts';
import * as D from '../src/device.ts';

const H = { connection: 'close' };

test('the owner page: log in, see the QR, create, block and unblock, log out', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'keykin-page-'));
  const b = await startBox({ dir, port: 0, log: () => {} });
  const base = `http://127.0.0.1:${b.port}`;
  const stop = () => new Promise((done) => { b.server.close(done); b.server.closeAllConnections(); });
  const get = (path: string, cookie = '') => fetch(base + path, { headers: { ...H, cookie }, redirect: 'manual' });
  const post = (path: string, form: Record<string, string>, cookie = '') =>
    fetch(base + path, { method: 'POST', body: new URLSearchParams(form), headers: { ...H, cookie }, redirect: 'manual' });
  try {
    assert.ok(b.ownerSecret);
    // Not logged in: the login form, and nothing else.
    let page = await (await get('/')).text();
    assert.match(page, /Log in/); assert.doesNotMatch(page, /<svg/);
    assert.equal((await get('/owner/state')).status, 401);
    // A wrong secret is refused.
    const bad = await post('/login', { secret: 'nope' });
    assert.equal(bad.headers.get('location'), '/?e=1'); assert.equal(bad.headers.get('set-cookie'), null);
    assert.match(await (await get('/?e=1')).text(), /not the owner secret/);
    // The right one gives a session cookie the page script cannot read.
    const ok = await post('/login', { secret: b.ownerSecret! });
    const setCookie = ok.headers.get('set-cookie')!;
    assert.match(setCookie, /HttpOnly; SameSite=Strict/);
    const cookie = setCookie.split(';')[0];
    // No account yet: the setup QR, pointing at the address the browser used.
    page = await (await get('/', cookie)).text();
    assert.match(page, /Scan to start/); assert.match(page, /<svg/);
    assert.deepEqual(await (await get('/owner/state', cookie)).json(), { account: false });
    const csrf = /name="csrf" value="([0-9a-f]+)"/.exec(page)![1];

    // A phone "scans" it and creates the account; a laptop joins.
    const qr = D.readQr(b.qr()!);
    const send: D.Send = async (r) => (await fetch(`${base}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: H })).json();
    const phone: D.Me = { ...newMemberKey(), name: 'Phone <b>', ...softwareChip() };
    const held = await D.createWithBox(phone, qr, send);
    const laptop: D.Me = { ...newMemberKey(), name: 'Laptop', ...softwareChip() };
    await D.addMember(phone, held, { key: laptop.key, name: 'Laptop', kind: 'device', chip: laptop.chip }, send);
    const lh = await D.join(laptop, held.boxKey, held.npub, send);
    const ev = { pubkey: held.npub, created_at: 1, kind: 1, tags: [], content: 'x' };

    // Now the page lists the devices, with names escaped.
    page = await (await get('/', cookie)).text();
    assert.match(page, /Devices/); assert.match(page, /Phone &lt;b&gt;/); assert.doesNotMatch(page, /Phone <b>/);
    assert.match(page, new RegExp(held.npub)); assert.match(page, /this box/);

    // Blocking needs the session and the page's token.
    assert.equal((await post('/owner/block', { key: phone.key, csrf })).headers.get('location'), '/');
    assert.equal((await post('/owner/block', { key: phone.key, csrf: 'wrong' }, cookie)).status, 403);
    await D.signEvent(phone, held, ev, send);
    const blocked = await post('/owner/block', { key: phone.key, csrf }, cookie);
    assert.match(decodeURIComponent(blocked.headers.get('location')!), /is blocked/);
    await assert.rejects(D.signEvent(phone, held, ev, send), /blocked/);
    assert.match(await (await get('/', cookie)).text(), /class="tag blocked"/);
    await D.signEvent(laptop, lh, ev, send);
    await post('/owner/unblock', { key: phone.key, csrf }, cookie);
    await D.signEvent(phone, held, ev, send);

    // Logging out ends the session.
    await post('/logout', { csrf }, cookie);
    assert.match(await (await get('/', cookie)).text(), /Log in/);
    // Too many wrong tries are slowed down.
    for (let k = 0; k < 5; k++) await post('/login', { secret: 'x' + k });
    assert.equal((await post('/login', { secret: b.ownerSecret! })).headers.get('location'), '/?e=wait');
  } finally { await stop(); }
});

test('the owner secret is shown only on the first start', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'keykin-page-'));
  let b = await startBox({ dir, port: 0, log: () => {} });
  const secret = b.ownerSecret!;
  await new Promise((done) => { b.server.close(done); b.server.closeAllConnections(); });
  b = await startBox({ dir, port: 0, log: () => {} });
  try {
    assert.equal(b.ownerSecret, null);
    const r = await fetch(`http://127.0.0.1:${b.port}/login`, { method: 'POST', body: new URLSearchParams({ secret }), headers: H, redirect: 'manual' });
    assert.ok(r.headers.get('set-cookie'));
  } finally { await new Promise((done) => { b.server.close(done); b.server.closeAllConnections(); }); }
});
