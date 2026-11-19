// A box with Keykin Login in front puts the login page's origin in its codes (SPEC 11.1).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startBox } from '../box/server.ts';
import { Box, loginOrigin } from '../box/box.ts';
import { newMemberKey, softwareChip } from '../src/member.ts';
import * as D from '../src/device.ts';

const dir = () => mkdtempSync(join(tmpdir(), 'keykin-login-field-'));

test('codes carry the login origin when it is set, and not otherwise', async () => {
  const b = await startBox({ dir: dir(), port: 0, login: 'https://account.example', log: () => {} });
  try {
    assert.equal(JSON.parse(b.qr()!).loginPage, 'https://account.example');
    assert.equal(JSON.parse(b.box.newSetupCode('https://account.example', 1)).loginPage, 'https://account.example');
  } finally { await b.close(); }
  const plain = await startBox({ dir: dir(), port: 0, log: () => {} });
  try { assert.equal(JSON.parse(plain.qr()!).loginPage, undefined); } finally { await plain.close(); }
});

test('a login origin with a path or plain http is refused at start', () => {
  assert.throws(() => startBox({ dir: dir(), port: 0, login: 'https://account.example/page', log: () => {} }));
  assert.throws(() => startBox({ dir: dir(), port: 0, login: 'http://account.example', log: () => {} }));
});

// The login page address as an admin setting on the box (KEYKIN_LOGIN_URL overrides it).
const H = { connection: 'close' };
const device = (name: string): D.Me => ({ ...newMemberKey(), name, ...softwareChip() });
const qrText = (page: string) => /id="qrtext"[^>]*>([^<]+)</.exec(page)![1].replaceAll('&quot;', '"');
async function admin(o: { login?: string; d?: string } = {}) {
  const b = await startBox({ dir: o.d ?? dir(), port: 0, sidePort: 0, behindLogin: true, login: o.login, log: () => {} });
  const base = `http://127.0.0.1:${b.port}`;
  const get = (path: string, h: Record<string, string> = {}) => fetch(base + path, { headers: { ...H, ...h }, redirect: 'manual' });
  const post = (path: string, form: Record<string, string>) => fetch(base + path, { method: 'POST', body: new URLSearchParams(form), headers: H, redirect: 'manual' });
  const send: D.Send = async (r) => (await fetch(`${base}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: H })).json();
  if (!b.box.accounts().length) await D.createWithBox(device('First'), D.readQr(b.qr()!), send);
  const csrf = /name="csrf" value="([0-9a-f]+)"/.exec(await (await get('/')).text())![1];
  const notice = async (r: Response) => decodeURIComponent(r.headers.get('location') ?? '').replace(/^\/\?n=/, '');
  const code = async () => JSON.parse(qrText(await (await post('/admin/code', { csrf })).text()));
  return { b, get, post, csrf, notice, code };
}

test('the box sets, checks and clears its login page address, and keeps it in its state', () => {
  const box = new Box(null);
  assert.equal(box.login, undefined);
  box.setLoginPage('https://account.example/');
  assert.equal(box.login, 'https://account.example'); assert.equal(box.state.loginPage, 'https://account.example');
  assert.equal(JSON.parse(box.newSetupCode('http://box', 1)).loginPage, 'https://account.example');
  for (const bad of ['http://account.example', 'https://account.example/page', 'https://account.example?x=1', 'https://account.example#a', 'account.example', 'https://'])
    assert.throws(() => box.setLoginPage(bad), /bad_login_page/);
  assert.equal(box.login, 'https://account.example');            // a refused address changes nothing
  assert.equal(loginOrigin(' https://a.example:8443 '), 'https://a.example:8443');
  box.setLoginPage(null);
  assert.equal(box.login, undefined); assert.equal(box.state.loginPage, undefined);
  assert.equal(JSON.parse(box.newSetupCode('http://box', 1)).loginPage, undefined);
  // KEYKIN_LOGIN_URL wins over the setting.
  box.setLoginPage('https://saved.example'); box.fixedLogin = 'https://env.example';
  assert.equal(box.login, 'https://env.example');
});

test('the admin page saves the address, setup codes carry it, a bad one is refused, and it can be cleared', async () => {
  const d = dir();
  let a = await admin({ d });
  try {
    let page = await (await a.get('/')).text();
    assert.match(page, /Your login page address/); assert.match(page, /No address yet/);
    assert.match(page, /Invites and setup codes include this address/);
    assert.equal((await a.code()).loginPage, undefined);
    assert.match(await a.notice(await a.post('/admin/loginpage', { csrf: a.csrf, do: 'save', address: 'https://account.example' })), /New codes carry https:\/\/account.example/);
    assert.equal((await a.code()).loginPage, 'https://account.example');
    // The account page's own code for a newcomer carries it too.
    assert.equal(JSON.parse(a.b.box.newSetupCode('http://box', 1, 'ab'.repeat(32))).loginPage, 'https://account.example');
    assert.match(await a.notice(await a.post('/admin/loginpage', { csrf: a.csrf, do: 'save', address: 'https://account.example/login' })), /That is not a login page address/);
    assert.match(await a.notice(await a.post('/admin/loginpage', { csrf: a.csrf, do: 'save', address: 'http://account.example' })), /That is not a login page address/);
    assert.equal(a.b.box.login, 'https://account.example');
    page = await (await a.get('/')).text();
    assert.match(page, /Codes carry<\/span><span class="mono">https:\/\/account.example/); assert.match(page, /value="clear"/);
  } finally { await a.b.close(); }
  // Kept across a restart.
  a = await admin({ d });
  try {
    assert.equal(a.b.box.login, 'https://account.example');
    assert.match(await a.notice(await a.post('/admin/loginpage', { csrf: a.csrf, do: 'clear' })), /cleared/);
    assert.equal(a.b.box.login, undefined); assert.equal((await a.code()).loginPage, undefined);
  } finally { await a.b.close(); }
});

test('KEYKIN_LOGIN_URL overrides the setting and shows as fixed', async () => {
  const d = dir();
  let a = await admin({ d });
  try { await a.post('/admin/loginpage', { csrf: a.csrf, do: 'save', address: 'https://saved.example' }); } finally { await a.b.close(); }
  a = await admin({ d, login: 'https://env.example' });
  try {
    assert.equal((await a.code()).loginPage, 'https://env.example');
    const page = await (await a.get('/')).text();
    assert.match(page, /Set by KEYKIN_LOGIN_URL on this box/); assert.doesNotMatch(page, /action="\/admin\/loginpage"/);
    assert.match(await a.notice(await a.post('/admin/loginpage', { csrf: a.csrf, do: 'clear' })), /set by KEYKIN_LOGIN_URL/);
    assert.equal(a.b.box.state.loginPage, 'https://saved.example'); assert.equal(a.b.box.login, 'https://env.example');
  } finally { await a.b.close(); }
});

test('the admin page suggests an address but saves nothing until the admin does', async () => {
  const a = await admin();
  try {
    // Nothing to go on: no suggestion.
    assert.match(await (await a.get('/')).text(), /value=""/);
    // Keykin Login says, through the side door, where it is.
    await fetch(`http://127.0.0.1:${a.b.sidePort}/page`, { method: 'POST', body: JSON.stringify({ call: 'pw_salt', username: 'x' }), headers: { ...H, 'x-keykin-origin': 'https://login.example' } });
    let page = await (await a.get('/')).text();
    assert.match(page, /value="https:\/\/login.example"/); assert.match(page, /where Keykin Login says it is/);
    // Visited over https: that address first.
    page = await (await a.get('/', { 'x-forwarded-proto': 'https' })).text();
    assert.match(page, new RegExp(`value="https://127.0.0.1:${a.b.port}"`)); assert.match(page, /the address you opened this page at/);
    assert.equal(a.b.box.login, undefined); assert.equal((await a.code()).loginPage, undefined);
  } finally { await a.b.close(); }
});

test('with the address set, passkeys belong to it, not to the host a request came in by', async () => {
  const a = await admin();
  try {
    const pk = (origin: string) => a.b.page.request({ call: 'pk_login_start', origin }, Math.floor(Date.now() / 1000));
    assert.equal((await pk('https://lookalike.example')).options.rpId, 'lookalike.example');
    a.b.box.setLoginPage('https://account.example');
    assert.equal((await pk('https://lookalike.example')).options.rpId, 'account.example');
  } finally { await a.b.close(); }
});
