// A box with Keykin Login in front puts the login page's origin in its codes (SPEC 11.1).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { startBox } from '../box/server.ts';

const dir = () => mkdtempSync(join(tmpdir(), 'keykin-login-field-'));

test('codes carry the login origin when it is set, and not otherwise', async () => {
  const b = await startBox({ dir: dir(), port: 0, login: 'https://account.example', log: () => {} });
  try {
    assert.equal(JSON.parse(b.qr()!).login, 'https://account.example');
    assert.equal(JSON.parse(b.box.newSetupCode('https://account.example', 1)).login, 'https://account.example');
  } finally { await b.close(); }
  const plain = await startBox({ dir: dir(), port: 0, log: () => {} });
  try { assert.equal(JSON.parse(plain.qr()!).login, undefined); } finally { await plain.close(); }
});

test('a login origin with a path or plain http is refused at start', () => {
  assert.throws(() => startBox({ dir: dir(), port: 0, login: 'https://account.example/page', log: () => {} }));
  assert.throws(() => startBox({ dir: dir(), port: 0, login: 'http://account.example', log: () => {} }));
});
