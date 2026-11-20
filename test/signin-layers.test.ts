// signin/: layer 1 (rules.js) imports in Node with no DOM, and stands apart from layers 2 and 3, so a server can use it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const dir = fileURLToPath(new URL('../signin/', import.meta.url));

// Every file a module loads, by static import or import(), following relative paths.
function graph(start: string): Set<string> {
  const seen = new Set<string>(), todo = [start];
  while (todo.length) {
    const f = todo.pop()!;
    if (seen.has(f)) continue;
    seen.add(f);
    const src = readFileSync(dir + f, 'utf8');
    for (const m of src.matchAll(/(?:from\s*|import\s*\(\s*|import\s+)"(\.\/[^"]+)"/g)) todo.push(new URL(m[1], 'file:///x/' + f).pathname.slice(3));
  }
  return seen;
}

test('signin: layer 1 loads none of the screen\'s files', () => {
  const files = [...graph('rules.js')].sort();
  assert.deepEqual(files, ['connect.js', 'hooks.js', 'ids.js', 'pointer.js', 'pool.js', 'rules.js', 'vendor/noble.js', 'vendor/sign.js']);
  // and layer 2 loads no part of layer 3
  for (const f of graph('me.js')) assert.ok(!['dialog.js', 'toast.js', 'account-page.js'].includes(f), f);
});

test('signin: layer 1 imports in Node with no DOM globals, and its rules work there', () => {
  const script = `
    const before = ['document', 'window', 'localStorage', 'sessionStorage', 'location'].filter((k) => k in globalThis);
    if (before.length) throw new Error('this Node already has ' + before.join(', '));
    const r = await import(${JSON.stringify(new URL('../signin/rules.js', import.meta.url).href)});
    await import(${JSON.stringify(new URL('../signin/vendor/sign.js', import.meta.url).href)});
    const after = ['document', 'window', 'localStorage', 'sessionStorage', 'location'].filter((k) => k in globalThis);
    const T = 'https://account.syb.lol/#connect=<nostrconnect>';
    const out = {
      after,
      origin: r.loginTemplate(T)?.origin,
      legacy: r.legacyTemplate('https://old.example/'),
      link: r.loginLink(T, 'nostrconnect://x?a=1'),
      origin2: r.originOnly('https://account.syb.lol/'),
      none: r.pointerOf([], 'a'.repeat(64)),
      bunker: r.parseBunker('bunker://' + 'b'.repeat(64) + '?relay=wss://r.example&secret=s'),
      code: r.siteCode({ pk: 'c'.repeat(64), relays: ['wss://r.example'], secret: 's', name: 'Tube', url: 'https://tube.example', perms: 'get_public_key' }),
      hex: await r.whose('D'.repeat(64)),
      npub: await r.whose('nostr:npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m'),
      key: await r.shortKey('1'.repeat(64)),
    };
    console.log(JSON.stringify(out));`;
  const out = JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', script], { encoding: 'utf8' }));
  assert.deepEqual(out.after, []);
  assert.equal(out.origin, 'https://account.syb.lol');
  assert.equal(out.legacy, 'https://old.example/#connect=<nostrconnect>');
  assert.equal(out.link, 'https://account.syb.lol/#connect=' + encodeURIComponent('nostrconnect://x?a=1'));
  assert.equal(out.origin2, 'https://account.syb.lol');
  assert.deepEqual(out.none, { none: true });
  assert.deepEqual(out.bunker, { signer: 'b'.repeat(64), relays: ['wss://r.example'], secret: 's' });
  assert.equal(out.code, `nostrconnect://${'c'.repeat(64)}?relay=wss%3A%2F%2Fr.example&secret=s&name=Tube&url=https%3A%2F%2Ftube.example&perms=get_public_key`);
  assert.equal(out.hex, 'd'.repeat(64));
  assert.equal(out.npub, '82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2');
  assert.match(out.key, /^[0-9a-f]{4}$/);
});

test('signin: a site\'s hooks are used, and a wrong name is refused', async () => {
  const { configure, hooks, defaults, whose }: any = await import(new URL('../signin/rules.js', import.meta.url).href);
  const asked: string[] = [];
  try {
    configure({ resolveNip05: async (a: string) => { asked.push(a); return { pubkey: 'E'.repeat(64) }; } });
    assert.equal(await whose('Aaron@Example.com'), 'e'.repeat(64));
    assert.equal(await whose('example.com'), 'e'.repeat(64));
    assert.deepEqual(asked, ['aaron@example.com', 'example.com']);
    assert.throws(() => configure({ resolveNip5: () => null }), /no hook named resolveNip5/);
    assert.throws(() => configure({ name: 'x' }), /must be a function/);
  } finally { configure({ ...defaults }); }
  assert.equal(hooks.resolveNip05, defaults.resolveNip05);
  // the default name: a short npub, as Marble Web's
  assert.equal(hooks.name('82341f882b6eabcd2ba7f1ef90aad961cf074af15b9ef44a09f9d2a8fbfbe6a2'), 'npub1sg6plzp…');
});
