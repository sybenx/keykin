// tools/signin-copy.mjs: a site's copy of signin/, and the check that it is still the same.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, appendFileSync, rmSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const tool = fileURLToPath(new URL('../tools/signin-copy.mjs', import.meta.url));
const run = (...args: string[]) => spawnSync(process.execPath, [tool, ...args], { encoding: 'utf8' });

test('signin-copy: a copy checks clean, and an edited one fails naming the file', () => {
  const tmp = mkdtempSync(join(tmpdir(), 'kk-signin-copy-'));
  try {
    const dest = join(tmp, 'js', 'signin');
    const made = run(dest);
    assert.equal(made.status, 0, made.stderr);
    const source = readFileSync(join(dest, 'SOURCE'), 'utf8').split('\n');
    assert.match(source[0], /^keykin [0-9a-f]{40}/);
    assert.ok(source.some((l) => /^[0-9a-f]{64} {2}rules\.js$/.test(l)) && source.some((l) => /^[0-9a-f]{64} {2}vendor\/sign\.js$/.test(l)));
    assert.ok(existsSync(join(dest, 'dialog.js')) && existsSync(join(dest, 'signin.css')));

    let c = run('--check', dest);
    assert.equal(c.status, 0, c.stderr);

    appendFileSync(join(dest, 'pointer.js'), '\n// a local fix\n');
    c = run('--check', dest);
    assert.equal(c.status, 1);
    assert.match(c.stderr, /edited in the copy: pointer\.js/);
    assert.doesNotMatch(c.stderr, /dialog\.js/);

    // copying again puts it back
    assert.equal(run(dest).status, 0);
    assert.equal(run('--check', dest).status, 0);

    // a file added in the copy, and one taken away
    writeFileSync(join(dest, 'mine.js'), 'export {};\n');
    rmSync(join(dest, 'toast.js'));
    c = run('--check', dest);
    assert.equal(c.status, 1);
    assert.match(c.stderr, /added to the copy: mine\.js/);
    assert.match(c.stderr, /missing from the copy: toast\.js/);

    // a folder that is not a copy is left alone
    const other = join(tmp, 'other');
    mkdirSync(other);
    writeFileSync(join(other, 'app.js'), '');
    assert.equal(run(other).status, 1);
    assert.equal(run('--check', other).status, 1);
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});
