// tools/calendar-copy.mjs: an app's copy of a part of calendar/, and the check that it is still the same.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, appendFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const tool = fileURLToPath(new URL('../tools/calendar-copy.mjs', import.meta.url));
const run = (...args: string[]) => spawnSync(process.execPath, [tool, ...args], { encoding: 'utf8' });

test('calendar-copy: each part copies, checks clean, and an edit fails naming the file', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'kk-calendar-copy-'));
  try {
    const js = join(tmp, 'web', 'calendar'), kt = join(tmp, 'app/src/main/java/cc/aaro/calendar'), vec = join(tmp, 'app/src/test/resources/calendar');
    const and = join(tmp, 'app/src/main/java/cc/aaro/calendar-android');
    for (const [part, dest] of [['js', js], ['kotlin', kt], ['android', and], ['vectors', vec]]) {
      const made = run(part, dest);
      assert.equal(made.status, 0, made.stderr);
      assert.equal(run('--check', part, dest).status, 0);
    }
    assert.ok(existsSync(join(js, 'calendar.js')) && existsSync(join(js, 'sha256.js')) && !existsSync(join(js, 'Calendar.kt')));
    assert.ok(existsSync(join(kt, 'Calendar.kt')) && existsSync(join(kt, 'CalendarRows.kt')) && !existsSync(join(kt, 'calendar.js')));
    assert.ok(existsSync(join(and, 'AndroidCalendar.kt')));
    assert.ok(existsSync(join(vec, 'calendar.json')));
    assert.match(readFileSync(join(kt, 'SOURCE'), 'utf8'), /^keykin [0-9a-f]{40}/);

    // the copied JS works from where it landed
    const mod = await import(join(js, 'calendar.js'));
    assert.equal(mod.merge([{ meta: { kind: 'event' }, data: null, deleted: true }]).deleted, true);

    appendFileSync(join(kt, 'Calendar.kt'), '\n// a local fix\n');
    const c = run('--check', 'kotlin', kt);
    assert.equal(c.status, 1);
    assert.match(c.stderr, /edited in the copy: Calendar\.kt/);
    assert.equal(run('kotlin', kt).status, 0);
    assert.equal(run('--check', 'kotlin', kt).status, 0);

    assert.equal(run('--check', 'js', kt).status, 1); // the wrong part
    assert.equal(run('ics', js).status, 2);
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});
