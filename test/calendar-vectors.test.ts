// calendar/vectors/calendar.json against calendar/js/calendar.js (the Kotlin copy runs the same file in calendar/test-kotlin).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
// @ts-ignore: plain JS module
import { canon, parse, stamp, merge, instanceView, instanceId, importId, settingsId } from '../calendar/js/calendar.js';

const V = parse(readFileSync(new URL('../calendar/vectors/calendar.json', import.meta.url), 'utf8'));

test('calendar vectors: stamping', () => {
  for (const c of V.stamp) assert.equal(canon(stamp(c.prev, c.next, { clock: c.clock, device: c.device })), canon(c.expect), c.name);
});

test('calendar vectors: merging, in any order, and the merge of a merge', () => {
  for (const c of V.merge) {
    const n = c.versions.length;
    for (let r = 0; r < n; r++) {
      const turned = [...c.versions.slice(r), ...c.versions.slice(0, r)];
      assert.equal(canon(merge(turned)), c.canon, `${c.name}, turned ${r}`);
      assert.equal(canon(merge([...turned].reverse())), c.canon, `${c.name}, reversed ${r}`);
    }
    assert.equal(canon(c.expect), c.canon, c.name);
    assert.equal(canon(merge([c.expect])), c.canon, `${c.name}: merge of the merge`);
    for (const v of c.versions) assert.equal(canon(merge([c.expect, v])), c.canon, `${c.name}: merge with an input`);
  }
});

test('calendar vectors: instance view, canonical JSON, entry ids', () => {
  for (const c of V.instance_view) assert.equal(canon(instanceView(c.series, c.instance)), canon(c.expect), c.name);
  for (const c of V.canon) assert.equal(canon(c.value), c.expect);
  for (const c of V.ids) {
    const got = c.fn === 'instance' ? instanceId(c.series, c.original) : c.fn === 'import' ? importId(c.vault, c.uid) : settingsId(c.vault);
    assert.equal(got, c.expect, JSON.stringify(c));
  }
});

test('calendar: refuses what it cannot merge', () => {
  assert.throws(() => merge([]));
  assert.throws(() => merge([{ meta: { kind: 'event' }, data: null }, { meta: { kind: 'settings' }, data: null }]));
  assert.throws(() => stamp(null, { meta: { kind: 'event', n: 1.5 } }, { clock: 1, device: 'a1b2c3d4' }));
  assert.throws(() => stamp(null, { meta: { kind: 'event' } }, { clock: 1, device: 'A1B2C3D4' }));
  assert.throws(() => instanceId('ab', { date: '2026-12-01' }));
});
