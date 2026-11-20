// signin/vectors/pointer.json, the shared pointer and name cases, against signin/ and against Keykin Login's own
// login/static/pointer.js. Each must give `expect`, or, where the case says it differs today, exactly what it says.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const V = JSON.parse(readFileSync(join(import.meta.dirname, '../signin/vectors/pointer.json'), 'utf8'));
const at = (p: string) => new URL(`../signin/${p}`, import.meta.url).href;
const { loginTemplate, legacyTemplate, loginLink }: any = await import(at('connect.js'));
const { originOnly, pointerOf, whose }: any = await import(at('pointer.js'));
const { configure, defaults, hooks }: any = await import(at('hooks.js'));
const box: any = {};
new Function('globalThis', readFileSync(join(import.meta.dirname, '../login/static/pointer.js'), 'utf8'))(box);
const P = box.KeykinPointer;

const KL = 'keykin-login';
/** What `impl` must give for case `c`: what the case says it gives today, else the rule. */
const want = (c: any, impl: string, rule: any) => (c.differs && impl in c.differs ? c.differs[impl] : rule);
const label = (c: any, impl: string) => `${impl}: ${c.why ?? ''} ${JSON.stringify(c.template ?? c.url ?? c.typed ?? c.origin ?? c.name ?? '')}`.slice(0, 200);
// signin/ reads the page's own hostname from location, as in a browser
function hereIs<T>(host: string, fn: () => T): T {
  (globalThis as any).location = { hostname: host };
  try { return fn(); } finally { delete (globalThis as any).location; }
}
const asState = (r: any) => r.url ? { state: 'found', origin: r.url, template: r.template, kind: r.legacy ? 30078 : 10046 } : r.removed ? { state: 'removed' } : { state: 'none' };
function asStateKL(r: any) {
  if (r.state !== 'found') return { state: r.state === 'bad' ? 'removed' : r.state };
  const template = r.kind === 10046 ? r.event.tags.find((t: any) => t[0] === 'nostrconnect_url')[1] : P.templateOf(r.origin);
  return { state: 'found', origin: r.origin, template, kind: r.kind };
}

test('vectors: every difference recorded is a real one', () => {
  const rule: Record<string, string> = { templates: 'origin', origins: 'origin', legacy: 'template', pointers: 'expect', typed: 'expect', nip05: 'expect' };
  for (const [list, field] of Object.entries(rule)) for (const c of V[list]) {
    assert.ok(field in c, `${list}: a case with no ${field}`);
    for (const [impl, got] of Object.entries(c.differs ?? {})) {
      assert.ok(['signin', KL].includes(impl), `${list}: unknown implementation ${impl}`);
      assert.notDeepEqual(got, c[field], `${list}: ${label(c, impl)} is not a difference`);
    }
  }
});

test('vectors: templates', () => {
  for (const c of V.templates) {
    const here = c.here ?? V.here;
    assert.deepEqual(hereIs(here, () => loginTemplate(c.template)?.origin ?? null), want(c, 'signin', c.origin), label(c, 'signin'));
    assert.deepEqual(P.checkTemplate(c.template, here), want(c, KL, c.origin), label(c, KL));
    // signin/ keeps the template as it was written
    const t = hereIs(here, () => loginTemplate(c.template));
    if (t) assert.equal(t.template, c.template);
  }
});

test('vectors: the old kind\'s url', () => {
  for (const c of V.origins) {
    const here = c.here ?? V.here;
    assert.deepEqual(hereIs(here, () => originOnly(c.url)), want(c, 'signin', c.origin), label(c, 'signin'));
    const r = P.read([{ kind: 30078, pubkey: V.account, created_at: 1, tags: [['d', 'keykin/login'], ['url', c.url]], content: '' }], here);
    assert.deepEqual(r.state === 'found' ? r.origin : null, want(c, KL, c.origin), label(c, KL));
  }
});

test('vectors: links and the old kind as a template', () => {
  for (const c of V.links) assert.equal(loginLink(c.template, c.code), c.link, label(c, 'signin'));
  for (const c of V.legacy) {
    assert.equal(legacyTemplate(c.origin), want(c, 'signin', c.template), label(c, 'signin'));
    assert.equal(P.templateOf(c.origin), want(c, KL, c.template), label(c, KL));
  }
});

test('vectors: what the pointers found say', () => {
  for (const c of V.pointers) {
    const here = c.here ?? V.here;
    assert.deepEqual(hereIs(here, () => asState(pointerOf(c.events, V.account))), want(c, 'signin', c.expect), label(c, 'signin'));
    // as the account page calls it: only this account's events (it checks the author, not the signature)
    assert.deepEqual(asStateKL(P.read(c.events.filter((e: any) => e?.pubkey === V.account), here)), want(c, KL, c.expect), label(c, KL));
  }
});

test('vectors: typed names', async () => {
  let asked: string | null = null;
  configure({ resolveNip05: async (address: string) => { asked = address; return null; } });
  try {
    for (const c of V.typed) {
      asked = null;
      const pk = await whose(c.typed);
      const a = asked as string | null;
      const got = pk ? { pubkey: pk } : a ? (a.includes('@') ? { name: a.split('@')[0], domain: a.split('@')[1] } : { name: '_', domain: a }) : null;
      assert.deepEqual(got, want(c, 'signin', c.expect), label(c, 'signin'));
    }
  } finally { configure({ resolveNip05: defaults.resolveNip05 }); }
});

test('vectors: NIP-05 answers, through the default lookup', async () => {
  const real = globalThis.fetch;
  try {
    for (const c of V.nip05) {
      const calls: [string, any][] = [];
      globalThis.fetch = (async (url: string, init: any) => {
        calls.push([url, init]);
        return new Response(typeof c.body === 'string' ? c.body : JSON.stringify(c.body), { status: c.status });
      }) as any;
      const r = await hooks.resolveNip05(c.name === '_' ? c.domain : `${c.name}@${c.domain}`);
      assert.deepEqual(r?.pubkey ?? null, want(c, 'signin', c.expect), label(c, 'signin'));
      assert.equal(calls[0][0], `https://${c.domain}/.well-known/nostr.json?name=${encodeURIComponent(c.name)}`);
      assert.equal(calls[0][1].redirect, 'error');
    }
  } finally { globalThis.fetch = real; }
});
