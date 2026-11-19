// The login-page pointer (SPEC 11.1): kind 10046 with a `nostrconnect_url` template, and the old kind
// 30078 (`d` = keykin/login, `url` = origin) kept beside it during the move. Plain rules, no I/O, so the
// account page and the tests use the same code.
'use strict';
(() => {
  const KIND = 10046, OLD = 30078, D = 'keykin/login', SLOT = '<nostrconnect>';
  const tag = (e, name) => e?.tags?.find((t) => Array.isArray(t) && t[0] === name)?.[1];
  const local = (host) => ['localhost', '127.0.0.1'].includes(host);
  const newest = (list) => list.reduce((a, e) => (!a || e.created_at > a.created_at ? e : a), null);

  /** A template's origin, or null if a reader must refuse it. `here` is the reader's own hostname. */
  function checkTemplate(t, here) {
    if (typeof t !== 'string' || !t.endsWith(SLOT) || t.indexOf(SLOT) !== t.length - SLOT.length) return null;
    let u; try { u = new URL(t.slice(0, -SLOT.length) + 'x'); } catch { return null; }
    if (u.username || u.password) return null;
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local(u.hostname) && local(here))) return null;
    return u.origin;
  }
  /** The old kind's `url`: an https origin only (or a local http one when the reader runs locally). */
  function checkOld(url, here) {
    let u; try { u = new URL(url); } catch { return null; }
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local(u.hostname) && local(here))) return null;
    if (u.username || u.password || u.href !== u.origin + '/') return null;
    return u.origin;
  }
  const templateOf = (origin) => `${origin}/#connect=${SLOT}`;

  /**
   * What the account says, from every event the relays gave (any mix of both kinds, any author checked by
   * the caller). 10046 first; 30078 only when there is no 10046 at all. A newest 10046 without a template
   * is a removal, and the old kind is not read then.
   * Returns { state: 'none' | 'removed' | 'bad' | 'found', origin?, kind?, event? }.
   */
  function read(events, here) {
    const n = newest(events.filter((e) => e?.kind === KIND));
    if (n) {
      const t = tag(n, 'nostrconnect_url');
      if (t === undefined) return { state: 'removed', kind: KIND, event: n };
      const origin = checkTemplate(t, here);
      return origin ? { state: 'found', origin, kind: KIND, event: n } : { state: 'bad', kind: KIND, event: n };
    }
    const o = newest(events.filter((e) => e?.kind === OLD && tag(e, 'd') === D));
    if (!o) return { state: 'none' };
    const url = tag(o, 'url');
    if (url === undefined) return { state: 'removed', kind: OLD, event: o };
    const origin = checkOld(url, here);
    return origin ? { state: 'found', origin, kind: OLD, event: o } : { state: 'bad', kind: OLD, event: o };
  }

  /** The events a new pointer is signed as: both kinds, during the move. */
  function pointerEvents(origin, now) {
    return [
      { kind: KIND, created_at: now, tags: [['nostrconnect_url', templateOf(origin)]], content: '' },
      { kind: OLD, created_at: now, tags: [['d', D], ['url', origin]], content: '' },
    ];
  }
  /** Removing it removes both. */
  function removalEvents(now) {
    return [{ kind: KIND, created_at: now, tags: [], content: '' }, { kind: OLD, created_at: now, tags: [['d', D]], content: '' }];
  }
  /**
   * The copies to send again as they are, with no new signature: for each kind, its newest event, to every
   * relay that answered without it. `byRelay` maps a relay that answered to the events it gave.
   * Only when the account's pointer names `origin`, and only events that name it too.
   */
  function missingCopies(byRelay, origin, here) {
    const all = Object.values(byRelay).flat();
    const now = read(all, here);
    if (now.state !== 'found' || now.origin !== origin) return [];
    const out = [];
    for (const kind of [KIND, OLD]) {
      const e = newest(all.filter((x) => x?.kind === kind && (kind === KIND || tag(x, 'd') === D)));
      if (!e) continue;
      const names = kind === KIND ? checkTemplate(tag(e, 'nostrconnect_url'), here) : checkOld(tag(e, 'url'), here);
      if (names !== origin) continue;
      for (const [relay, list] of Object.entries(byRelay)) if (!list.some((x) => x?.id === e.id)) out.push({ relay, event: e });
    }
    return out;
  }
  /** The filters a reader asks with: both kinds at once. */
  const filters = (author) => [{ kinds: [KIND], authors: [author] }, { kinds: [OLD], authors: [author], '#d': [D] }];

  /**
   * Signs `events` with `signer` and sends each to every relay with `send(relay, event) -> Promise<boolean>`.
   * Returns true if every kind reached at least one relay.
   */
  async function publish(signer, relays, events, send) {
    const signed = [];
    for (const e of events) signed.push(await signer.signEvent(e));
    const oks = await Promise.all(signed.map((e) => Promise.all(relays.map((r) => send(r, e))).then((x) => x.some(Boolean))));
    return oks.every(Boolean);
  }

  globalThis.KeykinPointer = { KIND, OLD, checkTemplate, read, pointerEvents, removalEvents, missingCopies, filters, publish, templateOf };
})();
