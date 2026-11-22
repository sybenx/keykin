// The Home section: the DMs home (bothy) this box is the back room of, and its file server (Keykin Storage).
// The page calls both itself, as the person, with the signer a scan left: bothy's NIP-86 calls and storage's
// /manage calls are both a JSON body signed by a NIP-98 kind 27235 event. Keykin Login and the box pass on and
// sign nothing here. Plain rules and calls with fetch, relays and the signer passed in, so the page and the
// tests run the same code.
'use strict';
(() => {
  const enc = new TextEncoder();
  const hexOf = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
  const sha256 = async (text) => hexOf(await crypto.subtle.digest('SHA-256', enc.encode(text)));
  const b64 = (text) => { let s = ''; for (const c of enc.encode(text)) s += String.fromCharCode(c); return btoa(s); };
  const isHex = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);

  // ---- npub, for Advanced (bech32, BIP-173) ----------------------------------------------------------
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  const polymod = (v) => { let c = 1; for (const x of v) { const t = c >>> 25; c = ((c & 0x1ffffff) << 5) ^ x; [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3].forEach((g, i) => { if ((t >>> i) & 1) c ^= g; }); } return c; };
  function npub(hex) {
    if (!isHex(hex)) return hex;
    const bytes = hex.match(/../g).map((h) => parseInt(h, 16)), words = [];
    let acc = 0, bits = 0;
    for (const b of bytes) { acc = (acc << 8) | b; bits += 8; while (bits >= 5) { bits -= 5; words.push((acc >>> bits) & 31); } }
    if (bits) words.push((acc << (5 - bits)) & 31);
    const hrp = 'npub', pre = [...hrp].map((c) => c.charCodeAt(0) >> 5).concat(0, [...hrp].map((c) => c.charCodeAt(0) & 31));
    const mod = polymod(pre.concat(words, [0, 0, 0, 0, 0, 0])) ^ 1;
    const check = [0, 1, 2, 3, 4, 5].map((i) => (mod >>> (5 * (5 - i))) & 31);
    return hrp + '1' + words.concat(check).map((w) => CHARSET[w]).join('');
  }
  const short = (hex) => (isHex(hex) ? `${hex.slice(0, 8)}…${hex.slice(-8)}` : String(hex));

  // ---- Signed calls --------------------------------------------------------------------------------
  /** A NIP-98 event for a POST of `body` to `url`, ready for the signer: `u`, `method`, `payload` (SHA-256 of the exact body). */
  async function authEvent(url, body, now = Math.floor(Date.now() / 1000)) {
    return { kind: 27235, created_at: now, tags: [['u', url], ['method', 'POST'], ['payload', await sha256(body)]], content: '' };
  }
  class CallError extends Error { constructor(message, status) { super(message); this.status = status; } }
  /**
   * One NIP-86-shaped call: POST {"method","params"} to `url`, signed by `signer` (signEvent). Resolves with
   * `result`, or throws a CallError with the server's own words (a 401's `error` too), or "no answer" when the
   * server cannot be reached. `fetch` is passed in for tests.
   */
  async function call(signer, url, method, params = [], o = {}) {
    const body = JSON.stringify({ method, params });
    const signed = await signer.signEvent(await authEvent(url, body));
    let r;
    try {
      r = await (o.fetch ?? fetch)(url, { method: 'POST', headers: { 'content-type': 'application/nostr+json+rpc', authorization: 'Nostr ' + b64(JSON.stringify(signed)) }, body });
    } catch { throw new CallError('no answer', 0); }
    let j = null; try { j = await r.json(); } catch {}
    if (j && 'error' in j && j.error) throw new CallError(String(j.error), r.status);
    if (!r.ok || !j || !('result' in j)) throw new CallError(r.status === 401 ? 'not allowed' : `no answer (${r.status})`, r.status);
    return j.result;
  }
  /** The home's relay information document (NIP-11): its owner (`pubkey`), name and file server (`storage.url`). */
  async function homeInfo(homeUrl, o = {}) {
    const r = await (o.fetch ?? fetch)(homeUrl, { headers: { accept: 'application/nostr+json' } });
    if (!r.ok) throw new CallError(`no answer (${r.status})`, r.status);
    return r.json();
  }
  /** The file server's own key and the home it follows, unsigned: GET <storage>/manage/info. */
  async function storageInfo(storageUrl, o = {}) {
    const r = await (o.fetch ?? fetch)(storageUrl + '/manage/info');
    if (!r.ok) throw new CallError(`no answer (${r.status})`, r.status);
    const j = await r.json();
    return j && typeof j === 'object' && 'result' in j ? j.result : j;
  }
  const manageUrl = (storageUrl) => storageUrl + '/manage';
  /** The home address as a relay: https://h/ → wss://h/. */
  const relayOf = (homeUrl) => homeUrl.replace(/^http/, 'ws');
  /** Two home addresses name the same home, whatever their trailing slash or scheme case. */
  const sameHome = (a, b) => { try { const x = new URL(a), y = new URL(b); return x.origin === y.origin && x.pathname.replace(/\/+$/, '') === y.pathname.replace(/\/+$/, ''); } catch { return false; } };

  // ---- Names and photos (kind 0 on the home) ----------------------------------------------------------
  /** The newest kind 0 for each pubkey, as {name, picture}. Only an https picture is kept. */
  function profiles(events) {
    const best = new Map();
    for (const e of events) if (e?.kind === 0 && isHex(e.pubkey) && (!best.has(e.pubkey) || e.created_at > best.get(e.pubkey).created_at)) best.set(e.pubkey, e);
    const out = {};
    for (const [pk, e] of best) {
      let c = {}; try { c = JSON.parse(e.content) ?? {}; } catch {}
      const name = [c.display_name, c.displayName, c.name].find((x) => typeof x === 'string' && x.trim());
      const picture = typeof c.picture === 'string' && /^https:\/\//.test(c.picture) ? c.picture : null;
      out[pk] = { name: name ? name.trim().slice(0, 64) : null, picture };
    }
    return out;
  }
  /**
   * Reads kind 0 for `authors` from one relay. A home may ask for NIP-42 first: then `auth(challenge)` signs the
   * kind 22242 and it asks again, once. Resolves with what came, after EOSE or `ms`.
   */
  function readProfiles(relay, authors, auth, ms = 6000) {
    return new Promise((resolve) => {
      const got = []; let ws, done = false, tried = false, challenge = null;
      const finish = () => { if (done) return; done = true; clearTimeout(t); try { ws?.close(); } catch {} resolve(got); };
      const t = setTimeout(finish, ms);
      const ask = () => ws.send(JSON.stringify(['REQ', 'kk-names', { kinds: [0], authors: authors.slice(0, 500) }]));
      try { ws = new WebSocket(relay); } catch { return finish(); }
      ws.onopen = ask;
      ws.onerror = finish;
      ws.onmessage = async (m) => {
        let d; try { d = JSON.parse(m.data); } catch { return; }
        if (d[0] === 'EVENT' && d[1] === 'kk-names') got.push(d[2]);
        else if (d[0] === 'EOSE' && d[1] === 'kk-names') finish();
        else if (d[0] === 'AUTH' && typeof d[1] === 'string') challenge = d[1];
        else if (d[0] === 'CLOSED' && d[1] === 'kk-names') {
          if (tried || !challenge || !auth || !/^auth-required/.test(String(d[2]))) return finish();
          tried = true;
          try { ws.send(JSON.stringify(['AUTH', await auth(challenge)])); } catch { return finish(); }
        } else if (d[0] === 'OK' && tried) { if (d[2] === true) ask(); else finish(); }
      };
    });
  }
  const authFor = (relay, challenge) => ({ kind: 22242, created_at: Math.floor(Date.now() / 1000), tags: [['relay', relay], ['challenge', challenge]], content: '' });

  // ---- The invite tree --------------------------------------------------------------------------------
  /**
   * The tree from `listmembers` and the owner: {pubkey, role, close, source, joinedAt, kids:[...], old:[...]}, the owner
   * at the root. People whose inviter is not known go in `old`, marked `legacy`, each with whoever they invited under
   * them, so the real tree stays readable: bothy (v0.29) marks them `inviterUnknown: true` while still naming the owner
   * in `invitedBy`; a null `invitedBy` or an inviter no longer listed counts the same. A key listed twice is shown
   * once. Children are in join order.
   */
  function tree(owner, list) {
    const rows = new Map();
    for (const m of list?.members ?? []) if (isHex(m?.pubkey) && m.pubkey !== owner && !rows.has(m.pubkey)) rows.set(m.pubkey, { ...m, kids: [] });
    const root = { pubkey: owner, role: 'owner', close: true, source: 'owner', joinedAt: null, invitedBy: null, kids: [], old: [] };
    const OLD = { kids: root.old };
    const parentOf = (n) => (n.inviterUnknown === true ? OLD : n.invitedBy === owner ? root : n.invitedBy && rows.has(n.invitedBy) && n.invitedBy !== n.pubkey ? rows.get(n.invitedBy) : OLD);
    // A loop (it should never come from bothy) is cut and put with the old rows, so every row is shown once.
    for (const n of rows.values()) {
      let p = parentOf(n); const seen = new Set([n.pubkey]);
      while (p !== root && p !== OLD && !seen.has(p.pubkey)) { seen.add(p.pubkey); p = parentOf(p); }
      (p === root || p === OLD ? parentOf(n) : OLD).kids.push(n);
    }
    const byJoin = (a, b) => (a.joinedAt ?? 0) - (b.joinedAt ?? 0) || (a.pubkey < b.pubkey ? -1 : 1);
    const order = (n) => { n.kids.sort(byJoin); n.kids.forEach(order); };
    order(root); root.old.sort(byJoin); root.old.forEach(order);
    for (const n of root.old) n.legacy = true;
    return root;
  }
  /** Everyone under `n`, not counting `n`. */
  const below = (n) => n.kids.flatMap((k) => [k, ...below(k)]);
  /** Depth-first, with each row's depth, for an indented list. */
  const flat = (n, depth = 0) => [{ node: n, depth }, ...n.kids.flatMap((k) => flat(k, depth + 1))];
  const find = (n, pk) => (n.pubkey === pk ? n : [...n.kids, ...(n.old ?? [])].map((k) => find(k, pk)).find(Boolean) ?? null);
  /** Everyone in the home but the owner: the tree and the old rows. */
  const everyone = (t) => [...below(t), ...(t.old ?? []).flatMap((n) => [n, ...below(n)])];
  /**
   * How someone came in, in plain words, from bothy's `source` (allowed_pubkeys.source): "owner" is let in by hand
   * (allowpubkey, and every row from before sources), "member" came with an invite code, "request" asked to join and
   * was let in, "invite" is an older invite. `by` is the inviter's name ("you" for the person looking), or null.
   */
  function howCame(n, by) {
    if (n.role === 'owner') return 'Owner';
    if (n.legacy) return null;                    // nobody knows who let them in: say nothing rather than guess
    if (!by) return n.source === 'request' ? 'Asked to join' : n.source === 'member' || n.source === 'invite' ? 'Came with an invite' : 'Added by hand';
    if (n.source === 'request') return `Asked to join, let in by ${by}`;
    if (n.source === 'member' || n.source === 'invite') return `Invited by ${by}`;
    return `Added by ${by}`;
  }
  /**
   * When someone was last here, in words, from bothy v0.29's `lastSeen`: a UTC day number (floor(unix / 86400)), null if
   * never. bothy began writing it on 2026-11-21 (day 20778), so for someone who joined before then null means "not
   * since". A value too big to be a day (over 100000) is read as seconds, so a change of units cannot print the year
   * 50000. Absent: null, nothing said. The day is shown in UTC, as bothy counts it, never with a time.
   */
  const SEEN_FROM_DAY = 20778;
  const utcDay = (d) => new Date(d * 86400000).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' });
  function seenWords(n) {
    if (!n || !('lastSeen' in n)) return null;
    const v = n.lastSeen;
    if (v === null || v === 0) return typeof n.joinedAt === 'number' && n.joinedAt < SEEN_FROM_DAY * 86400 ? `No sign-in since ${utcDay(SEEN_FROM_DAY)}` : 'Never signed in';
    if (typeof v !== 'number' || !isFinite(v) || v < 0) return null;
    return `Last here ${utcDay(v > 100000 ? Math.floor(v / 86400) : Math.floor(v))}`;
  }
  /** The last six characters of a key, for telling nameless people apart. */
  const tail = (hex) => (isHex(hex) ? hex.slice(-6) : '');

  /**
   * What `me` (role owner or admin) may do about removing `n`, the way bothy decides it, so the page offers
   * only what bothy will take: {remove, branch, why}. `branch` is whether "remove them too" is open.
   */
  function removal(n, me, role) {
    if (n.role === 'owner' || n.pubkey === me) return { remove: false, branch: false, why: null };
    const adminBelow = below(n).some((k) => k.role === 'admin');
    if (role === 'owner') return { remove: true, branch: true, why: null };
    if (role !== 'admin') return { remove: false, branch: false, why: null };
    if (n.role === 'admin') return { remove: false, branch: false, why: 'Only the owner can remove an admin.' };
    return { remove: true, branch: !adminBelow, why: adminBelow ? 'Someone they invited is an admin, so only the owner can remove them all.' : null };
  }

  // ---- Space and the bin --------------------------------------------------------------------------------
  /** Bytes as people read them: 1000-based, like the file server's own command line. */
  function size(n) {
    if (typeof n !== 'number' || !isFinite(n) || n < 0) return '';
    const units = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
    while (n >= 1000 && i < units.length - 1) { n /= 1000; i++; }
    return `${i ? n.toFixed(n < 10 ? 1 : 0) : n} ${units[i]}`;
  }
  /** `usage.accounts` by pubkey. */
  const usedBy = (usage) => Object.fromEntries((usage?.accounts ?? []).filter((a) => isHex(a?.pubkey)).map((a) => [a.pubkey, a]));
  /**
   * The bin by person, largest first: [{pubkey, items, bytes, erasesAt (the soonest)}]. Items charged to nobody
   * known come under null.
   */
  function binByPerson(bin) {
    const groups = new Map();
    for (const x of bin?.items ?? []) {
      if (!isHex(x?.sha256)) continue;
      const k = isHex(x.charged) ? x.charged : null;
      const g = groups.get(k) ?? { pubkey: k, items: [], bytes: 0, erasesAt: null };
      g.items.push(x); g.bytes += Number(x.size) || 0;
      if (x.erasesAt && (!g.erasesAt || x.erasesAt < g.erasesAt)) g.erasesAt = x.erasesAt;
      groups.set(k, g);
    }
    return [...groups.values()].sort((a, b) => b.bytes - a.bytes);
  }
  /** Lists cut into pieces of at most `n`, for calls that take up to 500 hashes. */
  const chunks = (list, n = 500) => { const out = []; for (let i = 0; i < list.length; i += n) out.push(list.slice(i, i + n)); return out; };

  // ---- Words -----------------------------------------------------------------------------------------
  const plural = (n, one, many = one + 's') => `${n} ${n === 1 ? one : many}`;
  /** The two choices when removing someone who invited people: neither is the "destructive" one. */
  function removeWords(name, kids) {
    const n = kids.length;
    if (!n) return { ask: `Remove ${name} from the home?`, keep: 'Remove', branch: null };
    return {
      ask: `${name} invited ${plural(n, 'person', 'people')}. What happens to them?`,
      keep: n === 1 ? 'Keep the person they invited' : `Keep the ${n} people they invited`,
      branch: 'Remove them too',
    };
  }

  globalThis.KeykinHome = { npub, short, authEvent, call, CallError, homeInfo, storageInfo, manageUrl, relayOf, sameHome, profiles, readProfiles, authFor, tree, below, flat, find, everyone, howCame, tail, seenWords, utcDay, removal, size, usedBy, binByPerson, chunks, removeWords, plural, sha256 };
})();
