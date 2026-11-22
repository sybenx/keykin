// The account page. It talks only to its own server (/api), which passes each call to the box. A
// signed-in page has the person's authority, but it holds no piece of the key: anything that needs a
// signature is left for one of the account's devices to do.
'use strict';
(() => {
  const app = document.getElementById('app');
  const api = async (call, more = {}) => {
    const r = await fetch('/api', { method: 'POST', headers: { 'content-type': 'application/json', 'x-keykin': '1' }, body: JSON.stringify({ call, ...more }) });
    return r.json();
  };
  const el = (tag, props = {}, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) { if (k === 'on') for (const [e, f] of Object.entries(v)) n.addEventListener(e, f); else if (k in n) n[k] = v; else n.setAttribute(k, v); }
    n.append(...kids.flat().filter((k) => k !== null && k !== undefined && k !== false));
    return n;
  };
  const day = (t) => new Date(t * 1000).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  const ago = (t) => {
    if (!t) return null;
    const s = Math.max(0, Date.now() / 1000 - t);
    if (s < 90) return 'a minute ago';
    if (s < 3600) return `${Math.round(s / 60)} minutes ago`;
    if (s < 2 * 3600) return 'an hour ago';
    if (s < 86400) return `${Math.round(s / 3600)} hours ago`;
    if (s < 2 * 86400) return 'yesterday';
    return day(t);
  };
  const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
  const say = (code) => ({
    wrong: 'That username and password do not match.', slow_down: 'Too many tries. Wait a minute.', no_box: 'The box cannot be reached right now.',
    cannot_block_box: 'The box itself cannot be blocked.', too_many: 'Too many things are waiting. Try again in a few minutes.', login: 'You were signed out. Sign in again.', not_open: 'The owner of this server has to let you in first.', box_full: 'This server holds as many accounts as its owner lets in. Ask the owner to make room.', not_here: 'This server does not look after your account yet.', gone: 'That ran out. Try again.',
    bad_username: 'A username is 3 to 32 letters, numbers, dots, dashes or underscores, in lower case.', username_taken: 'That username is taken on this box.', password_required: 'Your account always keeps a password. You can change it.',
  }[code] ?? `That did not work (${code}).`);
  const HOW = { password: 'a password', passkey: 'a passkey', scan: 'a device' };
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  const count = (n, one, many = one + 's') => `${n} ${n === 1 ? one : many}`;
  let timers = [];
  const every = (ms, f) => { const t = setInterval(f, ms); timers.push(t); return t; };
  const stopTimers = () => { timers.forEach(clearInterval); timers = []; };
  let me = null, section = 'home', flash = null, leave = () => {};
  const NO_PASSWORD = 'Your account has no password yet. Set one so you can reach your account page from any browser.';

  async function verifier(password, saltHex) {
    if (!crypto.subtle) throw new Error('insecure');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
    const salt = Uint8Array.from(saltHex.match(/../g).map((b) => parseInt(b, 16)));
    return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, key, 256));
  }
  const sha256hex = async (bytes) => hex(await crypto.subtle.digest('SHA-256', bytes));
  // What the box stores for a verifier: SHA-256("keykin2-pw" ‖ verifier).
  const checkOf = async (verifierHex) => sha256hex(new Uint8Array([...new TextEncoder().encode('keykin2-pw'), ...verifierHex.match(/../g).map((b) => parseInt(b, 16))]));


  // ---- A site sent you here to sign in: #connect=<nostrconnect:// code> ---------------------------------
  // `connect=` is the last fragment parameter: everything after it is the code, as it is when it starts with
  // nostrconnect:// (a raw code), else URL-decoded once. It is read once, taken out of the address bar and
  // history, and kept with the sender's origin (document.referrer) in this tab's sessionStorage, so it lives
  // through the passkey, the password or the scan. Nothing goes to a device until the person clicks (SPEC 11.6).
  const PENDING = 'kk-connect', NOPK = 'kk-skip-pk';
  const store = {
    get: (k) => { try { return sessionStorage.getItem(k); } catch { return null; } },
    set: (k, v) => { try { if (v === null) sessionStorage.removeItem(k); else sessionStorage.setItem(k, v); } catch {} },
  };
  let badConnect = false;
  function readConnect(text) {
    const uri = (text ?? '').trim();
    if (!uri.startsWith('nostrconnect://') || uri.length > 4000) return null;
    let u; try { u = new URL(uri); } catch { return null; }
    if (!/^[0-9a-f]{64}$/i.test(u.host)) return null;
    const relays = u.searchParams.getAll('relay').filter((r) => /^wss?:\/\/[^\s]+$/.test(r));
    if (!relays.length || !u.searchParams.get('secret')) return null;
    let meta = {}; try { meta = JSON.parse(u.searchParams.get('metadata') ?? '{}') ?? {}; } catch {}
    const name = String(u.searchParams.get('name') ?? meta.name ?? '').trim().slice(0, 60) || null;
    let url = u.searchParams.get('url') ?? meta.url ?? null;
    try { url = url && /^https?:$/.test(new URL(url).protocol) ? new URL(url).href : null; } catch { url = null; }
    // "Read your private lists" starts on when the code asks to decrypt (NIP-46 perms), as on a phone's scan; DMs never do.
    const perms = (u.searchParams.get('perms') ?? '').split(',').map((p) => p.trim().split(':')[0]);
    const asksLists = perms.includes('nip44_decrypt') || perms.includes('nip04_decrypt');
    return { uri, name, url, host: url ? new URL(url).host : null, relays, asksLists };
  }
  const senderOf = () => {
    try { const o = document.referrer ? new URL(document.referrer).origin : null; return o && /^https?:\/\//.test(o) ? o : null; } catch { return null; }
  };
  // The site that sent this tab here, if it is not this page itself: kept for the tab, through a sign-in, for 30 minutes.
  const CAME = 'kk-came-from';
  function noteCameFrom() {
    const o = senderOf();
    if (o && o !== location.origin) store.set(CAME, JSON.stringify({ origin: o, at: Date.now() }));
  }
  // A visit the person started themselves (typed, bookmarked, a new tab) with nothing in the fragment: what this tab
  // kept from an earlier visit (the site that sent it, a device's six digits) belongs to that visit, not this one.
  function freshVisit() {
    let nav = null; try { nav = performance.getEntriesByType('navigation')[0]?.type ?? null; } catch {}
    if (nav !== 'navigate' || senderOf() || /(^|[#&])(connect|add|p)=/.test(location.hash)) return;
    store.set(CAME, null); store.set(ADDED, null);
  }
  function cameFrom() {
    let o = null; try { o = JSON.parse(store.get(CAME) ?? 'null'); } catch {}
    if (!o || typeof o.origin !== 'string' || !/^https?:\/\/[^\s/?#]+$/.test(o.origin) || !(Date.now() - o.at < 30 * 60 * 1000)) return null;
    return { origin: o.origin, host: new URL(o.origin).host.replace(/^www\./, '') };
  }
  function takeConnect() {
    const hash = location.hash.slice(1);
    const at = hash.startsWith('connect=') ? 0 : hash.indexOf('&connect=') + 1;
    if (at === 0 && !hash.startsWith('connect=')) return;
    const raw = hash.slice(at + 'connect='.length);
    const rest = hash.slice(0, Math.max(0, at - 1)).split('&').filter(Boolean);
    history.replaceState(null, '', location.pathname + location.search + (rest.length ? '#' + rest.join('&') : ''));
    let text = raw;
    if (!raw.startsWith('nostrconnect://')) { try { text = decodeURIComponent(raw); } catch { text = ''; } }
    const c = readConnect(text);
    if (c) store.set(PENDING, JSON.stringify({ uri: c.uri, from: senderOf() })); else badConnect = true;
  }
  // The code, the site it says it is, and the sender: `match` is the one-click case.
  function pending() {
    const v = store.get(PENDING);
    let o = null; try { o = v && v.startsWith('{') ? JSON.parse(v) : v ? { uri: v, from: null } : null; } catch {}
    const c = o && readConnect(o.uri);
    if (!c) return null;
    const from = typeof o.from === 'string' && /^https?:\/\/[^\s/?#]+$/.test(o.from) ? o.from : null;
    const fromHost = from ? new URL(from).host : null;
    return { ...c, from, fromHost, match: !!(fromHost && c.host && fromHost === c.host) };
  }
  const siteName = (c) => c.match ? (c.name ?? c.host) : (c.fromHost ?? 'the site');
  // What the page can say about where the request came from, in plain words.
  const senderLine = (c) => c.match ? null
    : !c.from ? 'This page could not tell which site sent you here.'
    : c.host ? `This request came from ${c.fromHost}, but says it is ${c.host}.`
    : `This request came from ${c.fromHost}, but does not say which site it is.`;
  function asking() {
    if (badConnect) return el('div', { className: 'notice', id: 'asking', role: 'alert' }, 'A site sent you here with a sign-in code that is not a nostrconnect:// code, so it was left alone. Go back to the site and try again.');
    const c = pending();
    if (!c) return null;
    const warn = senderLine(c);
    return el('div', { className: 'card', id: 'asking' },
      el('div', { className: 'small dim' }, 'A site is asking you to sign in'),
      el('div', {}, el('strong', { id: 'askname' }, c.match ? (c.name ?? c.host) : (c.fromHost ?? 'A site')), c.match && c.name ? el('span', { className: 'dim' }, ` · ${c.host}`) : null),
      warn ? el('div', { className: 'small err', id: 'askwarn' }, warn, c.name || c.host ? ` It calls itself ${c.name ?? c.host}.` : '') : null,
      el('div', { className: 'small dim mono', id: 'askrelay' }, `Relay: ${c.relays.join(', ')}`),
      el('div', { className: 'small dim' }, 'Sign in below. You are asked once more before the site is signed in.'),
      el('button', { className: 'linkish small', id: 'notnow', type: 'button', style: 'align-self:flex-start', on: { click: () => { store.set(PENDING, null); document.getElementById('asking')?.remove(); } } }, 'Do not sign in there'));
  }

  // ---- An app sent you here to add it as a device: #challenge=…&return=…&state=…&add=<its Keykin invite> ------
  // Marble on a Mac signs in through Marble Web, which sends you here with the Mac's invite, the way an app signs
  // in with OAuth (RFC 8252 with PKCE). The same rules as `connect=`: `add=` is the last fragment parameter,
  // URL-decoded once, taken out of the address bar at once (with the parameters before it), kept in this tab's
  // sessionStorage through the sign-in, and never acted on without a click. After Add the box holds the new
  // device's piece until it shows the approval code this page gets, with the verifier its `challenge` was made
  // from. The code goes back only to a `return` address on this same computer (127.0.0.1 or localhost) or to a phone
  // app's own App Link (APP_RETURNS), and as six digits to type (SPEC 11.6). An app opening a browser sends no
  // referrer, so the card says when to say yes.
  const ADDING = 'kk-add', ADDED = 'kk-add-done';
  let badAdd = null;
  function readInvite(text) {
    const t = (text ?? '').trim();
    if (!t.startsWith('{') || t.length > 4000) return null;
    let v; try { v = JSON.parse(t); } catch { return null; }
    const inv = v && v.keykin === 2 && v.invite && typeof v.invite === 'object' ? v.invite : null;
    if (!inv || typeof inv.key !== 'string' || !/^[0-9a-f]{64}$/i.test(inv.key)) return null;
    const name = (typeof inv.name === 'string' ? inv.name.trim().slice(0, 60) : '') || 'A new device';
    return { text: t, key: inv.key.toLowerCase(), name };
  }
  const challengeOk = (c) => typeof c === 'string' && /^[A-Za-z0-9_-]{43}$/.test(c) ? c : null;
  const stateOk = (x) => typeof x === 'string' && /^[A-Za-z0-9_-]{8,128}$/.test(x) ? x : null;
  // The https addresses a phone app takes its approval back on (RFC 8252 7.2, a claimed App Link), exactly as written.
  const APP_RETURNS = ['https://marble.syb.lol/joined'];
  /**
   * Where the approval may go: a loopback address on this computer (http, 127.0.0.1 or localhost, a port, nothing
   * else; RFC 8252 7.3), or one of the phone apps' own App Link addresses above. Anything else is left alone.
   */
  function returnOk(r) {
    if (typeof r === 'string' && APP_RETURNS.includes(r)) return r;
    let u; try { u = new URL(r); } catch { return null; }
    return typeof r === 'string' && r.length < 300 && u.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(u.hostname) && u.port && !u.username && !u.password && !u.hash ? u.href : null;
  }
  const onPhone = (ret) => typeof ret === 'string' && APP_RETURNS.includes(ret);
  function takeAdd() {
    const hash = location.hash.slice(1);
    const at = hash.startsWith('add=') ? 0 : hash.indexOf('&add=') + 1;
    if (at === 0 && !hash.startsWith('add=')) return;
    const raw = hash.slice(at + 'add='.length);
    const before = hash.slice(0, Math.max(0, at - 1)).split('&').filter(Boolean);
    const param = (k) => { const p = before.find((x) => x.startsWith(k + '=')); try { return p ? decodeURIComponent(p.slice(k.length + 1)) : null; } catch { return ''; } };
    const rest = before.filter((x) => !/^(challenge|return|state)=/.test(x));
    history.replaceState(null, '', location.pathname + location.search + (rest.length ? '#' + rest.join('&') : ''));
    let text = ''; try { text = decodeURIComponent(raw); } catch {}
    store.set(CAME, null);                       // what sent this is an app adding a device, not a site to connect
    const a = readInvite(text);
    if (!a) { badAdd = 'Something sent you here to add a device, but what it sent is not a Keykin invite, so it was left alone. Go back to the app and try again.'; return; }
    const r = param('return'), c = param('challenge'), st = param('state');
    if (r !== null || c !== null || st !== null) {
      // An app's return: all three, and the address must be this computer. Anything else is left alone.
      const ret = r !== null ? returnOk(r) : null;
      if (r !== null && !ret) { let h = 'somewhere else'; try { h = new URL(r).host || h; } catch {} badAdd = `Something sent you here to add a device and send the approval to ${h}, which is not this device, so it was left alone.`; return; }
      if (!ret || !challengeOk(c) || !stateOk(st)) { badAdd = 'Something sent you here to add a device, but what it sent is not complete, so it was left alone. Go back to the app and try again.'; return; }
      store.set(ADDING, JSON.stringify({ invite: a.text, challenge: c, ret, state: st }));
    } else store.set(ADDING, JSON.stringify({ invite: a.text }));
  }
  function pendingAdd() {
    let o = null; try { o = JSON.parse(store.get(ADDING) ?? 'null'); } catch {}
    const a = o && readInvite(o.invite);
    if (!a) return null;
    const ret = o.ret ? returnOk(o.ret) : null;
    return { ...a, challenge: ret ? challengeOk(o.challenge) : null, ret, state: ret ? stateOk(o.state) : null };
  }
  // Above the sign-in, while the person signs in: what is waiting, and that nothing happens yet.
  function addAsking() {
    if (badAdd) return el('div', { className: 'notice', id: 'addasking', role: 'alert' }, badAdd);
    const a = pendingAdd();
    if (!a) return null;
    return el('div', { className: 'card', id: 'addasking' },
      el('div', { className: 'small dim' }, 'A device is asking to be added to your account'),
      el('div', {}, el('strong', { id: 'addname' }, a.name)),
      el('div', { className: 'small dim' }, 'Sign in below. You are asked once more before it is added.'),
      el('button', { className: 'linkish small', id: 'addnotnow', type: 'button', style: 'align-self:flex-start', on: { click: () => { store.set(ADDING, null); document.getElementById('addasking')?.remove(); } } }, 'Do not add it'));
  }
  const spaced = (d) => `${d.slice(0, 3)} ${d.slice(3)}`;
  // The six digits, kept for this tab until they run out, so they are still here if the way back to the app fails.
  function addedCard(o) {
    return card(el('h2', {}, `${o.name} was added`),
      el('p', { className: 'sub', id: 'addline' }, o.ret ? `Done. ${o.name} is signing in.` : 'Done.'),
      el('div', { className: 'small dim' }, o.ret ? `If ${o.name} did not sign in, type this only into ${o.name} on this ${o.phone ? 'phone' : 'computer'}:` : `Type this only into ${o.name}, with its join code below:`),
      el('div', { className: 'shortcode mono', id: 'shortcode' }, spaced(o.short)),
      el('div', { className: 'small dim', id: 'shortwhere' }, `Your account page: ${location.host}. The code works once, for 10 minutes.`),
      o.join ? el('details', { className: 'small', id: 'addcode' }, el('summary', { className: 'dim' }, 'Its join code'), el('p', { className: 'mono small', id: 'joincode' }, o.join)) : null);
  }
  function showAdded(o) {
    app.replaceChildren(el('div', { className: 'signin' },
      el('div', { className: 'title' }, el('h1', { style: 'font-size:26px' }, 'Your account'), el('div', { className: 'dim' }, location.host)),
      addedCard(o),
      el('button', { className: 'btn', id: 'toaccount', type: 'button', style: 'align-self:flex-start', on: { click: () => { store.set(ADDED, null); showAccount(); } } }, 'Go to your account')));
  }
  function added() {
    let o = null; try { o = JSON.parse(store.get(ADDED) ?? 'null'); } catch {}
    return o && o.until > Date.now() / 1000 && /^\d{6}$/.test(o.short ?? '') ? o : null;
  }

  // ---- The login-page pointer (section 11.1): does the account name a login page yet? ----------------
  // The page asks its own relays for both kinds (10046, and 30078 during the move); KeykinPointer holds the
  // rules. It does not check the signature: the answer only decides what to offer, and a reader such as
  // Marble checks it before it trusts it. A copy some relay lacks is sent there again as it is.
  const P = globalThis.KeykinPointer;
  function findPointer(author, relays) {
    return new Promise((resolve) => {
      let left = relays.length, over = false;
      const socks = [], byRelay = {};
      const finish = () => {
        if (over) return; over = true; clearTimeout(timer);
        socks.forEach((w) => { try { w.close(); } catch {} });
        if (!Object.keys(byRelay).length) return resolve({ state: 'unknown' });
        const r = P.read(Object.values(byRelay).flat(), location.hostname);
        for (const { relay, event } of P.missingCopies(byRelay, here(), location.hostname)) sendEvent(relay, event);
        resolve({ ...r, url: r.origin });
      };
      const timer = setTimeout(finish, 4000);
      if (!left) return finish();
      for (const relay of relays) {
        let ws, ended = false;
        const got = [];
        const end = () => { if (!ended) { ended = true; if (--left === 0) finish(); } };
        try { ws = new WebSocket(relay); } catch { end(); continue; }
        socks.push(ws);
        ws.onopen = () => ws.send(JSON.stringify(['REQ', 'kkp', ...P.filters(author)]));
        ws.onmessage = (m) => {
          let d; try { d = JSON.parse(m.data); } catch { return; }
          if (d[0] === 'EVENT' && d[2]?.pubkey === author) got.push(d[2]);
          if (d[0] === 'EOSE') { byRelay[relay] = got; end(); }
        };
        ws.onerror = end; ws.onclose = end;
      }
    });
  }
  // The account's name and picture (kind 0), for the sign-in card. Nothing is shown from it but those two.
  function findProfile(author, relays) {
    return new Promise((resolve) => {
      let left = relays.length, newest = null, over = false;
      const socks = [];
      const finish = () => {
        if (over) return; over = true; clearTimeout(timer);
        socks.forEach((w) => { try { w.close(); } catch {} });
        let p = {}; try { p = JSON.parse(newest?.content ?? '{}') ?? {}; } catch {}
        const name = String(p.display_name || p.name || '').trim().slice(0, 60) || null;
        let picture = null; try { picture = p.picture && new URL(p.picture).protocol === 'https:' ? new URL(p.picture).href : null; } catch {}
        resolve({ name, picture });
      };
      const timer = setTimeout(finish, 3000);
      if (!left) return finish();
      for (const relay of relays) {
        let ws, ended = false;
        const end = () => { if (!ended) { ended = true; if (--left === 0) finish(); } };
        try { ws = new WebSocket(relay); } catch { end(); continue; }
        socks.push(ws);
        ws.onopen = () => ws.send(JSON.stringify(['REQ', 'kkm', { kinds: [0], authors: [author], limit: 1 }]));
        ws.onmessage = (m) => {
          let d; try { d = JSON.parse(m.data); } catch { return; }
          if (d[0] === 'EVENT' && d[2]?.pubkey === author && d[2]?.kind === 0 && (!newest || d[2].created_at > newest.created_at)) newest = d[2];
          if (d[0] === 'EOSE') end();
        };
        ws.onerror = end; ws.onclose = end;
      }
    });
  }
  function sendEvent(relay, event) {
    return new Promise((resolve) => {
      let ws; const t = setTimeout(() => { try { ws?.close(); } catch {} resolve(false); }, 6000);
      try { ws = new WebSocket(relay); } catch { clearTimeout(t); return resolve(false); }
      ws.onopen = () => ws.send(JSON.stringify(['EVENT', event]));
      ws.onmessage = (m) => { let d; try { d = JSON.parse(m.data); } catch { return; } if (d[0] === 'OK' && d[1] === event.id) { clearTimeout(t); ws.close(); resolve(d[2] === true); } };
      ws.onerror = () => { clearTimeout(t); resolve(false); };
    });
  }
  const pageUrlOk = () => location.protocol === 'https:' || ['127.0.0.1', 'localhost', '[::1]'].includes(location.hostname);
  // What the account says about its sign-in page, for the account page: `found` from findPointer, the signer a
  // scan left behind (kept while there is something for it to sign), and the relays. Null when signed out.
  let ptr = null;
  const dropPointer = () => { ptr?.signer?.close().catch(() => {}); ptr = null; };
  // This page's address as the account should name it: the box's login page address when it has one (from
  // `me`), so a pointer a phone published for it counts as here; the page's own origin only when it has none.
  let boxLogin = null;
  const here = () => me?.loginPage ?? boxLogin ?? location.origin;
  const mineHere = (found) => found.state === 'found' && found.url === here();
  // A scan's signer is kept until sign-out, so the page can publish (or remove) it from the account page too.
  const holdPointer = (npub, found, signer, relays) => {
    if (ptr?.signer && ptr.signer !== signer) ptr.signer.close().catch(() => {});
    ptr = { npub, found, signer, relays };
  };
  const NO_SIGNER = 'Your account page can ask your phone to publish it, or you can publish it from Marble.';
  // Asking a device to publish it (a `pointer` note, SPEC 11.1) when no scan left a signer here. The box puts
  // in its own login page address. `phase` is waiting, checking, declined, failed, gone, or no_page.
  let ptrAsk = null;
  const hostOf = (url) => { try { return new URL(url).host; } catch { return url; } };
  async function askPhone() {
    const npub = me.npub;
    ptrAsk = { phase: 'sending' }; draw();
    const r = await api('note_put', { kind: 'pointer' }).catch(() => ({ error: 'no_box' }));
    if (r.error === 'login') return showLogin(say('login'));
    if (!r.ok) { ptrAsk = { phase: r.error === 'no_login_page' ? 'no_page' : 'error', error: r.error }; return draw(); }
    const ask = ptrAsk = { phase: 'waiting', note: r.note, url: r.url };
    draw();
    const t = every(2000, async () => {
      if (ptrAsk !== ask) return clearInterval(t);
      const g = await api('note_get', { note: ask.note }).catch(() => null);
      if (ptrAsk !== ask) return clearInterval(t);
      if (g && g.error === 'login') { clearInterval(t); return showLogin(say('login')); }
      if (!g || !g.ok || g.state === 'waiting') return;
      clearInterval(t);
      if (g.state !== 'done') { ptrAsk = { phase: 'gone' }; return draw(); }
      if (g.result === 'declined') { ptrAsk = { phase: 'declined' }; return draw(); }
      if (g.result !== 'ok') { ptrAsk = { phase: 'failed' }; return draw(); }
      // The phone published it: ask the relays again, and say what they show now.
      ptrAsk = { phase: 'checking', url: ask.url }; draw();
      const found = await findPointer(npub, me.relays ?? []);
      if (ptrAsk?.phase !== 'checking' || me?.npub !== npub) return;
      holdPointer(npub, found, ptr?.npub === npub ? ptr.signer : null, me.relays ?? []);
      ptrAsk = null;
      flash = found.state === 'found' && found.url === ask.url ? `Published. Sites send you to ${hostOf(ask.url)}.`
        : 'Your phone published it, but this page’s relays do not show it yet. Check again in a minute.';
      draw();
    });
  }
  function phoneParts() {
    const line = el('p', { className: 'small dim', role: 'status', id: 'pointerline' });
    const a = ptrAsk;
    if (a && ['sending', 'waiting', 'checking'].includes(a.phase)) {
      line.textContent = a.phase === 'checking' ? 'Your phone published it. Checking…' : 'Approve on your phone…';
      const cancel = a.phase === 'waiting' ? el('button', { className: 'go-link linkish', id: 'pointercancel', type: 'button', style: 'margin:0', on: { click: () => { ptrAsk = null; draw(); } } }, 'Cancel') : null;
      return [el('div', { className: 'with-note' }, line, cancel)];
    }
    const go = el('button', { className: 'btn go', id: 'pointerphone', type: 'button', on: { click: () => askPhone() } }, 'Publish it from my phone');
    line.textContent = !a ? 'Your phone asks you first, then signs it.'
      : a.phase === 'declined' ? 'Your phone said no.'
      : a.phase === 'gone' ? 'No device answered in time. Is one of them online?'
      : a.phase === 'failed' ? 'Your phone could not publish it. Try again.'
      : a.phase === 'no_page' ? 'This box has no login page address set yet. Its owner sets it on the box’s admin page.'
      : say(a.error);
    if (a?.phase === 'declined' || a?.phase === 'gone' || a?.phase === 'failed' || a?.phase === 'no_page') line.className = 'small err';
    return [el('div', { className: 'with-note' }, a?.phase === 'no_page' ? null : go, line)];
  }
  // The parts both the card and the alert use: the sub line, the Publish (or Remove) button, and a status line.
  // `after(text)` runs when it is done; without it the line says so and the button goes.
  function pointerParts(found, signer, relays, after) {
    const line = el('p', { className: 'small dim', role: 'status', id: 'pointerline' });
    const there = found.state === 'found', mine = mineHere(found);
    // Signs both kinds (or both removals), each on the phone, and sends them to the page's relays.
    const signAndSend = async (button, events, now, done) => {
      const hold = button.closest('.card'); hold?.setAttribute('data-busy', '1');
      button.disabled = true; line.textContent = 'Asking your phone to sign it…';
      try {
        const ok = await Promise.race([P.publish(signer, relays, events, sendEvent), new Promise((_, no) => setTimeout(() => no(new Error('slow')), 90000))]);
        if (ok) {
          if (ptr) ptr.found = now;
          hold?.removeAttribute('data-busy');
          if (after) return after(done);
          line.textContent = done; button.remove(); return;
        }
        line.textContent = 'Your phone signed it, but no relay took it. Try again.';
      } catch { line.textContent = 'Your phone did not sign it. Is Marble still open there?'; }
      hold?.removeAttribute('data-busy');
      button.disabled = false;
    };
    let go = null, off = null;
    if (signer && pageUrlOk()) {
      if (!mine) {
        go = el('button', { className: 'btn go', id: 'publishpointer', type: 'button' }, there ? `Name ${new URL(here()).host} instead` : 'Publish it');
        go.onclick = () => { const o = here(); signAndSend(go, P.pointerEvents(o, Math.floor(Date.now() / 1000)), { state: 'found', url: o, origin: o },
          `Published. Your account names ${o} as its sign-in page.`); };
      } else {
        off = el('button', { className: 'btn', id: 'removepointer', type: 'button' }, 'Remove it');
        off.onclick = () => { if (confirm('Remove your sign-in page? Marble will no longer find you by your name.')) signAndSend(off, P.removalEvents(Math.floor(Date.now() / 1000)), { state: 'removed' }, 'Removed. Your account names no sign-in page now.'); };
      }
    } else if (!mine) line.textContent = signer ? 'This page is not on https, so it cannot be named.' : NO_SIGNER;
    return { line, go, off };
  }
  function pointerCard(found, signer, relays, after) {
    const there = found.state === 'found';
    const sub = el('div', { className: 'sub', id: 'pointersub' }, there
      ? `Your account names ${found.url} as its sign-in page. Marble sends you there when you type your name.`
      : found.state === 'unknown' ? 'This page could not reach its relays to see whether your account names a sign-in page.'
      : found.state === 'removed' ? 'Your account’s sign-in page was removed. Publishing one names this page.'
      : found.state === 'bad' ? 'Your account names a sign-in page that cannot be used. Publishing one names this page instead.'
      : 'Your account does not name a sign-in page yet, so Marble cannot find you by your name. Publishing one names this page.');
    const { line, go, off } = pointerParts(found, signer, relays, after);
    return card(el('h2', {}, 'Your sign-in page'), sub, go, off, line);
  }
  // The same thing, at the top of the account page, when sites cannot find this page by your name. Nothing
  // when the account names this page, and a quiet note when the relays could not be asked.
  function pointerAlert() {
    if (!ptr || ptr.npub !== me.npub || ptr.found.state === 'checking' || mineHere(ptr.found)) return null;
    const { found, signer, relays } = ptr;
    if (found.state === 'unknown') {
      const again = el('button', { className: 'go-link linkish', id: 'pointeragain', style: 'margin:0', on: { click: () => checkPointer(true) } }, 'Check again');
      return el('div', { className: 'notice quiet', id: 'pointernote', role: 'status' },
        'This page could not check whether sites can find you by your name. ', again);
    }
    const other = found.state === 'found';
    const host = other ? found.url.replace(/^https?:\/\//, '') : '';
    // A scan left a signer: this page signs it with that. Otherwise it asks a device to (a `pointer` note).
    const { line, go } = signer ? pointerParts(found, signer, relays, (done) => { flash = done; draw(); }) : {};
    if (go && other) go.textContent = 'Name this page instead';
    return el('div', { className: 'card alert', id: 'pointeralert', role: 'alert' }, shield(false),
      el('div', { className: 'grow', style: 'display:flex;flex-direction:column;gap:8px' },
        el('h2', { id: 'pointertitle' }, other ? `Sites send you to ${host}, not here` : 'Sites can’t find you by name yet'),
        el('div', { className: 'sub', id: 'pointersub' }, other
          ? `When you type your name on a site like Marble, it sends you to ${host} to sign in, not here.`
          : found.state === 'bad' ? 'Your account names a sign-in page that cannot be used. Publish this page so a site like Marble can send you here when you type your name.'
          : 'Publish this page as your sign-in page, so a site like Marble can send you here when you type your name.'),
        signer ? [go ? el('div', { className: 'with-note' }, go) : null, line] : phoneParts()));
  }
  // Asks the relays once per sign-in (or again on a click), and redraws when they answer.
  function checkPointer(again) {
    if (!me || (!again && ptr?.npub === me.npub)) return;
    const npub = me.npub, relays = me.relays ?? [];
    holdPointer(npub, { state: 'checking' }, again ? ptr?.signer ?? null : null, relays);
    if (again) draw();
    findPointer(npub, relays).then((found) => {
      if (ptr?.npub !== npub) return;
      holdPointer(npub, found, ptr.signer, relays);
      if (!document.querySelector('[data-busy]') && !document.querySelector('input:focus') && document.querySelector('.shell')) draw();
    });
  }

  // ---- After signing in -------------------------------------------------------------------------------
  // `signer` is the remote signer a scan left behind, or null after a password.

  async function afterSignIn(signer) {
    leave(); stopTimers(); leave = () => {};
    const close = () => { signer?.close().catch(() => {}); };
    const r = await api('me').catch(() => ({ error: 'no_box' }));
    if (!r.ok || r.held === false) { close(); return showAccount(); }
    boxLogin = r.loginPage ?? null;
    me = r;
    if (r.how === 'scan' && passkeysHere() && !(r.passkeys ?? []).some((p) => p.host === location.hostname) && store.get(NOPK) !== '1') await askPasskey();
    const c = pending(), a = pendingAdd();
    const [found, profile] = await Promise.all([findPointer(r.npub, r.relays ?? []), c || a ? findProfile(r.npub, r.relays ?? []) : null]);
    // The account page says, at the top, what is left to do about the sign-in page, and keeps the signer for it.
    holdPointer(r.npub, found, signer, r.relays ?? []);
    if (!c && !a) return showAccount();
    showFinish(c, found, signer, r.relays ?? [], profile, a);
  }

  async function savePassword(username, password) {
    const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
    return api('pw_set', { username: username.trim().toLowerCase(), salt, check: await checkOf(await verifier(password, salt)) });
  }

  // ---- Passkeys (SPEC 11.3) ---------------------------------------------------------------------------
  // The box makes the options and checks the answers; this page only carries them to the browser.
  const b64 = { to: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)), (c) => c.charCodeAt(0)).buffer,
    from: (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') };
  const passkeysHere = () => !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);
  async function addPasskey() {
    const s = await api('pk_add_start');
    if (!s.ok) return s;
    const o = s.options;
    const c = await navigator.credentials.create({ publicKey: { ...o, challenge: b64.to(o.challenge), user: { ...o.user, id: b64.to(o.user.id) },
      excludeCredentials: (o.excludeCredentials ?? []).map((x) => ({ ...x, id: b64.to(x.id) })) } });
    const r = c.response;
    return api('pk_add', { response: { id: c.id, rawId: b64.from(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults(), authenticatorAttachment: c.authenticatorAttachment ?? undefined,
      response: { clientDataJSON: b64.from(r.clientDataJSON), attestationObject: b64.from(r.attestationObject), transports: r.getTransports?.() ?? [] } } });
  }
  async function usePasskey() {
    const s = await api('pk_login_start');
    if (!s.ok) return s;
    const o = s.options;
    const c = await navigator.credentials.get({ publicKey: { ...o, challenge: b64.to(o.challenge), allowCredentials: [] } });
    const r = c.response;
    return api('pk_login', { response: { id: c.id, rawId: b64.from(c.rawId), type: c.type, clientExtensionResults: c.getClientExtensionResults(), authenticatorAttachment: c.authenticatorAttachment ?? undefined,
      response: { clientDataJSON: b64.from(r.clientDataJSON), authenticatorData: b64.from(r.authenticatorData), signature: b64.from(r.signature), userHandle: r.userHandle ? b64.from(r.userHandle) : undefined } } });
  }
  const pkError = (x) => x?.name === 'NotAllowedError' ? 'No passkey was used.' : x?.name === 'InvalidStateError' ? 'This passkey is already saved for your account.' : say('no_box');

  // After a scan: an offer, never a push. Skip goes on, and the page does not ask again in this tab.
  function askPasskey() {
    return new Promise((resolve) => {
      const line = el('p', { className: 'err small', role: 'alert' });
      const save = el('button', { className: 'btn go', type: 'button', id: 'savepk' }, 'Save a passkey');
      const skip = el('button', { className: 'btn', type: 'button', id: 'skippk', on: { click: () => { store.set(NOPK, '1'); resolve(); } } }, 'Skip');
      save.onclick = async () => {
        save.disabled = true; line.textContent = '';
        try {
          const r = await addPasskey();
          if (r.error === 'login') return showLogin(say('login'));
          if (r.ok) return resolve();
          line.textContent = say(r.error);
        } catch (x) { line.textContent = pkError(x); }
        save.disabled = false;
      };
      app.replaceChildren(el('div', { className: 'signin' }, asking(), addAsking(),
        el('div', { className: 'title' }, el('h1', { style: 'font-size:26px' }, 'You are signed in'), el('div', { className: 'dim' }, location.host)),
        el('div', { className: 'panel' }, el('div', { className: 'half' },
          el('h2', {}, 'Save a passkey so next time it’s one tap'),
          el('div', { className: 'sub dim', style: 'font-size:14px;line-height:1.45' }, `Your computer or password manager keeps it, for ${location.host} only. You can still sign in by scanning, or with a password.`),
          line, el('div', { className: 'with-note' }, save, skip)))));
    });
  }

  function showFinish(c, found, signer, relays, profile, a = null) {
    const parts = [];
    if (a) parts.push(addCard(a, profile));
    if (c) parts.push(connectCard(c, profile));
    if (found.state !== 'found' || signer) parts.push(pointerCard(found, signer, relays));
    parts.push(el('button', { className: 'btn', id: 'toaccount', type: 'button', style: 'align-self:flex-start', on: { click: () => showAccount() } }, 'Go to your account'));
    app.replaceChildren(el('div', { className: 'signin' },
      el('div', { className: 'title' }, el('h1', { style: 'font-size:26px' }, 'You are signed in'), el('div', { className: 'dim' }, location.host)), ...parts));
  }

  // "Sign in to <host> as <name>?" Nothing is sent to a device until a click here, even when this browser
  // was signed in already. When the sender is unknown or not the site the code names, the card says so and
  // the button asks a second time.
  function connectCard(c, profile) {
    const who = profile?.name ?? me?.username ?? (me?.npubText ? me.npubText.slice(0, 12) + '…' : 'your account');
    const host = c.match ? c.host : c.fromHost;
    const warn = senderLine(c);
    const pic = profile?.picture
      ? el('img', { className: 'avatar small', src: profile.picture, alt: '', referrerPolicy: 'no-referrer' })
      : el('div', { className: 'avatar small', ariaHidden: 'true' }, who.charAt(0).toUpperCase());
    const go = el('button', { className: 'btn go', type: 'button', id: 'connectgo' }, warn ? 'Sign in anyway' : 'Sign in');
    const no = el('button', { className: 'btn', type: 'button', id: 'connectno' }, 'Not now');
    const own = el('button', { className: 'linkish small', type: 'button', id: 'connectsite', style: 'align-self:flex-start' }, 'Use a separate account for this site');
    // The site's two switches (SPEC 11.5), chosen here since no device shows a card for a code from this page.
    const scopes = { lists: !!c.asksLists, dms: false };
    const toggle = (k, text) => el('label', { className: 'toggle' },
      el('input', { type: 'checkbox', id: 'connect' + k, checked: scopes[k], on: { change: (e) => { scopes[k] = e.currentTarget.checked; } } }), text);
    const node = card(
      el('h2', { id: 'connecttitle' }, host ? `Sign in to ${host} as ${who}?` : `Sign in to a site as ${who}?`),
      el('div', { className: 'hello small-hello' }, pic, el('div', {}, el('div', { className: 'name', id: 'connectwho' }, who), me?.npubText ? el('div', { className: 'mono small dim' }, me.npubText.slice(0, 16) + '…' + me.npubText.slice(-6)) : null)),
      c.from ? el('div', { className: 'small dim', id: 'askfrom' }, `Sent from ${c.from}`) : null,
      warn ? el('div', { className: 'notice warn', id: 'connectwarn', role: 'alert' }, warn, c.name || c.host ? ` It calls itself ${c.name ?? c.host}. Only sign in if you trust it.` : ' Only sign in if you trust it.') : null,
      el('div', { className: 'small dim mono', id: 'askrelay' }, `Relay: ${c.relays.join(', ')}`),
      el('div', { className: 'stickopts', id: 'connectopts' }, toggle('lists', 'Read your private lists'), toggle('dms', 'Read and send DMs')),
      el('div', { className: 'with-note' }, go, no), own);
    node.id = 'connectcard';
    const yes = (as) => {
      if (warn && !confirm(`Sign in to ${host ?? 'this site'} anyway? This page could not check which site is asking.`)) return;
      const line = el('p', { className: 'sub', id: 'handoff', role: 'status' }, 'Waiting for one of your devices…');
      const slow = el('p', { className: 'small dim', id: 'slow', hidden: true }, 'No device has answered yet. One of your devices needs to be online with an up-to-date Marble. This page keeps waiting for a few more minutes.');
      const next = card(el('h2', {}, `Signing in to ${siteName(c)}`), el('div', { className: 'small dim mono' }, `Relay: ${c.relays.join(', ')}`), line, slow);
      node.replaceWith(next);
      handOff(c, line, slow, as, scopes);
    };
    go.onclick = () => yes('main');
    own.onclick = () => yes('site');
    no.onclick = () => { store.set(PENDING, null); node.replaceWith(el('p', { className: 'small dim', id: 'notsigned' }, `Nothing was sent to ${host ?? 'the site'}.`)); };
    return node;
  }

  // "Add <device> to your account?" for an app that sent its invite here (#add=). Nothing goes to a device
  // until Add, even when this browser was signed in already. On Add it leaves the same `invite` note as Devices,
  // Add a device, and hands the approval code and the join text back to the app at its `return` address.
  function addCard(a, profile) {
    const who = profile?.name ?? me?.username ?? (me?.npubText ? me.npubText.slice(0, 12) + '…' : 'your account');
    const pic = profile?.picture
      ? el('img', { className: 'avatar small', src: profile.picture, alt: '', referrerPolicy: 'no-referrer' })
      : el('div', { className: 'avatar small', ariaHidden: 'true' }, who.charAt(0).toUpperCase());
    const go = el('button', { className: 'btn go', type: 'button', id: 'addgo' }, 'Add');
    const no = el('button', { className: 'btn', type: 'button', id: 'addno' }, 'Not now');
    const node = card(
      el('h2', { id: 'addtitle' }, `Add ${a.name} to your account?`),
      el('div', { className: 'hello small-hello' }, pic, el('div', {}, el('div', { className: 'name', id: 'addwho' }, who), me?.npubText ? el('div', { className: 'mono small dim' }, me.npubText.slice(0, 16) + '…' + me.npubText.slice(-6)) : null)),
      el('div', { className: 'small dim', id: 'adddevice' }, `New device: ${a.name}`),
      el('p', { className: 'small dim', id: 'addwarn' }, `Add it only if you just pressed Sign in on ${a.name}.`),
      el('div', { className: 'with-note' }, go, no));
    node.id = 'addcard';
    go.onclick = () => {
      const line = el('p', { className: 'sub', id: 'addline', role: 'status' }, 'Waiting for one of your devices…');
      const slow = el('p', { className: 'small dim', id: 'addslow', hidden: true }, 'No device has answered yet. One of your devices needs to be online with an up-to-date Marble. This page keeps waiting for a few more minutes.');
      const next = card(el('h2', {}, `Adding ${a.name}`), line, slow);
      next.id = 'adddone'; next.style.alignSelf = 'stretch';
      node.replaceWith(next);
      addHandOff(a, next, line, slow);
    };
    no.onclick = () => { store.set(ADDING, null); node.replaceWith(el('p', { className: 'small dim', id: 'notadded' }, `${a.name} was not added.`)); };
    return node;
  }

  async function addHandOff(a, box, line, slow) {
    const r = await api('note_put', { kind: 'invite', text: a.text, ...(a.challenge ? { challenge: a.challenge } : {}) }).catch(() => ({ error: 'no_box' }));
    if (r.error === 'login') return showLogin(say('login'));
    if (!r.ok) { line.textContent = say(r.error); return; }
    store.set(ADDING, null);                     // the box holds it now; a reload must not add it twice
    const started = Date.now();
    const t = every(2000, async () => {
      if (Date.now() - started > 60000) slow.hidden = false;
      const g = await api('note_get', { note: r.note }).catch(() => null);
      if (g && g.error === 'login') { clearInterval(t); return showLogin('A device said No, so this browser was signed out.'); }
      if (!g || !g.ok || g.state === 'waiting') return;
      clearInterval(t); slow.hidden = true;
      if (g.state !== 'done') { line.textContent = `No device answered in time. One of your devices needs to be online with an up-to-date Marble. Go back to ${a.name} and try again.`; return; }
      if (!g.approval) { line.textContent = 'Done, but this page did not get the approval code. Go back to the app and try again.'; return; }
      const o = { name: a.name, short: g.approval.short, until: g.approval.until, ret: !!a.ret, phone: onPhone(a.ret), join: a.ret ? null : g.result };
      store.set(ADDED, JSON.stringify(o));
      // On the way back to the app the six digits stay out of sight: they show only if this tab is come back to
      // (the way back failed), from what was just kept. Without a way back they are what the person needs now.
      if (!a.ret) return void box.replaceWith(addedCard(o));
      const going = card(el('h2', {}, `Opening ${a.name}`), el('p', { className: 'sub', id: 'addline', role: 'status' }, `Done. ${a.name} is signing in.`));
      going.id = 'adddone';
      box.replaceWith(going);
      // Back to the app, with the code (RFC 8252): only a loopback address or a phone app's App Link gets here (returnOk).
      {
        const u = new URL(a.ret);
        const q = new URLSearchParams({ code: g.approval.code, state: a.state, join: g.result });
        // A phone app's https return takes them in the fragment, so its web server never sees them if the app does not open.
        if (onPhone(a.ret)) u.hash = q.toString(); else for (const [k, v] of q) u.searchParams.set(k, v);
        location.assign(u.href);
      }
    });
  }

  async function handOff(c, line, slow, as, scopes = {}) {
    const r = await api('note_put', { kind: 'nostrconnect', text: c.uri, from: c.from, as, ...(scopes.lists ? { lists: true } : {}), ...(scopes.dms ? { dms: true } : {}) }).catch(() => ({ error: 'no_box' }));
    if (r.error === 'login') return showLogin(say('login'));
    if (!r.ok) { line.textContent = say(r.error); return; }
    store.set(PENDING, null);                    // the box holds it now; a reload must not send it twice
    const started = Date.now(), site = siteName(c);
    const back = c.match ? c.url : c.from ? c.from + '/' : null;
    const t = every(2000, async () => {
      if (Date.now() - started > 60000) slow.hidden = false;
      const g = await api('note_get', { note: r.note }).catch(() => null);
      if (g && g.error === 'login') { clearInterval(t); return showLogin('A device said No, so this browser was signed out.'); }
      if (!g || !g.ok || g.state === 'waiting') return;
      clearInterval(t); slow.hidden = true;
      if (g.state === 'done') line.replaceChildren('Done. ', back ? el('a', { href: back, id: 'backto', rel: 'noopener' }, `Go back to ${site}`) : `Go back to ${site}.`);
      else line.textContent = `No device answered in time. One of your devices needs to be online with an up-to-date Marble. Go back to ${site} and try again.`;
    });
  }

  // ---- A phone's camera followed a sign-in code's link here -------------------------------------------
  // The code on the sign-in screen is a link to this page, so a camera app opens it. Nothing is acted
  // on: the page offers to hand the code to the app, and only when the person taps (QRST 11.2c).

  function showHandoff() {
    const hash = location.hash.slice(1), params = new URLSearchParams(hash);
    const rest = hash.split('&').filter((part) => !part.startsWith('npub=')).join('&');
    const handoff = `${params.get('npub')}?${rest}`;
    const get = 'https://github.com/sybenx/marble/releases/latest';
    const open = el('a', { className: 'btn go linkbtn', id: 'openapp', href: /Android/i.test(navigator.userAgent)
      ? `intent://${handoff}#Intent;scheme=qrst;S.browser_fallback_url=${encodeURIComponent(get)};end` : `qrst://${handoff}` }, 'Open in Marble');
    const here = el('button', { className: 'linkish', id: 'here', type: 'button', on: { click: () => { history.replaceState(null, '', location.pathname); showLogin(); } } }, 'Sign in on this device instead');
    app.replaceChildren(el('div', { className: 'signin' },
      el('div', { className: 'title' }, el('h1', { style: 'font-size:26px' }, 'Sign in'), el('div', { className: 'dim' }, location.host)),
      el('div', { className: 'panel' }, el('div', { className: 'half scan' },
        el('h2', {}, 'Finish in Marble'),
        el('div', { className: 'sub dim', style: 'font-size:14px;line-height:1.45' }, 'You scanned a sign-in code with your camera. Marble is the app that signs you in with it.'),
        open,
        el('a', { className: 'small', id: 'getapp', href: get, rel: 'noopener' }, 'Get Marble'))),
      here));
  }
  const fromCamera = () => { const h = location.hash; return window.top === window.self && /[#&]p=signer-ticket(&|$)/.test(h) && /[#&]npub=npub1/.test(h) && /[#&]v=/.test(h); };

  // ---- Signing in ------------------------------------------------------------------------------------

  async function showLogin(message) {
    leave(); stopTimers(); section = 'home'; flash = null; dropPointer(); ptrAsk = null; boxLogin = null; house = null; dropHouseScan();
    const scan = el('div', { className: 'kk', id: 'scan' });
    const err = el('p', { className: 'err small', role: 'alert', hidden: !message }, message ?? '');
    const user = el('input', { className: 'field', type: 'text', id: 'username', autocomplete: 'username', autocapitalize: 'none', spellcheck: false, required: true });
    const pass = el('input', { className: 'field', type: 'password', id: 'password', autocomplete: 'current-password', required: true });
    const btn = el('button', { className: 'btn go', type: 'submit', id: 'pwgo' }, 'Sign in');
    const form = el('form', { style: 'display:flex;flex-direction:column;gap:12px', on: { submit: async (e) => {
      e.preventDefault(); err.hidden = true; btn.disabled = true; btn.textContent = 'Checking…';
      try {
        const u = user.value.trim().toLowerCase();
        const s = await api('pw_salt', { username: u });
        const r = s.salt ? await api('pw_login', { username: u, verifier: await verifier(pass.value, s.salt) }) : s;
        if (r.ok) return afterSignIn(null);
        err.textContent = r.error === 'locked' ? `Too many wrong tries. Try again in ${Math.ceil(r.wait / 60)} minutes.` : say(r.error); err.hidden = false;
      } catch (x) { err.textContent = x.message === 'insecure' ? 'Password sign-in only works when this page is opened over https. Scan the code with your phone instead.' : say('no_box'); err.hidden = false; }
      btn.disabled = false; btn.textContent = 'Sign in';
    } } }, el('label', { htmlFor: 'username' }, 'Username'), user, el('label', { htmlFor: 'password' }, 'Password'), pass, btn);

    const pkErr = el('p', { className: 'err small', role: 'alert', hidden: true });
    const pk = passkeysHere() ? el('button', { className: 'btn go', type: 'button', id: 'pkgo', on: { click: async () => {
      pk.disabled = true; pkErr.hidden = true;
      try {
        const r = await usePasskey();
        if (r.ok) return afterSignIn(null);
        pkErr.textContent = r.error === 'wrong' ? 'That passkey is not one this account knows.' : say(r.error);
      } catch (x) { pkErr.textContent = pkError(x); }
      pkErr.hidden = false; pk.disabled = false;
    } } }, 'Sign in with a passkey') : null;
    app.replaceChildren(el('div', { className: 'signin' }, asking(), addAsking(),
      el('div', { className: 'title' }, el('h1', { style: 'font-size:26px' }, 'Sign in'), el('div', { className: 'dim' }, location.host)),
      pk ? el('div', { className: 'card', id: 'pkcard' }, pk, pkErr) : null,
      el('div', { className: 'panel' },
        el('div', { className: 'half scan' }, el('h2', {}, /Android|iPhone|iPad/i.test(navigator.userAgent) ? 'Use this phone' : 'Scan with your phone'), scan),
        el('div', { className: 'rule' }),
        el('div', { className: 'half' }, el('h2', {}, 'Or use your password'), err, form,
          el('div', { className: 'small dim', style: 'line-height:1.45' }, 'Your password signs you in fully. A few things that cannot be undone still ask for a Yes on one of your devices.'))),
      el('div', { className: 'small dim' }, 'Your account never leaves your phone. This page only asks it who you are.')));

    // The same sign-in any site uses: the phone scans the code, and then proves who it is by signing a
    // one-time challenge from the box. A code lasts a few minutes, so a new one is drawn when it runs out.
    let run = null, live = true;
    const onPhone = /Android|iPhone|iPad/i.test(navigator.userAgent);
    leave = () => { live = false; run?.cancel(); };
    const begin = async () => {
      if (!live) return;
      const c = await api('signin_start').catch(() => ({ error: 'no_box' }));
      if (!live) return;
      if (!c.ok) { scan.replaceChildren(el('p', { className: 'err small', role: 'alert' }, say(c.error))); return void setTimeout(begin, 5000); }
      if (onPhone) {
        // Marble is on this very phone: a button that opens it, since a phone cannot scan its own screen.
        const l = KeykinSignIn.link({ relays: c.relays, name: 'Your account', account: true });
        run = l;
        scan.replaceChildren(
          el('a', { className: 'btn go linkbtn', id: 'withapp', href: l.uri }, 'Sign in with Marble'),
          el('p', { className: 'kk-dim' }, 'Marble opens. Say yes there, then come back to this page.'),
          el('a', { className: 'small', id: 'getapp', href: 'https://github.com/sybenx/marble/releases/latest', rel: 'noopener' }, 'Get Marble'));
      } else {
        // No "Sign in?" question here: the phone already asked, and the box checks the phone's signature before it lets this browser in.
        run = KeykinSignIn.start(scan, { relays: c.relays, ask: false, account: true, words: {
          scan: 'Open Marble on your phone and scan this.',
          digits: 'Your phone shows five digits. They should be:', differ: 'If they differ, say no on your phone.',
        } });
      }
      try {
        const { signer } = await run.done;
        if (onPhone) scan.replaceChildren(el('p', { className: 'kk-dim' }, 'Signing in…'));
        const event = await signer.signEvent({ kind: 22242, created_at: Math.floor(Date.now() / 1000), tags: [['relay', location.origin], ['challenge', c.challenge]], content: '' });
        const r = await api('signin', { event });
        if (!live || !r.ok) signer.close().catch(() => {});
        if (!live) return;
        if (r.ok) { live = false; leave = () => {}; return afterSignIn(signer); }
        scan.replaceChildren(el('p', { className: 'err small', role: 'alert' }, say(r.error)));
      } catch (x) { if (!live) return; }
      setTimeout(begin, 2500);          // cancelled, ran out or failed: the widget has said why; then a fresh code
    };
    begin();
  }

  // ---- Signed in, but this server does not hold the account yet --------------------------------------

  function showNew(r) {
    const out = el('button', { className: 'linkish', id: 'signout', on: { click: async () => { await api('logout').catch(() => {}); showLogin(); } } }, 'Sign out');
    const body = el('div', { className: 'half scan', id: 'newbody' });
    const start = () => {
      const go = el('button', { className: 'btn go', id: 'protect', type: 'button' }, 'Protect this account');
      go.onclick = async () => {
        go.disabled = true;
        const p = await api('protect').catch(() => ({ error: 'no_box' }));
        if (p.error === 'login') return showLogin(say('login'));
        if (!p.ok) { go.disabled = false; return void note.replaceChildren(say(p.error)); }
        const qr = el('div', { className: 'qr', role: 'img', ariaLabel: 'Code to scan' }); qr.innerHTML = p.svg;      // made by this page's own server
        body.replaceChildren(el('h2', {}, 'Scan with your phone'), qr,
          el('div', { className: 'sub dim', style: 'font-size:14px;line-height:1.45' }, 'Open Marble on your phone and scan this. This page moves on when it is done.'),
          el('details', { className: 'small' }, el('summary', { className: 'dim' }, 'No camera? Copy the code as text'), el('p', { className: 'mono small', id: 'protecttext' }, p.text)));
      };
      const note = el('p', { className: 'err small', role: 'alert' });
      body.replaceChildren(
        el('h2', {}, 'You are signed in'),
        el('div', { className: 'mono small', id: 'who' }, r.npubText.slice(0, 16) + '…' + r.npubText.slice(-6)),
        el('div', { className: 'sub dim', style: 'font-size:14px;line-height:1.45' }, r.open
          ? 'This server does not look after your account yet. When it does, a lost phone can be blocked, you can see everything that is signed in, and you can sign in here with a password.'
          : 'This server does not look after your account yet. Its owner has to let you in first.'),
        r.open ? go : null, note);
    };
    start();
    app.replaceChildren(el('div', { className: 'signin' }, asking(), addAsking(),
      el('div', { className: 'title' }, el('h1', { style: 'font-size:26px' }, 'Your account'), el('div', { className: 'dim' }, location.host)),
      el('div', { className: 'panel' }, body), out));
    every(3000, async () => {
      const n = await api('me').catch(() => null);
      if (n && n.ok && n.held !== false) { if (pending() || pendingAdd()) afterSignIn(null); else showAccount(); }
      else if (n && n.error === 'login') showLogin(say('login'));
    });
  }

  // ---- The account -----------------------------------------------------------------------------------

  // ---- Shared home: the DMs home this box is the back room of (me.home, from KEYKIN_HOME_URL) ------------
  // The page calls the home (bothy, NIP-86) and its file server (/manage) itself, each call signed by the phone
  // a scan left here (kind 27235). Without that signer it asks for a scan: once each visit, by design.
  const K = globalThis.KeykinHome;
  let house = null;              // { phase, info, role, list, names, usage, bin, sinfo, linked, notes, adv, ask, line, busy }
  const houseSigner = () => (ptr?.npub === me?.npub ? ptr.signer : null);
  const nameOf = (pk) => (pk === me?.npub ? 'You' : house?.names?.[pk]?.name) || (house?.adv ? K.short(pk) : 'Someone');
  const withName = (pk) => (pk === me?.npub ? 'you' : nameOf(pk));
  function houseFail(x) {
    if (x?.message === 'no answer' || x?.status === 0) return 'Your home cannot be reached right now.';
    if (x?.status === 429) return 'Too many changes at once. Wait a few seconds and try again.';
    if (x?.status === 503) return 'The file server on your box is not set up yet.';
    if (/did not|rejected|denied|timed? ?out|cancel/i.test(String(x?.message))) return 'Your phone did not sign that. Is Marble still open there?';
    return String(x?.message ?? x);
  }
  // The scan widget is kept across redraws (the page redraws every 15 seconds), so a code being scanned is not torn down.
  let houseScan = null;
  function houseScanNode() {
    if (houseScan) return houseScan.node;
    const node = el('div', { className: 'kk', id: 'housescan' });
    const onPhone = /Android|iPhone|iPad/i.test(navigator.userAgent);
    const relays = me.relays ?? [];
    let run;
    if (onPhone) {
      run = KeykinSignIn.link({ relays, name: 'Your account', account: true });
      node.append(el('a', { className: 'btn go linkbtn', id: 'housewithapp', href: run.uri }, 'Open Marble'),
        el('p', { className: 'kk-dim' }, 'Say yes there, then come back to this page.'));
    } else run = KeykinSignIn.start(node, { relays, ask: false, account: true, words: { scan: 'Open Marble on your phone and scan this.', digits: 'Your phone shows five digits. They should be:', differ: 'If they differ, say no on your phone.' } });
    const npub = me.npub;
    houseScan = { node, run };
    run.done.then(async ({ signer }) => {
      houseScan = null;
      if (me?.npub !== npub || (await signer.getPublicKey()) !== npub) { signer.close().catch(() => {}); house = { ...house, line: 'That phone is signed in to a different account.' }; return draw(); }
      holdPointer(npub, ptr?.npub === npub ? ptr.found : { state: 'checking' }, signer, relays);
      loadHouse();
    }).catch(() => { houseScan = null; if (section === 'house') draw(); });
    return node;
  }
  const dropHouseScan = () => { houseScan?.run.cancel(); houseScan = null; };

  /** Everything the section shows, in as few signatures as the calls allow. */
  async function loadHouse() {
    const h = me.home, signer = houseSigner();
    house = { ...(house ?? {}), phase: 'loading', line: null };
    if (section === 'house') draw();
    try {
      const info = await K.homeInfo(h.url);
      const owner = info.pubkey, mine = owner === me.npub;
      const c = (m, p) => K.call(signer, h.url, m, p);
      const role = mine ? 'owner' : (await c('myrole', [])).role;
      if (role !== 'owner' && role !== 'admin') { house = { ...house, phase: 'none', info, role }; return draw(); }
      // File servers are a list (one today, more boxes later), each with its own usage, bin and key.
      const quiet = (p) => p.catch((x) => ({ failed: x }));
      const urls = houseFiles();
      const [list, linked, ...per] = await Promise.all([
        c('listmembers', []),
        role === 'owner' ? quiet(c('getstorage', [])) : null,
        ...urls.map((u) => Promise.all([quiet(K.call(signer, K.manageUrl(u), 'usage', [])), quiet(K.call(signer, K.manageUrl(u), 'bin', [])), quiet(K.storageInfo(u))])),
      ]);
      const files = urls.map((url, i) => { const [usage, bin, sinfo] = per[i]; return { url, usage, bin, sinfo }; });
      const t = K.tree(owner, list);
      house = { ...house, phase: 'ready', info, role, owner, list, tree: t, linked, files, names: house.names ?? {} };
      draw();
      // Names and photos come after, from the home itself: a home may ask the phone to sign in to read them.
      // Then, for anyone still nameless, the relays this page reads the account's own profile from (wss only, inside
      // the page's CSP). What was found is kept for the visit, and nobody is looked up twice.
      const all = [...new Set([owner, ...K.everyone(t).map((n) => n.pubkey), ...(list.removed ?? []).map((r) => r.pubkey), ...files.flatMap((f) => K.binByPerson(f.bin?.failed ? null : f.bin).map((g) => g.pubkey)).filter(Boolean)])];
      const looked = house.looked ?? (house.looked = new Set());
      const pks = all.filter((pk) => !looked.has(pk));
      if (!pks.length) return;
      const redraw = () => { if (house?.phase === 'ready' && section === 'house' && !document.querySelector('[data-busy]')) draw(); };
      const relay = K.relayOf(h.url);
      const fromHome = K.profiles(await K.readProfiles(relay, pks, (ch) => signer.signEvent(K.authFor(relay, ch))));
      if (house?.phase !== 'ready') return;
      house.names = { ...house.names, ...fromHome }; redraw();
      const missing = pks.filter((pk) => !house.names[pk]?.name);
      const elsewhere = (me.relays ?? []).filter((r) => /^wss:\/\//.test(r) || /^ws:\/\/(127\.0\.0\.1|localhost)[:/]/.test(r));
      if (missing.length && elsewhere.length) {
        const found = K.profiles((await Promise.all(elsewhere.map((r) => K.readProfiles(r, missing, null)))).flat());
        if (house?.phase !== 'ready') return;
        for (const [pk, p] of Object.entries(found)) if (!house.names[pk]?.name || (!house.names[pk]?.picture && p.picture)) house.names[pk] = { name: house.names[pk]?.name || p.name, picture: house.names[pk]?.picture || p.picture };
      }
      pks.forEach((pk) => looked.add(pk));
      redraw();
    } catch (x) {
      house = { ...house, phase: 'error', line: houseFail(x) };
      draw();
    }
  }
  /** One change: sign it, say what happened, then read the home again so the page shows what bothy now says. */
  async function houseDo(button, run, done) {
    const hold = button?.closest('.card'); hold?.setAttribute('data-busy', '1');
    if (button) button.disabled = true;
    try {
      const r = await run();
      house.ask = null; flash = typeof done === 'function' ? done(r) : done;
    } catch (x) { flash = houseFail(x); }
    hold?.removeAttribute('data-busy');
    await loadHouse();
    window.scrollTo(0, 0);
  }
  const bothy = (m, p) => K.call(houseSigner(), me.home.url, m, p);
  const store_ = (url, m, p) => K.call(houseSigner(), K.manageUrl(url), m, p);
  /** The home's file servers: a list, so a second box is one more entry. */
  const houseFiles = () => me.home.files ?? (me.home.storage ? [me.home.storage] : []);
  /** What each person stores, over every file server that answered: {pubkey: {used, blobs}}. */
  function storedBy() {
    const out = {};
    for (const f of house.files ?? []) for (const [pk, a] of Object.entries(K.usedBy(f.usage?.failed ? null : f.usage))) out[pk] = { used: (out[pk]?.used ?? 0) + (a.used ?? 0), blobs: (out[pk]?.blobs ?? 0) + (a.blobs ?? 0) };
    return out;
  }
  const anyUsage = () => (house.files ?? []).some((f) => f.usage && !f.usage.failed);

  function face(pk) {
    const pic = house.names?.[pk]?.picture, n = nameOf(pk);
    return pic ? el('img', { className: 'avatar small', src: pic, alt: '', referrerPolicy: 'no-referrer' })
      : el('div', { className: 'avatar small', ariaHidden: 'true' }, (n === 'Someone' ? '?' : n).charAt(0).toUpperCase());
  }
  function personRow({ node: n, depth }) {
    const pk = n.pubkey, used = storedBy()[pk];
    const can = K.removal(n, me.npub, house.role), kids = K.below(n).length;
    const asking = house.ask?.pk === pk;
    const by = n.invitedBy && n.invitedBy !== n.pubkey && K.find(house.tree, n.invitedBy) ? withName(n.invitedBy) : null;
    const waiting = typeof n.waiting === 'number' && n.waiting > 0 ? `${K.plural(n.waiting, 'message')} waiting` : null;
    const bits = [K.howCame(n, by), n.joinedAt ? `${n.legacy ? 'Joined' : 'joined'} ${day(n.joinedAt)}` : null, K.seenWords(n), kids ? `invited ${K.plural(n.kids.length, 'person', 'people')}` : null,
      n.role === 'owner' && !used ? null : used?.used ? `${K.size(used.used)} stored` : anyUsage() ? 'Nothing stored' : null, waiting].filter(Boolean);
    const named = pk === me.npub || !!house.names?.[pk]?.name;
    const adv = house.adv ? el('div', { className: 'detail tech' }, [K.npub(pk), n.source ? `source ${n.source}` : null, used ? `${used.blobs} files` : null, typeof n.push === 'boolean' ? (n.push ? 'has notifications' : 'no notifications') : null].filter(Boolean).join(' · ')) : null;
    const sw = n.role === 'owner' ? null : el('label', { className: 'toggle', title: 'Sees where photos were taken' },
      el('input', { type: 'checkbox', checked: !!n.close, ariaLabel: `${nameOf(pk)} sees where photos were taken`, on: { change: (e) => { const on = e.currentTarget.checked; houseDo(e.currentTarget, () => bothy('setclose', [pk, on]), `${nameOf(pk)} ${on ? 'now sees' : 'no longer sees'} where photos were taken.`); } } }),
      'Sees where photos were taken');
    const rm = can.remove ? el('button', { className: 'btn', ariaLabel: `Remove ${nameOf(pk)}`, on: { click: () => { house.ask = { pk }; draw(); } } }, 'Remove')
      : can.why ? el('span', { className: 'detail', title: can.why }, can.why) : null;
    const row = el('div', { className: 'row person', style: `padding-left:${Math.min(depth, 6) * 24}px` },
      face(pk), el('div', { className: 'grow' }, el('div', { className: 'name' }, nameOf(pk), named || house.adv ? null : el('span', { className: 'idtail', title: 'The end of their key' }, K.tail(pk)), n.role === 'admin' ? el('span', { className: 'tag' }, 'Admin') : null), el('div', { className: 'detail' }, bits.join(' · ')), adv),
      sw, asking ? null : rm);
    row.dataset.pk = pk;
    if (!asking) return row;
    const w = K.removeWords(nameOf(pk), n.kids);
    const names = n.kids.map((k) => nameOf(k.pubkey));
    const go = (invitees, label) => el('button', { className: 'btn', id: invitees === 'remove' ? 'houseremoveall' : 'houseremovekeep', on: { click: (e) => houseDo(e.currentTarget, () => bothy('unallowpubkey', [pk, { invitees }]),
      (r) => `${nameOf(pk)} is no longer in the home.${invitees === 'keep' && n.kids.length ? ` ${K.plural(n.kids.length, 'person', 'people')} they invited stay.` : ''}`) } }, label);
    return el('div', {}, row, el('div', { className: 'subcard', id: 'houseask', style: `margin:0 0 14px ${Math.min(depth, 6) * 24}px` },
      el('div', {}, w.ask), names.length ? el('div', { className: 'detail' }, names.join(', ')) : null,
      el('div', { className: 'with-note' }, go('keep', w.keep), w.branch && can.branch ? go('remove', w.branch) : null,
        el('button', { className: 'btn', on: { click: () => { house.ask = null; draw(); } } }, 'Cancel')),
      w.branch && !can.branch && can.why ? el('div', { className: 'detail' }, can.why) : null,
      el('div', { className: 'detail' }, 'Their messages and photo on the home are kept 14 days, and their files 30, in case you let them back in.')));
  }
  function houseView() {
    const h = me.home;
    const top = head(house?.info?.name || 'Shared home', null);
    const advBtn = el('button', { className: 'go-link linkish', id: 'houseadv', on: { click: () => { house = { ...(house ?? {}), adv: !house?.adv }; draw(); } } }, house?.adv ? 'Hide advanced' : 'Advanced');
    if (!houseSigner()) {
      return [top, card(el('h2', {}, 'Scan with your phone to manage your home'),
        el('div', { className: 'sub' }, 'Changes here are signed by your phone, so this page asks for a scan each visit.'),
        house?.line ? el('p', { className: 'err small', role: 'alert' }, house.line) : null, houseScanNode())];
    }
    dropHouseScan();
    if (!house || house.phase === 'loading') return [top, card(el('div', { className: 'sub', id: 'houseloading' }, 'Asking your phone and your home…'))];
    if (house.phase === 'error') return [top, card(el('p', { className: 'err', role: 'alert' }, house.line), el('div', {}, el('button', { className: 'btn', on: { click: () => loadHouse() } }, 'Try again')))];
    if (house.phase === 'none') return [top, card(el('div', { className: 'sub', id: 'housenone' }, 'This account is not the owner or an admin of this home, so there is nothing to manage here.'))];

    const t = house.tree, files = house.files ?? [], stored = storedBy(), now = Date.now() / 1000;
    const all = [...K.flat(t), ...(t.old ?? []).flatMap((n) => K.flat(n, 1))];
    // No name yet: people with no name or photo anywhere, nothing stored and nobody under them, once their names were
    // looked for. They sit apart, oldest first, so the people Aaron knows are easy to read.
    const looked = house.looked ?? new Set();
    const nameless = (n) => n.role === 'member' && !n.kids.length && looked.has(n.pubkey) && !house.names?.[n.pubkey]?.name && !house.names?.[n.pubkey]?.picture && !(stored[n.pubkey]?.used > 0);
    const quiet = all.filter((r) => nameless(r.node)).map((r) => ({ node: r.node, depth: 1 })).sort((a, b) => (a.node.joinedAt ?? 0) - (b.node.joinedAt ?? 0));
    const hide = new Set(quiet.map((r) => r.node.pubkey));
    const tree = K.flat(t).filter((r) => !hide.has(r.node.pubkey)), old = (t.old ?? []).flatMap((n) => K.flat(n, 1)).filter((r) => !hide.has(r.node.pubkey));
    const removed = house.list.removed ?? [];
    const answered = files.filter((f) => f.usage && !f.usage.failed);
    const homeBytes = answered.reduce((s, f) => s + (f.usage.total?.bytes ?? 0), 0);
    const denied = files.some((f) => f.usage?.failed?.status === 401), down = files.some((f) => f.usage?.failed && f.usage.failed.status !== 401);
    const storageNote = house.role === 'admin' && denied ? 'Space and the bin show here for the owner. The file server does not know the admins yet.' : down ? 'The file server cannot be reached right now.' : null;
    const sub = [K.plural(all.length, 'person', 'people'), answered.length ? `${K.size(homeBytes)} of photos and files` : null].filter(Boolean).join(' · ');
    const out = [head(house.info.name || 'Shared home', sub)];
    const heading = (id, title, line) => el('div', { className: 'oldhead', id }, el('h3', {}, title), el('div', { className: 'detail' }, line));

    // People: the invite tree, then rows from before it, then people with no name yet.
    out.push(el('div', { className: 'card rows', id: 'housepeople' }, el('h2', { style: 'padding:16px 0 4px' }, 'People'), tree.map(personRow),
      old.length ? heading('houseold', 'Added before invites', 'They joined before the home kept who invited whom.') : null, old.map(personRow),
      quiet.length ? heading('housequiet', 'No name yet', `${K.plural(quiet.length, 'person', 'people')} with no name or photo, who have stored nothing. Oldest first.`) : null, quiet.map(personRow)));
    const back = removed.filter((r) => !r.deletesAt || r.deletesAt > now);
    if (back.length) out.push(card(el('h2', {}, 'Recently removed'),
      el('div', { className: 'sub' }, 'They can come back with their messages and files until the date shown.'),
      el('div', { className: 'rows', id: 'houseremoved' }, back.map((r) => el('div', { className: 'row wrap' }, face(r.pubkey),
        el('div', { className: 'grow' }, el('div', { className: 'name' }, nameOf(r.pubkey)), el('div', { className: 'detail' }, `Removed ${day(r.removedAt)}${r.deletesAt ? `, gone after ${day(r.deletesAt)}` : ''}${typeof r.waiting === 'number' && r.waiting > 0 ? ` · ${K.plural(r.waiting, 'message')} waiting` : ''}`),
          house.adv ? el('div', { className: 'detail tech' }, K.npub(r.pubkey)) : null),
        el('button', { className: 'btn', ariaLabel: `Let ${nameOf(r.pubkey)} back in`, on: { click: (e) => houseDo(e.currentTarget, () => bothy('allowpubkey', [r.pubkey]), `${nameOf(r.pubkey)} is back in the home.`) } }, 'Let back in'))))));

    // Space: what the home stores first, then the room left on each box. Never the disk's other contents.
    if (answered.length) {
      const free = answered.map((f) => ({ f, free: f.usage.disk?.free })).filter((x) => typeof x.free === 'number');
      const room = free.reduce((s, x) => s + x.free, 0), pct = homeBytes + room ? Math.max(homeBytes ? 1 : 0, Math.round(100 * homeBytes / (homeBytes + room))) : 0;
      const by = Object.entries(stored).filter(([, a]) => a.used > 0).sort((a, b) => b[1].used - a[1].used);
      const host = (u) => { try { return new URL(u).host; } catch { return u; } };
      out.push(card(el('h2', {}, 'Space'),
        el('div', { className: 'sub', id: 'housespace' }, el('strong', {}, `Photos and files: ${K.size(homeBytes)}`)),
        free.length ? el('div', { className: 'detail', id: 'housefree' }, free.length === 1 ? `${K.size(free[0].free)} free on your box.` : free.map((x) => `${K.size(x.free)} free on ${host(x.f.url)}`).join(' · ')) : null,
        free.length ? el('div', { className: 'bar', role: 'img', ariaLabel: `Photos and files use ${pct}% of the room they have` }, el('div', { style: `width:${pct}%` })) : null,
        el('div', { className: 'rows' }, by.map(([pk, a]) => el('div', { className: 'row' }, face(pk), el('div', { className: 'grow' }, nameOf(pk)), el('div', { className: 'detail' }, K.size(a.used)))))));
    }

    // The bin, from each file server that answered.
    const owner = house.role === 'owner';
    const bins = files.filter((f) => f.bin && !f.bin.failed);
    if (bins.length) {
      const rows = bins.flatMap((f) => {
        const groups = K.binByPerson(f.bin), parked = f.bin.parked ?? [];
        const run = (m, list) => async () => { let n = 0; for (const c of K.chunks(list)) n += (await store_(f.url, m, [c]))?.[m === 'restore' ? 'restored' : 'erased'] ?? 0; return n; };
        return [
          ...groups.map((g) => el('div', { className: 'row wrap' }, g.pubkey ? face(g.pubkey) : el('div', { className: 'avatar small' }, '?'),
            el('div', { className: 'grow' }, el('div', { className: 'name' }, g.pubkey ? nameOf(g.pubkey) : 'People no longer here'),
              el('div', { className: 'detail' }, `${K.plural(g.items.length, 'file')}, ${K.size(g.bytes)}${g.erasesAt ? `, erased on ${day(g.erasesAt)}` : ''}${g.pubkey ? '' : '. Restoring gives them to you.'}`),
              house.adv ? el('div', { className: 'detail tech' }, g.items.map((x) => `${x.sha256} ${K.size(x.size)}`).join('\n')) : null),
            el('button', { className: 'btn', ariaLabel: `Restore ${nameOf(g.pubkey)}'s files`, on: { click: (e) => houseDo(e.currentTarget, run('restore', g.items.map((x) => x.sha256)), (n) => `${K.plural(n, 'file')} restored.`) } }, 'Restore'),
            owner ? el('button', { className: 'btn', ariaLabel: `Erase ${nameOf(g.pubkey)}'s files now`, on: { click: (e) => { if (confirm(`Erase ${K.plural(g.items.length, 'file')} now? This cannot be undone.`)) houseDo(e.currentTarget, run('erase', g.items.map((x) => x.sha256)), (n) => `${K.plural(n, 'file')} erased.`); } } }, 'Erase now') : null)),
          ...parked.map((p) => el('div', { className: 'row wrap' }, face(p.pubkey), el('div', { className: 'grow' }, el('div', { className: 'name' }, nameOf(p.pubkey)),
            el('div', { className: 'detail' }, `${K.plural(p.blobs ?? 0, 'file')}, ${K.size(p.bytes ?? 0)}. ${p.reason === 'erased' ? 'They deleted their account.' : `Comes back if you let ${nameOf(p.pubkey)} back in${p.erasesAt ? ` before ${day(p.erasesAt)}` : ''}.`}`)),
            p.reason === 'erased' ? null : el('button', { className: 'btn', ariaLabel: `Let ${nameOf(p.pubkey)} back in`, on: { click: (e) => houseDo(e.currentTarget, () => bothy('allowpubkey', [p.pubkey]), `${nameOf(p.pubkey)} is back in the home. Their files come back within a few minutes.`) } }, 'Let back in'))),
        ];
      });
      out.push(card(el('h2', {}, 'Bin'), el('div', { className: 'sub' }, 'Files people deleted or left behind are kept 30 days, then erased.'),
        rows.length ? null : el('div', { className: 'detail', id: 'housebinempty' }, 'The bin is empty.'),
        el('div', { className: 'rows', id: 'housebin' }, rows),
        bins.some((f) => f.bin.more) ? el('div', { className: 'detail', id: 'housebinmore' }, 'The bin holds more files than this page shows. These are the newest.') : null));
    }
    if (storageNote) out.push(card(el('div', { className: 'sub', id: 'housestoragenote' }, storageNote)));

    // File server: the owner links a box's file server to the home, after seeing its key. Plain when all is well.
    const ln = house.linked?.failed ? null : house.linked;
    const isLinked = (f) => { const si = f.sinfo?.failed ? null : f.sinfo; return !!(ln && si && ln.pubkey === si.pubkey && ln.url?.replace(/\/+$/, '') === f.url); };
    if (owner && files.length) {
      const parts = [el('h2', {}, 'File server')];
      if (files.some(isLinked)) parts.push(el('div', { className: 'sub', id: 'houselinked' }, 'Photos and files are kept on your box.'));
      else for (const f of files) {
        const si = f.sinfo?.failed ? null : f.sinfo, follows = si && (!si.home || K.sameHome(si.home, me.home.url));
        if (!si) parts.push(el('div', { className: 'sub' }, 'Your box’s file server cannot be reached right now.'));
        else if (!follows) parts.push(el('div', { className: 'sub err', id: 'housewronghome' }, 'Your box’s file server is set up for a different home, so it cannot be linked to this one. Its home setting needs changing on your box first.'));
        else if (house.ask?.link === f.url) parts.push(el('div', { className: 'subcard', id: 'houselinkask' },
          el('div', {}, 'Your box’s file server has this key:'), el('div', { className: 'mono', id: 'housekey' }, K.npub(si.pubkey)),
          el('div', { className: 'detail' }, 'Check it matches the key Keykin Storage printed when it started (in its logs on your box), then link it.'),
          el('div', { className: 'with-note' }, el('button', { className: 'btn go', id: 'houselinkgo', on: { click: (e) => houseDo(e.currentTarget, () => bothy('setstorage', [f.url, si.pubkey]), 'Linked. Photos and files are kept on your box.') } }, 'Link'),
            el('button', { className: 'btn', on: { click: () => { house.ask = null; draw(); } } }, 'Cancel'))));
        else parts.push(el('div', { className: 'sub' }, ln?.url ? 'Your home keeps photos and files somewhere else.' : 'Photos and files are not kept on your box yet.'),
          el('div', {}, el('button', { className: 'btn go', id: 'houselink', on: { click: () => { house.ask = { link: f.url }; draw(); } } }, 'Keep photos and files on your box')));
      }
      out.push(card(...parts));
    }

    // Advanced: everything technical, in one place, and unlinking.
    if (house.adv) {
      const lines = [`Home: ${me.home.url}`, `Owner: ${K.npub(house.owner)}`, `You are the ${house.role}.`,
        ...files.map((f) => { const si = f.sinfo?.failed ? null : f.sinfo; return `File server: ${f.url}${si ? `, key ${K.npub(si.pubkey)}, follows ${si.home ?? 'no home'}` : ', not answering'}`; }),
        ...(owner ? [ln?.url ? `The home names ${ln.url} as its file server, key ${K.npub(ln.pubkey)}.` : 'The home names no file server.'] : [])];
      out.push(card(el('h2', {}, 'Advanced'), el('div', { className: 'detail tech', id: 'houseaddr' }, lines.join('\n')),
        owner && ln?.url ? el('div', {}, el('button', { className: 'btn', id: 'houseunlink', on: { click: (e) => {
          if (confirm('Unlink the file server from the home? New photos and files then go only to the public mirror. Nothing already stored is deleted, and you can link it again.')) houseDo(e.currentTarget, () => bothy('setstorage', ['']), 'Unlinked. New photos and files go only to the public mirror.');
        } } }, 'Unlink file server')) : null));
    }
    out.push(el('div', {}, advBtn));
    return out;
  }

  const SECTIONS = [['home', 'Home'], ['house', 'Shared home'], ['devices', 'Devices'], ['sites', 'Sites and apps'], ['security', 'Security'], ['backup', 'Backup'], ['activity', 'Recent activity']];

  async function showAccount() {
    leave(); stopTimers();
    const r = await api('me').catch(() => ({ error: 'no_box' }));
    if (!r.ok) return showLogin(r.error === 'login' ? undefined : say(r.error));
    if (r.held === false) return showNew(r);
    me = r; checkPointer(); draw();
    every(15000, async () => {
      const n = await api('me').catch(() => null);
      if (n && n.ok) { me = n; if (!document.querySelector('[data-busy]') && !document.querySelector('input:focus, textarea:focus')) draw(); }
      else if (n && n.error === 'login') showLogin(say('login'));
    });
  }
  const refresh = async () => { const n = await api('me').catch(() => null); if (n && n.ok) me = n; };
  async function go(name) { section = name; flash = null; if (name === 'security') await refresh(); draw(); window.scrollTo(0, 0); if (name === 'house' && houseSigner() && (!house || house.phase !== 'loading')) loadHouse(); }
  async function act(button, call, more, done) {
    button.disabled = true;
    const r = await api(call, more).catch(() => ({ error: 'no_box' }));
    if (r.error === 'login') return showLogin(say('login'));
    flash = r.ok ? done : say(r.error);
    await refresh(); draw();
  }

  // A site's two switches beside Posts only (SPEC 11.5), where the device that let it in has them. A change
  // waits at the box until that device picks it up. Posts only already stops both, so they are off then.
  const SWITCHES = [['lists', 'Private lists', 'Let it read your private lists', 'read your private lists'], ['dms', 'DMs', 'Let it read and send your direct messages', 'read and send DMs']];
  function scopeSwitches(g) {
    if (g.kind !== 'site') return [];
    const site = g.name.replace(/^https?:\/\//, ''), posts = g.limit === 'posts';
    return SWITCHES.filter(([k]) => typeof g[k] === 'boolean').map(([k, label, title, what]) =>
      el('label', { className: 'toggle', title: posts ? 'Posts only is on, so it cannot read anything. Turn Posts only off first.' : title },
        el('input', { type: 'checkbox', checked: globalThis.KeykinRows.scopeShown(g, k), disabled: posts, ariaLabel: `${label} for ${g.name}`, on: { change: (e) => act(e.currentTarget, 'scopes', { grant: g.id, [k]: e.currentTarget.checked },
          `${site} can ${e.currentTarget.checked ? '' : 'no longer '}${what} once ${g.deviceName} picks it up.`) } }), label));
  }

  const card = (...kids) => el('div', { className: 'card' }, kids);
  const head = (title, sub) => el('div', { className: 'head' }, el('h1', {}, title), sub ? el('div', { className: 'dim' }, sub) : null);
  const link = (text, to) => el('button', { className: 'go-link linkish', on: { click: () => go(to) } }, text);

  function draw() {
    const devices = me.devices.filter((d) => d.kind === 'device'), blocked = me.devices.filter((d) => d.blocked), can = devices.filter((d) => !d.blocked);
    const name = me.username ?? me.npubText.slice(0, 12) + '…';
    const sections = {
      home: () => {
        // What can sign: any two pieces do. The account outlives losing one of them only with three or more,
        // say a second device, or another box (a backup box) next to this one.
        const boxes = me.devices.filter((d) => d.kind === 'box' && !d.blocked), others = boxes.filter((d) => d.key !== me.boxKey);
        const signers = can.length + boxes.length, backedUp = signers >= 3;
        const alert = pointerAlert(), alertUp = alert?.id === 'pointeralert';
        const fine = !blocked.length && backedUp;
        const line = blocked.length ? `${blocked.length === 1 ? '1 device is' : `${blocked.length} devices are`} blocked.`
          : !backedUp ? (can.length === 1 ? `You have one device. If ${can[0].name} is lost, the account goes with it.` : 'Your box alone cannot sign. Add a device.')
          : `${count(can.length, 'device')}${boxes.length ? ` and ${count(boxes.length, 'box', 'boxes')}` : ''} can sign, nothing is blocked.`;
        const mine = devices.map((d) => d.name), names = [...mine, ...others.map((d) => d.name), 'Box'];
        const sites = me.grants.map((g) => g.name.replace(/^https?:\/\//, ''));
        const backup = [can.length >= 2 ? (can.length === 2 ? 'a second device' : `${can.length - 1} more devices`) : null,
          others.length ? (others.length === 1 ? `another box (${others[0].name})` : `${others.length} more boxes`) : null].filter(Boolean);
        return [
          alert,
          stickCard(),
          el('div', { className: 'hello' }, el('div', { className: 'avatar', ariaHidden: 'true' }, (me.username ?? 'k').charAt(0).toUpperCase()),
            el('div', {}, el('h1', {}, me.username ? `Welcome, ${cap(me.username)}` : 'Welcome'), el('div', { className: 'mono dim', id: 'npub' }, me.npubText))),
          // With an alert up, the alert is the status: no line here that could say otherwise.
          alertUp ? null : el('div', { className: 'card statusline', id: 'statusline' }, shield(fine),
            el('div', { className: 'grow' }, el('strong', {}, fine ? 'Everything looks fine. ' : 'One thing to look at. '), line)),
          el('div', { className: 'grid2' },
            card(el('h2', {}, 'Devices'), el('div', { className: 'sub' }, `${[...mine, ...others.map((d) => d.name)].length ? [...mine, ...others.map((d) => d.name)].join(', ') + ' and your box' : 'Your box'}. Any two of them sign together.`),
              el('div', { className: 'chips' }, names.map((n) => el('span', { className: 'chip' }, n))), link('Manage devices', 'devices')),
            card(el('h2', {}, 'Sites and apps'), el('div', { className: 'sub' }, me.grants.length ? `${me.grants.length} ${me.grants.length === 1 ? 'is' : 'are'} signed in with your account. Revoke any of them here, from anywhere.` : 'Nothing is signed in with your account.'),
              sites.length ? el('div', { className: 'chips' }, sites.slice(0, 2).map((n) => el('span', { className: 'chip' }, n)), sites.length > 2 ? el('span', { className: 'chip' }, `+${sites.length - 2}`) : null) : null,
              link('See what is signed in', 'sites')),
            card(el('h2', {}, 'Security'), el('div', { className: 'sub' }, me.username ? 'Password set. It signs you in here fully. Forming the whole key stays in the app.' : 'No password yet.'), link('Password and sign-in', 'security')),
            card(el('h2', {}, 'Backup'), el('div', { className: 'sub', id: 'backupsub' }, backedUp
              ? `Backed up by ${backup.join(' and ')}. If one device is lost, the others still sign.`
              : 'No backup yet. If your only device is lost, your box alone cannot bring the account back.'), link(backedUp ? 'See your devices' : 'Set up a backup', backedUp ? 'devices' : 'backup'))),
          ptr?.npub === me.npub && mineHere(ptr.found) ? pointerCard(ptr.found, ptr.signer, ptr.relays, (done) => { flash = done; draw(); }) : null,
        ];
      },
      devices: () => [
        head('Devices', 'Each one holds a piece of your key. Any two sign together. One alone can do nothing.'),
        el('div', { className: 'card rows' }, [...devices, ...me.devices.filter((d) => d.kind === 'box')].map((d) => el('div', { className: 'row' },
          el('div', { className: 'grow' },
            el('div', { className: 'name' }, d.name, d.blocked ? el('span', { className: 'tag bad' }, 'Blocked') : null),
            el('div', { className: 'detail' }, d.key === me.boxKey ? 'Always on · cannot be blocked here'
              : d.blocked ? `Blocked${d.blockedAt ? ' ' + day(d.blockedAt) : ''}. It can no longer sign.`
              : d.kind === 'box' ? `Another box · added ${day(d.added)}`
              : [d.fingerprint ? 'Fingerprint key' : 'No fingerprint key', `added ${day(d.added)}`, d.last ? `signed ${ago(d.last)}` : 'has not signed yet'].join(' · '))),
          d.key === me.boxKey ? null : d.blocked
            ? el('button', { className: 'btn', ariaLabel: `Unblock ${d.name}`, on: { click: (e) => act(e.currentTarget, 'unblock', { key: d.key }, `${d.name} is unblocked.`) } }, 'Unblock')
            : el('button', { className: 'btn danger', ariaLabel: `Block ${d.name}`, on: { click: (e) => { if (confirm(`Block ${d.name}? It will not be able to sign until it is unblocked.`)) act(e.currentTarget, 'block', { key: d.key }, `${d.name} is blocked.`); } } }, 'Block')))),
        el('div', { className: 'grid2' },
          card(el('h2', {}, 'Add a device'), el('div', { className: 'sub' }, 'Paste the new device’s invite here. One of your devices adds it.'),
            noteForm({ kind: 'invite', keep: 600, label: 'Invite from the new device', placeholder: 'Paste the invite', button: 'Send to phone', waiting: 'Waiting for one of your devices…',
              // A pasted invite has no verifier behind it, so these six digits alone let it in (SPEC 11.6): give them only to it.
              done: (result, g) => el('div', { style: 'display:flex;flex-direction:column;gap:8px' }, el('div', { className: 'sub' }, 'Added. Give the new device this join code:'), el('div', { className: 'dashed has', id: 'joincode' }, result),
                g?.approval ? el('div', { className: 'sub', id: 'pastecode' }, 'Then type this only into the new device, once, within 10 minutes: ', el('strong', { className: 'mono' }, spaced(g.approval.short))) : null) })),
          card(el('h2', {}, 'Remove blocked devices for good'), el('div', { className: 'sub' }, 'A blocked device still holds its old piece. Removing makes that piece useless. Your npub does not change.'),
            blocked.length ? noteForm({ kind: 'cycle', button: `Remove ${blocked.length} ${blocked.length === 1 ? 'device' : 'devices'}`, plain: true, needs: 'Asks for a Yes on one of your devices', waiting: 'Waiting for a Yes on one of your devices…',
              done: () => { flash = 'Blocked devices are removed for good.'; refresh().then(draw); return el('div', { className: 'sub' }, 'Removed.'); } })
              : el('div', { className: 'with-note' }, el('button', { className: 'btn', disabled: true }, 'Nothing to remove')))),
        signingCard()],
      sites: () => [
        head('Sites and apps', 'Everything that can sign as you. Revoking here stops it at the box, even if the device that let it in is off.'),
        el('div', { className: 'card rows' }, me.grants.length ? globalThis.KeykinRows.grantOrder(me.grants).map(siteRow)
          : el('div', { className: 'row' }, el('div', { className: 'grow dim' }, 'Nothing is signed in.'))),
        link('Sign in to another app', 'home')],
      security: () => [
        head('Security', 'How you get in to this page, and what still asks a device.'),
        card(el('h2', {}, 'Password'), el('div', { className: 'sub' }, me.username ? ['Your username is ', el('strong', {}, me.username), '. Typing a new password here replaces the old one. Your account always keeps one.'] : 'Choose a username and a password. Once set, it can be changed but not removed.'), passwordForm()),
        passkeysCard(),
        card(el('h2', {}, 'What asks for a Yes on a device'),
          el('div', { className: 'sub' }, 'Signing in here, with your password or a device, lets you do everything on this page. A few things are hard to undo, so a device of yours shows a Yes or No first. No signs that browser out.'),
          el('ul', { className: 'plain' }, ['Removing blocked devices for good', 'Forming the whole key', 'Asking every relay to erase the account', 'Deleting five or more posts at once', 'Emptying your profile or your follow list'].map((t) => el('li', {}, t)))),
        browsersCard()],
      backup: () => [
        head('Backup', 'What brings the account back if devices are lost.'),
        card(el('h2', {}, 'A second device'), el('div', { className: 'sub' }, 'The backup that works today is another device. Any two pieces sign, so a second phone, a tablet or a computer keeps the account alive if one is lost.'), link('Add a device', 'devices')),
        card(el('h2', {}, 'The whole key'), el('div', { className: 'sub' }, 'A device can form the whole key, to write down or to use in an app that needs it. Do that in the app. Anyone who gets it controls the account for good, so keep it offline.')),
        card(el('h2', {}, 'Paper backup and undo'), el('div', { className: 'sub' }, 'Not available yet.'))],
      house: () => (me.home ? houseView() : []),
      activity: () => [
        head('Recent activity', 'What happened to this account at the box.'),
        el('div', { className: 'card rows' }, me.log.length ? me.log.map((l) => el('div', { className: 'row' }, el('div', { className: 'grow' }, l.text), el('div', { className: 'detail' }, ago(l.at))))
          : el('div', { className: 'row' }, el('div', { className: 'grow dim' }, 'Nothing yet.')))],
    };

    app.replaceChildren(
      el('div', { className: 'top' }, el('div', { className: 'brand' }, 'Your account'),
        el('div', { className: 'who' }, el('span', {}, `${name} · signed in with ${HOW[me.how] ?? 'a device'}`),
          el('button', { className: 'go-link linkish', style: 'margin:0', on: { click: async () => { await api('logout'); showLogin(); } } }, 'Sign out'))),
      el('div', { className: 'shell' },
        el('nav', { ariaLabel: 'Sections' }, SECTIONS.filter(([id]) => id !== 'house' || me.home).map(([id, label]) => el('button', { ariaCurrent: section === id ? 'page' : 'false', on: { click: () => go(id) } }, label))),
        el('main', {}, flash ? el('div', { className: 'notice', id: 'status', role: 'status' }, flash) : null, noPassword(), sections[section]())));
  }
  // Recent signing (SPEC 11.6): which two pieces made each signature or message key. Today only the box's own help.
  let allSigned = false;
  function signingCard() {
    const rows = me.signed ?? [], shown = allSigned ? rows : rows.slice(0, 15);
    return el('div', { className: 'card', id: 'signing' }, el('h2', {}, 'Recent signing'),
      el('div', { className: 'sub' }, 'Every signature takes two pieces. These are the ones your box helped with. Signatures two devices make without the box are not listed yet.'),
      el('div', { className: 'signed' }, shown.length ? shown.map((r) => {
        const { who, detail } = globalThis.KeykinRows.signedRow(r, me.boxKey, me.grants);
        return el('div', { className: 'row' }, el('div', { className: 'grow' }, el('div', { className: 'name' }, who), el('div', { className: 'detail' }, detail)));
      }) : el('div', { className: 'row' }, el('div', { className: 'grow dim' }, 'Nothing signed yet.'))),
      rows.length > shown.length ? el('button', { className: 'go-link linkish', on: { click: () => { allSigned = true; draw(); } } }, `Show all ${rows.length}`) : null);
  }
  // An account made before setup asked for a password has none: say so on every section until it is set (SPEC 11.3).
  function noPassword() {
    if (!me.held || me.username) return null;
    return el('div', { className: 'notice', id: 'nopw', role: 'status' }, NO_PASSWORD, ' ',
      section === 'security' ? null : el('button', { className: 'go-link linkish', style: 'margin:0', on: { click: () => go('security') } }, 'Set a password'));
  }

  const shield = (ok) => {
    const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    for (const [k, v] of Object.entries({ width: 22, height: 22, viewBox: '0 0 24 24', fill: 'none', stroke: ok ? 'var(--accent)' : 'var(--danger)', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) s.setAttribute(k, v);
    for (const d of ['M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6z', ok ? 'M9 12l2 2 4-4' : 'M12 8v5M12 16h.01']) { const p = document.createElementNS('http://www.w3.org/2000/svg', 'path'); p.setAttribute('d', d); s.append(p); }
    return s;
  };

  // What a device handed back that the person still has to copy (a bunker link, a join code), kept for a while.
  // The page redraws every 15 seconds, and without this the answer was wiped soon after it came.
  const kept = new Map();
  const keptOf = (kind) => { const k = kept.get(me.npub + '/' + kind); if (k && k.until > Date.now()) return k.result; kept.delete(me.npub + '/' + kind); return null; };
  // Something this page starts and a device finishes: leave a note, then wait for a device to answer it.
  function noteForm(o) {
    const box = el('div', { style: 'display:flex;flex-direction:column;gap:10px' });
    const had = o.keep ? keptOf(o.kind) : null;
    if (had !== null) { box.append(o.done(had.result, had.g)); return box; }
    const input = o.label ? el('input', { className: 'field', type: 'text', ariaLabel: o.label, placeholder: o.placeholder ?? '' }) : null;
    const btn = el('button', { className: o.plain ? 'btn' : 'btn go' }, o.button);
    const line = el('span', { className: 'small dim', role: 'status' }, o.needs ?? '');
    btn.addEventListener('click', async () => {
      const text = input ? input.value : '';
      const bad = input && (!text.trim() ? 'Paste it first.' : o.check ? o.check(text) : null);
      if (bad) { line.textContent = bad; return; }
      btn.disabled = true; box.dataset.busy = '1';
      const r = await api('note_put', { kind: o.kind, text: text.trim() }).catch(() => ({ error: 'no_box' }));
      if (r.error === 'login') return showLogin(say('login'));
      if (!r.ok) { btn.disabled = false; delete box.dataset.busy; line.textContent = say(r.error); return; }
      line.textContent = o.waiting;
      const t = every(2000, async () => {
        const g = await api('note_get', { note: r.note }).catch(() => null);
        if (g && g.error === 'login') { clearInterval(t); return showLogin('A device said No, so this browser was signed out.'); }
        if (!g || !g.ok || g.state === 'waiting') return;
        clearInterval(t); delete box.dataset.busy;
        if (g.state === 'done' && o.keep) kept.set(me.npub + '/' + o.kind, { result: { result: g.result, g }, until: Date.now() + o.keep * 1000 });
        if (g.state === 'done') { const old = document.getElementById('status'); if (old) old.remove(); flash = null; box.replaceChildren(o.done(g.result, g)); }
        else { line.textContent = 'No device answered in time. Is one of them online?'; btn.disabled = false; }
      });
    });
    const controls = el('div', { className: 'with-note' }, btn, line);
    box.append(...(input ? (o.stacked ? [input, controls] : [el('div', { className: 'inline' }, input, btn), line]) : [controls]));
    return box;
  }
  // One row of Sites and apps: what it is, how it came in, Posts only, Revoke. The connect card shows the same row.
  function siteRow(g) {
    const host = g.name.replace(/^https?:\/\//, '');
    return el('div', { className: 'row' },
      el('div', { className: 'grow' }, el('div', { className: 'name' }, host),
        el('div', { className: 'detail' }, globalThis.KeykinRows.siteDetail(g))),
      el('label', { className: 'toggle', title: 'Let it post, repost and react, and nothing else. It cannot read your messages.' },
        el('input', { type: 'checkbox', checked: g.limit === 'posts', ariaLabel: `Posts only for ${g.name}`, on: { change: (e) => act(e.currentTarget, 'limit', { grant: g.id, to: e.currentTarget.checked ? 'posts' : null },
          e.currentTarget.checked ? `${host} can only post now.` : `${host} can do everything again.`) } }), 'Posts only'),
      ...scopeSwitches(g),
      el('button', { className: 'btn danger', ariaLabel: `Revoke ${g.name}`, on: { click: (e) => act(e.currentTarget, 'revoke', { grant: g.id }, `${host} is revoked.`) } }, 'Revoke'));
  }

  // ---- Connect a site: one connection, two ends -------------------------------------------------------
  // A site either wants a link your end makes (bunker://, pasted into the site) or shows a code it made
  // (nostrconnect://, pasted here). The card draws both as the two ends of one stick. Where it is lives here,
  // per account, so the 15-second redraw and a section switch draw the same thing again. The link itself is
  // kept 900 s in `kept`, as before.
  const sticks = new Map(), WAIT_MS = 15 * 60 * 1000;
  const freshStick = () => ({ dir: 'link', lp: 'idle', cp: 'idle', done: false, grant: null, before: [], since: 0, linkNote: null, codeNote: null,
    code: '', name: '', codeSite: null, lists: false, dms: false, err: '', codeErr: '', busy: false, tick: null });
  const stickOf = () => { let s = sticks.get(me.npub); if (!s) sticks.set(me.npub, s = freshStick()); return s; };
  const typing = () => document.querySelector('input:focus, textarea:focus');
  const restick = () => { const n = document.getElementById('stick'); if (n) n.replaceWith(stickCard()); };
  // Connected: the whole section is drawn again, so the new row shows in Sites and apps too.
  const stickMoved = (full) => { if (full && !typing() && !document.querySelector('[data-busy]:not(#stick)')) draw(); else restick(); };
  const newGrantOf = (s, grants) => {
    const fresh = grants.filter((g) => !s.before.includes(g.id));
    return fresh.find((g) => g.via === 'bunker') ?? fresh.find((g) => g.kind === 'site') ?? null;
  };
  // One timer per card state: waits for the device's answer, then for the site to show up as a grant.
  function stickTick(s) {
    if (s.tick && timers.includes(s.tick)) return;
    const t = s.tick = every(3000, async () => {
      const stop = () => { clearInterval(t); if (s.tick === t) s.tick = null; };
      if (!me || s !== sticks.get(me.npub)) return stop();
      const note = s.lp === 'making' ? s.linkNote : s.cp === 'sending' ? s.codeNote : null;
      if (note) {
        const g = await api('note_get', { note }).catch(() => null);
        if (g && g.error === 'login') { stop(); return showLogin('A device said No, so this browser was signed out.'); }
        if (!g || !g.ok || g.state === 'waiting') return;
        if (note === s.linkNote && s.lp === 'making') {
          if (g.state === 'done') { kept.set(me.npub + '/bunker', { result: { result: g.result, g }, until: Date.now() + 900 * 1000 }); s.lp = 'waiting'; s.since = Date.now(); }
          else { s.lp = 'idle'; s.err = 'No device answered in time. Is one of them online?'; }
        } else if (note === s.codeNote && s.cp === 'sending') {
          if (g.state === 'done') { s.cp = 'idle'; s.code = ''; s.done = true; s.since = Date.now(); }     // its row shows up a few seconds later
          else { s.cp = 'idle'; s.codeErr = 'No device answered in time. Is one of them online?'; }
        }
        return stickMoved(s.done);
      }
      const looking = !s.grant && (s.done || s.lp === 'waiting');
      if (!looking) return stop();
      if (Date.now() - s.since > WAIT_MS) {
        stop();
        if (!s.done) { s.lp = 'idle'; s.err = 'Nothing used the link in 15 minutes. Make a new one if you still need it.'; kept.delete(me.npub + '/bunker'); restick(); }
        return;
      }
      const n = await api('me').catch(() => null);
      if (!n || !n.ok || s !== sticks.get(n.npub)) return;
      me = n;
      const g = newGrantOf(s, n.grants);
      if (!g) return;
      stop(); s.grant = g.id; s.done = true; stickMoved(true);
    });
  }
  async function makeLink(s, button) {
    s.err = ''; s.busy = true; button.disabled = true; button.closest('#stick')?.setAttribute('data-busy', '1');
    s.before = me.grants.map((g) => g.id);
    // The name the site goes by, for its grant: the site that sent you here, or what was typed.
    const name = (cameFrom()?.host ?? s.name.trim()).slice(0, 100);
    const r = await api('note_put', { kind: 'bunker', text: name, ...(s.lists ? { lists: true } : {}), ...(s.dms ? { dms: true } : {}) }).catch(() => ({ error: 'no_box' }));
    s.busy = false;
    if (r.error === 'login') return showLogin(say('login'));
    if (!r.ok) { s.err = say(r.error); return restick(); }
    s.linkNote = r.note; s.lp = 'making'; restick(); stickTick(s);
  }
  async function sendCode(s, button, err) {
    const t = s.code.trim();
    const bad = !t ? 'Paste the site\'s code first.'
      : t.startsWith('bunker://') ? 'That is a link for the site, not a code from it. Paste it in the site instead.'
      : !t.startsWith('nostrconnect://') ? 'The site\'s code starts with nostrconnect://' : null;
    if (bad) { s.codeErr = bad; err.textContent = bad; return; }
    s.codeErr = ''; s.busy = true; button.disabled = true; button.closest('#stick')?.setAttribute('data-busy', '1');
    s.before = me.grants.map((g) => g.id);
    const r = await api('note_put', { kind: 'nostrconnect', text: t }).catch(() => ({ error: 'no_box' }));
    s.busy = false;
    if (r.error === 'login') return showLogin(say('login'));
    if (!r.ok) { s.codeErr = say(r.error); return restick(); }
    const c = readConnect(t); s.codeSite = c ? (c.name ?? c.host) : null;
    s.codeNote = r.note; s.dir = 'code'; s.cp = 'sending'; restick(); stickTick(s);
  }
  const globe = () => {
    const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    for (const [k, v] of Object.entries({ width: 22, height: 22, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 1.6, 'aria-hidden': 'true' })) s.setAttribute(k, v);
    for (const d of ['M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18z', 'M3 12h18', 'M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9s1.3-6.4 3.8-9z']) { const p = document.createElementNS('http://www.w3.org/2000/svg', 'path'); p.setAttribute('d', d); s.append(p); }
    return s;
  };
  function stickCard() {
    const s = stickOf(), came = cameFrom();
    const link = keptOf('bunker')?.result ?? null;
    if (s.lp === 'waiting' && !link) s.lp = 'idle';
    const grant = s.grant ? me.grants.find((g) => g.id === s.grant) ?? null : null;
    // The name a pasted code gives itself counts too, so the card says Jumble at once, not "The site" until its row comes.
    const site = () => came?.host ?? (s.name.trim() || s.codeSite || (grant ? grant.name.replace(/^https?:\/\//, '') : null));
    const Site = () => site() ?? 'The site', theSite = () => site() ?? 'the site';
    const phase = () => s.done ? 'done' : s.dir === 'link' ? s.lp : s.cp;
    // Words that follow the "Which site?" field as it is typed, without drawing the field again.
    const words = [];
    let bodyWords = [];
    const live = (list) => (tag, props, f) => { const n = el(tag, props, f()); list.push(() => n.replaceChildren(f())); return n; };
    const top = live(words);

    const which = el('input', { className: 'field', id: 'whichsite', type: 'text', placeholder: 'e.g. iris', autocomplete: 'off', spellcheck: false, value: s.name,
      on: { input: (e) => { s.name = e.currentTarget.value.slice(0, 100); [...words, ...bodyWords].forEach((f) => f()); } } });
    const whichBox = el('div', { className: 'which' }, el('label', { htmlFor: 'whichsite' }, 'Which site?'), which);
    const siteEnd = el('div', { className: 'end' },
      top('div', { className: 'ball', ariaHidden: 'true' }, () => site() ? site().charAt(0).toUpperCase() : globe()),
      top('div', { className: 'endname', id: 'sitename' }, () => site() ?? 'A site'), whichBox);
    const youEnd = el('div', { className: 'end' },
      el('div', { className: 'ball', ariaHidden: 'true' }, (me.username ?? 'k').charAt(0).toUpperCase()),
      el('div', { className: 'endname' }, 'You'), el('div', { className: 'small dim' }, me.username ?? me.npubText.slice(0, 10) + '…'));
    const chip = top('span', { className: 'onwire', id: 'stickchip' }, () => phase() === 'done' ? '✓ connected'
      : s.dir === 'link' ? (s.lp === 'making' ? 'making…' : '← your link') : `${site() ?? 'site'}'s code →`);
    const stick = el('div', { className: 'stick', id: 'stickrow' }, siteEnd, el('div', { className: 'wire' }, chip, el('span', { className: 'runner', ariaHidden: 'true' })), youEnd);
    words.push(() => {
      const p = phase();
      stick.dataset.dir = s.dir; stick.dataset.phase = p;
      siteEnd.classList.toggle('held', p === 'done' || s.dir === 'code');
      youEnd.classList.toggle('held', p === 'done' || s.dir === 'link');
    });
    const title = top('h2', { id: 'sticktitle' }, () => s.done ? `${Site()} is connected` : site() ? `Connect ${site()} to your account` : 'Connect a site to your account');

    // What the site may do besides signing, chosen before the link is made. Off unless switched on.
    const opts = el('div', { className: 'stickopts' });
    const toggle = (k, text) => el('label', { className: 'toggle' },
      el('input', { type: 'checkbox', id: 'stick' + k, checked: s[k], on: { change: (e) => { s[k] = e.currentTarget.checked; } } }), text);

    const body = el('div', { className: 'stickbody' });
    const flipTo = (to, text) => (list) => live(list)('button', { className: 'go-link linkish small flip', id: to === 'code' ? 'flipcode' : 'fliplink', type: 'button',
      on: { click: () => { s.dir = to; s.err = ''; s.codeErr = ''; paint(); } } }, text);
    const linkBody = (w) => {
      const say_ = live(w);
      const slot = el('div', { className: 'dashed' + (link ? ' has' : ''), id: 'bunkerlink' }, link ?? (s.lp === 'making' ? 'Your phone is making the link…' : 'Your link shows up here.'));
      const out = [say_('div', { className: 'sub', id: 'stickline' }, () => `${Site()} asked for a link, so your end makes one. Paste it into ${theSite()}'s sign-in box.`), slot];
      if (s.lp === 'idle') out.push(el('div', { className: 'with-note' }, el('button', { className: 'btn go', id: 'makelink', type: 'button', on: { click: (e) => makeLink(s, e.currentTarget) } }, 'Make a link')),
        // Most sites show a nostrconnect:// code instead: the box for it is right here, not behind a switch.
        live(w)('div', { className: 'sub', id: 'orcode' }, () => `Or, if ${theSite()} shows a nostrconnect:// code, paste it here.`), ...pasteBox(false));
      if (s.lp === 'waiting' && link) {
        const copy = el('button', { className: 'btn go', id: 'copylink', type: 'button' }, 'Copy link');
        copy.onclick = async () => { try { await navigator.clipboard.writeText(link); copy.textContent = 'Copied'; } catch { getSelection()?.selectAllChildren(slot); } };
        out.push(el('div', { className: 'with-note' }, copy),
          say_('div', { className: 'sub', id: 'stickwait', role: 'status' }, () => `Waiting for ${theSite()} to use it. You can go back to ${theSite()} now.`));
      }
      if (s.err) out.push(el('p', { className: 'err small', role: 'alert', id: 'stickerr' }, s.err));
      if (s.lp !== 'idle') out.push(flipTo('code', () => `${Site()} showed a code instead? Paste it here`)(w));
      return out;
    };
    // The site's nostrconnect:// code and Connect: on the link side before a link is made, and on the code side.
    const pasteBox = (sending) => {
      const err = el('p', { className: 'err small', role: 'alert', id: 'codeerr' }, s.codeErr);
      const ta = el('textarea', { className: 'field mono', id: 'sitecode', rows: 3, placeholder: 'nostrconnect://…', ariaLabel: 'The site\'s code', spellcheck: false, value: s.code, disabled: sending,
        on: { input: (e) => { s.code = e.currentTarget.value; s.codeErr = ''; err.textContent = ''; } } });
      const go = el('button', { className: 'btn go', id: 'stickgo', type: 'button', disabled: sending, on: { click: (e) => sendCode(s, e.currentTarget, err) } }, 'Connect');
      return [ta, el('div', { className: 'with-note' }, go), err];
    };
    const codeBody = (w) => {
      const sending = s.cp === 'sending';
      return [live(w)('div', { className: 'sub', id: 'stickline', role: 'status' }, () => sending ? `Your phone is answering ${theSite()}.` : `${Site()} made the code, so your end takes it. Paste it here.`),
        ...pasteBox(sending), flipTo('link', () => `${Site()} wants a link instead? Make one`)(w)];
    };
    const doneBody = () => [
      el('div', { className: 'sub', id: 'stickline' }, 'It signs as you now. It lives in Sites and apps, where you can limit or revoke it.'),
      grant ? el('div', { className: 'rows', id: 'stickgrant' }, siteRow(grant)) : null,
      came ? el('a', { href: came.origin + '/', id: 'stickback', rel: 'noopener' }, `Back to ${came.host}`) : null,
      el('button', { className: 'go-link linkish small flip', id: 'stickagain', type: 'button',
        on: { click: () => { sticks.set(me.npub, freshStick()); kept.delete(me.npub + '/bunker'); restick(); } } }, 'Connect another site')];
    const paint = () => {
      words.forEach((f) => f());
      whichBox.hidden = !!came || s.done || (s.dir === 'link' && s.lp !== 'idle');
      const fixed = [s.lists ? 'Can read private lists' : null, s.dms ? 'Can read and send DMs' : null].filter(Boolean);
      opts.replaceChildren(...(s.done || s.dir !== 'link' ? [] : s.lp === 'idle' ? [toggle('lists', 'Read your private lists'), toggle('dms', 'Read and send DMs')]
        : fixed.map((t) => el('span', { className: 'small dim' }, t))));
      opts.hidden = !opts.childElementCount;
      bodyWords = [];
      body.replaceChildren(...(s.done ? doneBody() : s.dir === 'link' ? linkBody(bodyWords) : codeBody(bodyWords)).filter(Boolean));   // a missing part is left out, not drawn as "null"
    };
    const node = el('div', { className: 'card stickcard', id: 'stick' },
      came ? el('div', { className: 'small dim', id: 'camefrom' }, `You came from ${came.host}`) : null, title, stick, opts, body);
    if (s.busy || (!s.done && (s.lp === 'making' || s.cp === 'sending'))) node.dataset.busy = '1';
    paint();
    if (s.lp === 'making' || s.cp === 'sending' || (!s.grant && (s.done || s.lp === 'waiting'))) stickTick(s);
    return node;
  }
  // ---- Signed-in browsers (SPEC 11.6) -----------------------------------------------------------------
  function browserOf(agent) {
    const a = agent ?? '';
    const b = /Edg(e|A|iOS)?\//.test(a) ? 'Edge' : /OPR\/|Opera/.test(a) ? 'Opera' : /SamsungBrowser/.test(a) ? 'Samsung Internet' : /Firefox\/|FxiOS/.test(a) ? 'Firefox'
      : /Chrome\/|CriOS|Chromium/.test(a) ? 'Chrome' : /Safari\//.test(a) ? 'Safari' : null;
    const os = /Windows/.test(a) ? 'Windows' : /Android/.test(a) ? 'Android' : /iPhone/.test(a) ? 'iPhone' : /iPad/.test(a) ? 'iPad' : /CrOS/.test(a) ? 'ChromeOS'
      : /Macintosh|Mac OS X/.test(a) ? 'macOS' : /Linux/.test(a) ? 'Linux' : null;
    return b && os ? `${b} on ${os}` : b ?? (os ? `A browser on ${os}` : 'A browser');
  }
  const shortDay = (t) => new Date(t * 1000).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
  const dayWord = (t) => {
    const d = new Date(t * 1000), today = new Date(), y = new Date(Date.now() - 86400000);
    return d.toDateString() === today.toDateString() ? 'today' : d.toDateString() === y.toDateString() ? 'yesterday' : shortDay(t);
  };
  const HOW_SHORT = { password: 'password', passkey: 'passkey', scan: 'scan' };
  function browsersCard() {
    const list = me.browsers ?? [];
    const out = async (b, button) => {
      button.disabled = true;
      const r = await api('logout_browser', { id: b.id }).catch(() => ({ error: 'no_box' }));
      if (r.error === 'login' || r.this) return showLogin(r.this ? undefined : say('login'));
      flash = r.ok ? `${browserOf(b.agent)} is signed out.` : say(r.error);
      await refresh(); draw();
    };
    return card(el('h2', {}, 'Signed-in browsers'),
      el('div', { className: 'sub' }, me.how === 'passkey'
        ? 'This browser signed in with a passkey. It stays signed in while you use it, and signs out after 90 days unused.'
        : `This browser signed in with ${HOW[me.how] ?? 'a device'}. It signs out 12 hours after signing in.`),
      list.length ? el('div', { className: 'rows', id: 'browsers' }, list.map((b) => el('div', { className: 'row' },
        el('div', { className: 'grow' }, el('div', { className: 'name' }, browserOf(b.agent), b.this ? el('span', { className: 'tag' }, 'This browser') : null),
          el('div', { className: 'detail' }, [HOW_SHORT[b.how] ?? b.how, `signed in ${shortDay(b.made)}`, `last used ${dayWord(b.last)}`].join(' · '))),
        el('button', { className: 'btn', ariaLabel: `Sign out ${browserOf(b.agent)}${b.this ? ', this browser' : ''}`, 'data-browser': b.id, on: { click: (e) => out(b, e.currentTarget) } }, 'Sign out')))) : null,
      el('div', { className: 'with-note' },
        el('button', { className: 'btn', id: 'signout', on: { click: async () => { await api('logout'); showLogin(); } } }, 'Sign out here'),
        el('button', { className: 'btn', id: 'signoutall', on: { click: async () => { await api('logout_all'); showLogin(); } } }, 'Sign out everywhere')));
  }
  function passkeysCard() {
    const list = me.passkeys ?? [];
    const line = el('span', { className: 'small dim', role: 'status' });
    const add = passkeysHere() ? el('button', { className: 'btn go', id: 'addpk', on: { click: async () => {
      add.disabled = true; line.textContent = '';
      try {
        const r = await addPasskey();
        if (r.error === 'login') return showLogin(say('login'));
        if (r.ok) { flash = 'Passkey saved.'; await refresh(); return draw(); }
        line.textContent = say(r.error);
      } catch (x) { line.textContent = pkError(x); }
      add.disabled = false;
    } } }, 'Save a passkey') : null;
    return card(el('h2', {}, 'Passkeys'),
      el('div', { className: 'sub' }, list.length ? 'A passkey signs you in here with one tap. Each works on the page it was made on.' : 'No passkey yet. One lets you sign in here with one tap.'),
      list.length ? el('div', { className: 'rows' }, list.map((p) => el('div', { className: 'row' },
        el('div', { className: 'grow' }, el('div', { className: 'name' }, `Passkey for ${p.host}`), el('div', { className: 'detail' }, [`added ${day(p.added)}`, p.last ? `used ${ago(p.last)}` : 'not used yet'].join(' · '))),
        el('button', { className: 'btn danger', ariaLabel: `Remove passkey ${p.id.slice(0, 8)}`, on: { click: (e) => { if (confirm('Remove this passkey? It will no longer sign you in here.')) act(e.currentTarget, 'pk_remove', { id: p.id }, 'Passkey removed.'); } } }, 'Remove')))) : null,
      el('div', { className: 'with-note' }, add, line));
  }
  function passwordForm() {
    const user = el('input', { className: 'field', type: 'text', id: 'newuser', autocomplete: 'username', autocapitalize: 'none', spellcheck: false, value: me.username ?? '' });
    const pass = el('input', { className: 'field', type: 'password', id: 'newpass', autocomplete: 'new-password' });
    const again = el('input', { className: 'field', type: 'password', id: 'newpass2', autocomplete: 'new-password' });
    const line = el('span', { className: 'small dim', role: 'status' });
    const save = el('button', { className: 'btn go', id: 'savepw' }, me.username ? 'Change password' : 'Set password');
    save.addEventListener('click', async () => {
      if (pass.value.length < 10) { line.textContent = 'Use at least 10 characters.'; return; }
      if (pass.value !== again.value) { line.textContent = 'The two passwords do not match.'; return; }
      save.disabled = true; line.textContent = 'Saving…';
      try {
        const r = await savePassword(user.value, pass.value);
        if (r.error === 'login') return showLogin(say('login'));
        if (!r.ok) { line.textContent = say(r.error); save.disabled = false; return; }
        flash = 'Password saved.'; await refresh(); draw();
      } catch (x) { line.textContent = x.message === 'insecure' ? 'This only works when the page is opened over https.' : say('no_box'); save.disabled = false; }
    });
    return el('div', { style: 'display:flex;flex-direction:column;gap:10px;max-width:420px' }, el('label', { htmlFor: 'newuser' }, 'Username'), user, el('label', { htmlFor: 'newpass' }, 'New password'), pass,
      el('label', { htmlFor: 'newpass2' }, 'New password again'), again,
      el('div', { className: 'with-note' }, save, line));
  }

  freshVisit(); noteCameFrom(); takeConnect(); takeAdd();
  // Come back to this tab from the app's page (the browser may restore it as it was, "Opening …"): show the six
  // digits kept for it, in case the way back failed.
  addEventListener('pageshow', (e) => { if (e.persisted && added() && document.getElementById('adddone')) showAdded(added()); });
  if (fromCamera()) showHandoff(); else if (pending() || pendingAdd()) afterSignIn(null); else if (added()) showAdded(added()); else showAccount();
})();
