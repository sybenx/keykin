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
    cannot_block_box: 'The box itself cannot be blocked.', too_many: 'Too many things are waiting. Try again in a few minutes.', login: 'You were signed out. Sign in again.', not_open: 'The owner of this server has to let you in first.', not_here: 'This server does not look after your account yet.', gone: 'That ran out. Try again.',
    bad_username: 'A username is 3 to 32 letters, numbers, dots, dashes or underscores, in lower case.', username_taken: 'That username is taken on this box.',
  }[code] ?? `That did not work (${code}).`);
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  let timers = [];
  const every = (ms, f) => { const t = setInterval(f, ms); timers.push(t); return t; };
  const stopTimers = () => { timers.forEach(clearInterval); timers = []; };
  let me = null, section = 'home', flash = null, leave = () => {};

  async function verifier(password, saltHex) {
    if (!crypto.subtle) throw new Error('insecure');
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
    const salt = Uint8Array.from(saltHex.match(/../g).map((b) => parseInt(b, 16)));
    return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, key, 256));
  }
  const sha256hex = async (bytes) => hex(await crypto.subtle.digest('SHA-256', bytes));
  // What the box stores for a verifier: SHA-256("keykin2-pw" ‖ verifier).
  const checkOf = async (verifierHex) => sha256hex(new Uint8Array([...new TextEncoder().encode('keykin2-pw'), ...verifierHex.match(/../g).map((b) => parseInt(b, 16))]));

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
    leave(); stopTimers(); section = 'home'; flash = null;
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
        if (r.ok) return showAccount();
        err.textContent = r.error === 'locked' ? `Too many wrong tries. Try again in ${Math.ceil(r.wait / 60)} minutes.` : say(r.error); err.hidden = false;
      } catch (x) { err.textContent = x.message === 'insecure' ? 'Password sign-in only works when this page is opened over https. Scan the code with your phone instead.' : say('no_box'); err.hidden = false; }
      btn.disabled = false; btn.textContent = 'Sign in';
    } } }, el('label', { htmlFor: 'username' }, 'Username'), user, el('label', { htmlFor: 'password' }, 'Password'), pass, btn);

    app.replaceChildren(el('div', { className: 'signin' },
      el('div', { className: 'title' }, el('h1', { style: 'font-size:26px' }, 'Sign in'), el('div', { className: 'dim' }, location.host)),
      el('div', { className: 'panel' },
        el('div', { className: 'half scan' }, el('h2', {}, 'Scan with your phone'), scan),
        el('div', { className: 'rule' }),
        el('div', { className: 'half' }, el('h2', {}, 'Or use your password'), err, form,
          el('div', { className: 'small dim', style: 'line-height:1.45' }, 'Your password signs you in fully. A few things that cannot be undone still ask for a Yes on one of your devices.'))),
      el('div', { className: 'small dim' }, 'Your account never leaves your phone. This page only asks it who you are.')));

    // The same sign-in any site uses: the phone scans the code, and then proves who it is by signing a
    // one-time challenge from the box. A code lasts a few minutes, so a new one is drawn when it runs out.
    let run = null, live = true;
    leave = () => { live = false; run?.cancel(); };
    const begin = async () => {
      if (!live) return;
      const c = await api('signin_start').catch(() => ({ error: 'no_box' }));
      if (!live) return;
      if (!c.ok) { scan.replaceChildren(el('p', { className: 'err small', role: 'alert' }, say(c.error))); return void setTimeout(begin, 5000); }
      // No "Sign in?" question here: the phone already asked, and the box checks the phone's signature before it lets this browser in.
      run = KeykinSignIn.start(scan, { relays: c.relays, ask: false, words: {
        scan: 'Open Marble on your phone and scan this.',
        digits: 'Your phone shows five digits. They should be:', differ: 'If they differ, say no on your phone.',
      } });
      try {
        const { signer } = await run.done;
        const event = await signer.signEvent({ kind: 22242, created_at: Math.floor(Date.now() / 1000), tags: [['relay', location.origin], ['challenge', c.challenge]], content: '' });
        signer.close().catch(() => {});
        const r = await api('signin', { event });
        if (!live) return;
        if (r.ok) return showAccount();
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
    app.replaceChildren(el('div', { className: 'signin' },
      el('div', { className: 'title' }, el('h1', { style: 'font-size:26px' }, 'Your account'), el('div', { className: 'dim' }, location.host)),
      el('div', { className: 'panel' }, body), out));
    every(3000, async () => {
      const n = await api('me').catch(() => null);
      if (n && n.ok && n.held !== false) showAccount();
      else if (n && n.error === 'login') showLogin(say('login'));
    });
  }

  // ---- The account -----------------------------------------------------------------------------------

  const SECTIONS = [['home', 'Home'], ['devices', 'Devices'], ['sites', 'Sites and apps'], ['security', 'Security'], ['backup', 'Backup'], ['activity', 'Recent activity']];

  async function showAccount() {
    leave(); stopTimers();
    const r = await api('me').catch(() => ({ error: 'no_box' }));
    if (!r.ok) return showLogin(r.error === 'login' ? undefined : say(r.error));
    if (r.held === false) return showNew(r);
    me = r; draw();
    every(15000, async () => {
      const n = await api('me').catch(() => null);
      if (n && n.ok) { me = n; if (!document.querySelector('[data-busy]') && !document.querySelector('input:focus')) draw(); }
      else if (n && n.error === 'login') showLogin(say('login'));
    });
  }
  const refresh = async () => { const n = await api('me').catch(() => null); if (n && n.ok) me = n; };
  function go(name) { section = name; flash = null; draw(); window.scrollTo(0, 0); }
  async function act(button, call, more, done) {
    button.disabled = true;
    const r = await api(call, more).catch(() => ({ error: 'no_box' }));
    if (r.error === 'login') return showLogin(say('login'));
    flash = r.ok ? done : say(r.error);
    await refresh(); draw();
  }

  const card = (...kids) => el('div', { className: 'card' }, kids);
  const head = (title, sub) => el('div', { className: 'head' }, el('h1', {}, title), sub ? el('div', { className: 'dim' }, sub) : null);
  const link = (text, to) => el('button', { className: 'go-link linkish', on: { click: () => go(to) } }, text);

  function draw() {
    const devices = me.devices.filter((d) => d.kind === 'device'), blocked = me.devices.filter((d) => d.blocked), can = devices.filter((d) => !d.blocked);
    const name = me.username ?? me.npubText.slice(0, 12) + '…';
    const sections = {
      home: () => {
        const fine = !blocked.length && can.length >= 2;
        const line = blocked.length ? `${blocked.length === 1 ? '1 device is' : `${blocked.length} devices are`} blocked.`
          : can.length < 2 ? 'You have one device. If it is lost, the account goes with it.' : `${can.length} devices can sign, nothing is blocked.`;
        const mine = devices.map((d) => d.name), names = [...mine, 'Box'];
        const sites = me.grants.map((g) => g.name.replace(/^https?:\/\//, ''));
        return [
          el('div', { className: 'hello' }, el('div', { className: 'avatar', ariaHidden: 'true' }, (me.username ?? 'k').charAt(0).toUpperCase()),
            el('div', {}, el('h1', {}, me.username ? `Welcome, ${cap(me.username)}` : 'Welcome'), el('div', { className: 'mono dim', id: 'npub' }, me.npubText))),
          el('div', { className: 'card statusline' }, shield(fine),
            el('div', { className: 'grow' }, el('strong', {}, fine ? 'Everything looks fine. ' : 'One thing to look at. '), line)),
          el('div', { className: 'grid2' },
            card(el('h2', {}, 'Devices'), el('div', { className: 'sub' }, `${mine.length ? mine.join(', ') + ' and your box' : 'Your box'}. Any two of them sign together.`),
              el('div', { className: 'chips' }, names.map((n) => el('span', { className: 'chip' }, n))), link('Manage devices', 'devices')),
            card(el('h2', {}, 'Sites and apps'), el('div', { className: 'sub' }, me.grants.length ? `${me.grants.length} ${me.grants.length === 1 ? 'is' : 'are'} signed in with your account. Revoke any of them here, from anywhere.` : 'Nothing is signed in with your account.'),
              sites.length ? el('div', { className: 'chips' }, sites.slice(0, 2).map((n) => el('span', { className: 'chip' }, n)), sites.length > 2 ? el('span', { className: 'chip' }, `+${sites.length - 2}`) : null) : null,
              link('See what is signed in', 'sites')),
            card(el('h2', {}, 'Security'), el('div', { className: 'sub' }, me.username ? 'Password set. It signs you in here fully. Forming the whole key stays in the app.' : 'No password. You sign in here with a device.'), link('Password and sign-in', 'security')),
            card(el('h2', {}, 'Backup'), el('div', { className: 'sub' }, 'No backup yet. If every device is lost, your box alone cannot bring the account back.'), link('Set up a backup', 'backup'))),
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
            noteForm({ kind: 'invite', label: 'Invite from the new device', placeholder: 'Paste the invite', button: 'Send to phone', waiting: 'Waiting for one of your devices…',
              done: (result) => el('div', { style: 'display:flex;flex-direction:column;gap:8px' }, el('div', { className: 'sub' }, 'Added. Give the new device this join code:'), el('div', { className: 'dashed has', id: 'joincode' }, result)) })),
          card(el('h2', {}, 'Remove blocked devices for good'), el('div', { className: 'sub' }, 'A blocked device still holds its old piece. Removing makes that piece useless. Your npub does not change.'),
            blocked.length ? noteForm({ kind: 'cycle', button: `Remove ${blocked.length} ${blocked.length === 1 ? 'device' : 'devices'}`, plain: true, needs: 'Asks for a Yes on one of your devices', waiting: 'Waiting for a Yes on one of your devices…',
              done: () => { flash = 'Blocked devices are removed for good.'; refresh().then(draw); return el('div', { className: 'sub' }, 'Removed.'); } })
              : el('div', { className: 'with-note' }, el('button', { className: 'btn', disabled: true }, 'Nothing to remove'))))],
      sites: () => [
        head('Sites and apps', 'Everything that can sign as you. Revoking here stops it at the box, even if the device that let it in is off.'),
        el('div', { className: 'card rows' }, me.grants.length ? me.grants.map((g) => el('div', { className: 'row' },
          el('div', { className: 'grow' }, el('div', { className: 'name' }, g.name.replace(/^https?:\/\//, '')),
            el('div', { className: 'detail' }, [g.kind === 'site' ? `Site · through ${g.deviceName}` : `App on ${g.deviceName}`, `since ${day(g.since)}`, g.last ? `last used ${ago(g.last)}` : 'not used yet'].join(' · '))),
          el('label', { className: 'toggle', title: 'Let it post, repost and react, and nothing else. It cannot read your messages.' },
            el('input', { type: 'checkbox', checked: g.limit === 'posts', ariaLabel: `Posts only for ${g.name}`, on: { change: (e) => act(e.currentTarget, 'limit', { grant: g.id, to: e.currentTarget.checked ? 'posts' : null },
              e.currentTarget.checked ? `${g.name.replace(/^https?:\/\//, '')} can only post now.` : `${g.name.replace(/^https?:\/\//, '')} can do everything again.`) } }), 'Posts only'),
          el('button', { className: 'btn danger', ariaLabel: `Revoke ${g.name}`, on: { click: (e) => act(e.currentTarget, 'revoke', { grant: g.id }, `${g.name.replace(/^https?:\/\//, '')} is revoked.`) } }, 'Revoke')))
          : el('div', { className: 'row' }, el('div', { className: 'grow dim' }, 'Nothing is signed in.'))),
        card(el('h2', {}, 'Sign in to a site'), el('div', { className: 'sub' }, 'No extension needed. The site gets access of its own, which you can revoke above. It works while one of your devices can answer.'),
          el('div', { className: 'grid2', style: 'gap:16px' },
            el('div', { className: 'subcard' }, el('h3', {}, 'The site shows a code'), el('div', { className: 'detail' }, 'Paste its nostrconnect:// code.'),
              noteForm({ kind: 'nostrconnect', label: 'nostrconnect code', placeholder: 'nostrconnect://…', button: 'Send to phone', stacked: true, waiting: 'Waiting for one of your devices…',
                check: (t) => t.trim().startsWith('nostrconnect://') ? null : 'That code should start with nostrconnect://', done: () => el('div', { className: 'sub' }, 'Done. Go back to the site: it is signed in.') })),
            el('div', { className: 'subcard' }, el('h3', {}, 'The site wants a link'), el('div', { className: 'detail' }, 'One of your devices makes a bunker:// link for you to paste there.'),
              bunkerBox())))],
      security: () => [
        head('Security', 'How you get in to this page, and what still asks a device.'),
        card(el('h2', {}, 'Password'), el('div', { className: 'sub' }, me.username ? ['Your username is ', el('strong', {}, me.username), '. Typing a new password here replaces the old one.'] : 'No password is set. Setting one lets you sign in here from any browser.'), passwordForm()),
        card(el('h2', {}, 'What asks for a Yes on a device'),
          el('div', { className: 'sub' }, 'Signing in here, with your password or a device, lets you do everything on this page. A few things are hard to undo, so a device of yours shows a Yes or No first. No signs that browser out.'),
          el('ul', { className: 'plain' }, ['Removing blocked devices for good', 'Forming the whole key', 'Asking every relay to erase the account', 'Deleting five or more posts at once', 'Emptying your profile or your follow list'].map((t) => el('li', {}, t)))),
        card(el('h2', {}, 'This browser'), el('div', { className: 'sub' }, `Signed in with ${me.how === 'password' ? 'a password' : 'a device'}. It lasts 12 hours.`),
          el('div', { className: 'with-note' },
            el('button', { className: 'btn', id: 'signout', on: { click: async () => { await api('logout'); showLogin(); } } }, 'Sign out'),
            el('button', { className: 'btn', on: { click: async () => { await api('logout_all'); showLogin(); } } }, 'Sign out every browser')))],
      backup: () => [
        head('Backup', 'What brings the account back if devices are lost.'),
        card(el('h2', {}, 'A second device'), el('div', { className: 'sub' }, 'The backup that works today is another device. Any two pieces sign, so a second phone, a tablet or a computer keeps the account alive if one is lost.'), link('Add a device', 'devices')),
        card(el('h2', {}, 'The whole key'), el('div', { className: 'sub' }, 'A device can form the whole key, to write down or to use in an app that needs it. Do that in the app. Anyone who gets it controls the account for good, so keep it offline.')),
        card(el('h2', {}, 'Paper backup and undo'), el('div', { className: 'sub' }, 'Not available yet.'))],
      activity: () => [
        head('Recent activity', 'What happened to this account at the box.'),
        el('div', { className: 'card rows' }, me.log.length ? me.log.map((l) => el('div', { className: 'row' }, el('div', { className: 'grow' }, l.text), el('div', { className: 'detail' }, ago(l.at))))
          : el('div', { className: 'row' }, el('div', { className: 'grow dim' }, 'Nothing yet.')))],
    };

    app.replaceChildren(
      el('div', { className: 'top' }, el('div', { className: 'brand' }, 'Your account'),
        el('div', { className: 'who' }, el('span', {}, `${name} · signed in with ${me.how === 'password' ? 'a password' : 'a device'}`),
          el('button', { className: 'go-link linkish', style: 'margin:0', on: { click: async () => { await api('logout'); showLogin(); } } }, 'Sign out'))),
      el('div', { className: 'shell' },
        el('nav', { ariaLabel: 'Sections' }, SECTIONS.map(([id, label]) => el('button', { ariaCurrent: section === id ? 'page' : 'false', on: { click: () => go(id) } }, label))),
        el('main', {}, flash ? el('div', { className: 'notice', id: 'status', role: 'status' }, flash) : null, sections[section]())));
  }

  const shield = (ok) => {
    const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    for (const [k, v] of Object.entries({ width: 22, height: 22, viewBox: '0 0 24 24', fill: 'none', stroke: ok ? 'var(--accent)' : 'var(--danger)', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' })) s.setAttribute(k, v);
    for (const d of ['M12 3l8 3v6c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V6z', ok ? 'M9 12l2 2 4-4' : 'M12 8v5M12 16h.01']) { const p = document.createElementNS('http://www.w3.org/2000/svg', 'path'); p.setAttribute('d', d); s.append(p); }
    return s;
  };

  // Something this page starts and a device finishes: leave a note, then wait for a device to answer it.
  function noteForm(o) {
    const box = el('div', { style: 'display:flex;flex-direction:column;gap:10px' });
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
        if (g.state === 'done') { const old = document.getElementById('status'); if (old) old.remove(); flash = null; box.replaceChildren(o.done(g.result)); }
        else { line.textContent = 'No device answered in time. Is one of them online?'; btn.disabled = false; }
      });
    });
    const controls = el('div', { className: 'with-note' }, btn, line);
    box.append(...(input ? (o.stacked ? [input, controls] : [el('div', { className: 'inline' }, input, btn), line]) : [controls]));
    return box;
  }
  function bunkerBox() {
    const slot = el('div', { className: 'dashed', id: 'bunkerlink' }, 'bunker://… appears here');
    const copy = el('button', { className: 'btn', hidden: true, on: { click: async () => { await navigator.clipboard.writeText(slot.textContent); copy.textContent = 'Copied'; } } }, 'Copy');
    const form = noteForm({ kind: 'bunker', button: 'Ask my phone for a link', plain: true, waiting: 'Waiting for one of your devices…',
      done: (result) => { slot.textContent = result; slot.classList.add('has'); copy.hidden = false; return copy; } });
    return el('div', { style: 'display:flex;flex-direction:column;gap:10px' }, slot, form);
  }
  function passwordForm() {
    const user = el('input', { className: 'field', type: 'text', id: 'newuser', autocomplete: 'username', autocapitalize: 'none', spellcheck: false, value: me.username ?? '' });
    const pass = el('input', { className: 'field', type: 'password', id: 'newpass', autocomplete: 'new-password' });
    const line = el('span', { className: 'small dim', role: 'status' });
    const save = el('button', { className: 'btn go', id: 'savepw' }, me.username ? 'Change password' : 'Set password');
    save.addEventListener('click', async () => {
      if (pass.value.length < 10) { line.textContent = 'Use at least 10 characters.'; return; }
      save.disabled = true; line.textContent = 'Saving…';
      try {
        const salt = hex(crypto.getRandomValues(new Uint8Array(16)));
        const r = await api('pw_set', { username: user.value.trim().toLowerCase(), salt, check: await checkOf(await verifier(pass.value, salt)) });
        if (r.error === 'login') return showLogin(say('login'));
        if (!r.ok) { line.textContent = say(r.error); save.disabled = false; return; }
        flash = 'Password saved.'; await refresh(); draw();
      } catch (x) { line.textContent = x.message === 'insecure' ? 'This only works when the page is opened over https.' : say('no_box'); save.disabled = false; }
    });
    const off = me.username ? el('button', { className: 'btn', on: { click: (e) => { if (confirm('Turn off password sign-in? You will sign in here with a device.')) act(e.currentTarget, 'pw_clear', {}, 'Password sign-in is off.'); } } }, 'Turn off password sign-in') : null;
    return el('div', { style: 'display:flex;flex-direction:column;gap:10px;max-width:420px' }, el('label', { htmlFor: 'newuser' }, 'Username'), user, el('label', { htmlFor: 'newpass' }, 'New password'), pass,
      el('div', { className: 'with-note' }, save, off, line));
  }

  if (fromCamera()) showHandoff(); else showAccount();
})();
