// The account page. It talks only to its own server (/api), which passes each call to the box. Nothing
// here can sign or change who may sign: those need a device and a fingerprint.
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
  const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
  const say = (code) => ({
    wrong: 'That username and password do not match.', slow_down: 'Too many tries. Wait a minute.', no_box: 'The box cannot be reached right now.',
    cannot_block_box: 'The box itself cannot be blocked.', too_many: 'Too many things are waiting. Try again in a few minutes.', login: 'You were signed out. Sign in again.',
  }[code] ?? `That did not work (${code}).`);
  let timers = [];
  const every = (ms, f) => { const t = setInterval(f, ms); timers.push(t); return t; };
  const stopTimers = () => { timers.forEach(clearInterval); timers = []; };

  let me = null, section = 'home';

  // ---- Signing in to the page -----------------------------------------------------------------------

  async function verifier(password, saltHex) {
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
    const salt = Uint8Array.from(saltHex.match(/../g).map((b) => parseInt(b, 16)));
    return hex(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, key, 256));
  }

  async function showLogin(message) {
    stopTimers(); section = 'home';
    const qrBox = el('div', { className: 'qr', role: 'img', ariaLabel: 'Sign-in code' });
    const qrNote = el('p', { className: 'dim small' }, 'Open your Keykin or Marble app, scan this, and approve with your fingerprint.');
    const codeText = el('p', { className: 'mono small', id: 'logintext' });
    const err = el('p', { className: 'err small', role: 'alert', hidden: !message }, message ?? '');
    const user = el('input', { type: 'text', id: 'username', autocomplete: 'username', autocapitalize: 'none', spellcheck: false, required: true });
    const pass = el('input', { type: 'password', id: 'password', autocomplete: 'current-password', required: true });
    const btn = el('button', { className: 'go', type: 'submit', id: 'pwgo' }, 'Sign in');
    const form = el('form', { on: { submit: async (e) => {
      e.preventDefault(); err.hidden = true; btn.disabled = true; btn.textContent = 'Checking…';
      try {
        const u = user.value.trim().toLowerCase();
        const s = await api('pw_salt', { username: u });
        const r = s.salt ? await api('pw_login', { username: u, verifier: await verifier(pass.value, s.salt) }) : s;
        if (r.ok) return showAccount();
        err.textContent = r.error === 'locked' ? `Too many wrong tries. Try again in ${Math.ceil(r.wait / 60)} minutes.` : say(r.error); err.hidden = false;
      } catch { err.textContent = say('no_box'); err.hidden = false; }
      btn.disabled = false; btn.textContent = 'Sign in';
    } } }, el('label', { htmlFor: 'username' }, 'Username'), user, el('label', { htmlFor: 'password' }, 'Password'), pass, btn);

    app.replaceChildren(el('div', { className: 'login' },
      el('h1', {}, 'Your Keykin account'),
      el('p', { className: 'dim' }, 'See your devices and what is signed in, and shut any of it off.'),
      el('div', { className: 'two' },
        el('div', { className: 'card' }, el('h2', {}, 'Sign in with a device'), qrNote, qrBox,
          el('details', { className: 'small' }, el('summary', { className: 'dim' }, 'No camera? Copy the code as text'), codeText)),
        el('div', { className: 'card' }, el('h2', {}, 'Or with your password'), err, form,
          el('p', { className: 'dim small', style: 'margin-top:14px' }, 'A password can look, block a device, end a sign-in and sign out. Anything that signs or adds access needs a device.')))));

    const fresh = async () => {
      const r = await api('login_start').catch(() => ({ error: 'no_box' }));
      if (!r.ok) { qrBox.replaceChildren(); qrNote.textContent = say(r.error); return null; }
      qrBox.innerHTML = r.svg; codeText.textContent = r.text;      // the svg is made by this page's own server
      return r.code;
    };
    let code = await fresh(), started = Date.now();
    every(1500, async () => {
      if (!code) return;
      if (Date.now() - started > 170000) { code = await fresh(); started = Date.now(); return; }
      const r = await api('login_wait', { code }).catch(() => null);
      if (r && r.ok && !r.waiting) showAccount();
      else if (r && r.error === 'gone') { code = await fresh(); started = Date.now(); }
    });
  }

  // ---- The account ----------------------------------------------------------------------------------

  const SECTIONS = [['home', 'Home'], ['devices', 'Devices'], ['signedin', 'Signed in'], ['sites', 'Sign in to a site'], ['security', 'Security'], ['backup', 'Backup']];

  async function showAccount() {
    stopTimers();
    const r = await api('me').catch(() => ({ error: 'no_box' }));
    if (!r.ok) return showLogin(r.error === 'login' ? undefined : say(r.error));
    me = r;
    draw();
    every(15000, async () => { const n = await api('me').catch(() => null); if (n && n.ok) { me = n; if (!document.querySelector('[data-busy]')) draw(); } else if (n && n.error === 'login') showLogin(say('login')); });
  }

  function go(name) { section = name; draw(); window.scrollTo(0, 0); }
  async function act(button, call, more, done) {
    button.disabled = true;
    const r = await api(call, more).catch(() => ({ error: 'no_box' }));
    if (r.error === 'login') return showLogin(say('login'));
    if (!r.ok) { button.disabled = false; alertLine(say(r.error)); return; }
    const n = await api('me').catch(() => null); if (n && n.ok) me = n;
    draw(); if (done) alertLine(done);
  }
  function alertLine(text) { const s = document.getElementById('status'); if (s) { s.textContent = text; s.hidden = false; } }

  function draw() {
    const name = me.username ?? me.npubText.slice(0, 14) + '…';
    const devices = me.devices.filter((d) => d.kind === 'device'), blocked = devices.filter((d) => d.blocked).length;
    const body = {
      home: () => [
        el('h1', {}, me.username ? `Hello, ${me.username}` : 'Your account'),
        el('p', { className: 'mono dim', id: 'npub' }, me.npubText),
        el('div', { className: 'tiles' },
          el('button', { className: 'tile', on: { click: () => go('devices') } }, el('div', { className: 'n' }, String(devices.length)), el('div', {}, devices.length === 1 ? 'device' : 'devices'), blocked ? el('div', { className: 'small err' }, `${blocked} blocked`) : null),
          el('button', { className: 'tile', on: { click: () => go('signedin') } }, el('div', { className: 'n' }, String(me.grants.length)), el('div', {}, me.grants.length === 1 ? 'site or app signed in' : 'sites and apps signed in')),
          el('button', { className: 'tile', on: { click: () => go('security') } }, el('div', { className: 'n' }, me.username ? 'On' : 'Off'), el('div', {}, 'Password sign-in'))),
        el('div', { className: 'card' }, el('h2', {}, 'How your account is kept'),
          el('p', {}, 'Your key is never in one place. Each device holds a piece and the box holds a piece. Any two pieces together can sign, and one alone can do nothing.'),
          el('p', { className: 'dim small' }, devices.length < 2 ? 'You have one device. If it is lost, the account is lost with it. Add a second device.' : 'With two or more devices, losing one is not the end: block it here and carry on.')),
      ],
      devices: () => [
        el('h1', {}, 'Devices'),
        el('p', { className: 'dim' }, 'Every device that holds a piece of your key.'),
        el('div', { className: 'card' }, el('ul', { className: 'rows' }, me.devices.map((d) => el('li', {},
          el('div', { className: 'grow' }, el('div', { className: 'name' }, d.name, d.kind === 'box' ? el('span', { className: 'tag' }, 'the box') : null, d.blocked ? el('span', { className: 'tag bad' }, 'blocked') : null),
            el('div', { className: 'dim small' }, `Added ${day(d.added)}`, d.kind === 'device' && !d.fingerprint ? ' · no fingerprint key' : '')),
          d.kind === 'device' && !d.blocked ? el('button', { className: 'danger', ariaLabel: `Block ${d.name}`, on: { click: (e) => {
            if (confirm(`Block ${d.name}? It will not be able to sign until a device of yours unblocks it.`)) act(e.currentTarget, 'block', { key: d.key }, `${d.name} is blocked.`);
          } } }, 'Block') : null))),
          blocked ? el('p', { className: 'dim small', style: 'margin-top:14px' }, 'To unblock a device, or to remove a blocked one for good, use the app on a device you still have. Both need your fingerprint.') : null),
        el('div', { className: 'card' }, el('h2', {}, 'Add a device'),
          el('p', { className: 'dim small' }, 'On the new device, open the app and choose to join an account. It shows an invite. Paste it here, then approve it on a device you already have.'),
          noteForm('invite', 'Invite from the new device', 'Send to my devices', (result) => el('div', {}, el('p', {}, 'Approved. Give the new device this join code:'), el('p', { className: 'mono', id: 'joincode' }, result)))),
      ],
      signedin: () => [
        el('h1', {}, 'Signed in'),
        el('p', { className: 'dim' }, 'Sites and apps that can sign as you. Ending one stops it at once, on every device.'),
        el('div', { className: 'card' }, me.grants.length ? el('ul', { className: 'rows' }, me.grants.map((g) => el('li', {},
          el('div', { className: 'grow' }, el('div', { className: 'name' }, g.name, el('span', { className: 'tag' }, g.kind === 'site' ? 'site' : 'app')),
            el('div', { className: 'dim small' }, `Since ${day(g.since)} · through ${g.deviceName}`)),
          el('button', { className: 'danger', ariaLabel: `End ${g.name}`, on: { click: (e) => act(e.currentTarget, 'revoke', { grant: g.id }, `${g.name} is signed out.`) } }, 'End'))))
          : el('p', { className: 'dim' }, 'Nothing is signed in.')),
      ],
      sites: () => [
        el('h1', {}, 'Sign in to a site'),
        el('p', { className: 'dim' }, 'For a site that offers a remote signer. A device of yours does the signing, so one has to be reachable while you use the site.'),
        el('div', { className: 'card' }, el('h2', {}, 'The site shows a code'),
          el('p', { className: 'dim small' }, 'If the site shows a code that starts with nostrconnect://, paste it here and approve it on a device.'),
          noteForm('nostrconnect', 'Code from the site', 'Send to my devices', () => el('p', {}, 'Approved. Go back to the site: it is signed in.'), (t) => t.trim().startsWith('nostrconnect://') ? null : 'That code should start with nostrconnect://')),
        el('div', { className: 'card' }, el('h2', {}, 'The site asks for a link'),
          el('p', { className: 'dim small' }, 'If the site asks for a bunker link, get one here and paste it into the site.'),
          noteForm('bunker', null, 'Get a bunker link', (result) => {
            const b = el('button', { on: { click: async () => { await navigator.clipboard.writeText(result); b.textContent = 'Copied'; } } }, 'Copy');
            return el('div', {}, el('p', { className: 'mono', id: 'bunkerlink' }, result), b);
          })),
      ],
      security: () => [
        el('h1', {}, 'Security'),
        el('div', { className: 'card' }, el('h2', {}, 'Password sign-in'),
          el('p', {}, me.username ? ['Username ', el('strong', {}, me.username), '.'] : 'No password is set. You sign in to this page with a device.'),
          el('p', { className: 'dim small' }, 'Setting, changing or removing the password is done in the app, with your fingerprint. The password never leaves the device you type it on.')),
        el('div', { className: 'card' }, el('h2', {}, 'What needs a device'),
          el('table', { className: 'can' }, el('thead', {}, el('tr', {}, el('th', {}, 'From this page'), el('th', {}, 'Only with a device and fingerprint'))),
            el('tbody', {}, [['See devices and what is signed in', 'Add a device'], ['Block a device', 'Unblock a device'], ['End a sign-in', 'Sign, or read encrypted messages'], ['Sign out of this page', 'Remove a blocked device for good'], ['', 'Form the whole key'], ['', 'Set or change the password']]
              .map(([a, b]) => el('tr', {}, el('td', {}, a), el('td', {}, b))))),
          el('p', { className: 'dim small', style: 'margin-top:12px' }, 'Everything this page can do alone only ever reduces access.')),
        el('div', { className: 'card' }, el('h2', {}, 'This page'),
          el('div', { className: 'acts' },
            el('button', { id: 'signout', on: { click: async () => { await api('logout'); showLogin(); } } }, 'Sign out'),
            el('button', { on: { click: async () => { await api('logout_all'); showLogin(); } } }, 'Sign out everywhere'))),
      ],
      backup: () => [
        el('h1', {}, 'Backup'),
        el('div', { className: 'card' }, el('h2', {}, 'A second device'),
          el('p', {}, 'The backup that works today is another device. Any two pieces sign, so a second phone, a tablet or a computer keeps the account alive if one is lost.'),
          el('button', { on: { click: () => go('devices') } }, 'Add a device')),
        el('div', { className: 'card' }, el('h2', {}, 'The whole key'),
          el('p', {}, 'A device can form the whole key with your fingerprint, for an app that needs it or to write it down. Do that in the app.'),
          el('p', { className: 'dim small' }, 'Anyone who gets the whole key controls the account for good, so keep it offline.')),
        el('div', { className: 'card' }, el('h2', {}, 'Paper backup and undo'),
          el('p', { className: 'dim' }, 'Not available yet.')),
      ],
    }[section]();

    app.replaceChildren(
      el('div', { className: 'top' }, el('div', { className: 'brand' }, 'Keykin'),
        el('div', { className: 'who' }, el('span', { className: 'dim small' }, name), el('button', { className: 'link small', on: { click: async () => { await api('logout'); showLogin(); } } }, 'Sign out'))),
      el('div', { className: 'shell' },
        el('nav', { ariaLabel: 'Sections' }, SECTIONS.map(([id, label]) => el('button', { ariaCurrent: section === id ? 'page' : 'false', on: { click: () => go(id) } }, label))),
        el('main', {}, el('div', { className: 'status', id: 'status', role: 'status', hidden: true }), body)));
  }

  // Something this page starts and a device finishes: leave a note, then wait for a device to answer it.
  function noteForm(kind, label, button, whenDone, check) {
    const box = el('div', {});
    const input = label ? el('textarea', { ariaLabel: label, placeholder: label }) : null;
    const btn = el('button', { className: 'go' }, button);
    const line = el('p', { className: 'dim small', role: 'status', hidden: true });
    btn.addEventListener('click', async () => {
      const text = input ? input.value : '';
      const bad = input && (!text.trim() ? 'Paste it first.' : check ? check(text) : null);
      if (bad) { line.textContent = bad; line.hidden = false; return; }
      btn.disabled = true; box.dataset.busy = '1';
      const r = await api('note_put', { kind, text: text.trim() }).catch(() => ({ error: 'no_box' }));
      if (r.error === 'login') return showLogin(say('login'));
      if (!r.ok) { btn.disabled = false; delete box.dataset.busy; line.textContent = say(r.error); line.hidden = false; return; }
      line.textContent = 'Waiting for one of your devices. Open the app and approve it there.'; line.hidden = false;
      const t = every(2000, async () => {
        const g = await api('note_get', { note: r.note }).catch(() => null);
        if (!g || !g.ok || g.state === 'waiting') return;
        clearInterval(t); delete box.dataset.busy;
        if (g.state === 'done') box.replaceChildren(whenDone(g.result));
        else { line.textContent = 'No device answered in time. Try again with the app open.'; btn.disabled = false; }
      });
    });
    box.append(...[input, btn, line].filter(Boolean));
    return box;
  }

  showAccount();
})();
