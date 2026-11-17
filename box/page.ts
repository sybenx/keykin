// The box's admin page: what the person who runs the box sees. Plain HTML built here, no framework and
// nothing loaded from anywhere else. It is never served on the public side.

import qrcode from 'qrcode-generator';
import { npubEncode } from 'nostr-tools/nip19';
import type { Account, Ask } from './box.ts';

export const esc = (s: unknown) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));

export const CSS = `
:root { --bg:#f4f4f4; --card:#fff; --line:#dcdcdc; --text:#1c1c1c; --dim:#6b6b6b; --accent:#0b7a5c; --on:#fff; --danger:#b3261e; }
@media (prefers-color-scheme: dark) { :root { --bg:#161616; --card:#212121; --line:#383838; --text:#ededed; --dim:#9a9a9a; --accent:#3ecfa3; --on:#0c0c0c; --danger:#ff7a70; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width:640px; margin:0 auto; padding:32px 16px 48px; }
header { display:flex; align-items:baseline; justify-content:space-between; margin-bottom:24px; }
h1 { font-size:22px; margin:0; letter-spacing:-0.01em; }
h2 { font-size:16px; margin:0 0 4px; } h3 { font-size:15px; margin:0; }
p { margin:0 0 12px; } .dim { color:var(--dim); } .small { font-size:13px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:20px; margin-bottom:16px; }
.mono { font:13px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; word-break:break-all; }
input[type=password], input[type=text] { width:100%; padding:10px 12px; font:inherit; color:inherit; background:var(--bg); border:1px solid var(--line); border-radius:8px; margin-bottom:12px; }
button { font:inherit; padding:8px 14px; border-radius:8px; border:1px solid var(--line); background:var(--card); color:var(--text); cursor:pointer; min-height:40px; }
button.go { background:var(--accent); border-color:var(--accent); color:var(--on); font-weight:600; }
button.danger { color:var(--danger); } button.link { border:0; background:none; color:var(--dim); padding:0; text-decoration:underline; min-height:0; }
:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
.qr { background:#fff; padding:12px; border-radius:8px; width:min(100%, 320px); margin:8px auto 16px; display:block; }
.qr svg { display:block; width:100%; height:auto; }
ul.rows { list-style:none; margin:0; padding:0; }
ul.rows li { display:flex; align-items:center; gap:12px; padding:12px 0; border-top:1px solid var(--line); }
ul.rows li:first-child { border-top:0; padding-top:4px; } ul.rows li:last-child { padding-bottom:4px; }
.who { flex:1; min-width:0; overflow-wrap:anywhere; } .name { font-weight:600; }
.tag { font-size:12px; padding:1px 7px; border-radius:99px; border:1px solid var(--line); color:var(--dim); margin-left:6px; font-weight:400; white-space:nowrap; }
.tag.bad { color:var(--danger); border-color:var(--danger); }
.err { color:var(--danger); } .acts { display:flex; gap:8px; flex-wrap:wrap; }
details > summary { cursor:pointer; } label.check { display:flex; gap:8px; align-items:flex-start; margin:8px 0 12px; }
`;

export const shell = (title: string, body: string, nonce = '', script = '') => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)}</title><style>${CSS}</style></head>
<body><main>${body}</main>${script ? `<script nonce="${nonce}">${script}</script>` : ''}</body></html>`;

export function qrSvg(text: string) { const qr = qrcode(0, 'M'); qr.addData(text); qr.make(); return qr.createSvgTag({ cellSize: 4, margin: 0, scalable: true }); }

export function loginPage(o: { error?: string }) {
  return shell('Keykin box', `
<header><h1>Keykin box</h1></header>
<form class="card" method="post" action="/login">
  <h2>Admin</h2>
  <p class="dim small">For the person who runs this box.</p>
  ${o.error ? `<p class="err small" role="alert">${esc(o.error)}</p>` : ''}
  <label class="small dim" for="secret">Owner secret</label>
  <input id="secret" name="secret" type="password" autocomplete="current-password" required>
  <button class="go" type="submit">Log in</button>
</form>`);
}

// No Log out button behind someone else's login: there is nothing of the box's own to log out of.
const top = (csrf: string, logout: boolean) => `<header><h1>Keykin box</h1>${logout ? `
<form method="post" action="/logout"><input type="hidden" name="csrf" value="${esc(csrf)}"><button class="link small" type="submit">Log out</button></form>` : ''}</header>`;
const hidden = (csrf: string, more: Record<string, string> = {}) =>
  `<input type="hidden" name="csrf" value="${esc(csrf)}">` + Object.entries(more).map(([k, v]) => `<input type="hidden" name="${k}" value="${esc(v)}">`).join('');
const day = (t: number) => new Date(t * 1000).toISOString().slice(0, 10);

/** A setup code for one new account: the first on an empty box, or one the admin just made. */
export function codePage(o: { qrText: string; csrf: string; nonce: string; logout: boolean; first: boolean; count: number }) {
  return shell('Keykin box: new account', `${top(o.csrf, o.logout)}
<div class="card">
  <h2>${o.first ? 'Scan to start' : 'Scan to make a new account'}</h2>
  <p class="dim small">Scan this with the account's first device. The device and this box make the key together. The whole key never exists on either.</p>
  <div class="qr" role="img" aria-label="Setup QR code">${qrSvg(o.qrText)}</div>
  <p class="dim small">${o.first ? 'This code changes each time the box restarts, and stops working once an account exists.' : 'This code works once, for 24 hours.'}</p>
  <details class="small"><summary class="dim">No camera? Copy the code as text</summary>
    <p class="mono" id="qrtext" style="margin-top:8px">${esc(o.qrText)}</p></details>
  ${o.first ? '' : '<p style="margin-top:12px"><a href="/">Back to the accounts</a></p>'}
</div>`, o.nonce,
  `setInterval(async()=>{try{const r=await fetch('/admin/state');if(r.ok&&(await r.json()).accounts>${o.count})location.href='/'}catch{}},2000)`);
}

export function adminPage(o: { accounts: Account[]; requests: Ask[]; csrf: string; notice?: string; logout: boolean; boxKey: string }) {
  const waiting = o.requests.filter((r) => r.state === 'waiting');
  const asks = waiting.length ? `<div class="card"><h2>Waiting for your answer</h2>
  <p class="dim small">Someone asked for an account on this box. Nothing is made until you approve.</p>
  <ul class="rows">${waiting.map((r) => `<li><div class="who"><div class="name">${esc(r.name ?? 'A device')}<span class="tag">${r.what === 'make' ? 'new account' : 'move an account here'}</span></div>
    ${r.note ? `<div class="small">${esc(r.note)}</div>` : ''}
    <div class="dim small">Asked ${day(r.asked)} · device ${esc((r.key ?? '').slice(0, 8))}${r.account ? ` · ${esc(npubEncode(r.account).slice(0, 16))}…` : ''}</div></div>
    <div class="acts"><form method="post" action="/admin/approve">${hidden(o.csrf, { id: r.id })}<button class="go" type="submit" aria-label="Approve ${esc(r.name ?? 'device')}">Approve</button></form>
    <form method="post" action="/admin/refuse">${hidden(o.csrf, { id: r.id })}<button type="submit" aria-label="Refuse ${esc(r.name ?? 'device')}">Refuse</button></form></div></li>`).join('')}</ul></div>` : '';

  const accounts = o.accounts.map((a) => {
    const rows = a.members.map((m) => {
      const act = m.kind === 'box' ? '' : `<form method="post" action="/admin/${m.blocked ? 'unblock' : 'block'}">${hidden(o.csrf, { key: m.key, account: a.npub })}
      <button class="${m.blocked ? '' : 'danger'}" type="submit" aria-label="${m.blocked ? 'Unblock' : 'Block'} ${esc(m.name)}">${m.blocked ? 'Unblock' : 'Block'}</button></form>`;
      return `<li><div class="who"><div class="name">${esc(m.name)}${m.kind === 'box' ? '<span class="tag">this box</span>' : ''}${m.blocked ? '<span class="tag bad">blocked</span>' : ''}</div>
      <div class="dim small">Added ${day(m.added)}${m.kind === 'device' && !m.chip ? ' · no fingerprint key' : ''}</div></div>${act}</li>`;
    }).join('');
    return `<div class="card"><h2>${a.login ? esc(a.login.username) : 'Account'}</h2>
  <div class="mono dim" style="margin-bottom:8px">${esc(npubEncode(a.npub))}</div>
  <ul class="rows">${rows}</ul>
  <details class="small" style="margin-top:12px"><summary class="dim">Remove this account</summary>
    <form method="post" action="/admin/remove">${hidden(o.csrf, { account: a.npub })}
    <p style="margin-top:8px">This deletes the box's piece of this account. If its devices cannot sign with each other, the account is lost for good.</p>
    <label class="check"><input type="checkbox" name="sure" value="1" required><span>I understand this cannot be undone.</span></label>
    <button class="danger" type="submit">Remove the account</button></form></details></div>`;
  }).join('');

  return shell('Keykin box', `${top(o.csrf, o.logout)}
${o.notice ? `<p class="small" role="status">${esc(o.notice)}</p>` : ''}
${asks}
${accounts}
<div class="card"><h2>Add an account</h2>
  <p class="dim small">Makes a code for one new account. You can also let someone ask from their device and approve it here.</p>
  <form method="post" action="/admin/code">${hidden(o.csrf)}<button type="submit">Make a setup code</button></form></div>
<p class="dim small">A blocked device gets no help from this box, so it cannot sign. Box key ${esc(o.boxKey.slice(0, 16))}…</p>`);
}
