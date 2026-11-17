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

// The admin page wears a dark header and an "Admin" tag, so it cannot be mistaken for the account page.
const ADMIN_CSS = `
body { font:15px/1.5 Inter, system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width:none; margin:0; padding:0; }
.bar { min-height:64px; padding:10px 32px; display:flex; align-items:center; justify-content:space-between; gap:16px; flex-wrap:wrap; background:#1c1c1c; color:#fff; }
.bar .brand { display:flex; align-items:center; gap:12px; font-weight:700; font-size:19px; }
.bar .admin { font-size:12px; font-weight:600; border:1px solid #9a9a9a; border-radius:99px; padding:2px 10px; }
.bar .where { color:#d0d0d0; font-size:14px; display:flex; align-items:center; gap:16px; }
.bar button.link { color:#d0d0d0; }
.cols { display:grid; grid-template-columns:repeat(2, minmax(0, 1fr)); gap:20px; padding:28px 32px 56px; max-width:1280px; margin:0 auto; align-items:start; }
@media (max-width:860px) { .cols { grid-template-columns:minmax(0, 1fr); padding:16px; } .bar { padding:10px 16px; } }
.col { display:flex; flex-direction:column; gap:20px; }
.card { border-radius:14px; padding:22px; margin:0; display:flex; flex-direction:column; gap:10px; }
.card h2 { font-size:17px; font-weight:600; margin:0; }
.sub { font-size:14px; color:var(--dim); line-height:1.5; margin:0; }
.item { display:flex; align-items:center; gap:12px; padding:14px 0; border-bottom:1px solid var(--line); }
.item:last-of-type { border-bottom:0; }
.item .who { flex:1; min-width:0; overflow-wrap:anywhere; }
.item .name { font-weight:600; font-size:15px; } .acct .item .name { font-weight:500; }
button { height:44px; padding:0 18px; border-radius:10px; font:500 15px Inter, system-ui, sans-serif; white-space:nowrap; }
button.go { border:0; }
.kv { display:flex; justify-content:space-between; gap:16px; font-size:14px; } .kv span:first-child { color:var(--dim); } .kv span:last-child { font-weight:500; text-align:right; }
.ok { color:#075c45; } @media (prefers-color-scheme: dark) { .ok { color:#7fe0c2; } }
.acct-head { display:flex; align-items:baseline; justify-content:space-between; gap:12px; flex-wrap:wrap; }
.acct-head .mono { color:var(--dim); }
details.remove summary { color:var(--danger); font-size:14px; text-decoration:underline; list-style:none; } details.remove summary::-webkit-details-marker { display:none; }
.notice { margin:20px 32px 0; padding:12px 16px; border-radius:10px; background:#e2efea; color:#075c45; font-size:14px; max-width:1216px; }
@media (prefers-color-scheme: dark) { .notice { background:#1f3a32; color:#9be8d0; } }
.single { max-width:640px; margin:0 auto; padding:28px 16px 56px; }
`;
const adminShell = (title: string, where: string, csrf: string, logout: boolean, body: string, nonce = '', script = '') => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)}</title><style>${CSS}${ADMIN_CSS}</style></head>
<body><div class="bar"><div class="brand"><span>Keykin Box</span><span class="admin">Admin</span></div>
<div class="where"><span>${esc(where)}</span>${logout ? `<form method="post" action="/logout"><input type="hidden" name="csrf" value="${esc(csrf)}"><button class="link small" type="submit" style="height:auto;padding:0">Log out</button></form>` : ''}</div></div>
<main>${body}</main>${script ? `<script nonce="${nonce}">${script}</script>` : ''}</body></html>`;

const hidden = (csrf: string, more: Record<string, string> = {}) =>
  `<input type="hidden" name="csrf" value="${esc(csrf)}">` + Object.entries(more).map(([k, v]) => `<input type="hidden" name="${k}" value="${esc(v)}">`).join('');
const day = (t: number) => new Date(t * 1000).toISOString().slice(0, 10);
const shortNpub = (hex: string) => { const n = npubEncode(hex); return `${n.slice(0, 12)}…${n.slice(-7)}`; };
const ago = (t: number, now: number) => { const s = now - t; return s < 90 ? 'a minute ago' : s < 3600 ? `${Math.round(s / 60)} minutes ago` : s < 86400 ? `${Math.round(s / 3600)} hours ago` : day(t); };

/** Where this page is and how it is guarded, for the header. */
export interface Where { host: string; behindLogin: boolean }
const whereText = (w: Where) => `${w.host} · ${w.behindLogin ? 'behind another login' : 'owner login'} · not on the public side`;

/** A setup code for one new account: the first on an empty box, or one the admin just made. */
export function codePage(o: { qrText: string; csrf: string; nonce: string; logout: boolean; first: boolean; count: number; where: Where }) {
  return adminShell('Keykin Box: new account', whereText(o.where), o.csrf, o.logout, `<div class="single"><div class="card">
  <h2>${o.first ? 'Scan to start' : 'Scan to make a new account'}</h2>
  <p class="sub">Scan this with the account's first device. The device and this box make the key together. The whole key never exists on either.</p>
  <div class="qr" role="img" aria-label="Setup QR code">${qrSvg(o.qrText)}</div>
  <p class="sub">${o.first ? 'This code changes each time the box restarts, and stops working once an account exists.' : 'This code works once, for 24 hours.'}</p>
  <details class="small"><summary class="dim">No camera? Copy the code as text</summary>
    <p class="mono" id="qrtext" style="margin-top:8px">${esc(o.qrText)}</p></details>
  ${o.first ? '' : '<p class="sub"><a href="/">Back to the accounts</a></p>'}
</div></div>`, o.nonce,
  `setInterval(async()=>{try{const r=await fetch('/admin/state');if(r.ok&&(await r.json()).accounts>${o.count})location.href='/'}catch{}},2000)`);
}

/** `door`: the public address if one is set, and when Keykin Login last reached the box (0 if never). */
export function adminPage(o: { accounts: Account[]; requests: Ask[]; csrf: string; notice?: string; logout: boolean; where: Where; door: { url?: string; seen: number; side: boolean }; now: number }) {
  const waiting = o.requests.filter((r) => r.state === 'waiting');
  const asks = `<div class="card"><h2>Waiting for your answer</h2>
  <p class="sub">${waiting.length ? 'Nothing is made until you approve.' : 'Nobody is asking for an account.'}</p>
  ${waiting.map((r) => `<div class="item"><div class="who"><div class="name">${esc(r.name ?? 'A device')}<span class="tag">${r.what === 'make' ? 'new account' : 'move an account here'}</span></div>
    ${r.note ? `<div style="font-size:14px">“${esc(r.note)}”</div>` : ''}
    <div class="dim small">Asked ${day(r.asked)}${r.account ? ` · ${esc(shortNpub(r.account))}` : ''} · device ${esc((r.key ?? '').slice(0, 8))}</div></div>
    <form method="post" action="/admin/approve">${hidden(o.csrf, { id: r.id })}<button class="go" type="submit" aria-label="Approve ${esc(r.name ?? 'device')}">Approve</button></form>
    <form method="post" action="/admin/refuse">${hidden(o.csrf, { id: r.id })}<button type="submit" aria-label="Refuse ${esc(r.name ?? 'device')}">Refuse</button></form></div>`).join('')}</div>`;

  const running = o.door.seen && o.now - o.door.seen < 600;
  const door = `<div class="card"><h2>The outside door</h2>
  <div class="kv"><span>Keykin Login</span><span class="${running ? 'ok' : ''}">${!o.door.side ? 'No side door is open for it' : running ? `Running${o.door.url ? ' at ' + esc(o.door.url.replace(/^https?:\/\//, '')) : ''}` : o.door.seen ? `Last seen ${ago(o.door.seen, o.now)}` : 'Not seen yet'}</span></div>
  <div class="kv"><span>What it can reach</span><span>Device requests and the account page only</span></div>
  <p class="sub small">Stopping Keykin Login closes the outside door. This page and devices on the private network keep working.</p></div>`;

  const accounts = o.accounts.map((a) => {
    const rows = [...a.members.filter((m) => m.kind === 'device'), ...a.members.filter((m) => m.kind === 'box')].map((m) => {
      const act = m.kind === 'box' ? '' : `<form method="post" action="/admin/${m.blocked ? 'unblock' : 'block'}">${hidden(o.csrf, { key: m.key, account: a.npub })}
      <button class="${m.blocked ? '' : 'danger'}" type="submit" aria-label="${m.blocked ? 'Unblock' : 'Block'} ${esc(m.name)}">${m.blocked ? 'Unblock' : 'Block'}</button></form>`;
      return `<div class="item"><div class="who"><div class="name">${esc(m.name)}${m.kind === 'box' ? '<span class="tag">this box</span>' : ''}${m.blocked ? '<span class="tag bad">Blocked</span>' : ''}</div>
      ${m.kind === 'box' ? '' : `<div class="dim small">Added ${day(m.added)}${!m.chip ? ' · no fingerprint key' : ''}</div>`}</div>${act}</div>`;
    }).join('');
    return `<div class="card acct"><div class="acct-head"><h2>${a.login ? esc(a.login.username) : 'No username'}</h2><div class="mono small" title="${esc(npubEncode(a.npub))}">${esc(shortNpub(a.npub))}</div></div>
  ${rows}
  <details class="remove"><summary>Remove this account</summary>
    <form method="post" action="/admin/remove" style="margin-top:8px">${hidden(o.csrf, { account: a.npub })}
    <p class="sub">This deletes the box's piece of this account. If its devices cannot sign with each other, the account is lost for good.</p>
    <label class="check"><input type="checkbox" name="sure" value="1" required><span>I understand this cannot be undone.</span></label>
    <button class="danger" type="submit">Remove the account</button></form></details></div>`;
  }).join('');

  return adminShell('Keykin Box', whereText(o.where), o.csrf, o.logout, `${o.notice ? `<div class="notice" role="status">${esc(o.notice)}</div>` : ''}
<div class="cols"><div class="col">
${asks}
<div class="card"><h2>Add an account yourself</h2>
  <p class="sub">Makes a code for one new account. It works once, for 24 hours.</p>
  <form method="post" action="/admin/code">${hidden(o.csrf)}<button type="submit">Make a setup code</button></form></div>
${door}
</div><div class="col">${accounts || '<div class="card"><h2>No accounts yet</h2></div>'}</div></div>`);
}
