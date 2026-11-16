// The box's page: what its owner sees in a browser. Plain HTML built here, no framework and nothing
// loaded from anywhere else. Three screens: log in, the setup QR, and the device list.

import qrcode from 'qrcode-generator';
import type { Account } from './box.ts';

const esc = (s: unknown) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));

const CSS = `
:root { --bg:#f4f4f4; --card:#fff; --line:#dcdcdc; --text:#1c1c1c; --dim:#6b6b6b; --accent:#0b7a5c; --danger:#b3261e; }
@media (prefers-color-scheme: dark) { :root { --bg:#161616; --card:#212121; --line:#383838; --text:#ededed; --dim:#9a9a9a; --accent:#3ecfa3; --danger:#ff7a70; } }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width:560px; margin:0 auto; padding:32px 16px 48px; }
header { display:flex; align-items:baseline; justify-content:space-between; margin-bottom:24px; }
h1 { font-size:22px; margin:0; letter-spacing:-0.01em; }
h2 { font-size:15px; margin:0 0 4px; }
p { margin:0 0 12px; } .dim { color:var(--dim); } .small { font-size:13px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:20px; margin-bottom:16px; }
.mono { font:13px/1.4 ui-monospace, SFMono-Regular, Menlo, monospace; word-break:break-all; }
input[type=password] { width:100%; padding:10px 12px; font:inherit; color:inherit; background:var(--bg); border:1px solid var(--line); border-radius:8px; margin-bottom:12px; }
button { font:inherit; padding:8px 14px; border-radius:8px; border:1px solid var(--line); background:var(--card); color:var(--text); cursor:pointer; }
button.go { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; }
@media (prefers-color-scheme: dark) { button.go { color:#0c0c0c; } }
button.block { color:var(--danger); } button.link { border:0; background:none; color:var(--dim); padding:0; text-decoration:underline; }
:focus-visible { outline:2px solid var(--accent); outline-offset:2px; }
.qr { background:#fff; padding:12px; border-radius:8px; width:min(100%, 320px); margin:8px auto 16px; display:block; }
.qr svg { display:block; width:100%; height:auto; }
ul.devices { list-style:none; margin:0; padding:0; }
ul.devices li { display:flex; align-items:center; gap:12px; padding:14px 0; border-top:1px solid var(--line); }
ul.devices li:first-child { border-top:0; padding-top:4px; } ul.devices li:last-child { padding-bottom:4px; }
.who { flex:1; min-width:0; } .name { font-weight:600; }
.tag { font-size:12px; padding:1px 7px; border-radius:99px; border:1px solid var(--line); color:var(--dim); margin-left:6px; font-weight:400; }
.tag.blocked { color:var(--danger); border-color:var(--danger); }
.err { color:var(--danger); }
`;

const shell = (title: string, body: string, nonce = '', script = '') => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)}</title><style>${CSS}</style></head>
<body><main>${body}</main>${script ? `<script nonce="${nonce}">${script}</script>` : ''}</body></html>`;

export function loginPage(o: { error?: string }) {
  return shell('Keykin box', `
<header><h1>Keykin box</h1></header>
<form class="card" method="post" action="/login">
  <h2>Log in</h2>
  <p class="dim small">For the person who runs this box.</p>
  ${o.error ? `<p class="err small" role="alert">${esc(o.error)}</p>` : ''}
  <label class="small dim" for="secret">Owner secret</label>
  <input id="secret" name="secret" type="password" autocomplete="current-password" autofocus required>
  <button class="go" type="submit">Log in</button>
</form>`);
}

const top = (csrf: string) => `<header><h1>Keykin box</h1>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="${esc(csrf)}"><button class="link small" type="submit">Log out</button></form></header>`;

export function setupPage(o: { qrText: string; csrf: string; nonce: string }) {
  const qr = qrcode(0, 'M'); qr.addData(o.qrText); qr.make();
  return shell('Keykin box: set up', `${top(o.csrf)}
<div class="card">
  <h2>Scan to start</h2>
  <p class="dim small">Scan this with the first device. The device and this box make the key together. The whole key never exists on either.</p>
  <div class="qr" role="img" aria-label="Setup QR code">${qr.createSvgTag({ cellSize: 4, margin: 0, scalable: true })}</div>
  <p class="dim small">The code changes each time the box restarts, and stops working once an account exists.</p>
  <details class="small"><summary class="dim">No camera? Copy the code as text</summary>
    <p class="mono" id="qrtext" style="margin-top:8px">${esc(o.qrText)}</p></details>
</div>`, o.nonce,
  `setInterval(async()=>{try{const r=await fetch('/owner/state');if(r.ok&&(await r.json()).account)location.reload()}catch{}},2000)`);
}

const day = (t: number) => new Date(t * 1000).toISOString().slice(0, 10);

export function devicesPage(o: { account: Account; csrf: string; notice?: string }) {
  const rows = o.account.members.map((m) => {
    const act = m.kind === 'box' ? '' : `<form method="post" action="/owner/${m.blocked ? 'unblock' : 'block'}">
      <input type="hidden" name="csrf" value="${esc(o.csrf)}"><input type="hidden" name="key" value="${esc(m.key)}">
      <button class="${m.blocked ? '' : 'block'}" type="submit" aria-label="${m.blocked ? 'Unblock' : 'Block'} ${esc(m.name)}">${m.blocked ? 'Unblock' : 'Block'}</button></form>`;
    return `<li><div class="who"><div class="name">${esc(m.name)}${m.kind === 'box' ? '<span class="tag">this box</span>' : ''}${m.blocked ? '<span class="tag blocked">blocked</span>' : ''}</div>
      <div class="dim small">Added ${day(m.added)}${m.kind === 'device' && !m.chip ? ' · no fingerprint key' : ''}</div></div>${act}</li>`;
  }).join('');
  return shell('Keykin box', `${top(o.csrf)}
${o.notice ? `<p class="small" role="status">${esc(o.notice)}</p>` : ''}
<div class="card"><h2>Account</h2><div class="mono dim">${esc(o.account.npub)}</div></div>
<div class="card"><h2>Devices</h2>
  <p class="dim small">A blocked device gets no help from this box, so it cannot sign.</p>
  <ul class="devices">${rows}</ul></div>`);
}
