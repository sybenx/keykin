// The extension's small window: set this browser up, see the devices, and see which sites are signed in.
const app = document.getElementById('app')!, msg = document.getElementById('msg')!;
const ui = async (cmd: string, more: object = {}) => {
  const r = await chrome.runtime.sendMessage({ kind: 'ui', cmd, ...more });
  if (r?.error) throw new Error(r.error);
  return r.result;
};
const el = (tag: string, props: Record<string, any> = {}, ...kids: (Node | string)[]) => {
  const n = Object.assign(document.createElement(tag), props); n.append(...kids); return n;
};
const fail = (e: any) => { msg.textContent = e.message ?? String(e); msg.hidden = false; };
const busy = async (b: HTMLButtonElement, work: () => Promise<unknown>) => {
  msg.hidden = true; b.disabled = true;
  try { await work(); await draw(); } catch (e) { fail(e); b.disabled = false; }
};

async function draw() {
  const s = await ui('state');
  app.replaceChildren();
  if (!s.account) {
    const code = el('textarea', { id: 'code', placeholder: 'Paste the code from the box page', ariaLabel: 'Code from the box page' }) as HTMLTextAreaElement;
    const create = el('button', { className: 'go', id: 'create', textContent: 'Make an account with the box' }) as HTMLButtonElement;
    create.onclick = () => busy(create, () => ui('create', { text: code.value }));
    const join = el('textarea', { id: 'jointext', placeholder: 'Paste the join code from the other device', ariaLabel: 'Join code' }) as HTMLTextAreaElement;
    const joinB = el('button', { id: 'join', textContent: 'Join' }) as HTMLButtonElement;
    joinB.onclick = () => busy(joinB, () => ui('join', { text: join.value }));
    const copy = el('button', { textContent: 'Copy this browser’s invite' }) as HTMLButtonElement;
    copy.onclick = async () => { await navigator.clipboard.writeText(s.invite); copy.textContent = 'Copied'; };
    app.append(
      el('div', { className: 'card' }, el('h2', { textContent: 'Start with your box' }),
        el('p', { className: 'dim small', textContent: 'On the box page, open “No camera? Copy the code as text” and paste it here.' }), code, create),
      el('div', { className: 'card' }, el('h2', { textContent: 'Already have an account?' }),
        el('p', { className: 'dim small', textContent: '1. Give this invite to a device in the account (Add a device, then paste).' }),
        el('p', { className: 'mono', id: 'invite', textContent: s.invite }), copy,
        el('p', { className: 'dim small', textContent: '2. Paste the join code it shows.', style: 'margin-top:10px' }), join, joinB));
    return;
  }
  if (s.problem) fail(new Error(s.problem));
  const devices = el('div', { className: 'card' }, el('h2', { textContent: 'Devices' }));
  for (const m of s.members) {
    const row = el('div', { className: 'row' }, el('div', { className: 'who' }, m.name + (m.key === s.me ? ' (this browser)' : m.kind === 'box' ? ' (box)' : ''),
      ...(m.blocked ? [el('span', { className: 'tag', textContent: 'Blocked' })] : [])));
    if (m.kind === 'device' && m.key !== s.me && !m.blocked) {
      const b = el('button', { className: 'danger', textContent: 'Block', ariaLabel: `Block ${m.name}` }) as HTMLButtonElement;
      b.onclick = () => busy(b, () => ui('block', { key: m.key }));
      row.append(b);
    }
    devices.append(row);
  }
  devices.append(el('p', { className: 'dim small', style: 'margin-top:8px', textContent: 'Adding a device, unblocking one and forming the whole key need a fingerprint. Do those from your phone.' }));
  const sites = el('div', { className: 'card' }, el('h2', { textContent: 'Sites signed in' }));
  if (!s.sites.length) sites.append(el('p', { className: 'dim small', textContent: 'None yet. A site asks the first time it wants to sign in.' }));
  for (const o of s.sites) {
    const b = el('button', { textContent: 'Sign out', ariaLabel: `Sign out ${o}` }) as HTMLButtonElement;
    b.onclick = () => busy(b, () => ui('signout', { origin: o }));
    sites.append(el('div', { className: 'row' }, el('div', { className: 'who', textContent: o }), b));
  }
  app.append(el('div', { className: 'card' }, el('h2', { textContent: 'Your account' }), el('p', { className: 'mono', id: 'npub', textContent: s.npub })), devices, sites);
}
draw().catch(fail);
