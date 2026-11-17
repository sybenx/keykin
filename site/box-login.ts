// The box page's use of sign-in by code: once signed in, the account proves itself to the box by
// signing the box's challenge, and the box logs this browser in.
import { start } from './signin.ts';

const box = document.getElementById('signin');
const relays: string[] = JSON.parse(box?.dataset.relays ?? '[]');
if (box && relays.length) {
  const run = start(box, { relays });
  run.done.then(async ({ signer }) => {
    const { challenge } = await (await fetch('/login/challenge', { method: 'POST' })).json();
    const event = await signer.signEvent({ kind: 22242, created_at: Math.floor(Date.now() / 1000), tags: [['relay', location.origin], ['challenge', challenge]], content: '' });
    const r = await fetch('/login/nostr', { method: 'POST', body: JSON.stringify({ event }) });
    await signer.close().catch(() => {});
    if (r.ok) location.href = '/';
    else box.replaceChildren(Object.assign(document.createElement('p'), { className: 'kk-err', role: 'alert', textContent: (await r.json().catch(() => ({}))).error === 'wrong_account' ? 'That is not this box’s account.' : 'The box did not accept the sign-in.' }));
  }).catch(() => { /* the widget already says what went wrong */ });
}
