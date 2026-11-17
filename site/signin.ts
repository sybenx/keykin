// "Sign in with your signer" for any web page: shows a code, and ends with a NIP-46 signer for the
// account that scanned it (QRST signer-ticket, see src/ticket.ts). No server of its own.
//
//   const { pubkey, signer } = await KeykinSignIn.start(element, { relays: ['wss://…'] });
//
// The element gets plain markup with `kk-` classes; the page styles it.

import qrcode from 'qrcode-generator';
import { generateSecretKey } from 'nostr-tools/pure';
import { BunkerSigner } from 'nostr-tools/nip46';
import { startSignIn, type Ticket, type SignInView } from '../src/ticket.ts';

export interface SignedIn { pubkey: string; signer: BunkerSigner; ticket: Ticket }

const el = (tag: string, props: Record<string, any> = {}, ...kids: (Node | string)[]) => { const n = Object.assign(document.createElement(tag), props); n.append(...kids); return n; };

export function start(box: HTMLElement, o: { relays: string[] }): { done: Promise<SignedIn>; cancel: () => void } {
  let signer: BunkerSigner | undefined;
  let answer: ((yes: boolean) => void) | undefined;
  const draw = (v: SignInView) => {
    box.replaceChildren();
    if (v.state === 'starting') return void box.append(el('p', { className: 'kk-dim', textContent: 'Getting a code ready…' }));
    if (v.state === 'showing' && v.uri) {
      const qr = qrcode(0, 'L'); qr.addData(v.uri); qr.make();
      const pic = el('div', { className: 'kk-qr', role: 'img', ariaLabel: 'Sign-in code' }); pic.innerHTML = qr.createSvgTag({ cellSize: 3, margin: 0, scalable: true });
      const copy = el('button', { type: 'button', className: 'kk-copy', textContent: 'Copy the code as a link' }) as HTMLButtonElement;
      copy.onclick = async () => { try { await navigator.clipboard.writeText(v.uri!); copy.textContent = 'Copied'; } catch { copy.textContent = 'Could not copy'; } };
      return void box.append(pic, el('p', { className: 'kk-dim', textContent: 'Scan this with your signer.' }), copy, el('p', { className: 'kk-link', id: 'kk-uri', hidden: true, textContent: v.uri }));
    }
    if (v.state === 'checking') return void box.append(
      el('p', { textContent: 'Your signer shows five digits. They should be:' }), el('p', { className: 'kk-digits', id: 'kk-digits', textContent: v.digits ?? '' }),
      el('p', { className: 'kk-dim', textContent: 'If they differ, say no on your signer.' }));
    if (v.state === 'asking') {
      const yes = el('button', { type: 'button', className: 'kk-go', id: 'kk-yes', textContent: 'Sign in' }) as HTMLButtonElement;
      const no = el('button', { type: 'button', id: 'kk-no', textContent: 'Cancel' }) as HTMLButtonElement;
      yes.onclick = () => answer?.(true); no.onclick = () => answer?.(false);
      return void box.append(el('p', { id: 'kk-asking', textContent: v.asking ?? 'Sign in?' }), yes, document.createTextNode(' '), no);
    }
    if (v.state === 'connecting') return void box.append(el('p', { className: 'kk-dim', textContent: 'Signing in…' }));
    if (v.state === 'done') return void box.append(el('p', { className: 'kk-dim', textContent: 'Signed in.' }));
    box.append(el('p', { className: 'kk-err', role: 'alert', textContent: v.problem ?? 'That did not work.' }));
  };
  const origin = location.origin, baseUrl = location.origin + location.pathname;
  const run = startSignIn({
    relays: o.relays, baseUrl, origin, onView: draw,
    confirm: () => new Promise<boolean>((resolve) => { answer = resolve; }),
    redeem: async (t) => {
      signer = BunkerSigner.fromBunker(generateSecretKey(), { pubkey: t.signer, relays: t.relays, secret: t.t });
      await signer.connect();
      // The signer must really be for the account the ticket named.
      if ((await signer.getPublicKey()) !== t.pubkey) throw new Error('That signer is for a different account.');
    },
  });
  return { done: run.done.then((ticket) => ({ pubkey: ticket.pubkey, signer: signer!, ticket })), cancel: run.cancel };
}
