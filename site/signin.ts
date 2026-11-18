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

/** `ask: false` skips the page's own "Sign in?" question, for a page that proves who signed in some other way before it trusts the signer. */
/** `words` replaces the wording, for a page that speaks to people who have never heard of a signer. */
/** What a Keykin account page adds to its code and its link (SPEC 11.6): it is about the main account, so a signer never offers another one there. */
const mark = (account?: boolean) => (account ? '&kk=account' : '');

export function start(box: HTMLElement, o: { relays: string[]; words?: { scan?: string; digits?: string; differ?: string; ask?: string }; ask?: boolean; account?: boolean }): { done: Promise<SignedIn>; cancel: () => void } {
  let signer: BunkerSigner | undefined;
  let answer: ((yes: boolean) => void) | undefined;
  const draw = (v: SignInView) => {
    box.replaceChildren();
    if (v.state === 'starting') return void box.append(el('p', { className: 'kk-dim', textContent: 'Getting a code ready…' }));
    if (v.state === 'showing' && v.uri) {
      v = { ...v, uri: v.uri + mark(o.account) };
      const qr = qrcode(0, 'L'); qr.addData(v.uri); qr.make();
      const pic = el('div', { className: 'kk-qr', role: 'img', ariaLabel: 'Sign-in code' }); pic.innerHTML = qr.createSvgTag({ cellSize: 3, margin: 0, scalable: true });
      const copy = el('button', { type: 'button', className: 'kk-copy', textContent: 'Copy the code as a link' }) as HTMLButtonElement;
      copy.onclick = async () => { try { await navigator.clipboard.writeText(v.uri!); copy.textContent = 'Copied'; } catch { copy.textContent = 'Could not copy'; } };
      return void box.append(pic, el('p', { className: 'kk-dim', textContent: o.words?.scan ?? 'Scan this with your signer.' }), copy, el('p', { className: 'kk-link', id: 'kk-uri', hidden: true, textContent: v.uri }));
    }
    if (v.state === 'checking') return void box.append(
      el('p', { textContent: o.words?.digits ?? 'Your signer shows five digits. They should be:' }), el('p', { className: 'kk-digits', id: 'kk-digits', textContent: v.digits ?? '' }),
      el('p', { className: 'kk-dim', textContent: o.words?.differ ?? 'If they differ, say no on your signer.' }));
    if (v.state === 'asking' && o.ask === false) return void box.append(el('p', { className: 'kk-dim', textContent: 'Signing in…' }));
    if (v.state === 'asking') {
      const yes = el('button', { type: 'button', className: 'kk-go', id: 'kk-yes', textContent: 'Sign in' }) as HTMLButtonElement;
      const no = el('button', { type: 'button', id: 'kk-no', textContent: 'Cancel' }) as HTMLButtonElement;
      yes.onclick = () => answer?.(true); no.onclick = () => answer?.(false);
      return void box.append(el('p', { id: 'kk-asking', textContent: o.words?.ask ?? v.asking ?? 'Sign in?' }), yes, document.createTextNode(' '), no);
    }
    if (v.state === 'connecting') return void box.append(el('p', { className: 'kk-dim', textContent: 'Signing in…' }));
    if (v.state === 'done') return void box.append(el('p', { className: 'kk-dim', textContent: 'Signed in.' }));
    box.append(el('p', { className: 'kk-err', role: 'alert', textContent: v.problem ?? 'That did not work.' }));
  };
  const origin = location.origin, baseUrl = location.origin + location.pathname;
  const run = startSignIn({
    relays: o.relays, baseUrl, origin, onView: draw,
    confirm: () => o.ask === false ? Promise.resolve(true) : new Promise<boolean>((resolve) => { answer = resolve; }),
    redeem: async (t) => {
      signer = BunkerSigner.fromBunker(generateSecretKey(), { pubkey: t.signer, relays: t.relays, secret: t.t });
      await signer.connect();
      // The signer must really be for the account the ticket named.
      if ((await signer.getPublicKey()) !== t.pubkey) throw new Error('That signer is for a different account.');
    },
  });
  return { done: run.done.then((ticket) => ({ pubkey: ticket.pubkey, signer: signer!, ticket })), cancel: run.cancel };
}

// ---- On the same phone as the signer: a link to tap, not a code to scan ------------------------------
//
//   const { uri, done, cancel } = KeykinSignIn.link({ relays, name: 'Your account' });
//
// `uri` is a nostrconnect:// link (NIP-46). The signer app opens on it, and answers on the relays. A phone
// drops a page's connections while the page is in the background, which is exactly when the answer comes,
// so the page asks again from the start time whenever it is looked at again.

import { getPublicKey } from 'nostr-tools/pure';
import { createNostrConnectURI } from 'nostr-tools/nip46';
import { SimplePool } from 'nostr-tools/pool';
import * as nip44 from 'nostr-tools/nip44';

export function link(o: { relays: string[]; name?: string; account?: boolean }): { uri: string; done: Promise<{ pubkey: string; signer: BunkerSigner }>; cancel: () => void } {
  const sk = generateSecretKey(), me = getPublicKey(sk);
  const secret = Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
  const uri = createNostrConnectURI({ clientPubkey: me, relays: o.relays, secret, name: o.name ?? location.host, url: location.origin }) + mark(o.account);
  const since = Math.floor(Date.now() / 1000) - 10;
  const pool = new SimplePool();
  let sub: { close: () => void } | undefined, stopped = false, found: ((signerKey: string) => void) | undefined;
  const listen = () => {
    sub?.close();
    sub = pool.subscribe(o.relays, { kinds: [24133], '#p': [me], since }, {
      onevent: (e) => {
        try {
          const answer = JSON.parse(nip44.v2.decrypt(e.content, nip44.v2.utils.getConversationKey(sk, e.pubkey)));
          if (answer.result === secret) found?.(e.pubkey);
        } catch { /* not for us */ }
      },
    });
  };
  const seen = () => { if (!stopped && document.visibilityState === 'visible') listen(); };
  const stop = () => { stopped = true; document.removeEventListener('visibilitychange', seen); sub?.close(); pool.close(o.relays); };
  const done = (async () => {
    document.addEventListener('visibilitychange', seen);
    listen();
    const signerKey = await new Promise<string>((resolve) => { found = resolve; });
    stop();
    const signer = BunkerSigner.fromBunker(sk, { pubkey: signerKey, relays: o.relays, secret });
    return { pubkey: await signer.getPublicKey(), signer };
  })();
  return { uri, done, cancel: stop };
}
