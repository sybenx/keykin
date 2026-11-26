// A stand-in browser extension (NIP-07) for headless Chromium tests, with a throwaway account. Ported from the fake
// extension in ~/archive/signin/test/run.mjs. An init script defines window.nostr on every page of the context; each
// call goes to this test process (an exposed binding), which signs and encrypts for real with nostr-tools, so the
// page's checks (right account, good signature) pass. Use, before the context's first page:
//
//   import { fakeExtension } from './standins/extension.ts';
//   const ext = await fakeExtension(context);                   // answers at once
//   const ext = await fakeExtension(context, { mode: 'slow', delay: 2000 });  // answers after a while
//   const ext = await fakeExtension(context, { mode: 'locked' });   // getPublicKey waits until ext.unlock()
//   const ext = await fakeExtension(context, { mode: 'refuse' });   // getPublicKey throws "User rejected"
//   const ext = await fakeExtension(context, { nip44: false });     // no window.nostr.nip44
//   ext.setMode('ready');                                       // changes it from now on
//
// ext.pubkey is the account; ext.calls lists what the page asked ("getPublicKey", "signEvent", "nip44.encrypt", …).
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';

export type ExtensionMode = 'ready' | 'slow' | 'locked' | 'refuse';
export type ExtensionOptions = { mode?: ExtensionMode; delay?: number; nip44?: boolean; sk?: Uint8Array };

export async function fakeExtension(context: any, opts: ExtensionOptions = {}) {
  const sk = opts.sk ?? generateSecretKey(), pubkey = getPublicKey(sk);
  let mode: ExtensionMode = opts.mode ?? 'ready';
  const calls: string[] = [];
  const unlocks: (() => void)[] = [];
  await context.exposeBinding('__standinExtension', async (_source: unknown, method: string, args: any[]) => {
    calls.push(method);
    if (method === 'getPublicKey') {
      if (mode === 'slow') await new Promise((r) => setTimeout(r, opts.delay ?? 4000));
      if (mode === 'locked') await new Promise<void>((r) => unlocks.push(r));
      if (mode === 'refuse') throw new Error('User rejected');
      return pubkey;
    }
    if (mode === 'refuse') throw new Error('User rejected');
    if (method === 'signEvent') return finalizeEvent({ kind: args[0].kind, created_at: args[0].created_at, tags: args[0].tags ?? [], content: args[0].content ?? '' }, sk);
    if (method === 'nip44.encrypt') return nip44.v2.encrypt(args[1], nip44.v2.utils.getConversationKey(sk, args[0]));
    if (method === 'nip44.decrypt') return nip44.v2.decrypt(args[1], nip44.v2.utils.getConversationKey(sk, args[0]));
    throw new Error('no such method');
  });
  await context.addInitScript((withNip44: boolean) => {
    const call = (m: string, ...a: unknown[]) => (window as any).__standinExtension(m, a);
    (window as any).nostr = {
      getPublicKey: () => call('getPublicKey'),
      signEvent: (t: unknown) => call('signEvent', t),
      ...(withNip44 ? { nip44: { encrypt: (pk: string, s: string) => call('nip44.encrypt', pk, s), decrypt: (pk: string, s: string) => call('nip44.decrypt', pk, s) } } : {}),
    };
  }, opts.nip44 !== false);
  return {
    pubkey,
    calls,
    setMode(m: ExtensionMode) { mode = m; },
    /** A locked extension, unlocked: what was waiting gets the account (if still in 'locked' mode, set another first or not). */
    unlock() { mode = mode === 'locked' ? 'ready' : mode; for (const u of unlocks.splice(0)) u(); },
  };
}
export type FakeExtension = Awaited<ReturnType<typeof fakeExtension>>;
