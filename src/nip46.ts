// Site sign-in: this device as a NIP-46 remote signer ("bunker"). A site talks to the bunker's own
// key over a relay; the bunker signs with the device's piece and the box. Tier 2: once a site has
// connected with the bunker's secret, its requests are answered with no prompt.

import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools/pure';
import { v2 as nip44 } from 'nostr-tools/nip44';
import { Relay } from 'nostr-tools/relay';
import * as D from './device.ts';
import { KeykinError, hexToBytes, bytesToHex, randomBytes } from './bytes.ts';

export interface BunkerState { sk: string; secret: string; clients: string[] }
export const newBunker = (): BunkerState => ({ sk: bytesToHex(randomBytes(32)), secret: bytesToHex(randomBytes(16)), clients: [] });
export const bunkerUrl = (b: BunkerState, relay: string) =>
  `bunker://${getPublicKey(hexToBytes(b.sk))}?relay=${encodeURIComponent(relay)}&secret=${b.secret}`;

/** Answers one request from `client`. Returns the NIP-46 `result` string, or throws. */
export async function answerRequest(b: BunkerState, me: D.Me, h: D.Held, send: D.Send, client: string, method: string, params: string[], onChange: () => void): Promise<string> {
  if (method === 'connect') {
    const known = b.clients.includes(client);
    if (!known && params[1] !== b.secret) throw new KeykinError('bad_secret');
    if (!known) { b.clients.push(client); onChange(); }
    return params[1] ? params[1] : 'ack';
  }
  if (!b.clients.includes(client)) throw new KeykinError('not_connected');
  switch (method) {
    case 'ping': return 'pong';
    case 'get_public_key': return h.npub;
    case 'sign_event': {
      const e = JSON.parse(params[0]);
      const signed = await D.signEvent(me, h, { pubkey: h.npub, created_at: e.created_at, kind: e.kind, tags: e.tags ?? [], content: e.content ?? '' }, send);
      return JSON.stringify(signed);
    }
    case 'nip44_encrypt': return D.nip44Encrypt(me, h, params[0], params[1], send);
    case 'nip44_decrypt': return D.nip44Decrypt(me, h, params[0], params[1], send);
    default: throw new KeykinError('unsupported');
  }
}

/** Runs the bunker on one relay until `close()` is called. */
export async function runBunker(o: { bunker: BunkerState; me: D.Me; held: D.Held; send: D.Send; relay: string; onChange?: () => void; log?: (s: string) => void }) {
  const sk = hexToBytes(o.bunker.sk), pub = getPublicKey(sk), log = o.log ?? (() => {});
  const relay = await Relay.connect(o.relay);
  const seen = new Set<string>();
  const sub = relay.subscribe([{ kinds: [24133], '#p': [pub], since: Math.floor(Date.now() / 1000) - 10 }], {
    onevent: async (ev: Event) => {
      if (seen.has(ev.id)) return; seen.add(ev.id);
      const key = nip44.utils.getConversationKey(sk, ev.pubkey);
      let req: { id: string; method: string; params: string[] };
      try { req = JSON.parse(nip44.decrypt(ev.content, key)); } catch { return; }
      let body: { id: string; result?: string; error?: string };
      try { body = { id: req.id, result: await answerRequest(o.bunker, o.me, o.held, o.send, ev.pubkey, req.method, req.params ?? [], o.onChange ?? (() => {})) }; }
      catch (e) { body = { id: req.id, error: e instanceof KeykinError ? e.code : 'failed' }; if (!(e instanceof KeykinError)) log(`bunker: ${String(e)}`); }
      log(`bunker: ${req.method} from ${ev.pubkey.slice(0, 8)} -> ${body.error ?? 'ok'}`);
      const reply = finalizeEvent({ kind: 24133, created_at: Math.floor(Date.now() / 1000), tags: [['p', ev.pubkey]], content: nip44.encrypt(JSON.stringify(body), key) }, sk);
      await relay.publish(reply).catch((e) => log(`bunker: publish failed: ${String(e)}`));
    },
  });
  return { url: bunkerUrl(o.bunker, o.relay), close: () => { sub.close(); relay.close(); } };
}
