// Site sign-in: this device as a NIP-46 remote signer ("bunker"). A site talks to the bunker's own
// key over a relay; the bunker signs with the device's piece and the box. Tier 2: once a site has
// connected with the bunker's secret, its requests are answered with no prompt.

import { finalizeEvent, getPublicKey, type Event } from 'nostr-tools/pure';
import { v2 as nip44 } from 'nostr-tools/nip44';
import { Relay } from 'nostr-tools/relay';
import * as D from './device.ts';
import { KeykinError, hexToBytes, bytesToHex, randomBytes } from './bytes.ts';
import { TICKET_SECONDS } from './ticket.ts';
import { onlyFromPhone } from './destructive.ts';

export interface BunkerState {
  sk: string; secret: string; clients: string[];
  /** The relay the signer listens on, so a ticket can name it. */
  relay?: string;
  /** Sign-in tickets handed out and not yet used (QRST signer-ticket). Each works once, until `expires`. */
  /** A bunker link's ticket may carry the site's name, as the person typed it, and its two switches. */
  tickets?: { t: string; expires: number; origin?: string; name?: string; lists?: boolean; dms?: boolean }[];
  /** Which site each signed-in client key belongs to, when it came in by a ticket. */
  origins?: Record<string, string>;
  /** A site's name when it has no origin: the one the person typed, else the site's own (its code's, or its first post's client tag). */
  names?: Record<string, string>;
  /** A site's two switches, "Read your private lists" and "Read and send DMs", when its link turned one on. Kept for the site; this core does not act on them yet. */
  scopes?: Record<string, { lists: boolean; dms: boolean }>;
  /** The grant each signed-in client key is known by at the box (SPEC 11.5). */
  grants?: Record<string, D.Grant>;
  /** For a site that came in by a nostrconnect:// code: the relays its code named, which the signer also listens on. */
  relaysOf?: Record<string, string[]>;
}
/** Signs one site out. The link's secret changes too, so an old link cannot be used to come back. */
export function signOut(b: BunkerState, prefix: string): string[] {
  const gone = b.clients.filter((c) => c.startsWith(prefix));
  const named = Object.entries({ ...b.names, ...b.origins }).filter(([, o]) => o === prefix || o.includes(prefix)).map(([k]) => k);
  for (const k of named) if (!gone.includes(k)) gone.push(k);
  if (gone.length) { b.clients = b.clients.filter((c) => !gone.includes(c)); for (const k of gone) { delete b.origins?.[k]; delete b.names?.[k]; delete b.scopes?.[k]; delete b.grants?.[k]; delete b.relaysOf?.[k]; } b.secret = bytesToHex(randomBytes(16)); }
  return gone;
}
export const newBunker = (): BunkerState => ({ sk: bytesToHex(randomBytes(32)), secret: bytesToHex(randomBytes(16)), clients: [] });
export const bunkerUrl = (b: BunkerState, relay: string) =>
  `bunker://${getPublicKey(hexToBytes(b.sk))}?relay=${encodeURIComponent(relay)}&secret=${b.secret}`;
/** A bunker link whose secret is a ticket: it works once, for 15 minutes, and names the site and sets its switches as asked. */
export function bunkerTicket(b: BunkerState, relay: string, o: { name?: string; lists?: boolean; dms?: boolean } = {}): string {
  const t = bytesToHex(randomBytes(16)), name = D.siteName(o.name);
  (b.tickets ??= []).push({ t, expires: Math.floor(Date.now() / 1000) + TICKET_SECONDS, ...(name ? { name } : {}), ...(o.lists ? { lists: true } : {}), ...(o.dms ? { dms: true } : {}) });
  return `bunker://${getPublicKey(hexToBytes(b.sk))}?relay=${encodeURIComponent(relay)}&secret=${t}`;
}

/** Answers one request from `client`. Returns the NIP-46 `result` string, or throws. */
export async function answerRequest(b: BunkerState, me: D.Me, h: D.Held, send: D.Send, client: string, method: string, params: string[], onChange: () => void): Promise<string> {
  if (method === 'connect') {
    const known = b.clients.includes(client);
    if (!known) {
      const now = Math.floor(Date.now() / 1000);
      b.tickets = (b.tickets ?? []).filter((x) => x.expires > now);
      const ticket = b.tickets.find((x) => x.t === params[1]);
      if (!ticket && params[1] !== b.secret) throw new KeykinError('bad_secret');
      if (ticket) {            // a ticket works once, and the site's key is tied to the origin the person approved
        b.tickets = b.tickets.filter((x) => x !== ticket);
        if (ticket.origin) (b.origins ??= {})[client] = ticket.origin;
        if (ticket.name) (b.names ??= {})[client] = ticket.name;
        if (ticket.lists || ticket.dms) (b.scopes ??= {})[client] = { lists: !!ticket.lists, dms: !!ticket.dms };
      }
      admit(b, client, b.origins?.[client] ?? b.names?.[client]);
      onChange();
    }
    return params[1] ? params[1] : 'ack';
  }
  if (!b.clients.includes(client)) throw new KeykinError('not_connected');
  const grant = b.grants?.[client]?.id;
  try { return await serve(); }
  catch (e) {
    // Revoked at the box: this site is done here too.
    if (e instanceof KeykinError && e.code === 'revoked') { dropClient(b, client); onChange(); }
    throw e;
  }
  async function serve(): Promise<string> {
  switch (method) {
    case 'ping': return 'pong';
    case 'get_public_key': return h.npub;
    case 'sign_event': {
      const e = JSON.parse(params[0]);
      nameFromPost(b, client, e.tags, onChange);
      const signed = await D.signEvent(me, h, { pubkey: h.npub, created_at: e.created_at, kind: e.kind, tags: e.tags ?? [], content: e.content ?? '' }, send, undefined, grant);
      return JSON.stringify(signed);
    }
    case 'nip44_encrypt': return D.nip44Encrypt(me, h, params[0], params[1], send, undefined, grant);
    case 'nip44_decrypt': return D.nip44Decrypt(me, h, params[0], params[1], send, undefined, grant);
    default: throw new KeykinError('unsupported');
  }
  }
}

/**
 * The NIP-46 error a site gets. The box's reason travels with its error (`needs_tap: Empty your follow list`): this
 * signer cannot ask the person, so the site is told why rather than a bare code. An event that is never done by
 * accident (level 2, SPEC 11.6) also says where it is done: `needs_fingerprint: Empty your follow list. Do this from
 * your phone.`
 */
export function errorText(e: unknown): string {
  if (!(e instanceof KeykinError)) return 'failed';
  if (!e.why) return e.code;
  return `${e.code}: ${phoneOnly(e) ? onlyFromPhone(e.why) : e.why}`;
}
/** A level 2 refusal: the box wants the phone's fingerprint for this event (an account change's refusal carries no words). */
export const phoneOnly = (e: unknown) => e instanceof KeykinError && !!e.why && (e.code === 'needs_fingerprint' || e.code === 'no_chip_key');

/** Lets a site's key in, as a grant the account page lists under Sites and apps (SPEC 11.5). */
function admit(b: BunkerState, client: string, name?: string) {
  if (!b.clients.includes(client)) b.clients.push(client);
  (b.grants ??= {})[client] ??= D.newGrant('site', name ?? `A site (${client.slice(0, 8)})`);
}

/**
 * A site with no origin and no name takes the name its first post carries in a client tag
 * (`["client", "<name>", ...]`). A name, once there, stays: the person's own word, or the first tag.
 */
function nameFromPost(b: BunkerState, client: string, tags: unknown, onChange: () => void) {
  if (b.origins?.[client] || b.names?.[client] || !Array.isArray(tags)) return;
  const name = D.siteName(tags.find((t) => Array.isArray(t) && t[0] === 'client' && D.siteName(t[1]))?.[1]);
  if (!name) return;
  (b.names ??= {})[client] = name;
  const g = b.grants?.[client]; if (g) g.name = name;
  onChange();
}

/** Forgets a site: its key, its grant, the origin it was approved for, its name and the relays it named. */
export function dropClient(b: BunkerState, client: string) {
  b.clients = b.clients.filter((c) => c !== client);
  if (b.grants) delete b.grants[client];
  if (b.origins) delete b.origins[client];
  if (b.names) delete b.names[client];
  if (b.scopes) delete b.scopes[client];
  if (b.relaysOf) delete b.relaysOf[client];
}

/** What a site's nostrconnect:// code says (NIP-46): its own key, the relays it listens on, and the secret to echo. */
export interface ConnectCode { client: string; relays: string[]; secret: string; name?: string; url?: string }
export function readNostrConnect(text: string): ConnectCode {
  let u: URL; try { u = new URL(text.trim()); } catch { throw new KeykinError('bad_code'); }
  const client = u.host.toLowerCase();
  if (u.protocol !== 'nostrconnect:' || !/^[0-9a-f]{64}$/.test(client)) throw new KeykinError('bad_code');
  const relays = [...new Set(u.searchParams.getAll('relay').map((r) => r.trim()).filter((r) => /^wss?:\/\/[^\s]+$/.test(r)))].slice(0, 5);
  const secret = u.searchParams.get('secret') ?? '';
  if (!relays.length || !secret || secret.length > 200) throw new KeykinError('bad_code');
  let url: string | undefined;
  try { const o = new URL(u.searchParams.get('url') ?? ''); if (o.protocol === 'https:' || o.protocol === 'http:') url = o.origin; } catch { /* none */ }
  const name = u.searchParams.get('name')?.slice(0, 60) || undefined;
  return { client, relays, secret, name, url };
}
/** Tells the box what this signer has let in, and forgets whatever was revoked there. */
export async function syncGrants(b: BunkerState, me: D.Me, h: D.Held, send: D.Send): Promise<number> {
  const revoked = await D.reportGrants(me, h, Object.values(b.grants ?? {}), send);
  for (const [client, g] of Object.entries(b.grants ?? {})) if (revoked.includes(g.id)) dropClient(b, client);
  return revoked.length;
}

/**
 * Runs the bunker until `close()` is called. It listens on `relay`, and also on any relay a site's
 * nostrconnect:// code named. Each answer goes back on the relay the request came in on.
 */
export async function runBunker(o: { bunker: BunkerState; me: D.Me; held: D.Held; send: D.Send; relay: string; onChange?: () => void; before?: () => void; log?: (s: string) => void }) {
  const sk = hexToBytes(o.bunker.sk), pub = getPublicKey(sk), log = o.log ?? (() => {});
  const seen = new Set<string>();
  const open = new Map<string, Promise<{ relay: Relay; close: () => void }>>();
  const reply = (relay: Relay, client: string, body: object) => {
    const ev = finalizeEvent({ kind: 24133, created_at: Math.floor(Date.now() / 1000), tags: [['p', client]], content: nip44.encrypt(JSON.stringify(body), nip44.utils.getConversationKey(sk, client)) }, sk);
    return relay.publish(ev).catch((e) => log(`bunker: publish failed: ${String(e)}`));
  };
  /** Listens on one more relay, once. */
  const listen = (url: string) => {
    if (!open.has(url)) {
      const p = Relay.connect(url).then((relay) => {
        const sub = relay.subscribe([{ kinds: [24133], '#p': [pub], since: Math.floor(Date.now() / 1000) - 10 }], {
          onevent: async (ev: Event) => {
            if (seen.has(ev.id)) return; seen.add(ev.id);
            let req: { id: string; method: string; params: string[] };
            try { req = JSON.parse(nip44.decrypt(ev.content, nip44.utils.getConversationKey(sk, ev.pubkey))); } catch { return; }
            let body: { id: string; result?: string; error?: string };
            o.before?.();   // pick up sign-outs made while running
            try { body = { id: req.id, result: await answerRequest(o.bunker, o.me, o.held, o.send, ev.pubkey, req.method, req.params ?? [], o.onChange ?? (() => {})) }; }
            catch (e) { body = { id: req.id, error: errorText(e) }; if (!(e instanceof KeykinError)) log(`bunker: ${String(e)}`); }
            log(`bunker: ${req.method} from ${ev.pubkey.slice(0, 8)} -> ${body.error ?? 'ok'}`);
            await reply(relay, ev.pubkey, body);
          },
        });
        return { relay, close: () => { sub.close(); relay.close(); } };
      });
      p.catch(() => open.delete(url));      // a relay that cannot be reached is tried again next time
      open.set(url, p);
    }
    return open.get(url)!;
  };
  await listen(o.relay);
  if (o.bunker.relay !== o.relay) { o.bunker.relay = o.relay; o.onChange?.(); }
  for (const urls of Object.values(o.bunker.relaysOf ?? {})) for (const u of urls) listen(u).catch((e) => log(`bunker: cannot reach ${u}: ${String(e)}`));

  /**
   * Becomes the signer for a site that shows a nostrconnect:// code. The site is let in at once (the person
   * asked for it, on the account page or here), listened for on the relays its code names, and sent the
   * connect answer it waits for: a response whose result is the code's secret. False if no relay could be reached.
   */
  const connect = async (text: string): Promise<boolean> => {
    const c = readNostrConnect(text);
    o.before?.();
    if (c.url) (o.bunker.origins ??= {})[c.client] = c.url;
    const name = D.siteName(c.name); if (name) (o.bunker.names ??= {})[c.client] = name;
    admit(o.bunker, c.client, c.url ?? name);
    (o.bunker.relaysOf ??= {})[c.client] = c.relays;
    o.onChange?.();
    let sent = 0;
    for (const u of c.relays) {
      try { const { relay } = await listen(u); await reply(relay, c.client, { id: bytesToHex(randomBytes(8)), result: c.secret }); sent++; }
      catch (e) { log(`bunker: cannot reach ${u}: ${String(e)}`); }
    }
    log(`bunker: connected to ${c.client.slice(0, 8)}${c.url ? ` (${c.url})` : ''} on ${sent} relay${sent === 1 ? '' : 's'}`);
    return sent > 0;
  };
  const close = () => { for (const p of open.values()) p.then((r) => r.close(), () => {}); open.clear(); };
  return { url: bunkerUrl(o.bunker, o.relay), close, connect };
}
