// Signing in to a site by scanning its code: the QRST `signer-ticket` profile
// (qr-secret-transfer/profiles/signer-ticket.md). What moves is a single-use ticket, never a key.
// The site redeems it with this account's remote signer as the secret of a NIP-46 `connect`, and from
// then on has access of its own, which the signer can remove.
//
// Both halves are here. `answerCode` is the signer's: a device that scanned a site's code.
// `startSignIn` is the site's: it shows the code and ends up with a working signer.

import { base64 } from '@scure/base';
import { Transfer, Store, parseUri, relayPolicy, isPrivateHost, type Profile, type PairingParams, type TransferView, type CodeCheck, type Env } from '../vendor/qrst.js';
import { utf8ToBytes, randomBytes, bytesToHex } from './bytes.ts';

export interface Ticket { v: 1; pubkey: string; signer: string; relays: string[]; t: string; expires: number }
export const TICKET_SECONDS = 900;

const HEX64 = /^[0-9a-f]{64}$/, HEX32 = /^[0-9a-f]{32}$/;
const relayOk = (u: unknown) => {
  if (typeof u !== 'string') return false;
  try { const x = new URL(u); return x.protocol === 'wss:' || (x.protocol === 'ws:' && relayPolicy.loopback && isPrivateHost(x.hostname)); } catch { return false; }
};
const short = (hex: string) => `${hex.slice(0, 8)}…`;
const host = (u: string) => { try { return new URL(u).host; } catch { return u; } };

export const signerTicket: Profile<Ticket> = {
  id: 'signer-ticket',
  maxPayloadBytes: 2048,
  revocable: true,
  minCheck: 'none',          // only when the signer's own camera read the code; `answerCode` asks for `compare` otherwise
  encode(v) { return base64.encode(utf8ToBytes(JSON.stringify({ v: 1, pubkey: v.pubkey, signer: v.signer, relays: v.relays, t: v.t, expires: v.expires }))); },
  check(content) {
    let o: any;
    try { o = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(base64.decode(content))); } catch { return { ok: false, reason: 'not a ticket' }; }
    if (!o || typeof o !== 'object' || Array.isArray(o) || Object.keys(o).sort().join() !== 'expires,pubkey,relays,signer,t,v') return { ok: false, reason: 'not a ticket' };
    if (o.v !== 1 || !HEX64.test(o.pubkey) || !HEX64.test(o.signer) || !HEX32.test(o.t)) return { ok: false, reason: 'malformed ticket' };
    if (!Array.isArray(o.relays) || o.relays.length < 1 || o.relays.length > 6 || !o.relays.every(relayOk)) return { ok: false, reason: 'bad relays' };
    if (!Number.isInteger(o.expires) || o.expires <= Math.floor(Date.now() / 1000)) return { ok: false, reason: 'expired' };
    return { ok: true, value: o as Ticket };
  },
  render(v) { return `Sign in as ${short(v.pubkey)}, through your signer ${short(v.signer)} on ${host(v.relays[0])}?`; },
  direction: { offer: 'Scan this with your signer to sign in.', request: '' },
  release: {
    heading: 'Let this site sign as you?',
    body: 'The site gets access of its own. You remove it in your signer’s list of sites. Removing it stops future signing, not what was already signed.',
    confirm: (origin) => (origin ? `Let ${origin} sign as me` : 'Let that site sign as me'),
    decline: 'Don’t allow',
  },
  accept: { heading: 'Sign in?', confirm: 'Sign in', decline: 'Cancel' },
};

const env: Env = { random: (n) => crypto.getRandomValues(new Uint8Array(n)), now: () => Math.floor(Date.now() / 1000) };
const allowLocal = (relays: readonly string[]) => { if (relays.some((r) => { try { return isPrivateHost(new URL(r).hostname); } catch { return false; } })) relayPolicy.loopback = true; };
function until<T>(t: Transfer<T>, pred: (v: TransferView<T>) => boolean, ms: number): Promise<TransferView<T>> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out')), ms);
    const look = () => { const v = t.view(); if (pred(v)) { clearTimeout(timer); resolve(v); } };
    const before = t.onChange;
    t.onChange = () => { before(); look(); };
    look();
  });
}

/** A site's code, read by a signer. Throws unless it is a sign-in code. */
export function readCode(text: string): PairingParams {
  // A signer is an app, not a public web page, and Keykin's relays are often on a tailnet or this machine,
  // so a code may name a private relay. (QRST forbids that only to pages, which a link could aim at a local service.)
  relayPolicy.loopback = true;
  const p = parseUri(text.trim());
  if (p.profile !== signerTicket.id || p.mode !== 'offer') throw new Error('That is not a sign-in code.');
  return p;
}

export interface AnswerOptions {
  params: PairingParams;
  /** True only if this device's own camera read the code. Anything pasted or handed over gets the five-digit check. */
  viaCamera: boolean;
  /** "Let <origin> sign as you?" Asked before anything is made. */
  consent: (origin: string | undefined) => Promise<boolean>;
  /** Makes the ticket, once the person has said yes, and tells the signer to accept it once. */
  mint: (origin: string | undefined) => Promise<Ticket> | Ticket;
  /** When the code was not read by camera: "Does the site show these five digits?" */
  sameDigits: (digits: string) => Promise<boolean>;
  timeoutMs?: number;
}

/** The signer's half. Resolves once the site has the ticket; throws if the person said no or it did not arrive. */
export async function answerCode(o: AnswerOptions): Promise<Ticket> {
  const origin = o.params.origin;
  if (!(await o.consent(origin))) throw new Error('Not allowed.');
  allowLocal(o.params.relays);
  const ticket = await o.mint(origin);
  const check: CodeCheck = o.viaCamera ? 'none' : 'compare';
  const deps = { profile: signerTicket, store: new Store(undefined, env.now, [], []), env, baseUrl: 'https://keykin.invalid/', origin: 'https://keykin.invalid', check, replenish: false };
  if (Transfer.refusal(deps, o.params)) throw new Error('That code cannot be used.');
  const t = Transfer.join(deps, o.params, { viaCamera: o.viaCamera }, ticket);
  try {
    const ms = o.timeoutMs ?? 60_000;
    const v = await until(t, (v) => v.session.phase === 'release' || v.stage === 'ended', ms);
    if (v.stage === 'ended') throw new Error('The site did not answer.');
    if (v.session.check === 'none') t.release();
    else if (v.session.check === 'compare') { if (await o.sameDigits(v.session.compare!)) t.confirmMatch(); else { t.rejectMatch(); throw new Error('The digits did not match. Nothing was sent.'); } }
    else throw new Error('That site asks for the digits to be typed, which this signer does not do.');
    const end = await until(t, (v) => v.stage === 'ended', ms);
    if (end.session.outcome !== 'delivered') throw new Error('The site did not take the sign-in.');
    return ticket;
  } finally { t.dispose(); }
}

export interface SignInView {
  /** The link to show as a QR, once a relay is ready. */
  uri?: string;
  /** Five digits to show, when the signer did not read the code by camera. */
  digits?: string;
  /** Set when a ticket has arrived: what to ask the person before signing in. */
  asking?: string;
  state: 'starting' | 'showing' | 'checking' | 'asking' | 'connecting' | 'done' | 'failed';
  problem?: string;
}
export interface SignInOptions {
  /** Relays this site listens on for the answer. */
  relays: string[];
  /** This page's address without a fragment, and its origin. */
  baseUrl: string; origin: string;
  onView: (v: SignInView) => void;
  /** "Sign in as …, through your signer … on …?" The site MUST ask, since it has no signer set up beforehand. */
  confirm: (question: string) => Promise<boolean>;
  /** Redeems the ticket: a NIP-46 `connect` to `ticket.signer` on `ticket.relays` with `ticket.t` as the secret. */
  redeem: (ticket: Ticket) => Promise<void>;
}

/** The site's half. Shows a code, takes the ticket, asks, and redeems it. `cancel` stops it. */
export function startSignIn(o: SignInOptions): { done: Promise<Ticket>; cancel: () => void } {
  allowLocal(o.relays);
  const deps = { profile: signerTicket, store: new Store(undefined, env.now, [], o.relays), env, baseUrl: o.baseUrl, origin: o.origin, check: 'none' as CodeCheck, replenish: false };
  const t = Transfer.show(deps, 'receiver');
  let stopped = false;
  const show = (extra: Partial<SignInView> = {}) => {
    const v = t.view();
    const state: SignInView['state'] = v.session.phase === 'code' && v.session.code ? 'checking' : v.uri ? 'showing' : 'starting';
    o.onView({ state, ...(v.uri ? { uri: v.uri } : {}), ...(v.session.code ? { digits: v.session.code } : {}), ...extra });
  };
  t.onChange = () => { if (!stopped && t.view().session.phase !== 'accept' && t.view().stage !== 'ended') show(); };
  const done = (async () => {
    try {
      show();
      const v = await until(t, (v) => v.session.phase === 'accept' || v.stage === 'ended', 600_000);
      if (v.stage === 'ended') throw new Error('The code ran out. Try again.');
      const question = v.session.rendering!;
      // The payload is only held so far. Ask, then commit it; only a committed ticket is redeemed (QRST §9.4).
      o.onView({ state: 'asking', asking: question });
      const peek = await new Promise<Ticket>((resolve, reject) => {
        // The value becomes readable after accept(); ask first with the rendering, which names the account and signer.
        o.confirm(question).then((yes) => {
          if (!yes) { t.decline(); reject(new Error('Cancelled.')); return; }
          t.accept();
          const got = t.view().value;
          got ? resolve(got) : reject(new Error('The sign-in did not arrive.'));
        }, reject);
      });
      o.onView({ state: 'connecting' });
      await o.redeem(peek);
      o.onView({ state: 'done' });
      return peek;
    } catch (e: any) {
      if (!stopped) o.onView({ state: 'failed', problem: e?.message ?? String(e) });
      throw e;
    } finally { stopped = true; setTimeout(() => t.dispose(), 1500); }   // let the acknowledgement leave first
  })();
  return { done, cancel: () => { stopped = true; t.cancel(); t.dispose(); } };
}

/** A fresh ticket for `origin`, for a signer to hand out. */
export const newTicket = (pubkey: string, signer: string, relays: string[]): Ticket =>
  ({ v: 1, pubkey, signer, relays, t: bytesToHex(randomBytes(16)), expires: Math.floor(Date.now() / 1000) + TICKET_SECONDS });
