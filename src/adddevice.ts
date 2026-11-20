// Adding a device with one code: the QRST `keykin-device` profile (qr-secret-transfer/profiles/
// keykin-device.md, SPEC 8b). The new device shows the code, with its invite in it. A device in the
// account scans it, adds the newcomer, and releases the join text (the newcomer then collects its own
// piece from the box) or, for an account with no box, the whole key. What it gives is that device's
// decision, never the newcomer's.
//
// Both halves are here. `showAddCode` is the new device's; `answerAddCode` is the adding device's.
// The profile is the same as qr-secret-transfer's src/core/keykin-device.ts, kept here like `signerTicket`
// in ticket.ts, because vendor/qrst.js is built from that repository's main branch.

import { base64, base64urlnopad } from '@scure/base';
import { Transfer, Store, parseUri, relayPolicy, isPrivateHost, isValidPublicKey, publicKey, npubEncode, bytesToHex, hexToBytes, type Profile, type PairingParams, type TransferView, type CodeCheck, type Env } from '../vendor/qrst.js';

export const KEYKIN_DEVICE = 'keykin-device';
/** The account's join text (SPEC 8b). Nothing secret. */
export interface KeykinJoin { addr: string; boxKey: string; npub: string; loginPage?: string }
/** What the new device receives. */
export type KeykinGift = { join: KeykinJoin } | { nsec: Uint8Array };
/** A new device's invite (SPEC 8b). */
export interface KeykinInvite { text: string; key: string; name: string; chip?: string }

const HEX64 = /^[0-9a-f]{64}$/, CHIP = /^0[23][0-9a-f]{64}$/;
const enc = new TextEncoder(), dec = new TextDecoder('utf-8', { fatal: true });
function addrOk(a: unknown): a is string {
  if (typeof a !== 'string' || a.length > 300) return false;
  try { const u = new URL(a); return (u.protocol === 'https:' || u.protocol === 'http:') && !u.username && !u.password && !u.hash; } catch { return false; }
}
function loginOk(a: unknown): a is string {
  if (typeof a !== 'string') return false;
  try { const u = new URL(a); return (u.protocol === 'https:' || (u.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(u.hostname))) && u.origin === a; } catch { return false; }
}
function validSecret(k: Uint8Array): boolean { if (k.length !== 32) return false; try { return isValidPublicKey(publicKey(k)); } catch { return false; } }
const shortNpub = (hex: string) => { const n = npubEncode(hex); return `${n.slice(0, 12)}…${n.slice(-6)}`; };

export const keykinDevice: Profile<KeykinGift> = {
  id: KEYKIN_DEVICE,
  maxPayloadBytes: 2048,
  revocable: false,
  minCheck: 'none',          // only when the adding device's own camera read the code; `answerAddCode` asks for `compare` otherwise
  encode(v) {
    let o: unknown;
    if ('join' in v) {
      const j = v.join;
      if (!addrOk(j.addr) || !HEX64.test(j.boxKey) || !HEX64.test(j.npub) || (j.loginPage !== undefined && !loginOk(j.loginPage))) throw new Error('not a join text');
      o = { keykin: 2, join: { addr: j.addr, boxKey: j.boxKey, npub: j.npub, ...(j.loginPage ? { loginPage: j.loginPage } : {}) } };
    } else {
      if (!validSecret(v.nsec)) throw new Error('not a valid key');
      o = { keykin: 2, nsec: bytesToHex(v.nsec) };
    }
    return base64.encode(enc.encode(JSON.stringify(o)));
  },
  check(content) {
    let o: any;
    try { o = JSON.parse(dec.decode(base64.decode(content))); } catch { return { ok: false, reason: 'not a keykin-device payload' }; }
    if (!o || typeof o !== 'object' || Array.isArray(o) || o.keykin !== 2) return { ok: false, reason: 'not a keykin-device payload' };
    const keys = Object.keys(o).sort().join();
    if (keys === 'join,keykin') {
      const j = o.join;
      if (!j || typeof j !== 'object' || Array.isArray(j)) return { ok: false, reason: 'malformed join text' };
      if (Object.keys(j).some((k) => !['addr', 'boxKey', 'npub', 'loginPage'].includes(k)) || !addrOk(j.addr) || !HEX64.test(j.boxKey) || !HEX64.test(j.npub) || !isValidPublicKey(j.npub)) return { ok: false, reason: 'malformed join text' };
      if (j.loginPage !== undefined && !loginOk(j.loginPage)) return { ok: false, reason: 'bad login page' };
      return { ok: true, value: { join: { addr: j.addr, boxKey: j.boxKey, npub: j.npub, ...(j.loginPage ? { loginPage: j.loginPage } : {}) } } };
    }
    if (keys === 'keykin,nsec') {
      if (typeof o.nsec !== 'string' || !HEX64.test(o.nsec)) return { ok: false, reason: 'malformed key' };
      const k = hexToBytes(o.nsec);
      return validSecret(k) ? { ok: true, value: { nsec: k } } : { ok: false, reason: 'not a valid secp256k1 key' };
    }
    return { ok: false, reason: 'not a keykin-device payload' };
  },
  render(v) { return `Your account ${shortNpub('join' in v ? v.join.npub : publicKey(v.nsec))}`; },
  direction: { offer: 'Scan with your phone', request: '' },
  release: { heading: 'Add this device?', body: '', confirm: () => 'Add', decline: 'Not now' },
  accept: { heading: 'Signed in', confirm: 'OK', decline: 'Cancel' },
};

/** Reads an invite from its JSON text, or null. */
export function readInvite(text: unknown): KeykinInvite | null {
  if (typeof text !== 'string' || text.length > 1024) return null;
  let o: any; try { o = JSON.parse(text); } catch { return null; }
  const i = o && o.keykin === 2 && o.invite && typeof o.invite === 'object' && !Array.isArray(o.invite) ? o.invite : null;
  if (!i || typeof i.key !== 'string' || !HEX64.test(i.key) || !isValidPublicKey(i.key)) return null;
  if (i.chip !== undefined && (typeof i.chip !== 'string' || !CHIP.test(i.chip))) return null;
  const name = (typeof i.name === 'string' ? i.name.trim().slice(0, 60) : '') || 'A new device';
  return { text, key: i.key, name, ...(i.chip !== undefined ? { chip: i.chip } : {}) };
}
export const withInvite = (uri: string, inviteText: string) => {
  if (!readInvite(inviteText)) throw new Error('not a Keykin invite');
  return `${uri}&invite=${base64urlnopad.encode(enc.encode(inviteText))}`;
};
export function inviteOf(uri: string): KeykinInvite | null {
  const t = uri.trim();
  const params = t.includes('#') ? t.slice(t.indexOf('#') + 1) : t.includes('?') ? t.slice(t.indexOf('?') + 1) : t;
  const found = params.split('&').filter((p) => p.startsWith('invite='));
  if (found.length !== 1) return null;
  try { return readInvite(dec.decode(base64urlnopad.decode(decodeURIComponent(found[0]!.slice(7))))); } catch { return null; }
}

/** An add code, read by a device in the account. Throws unless it is one, with a good invite. */
export function readAddCode(text: string): { params: PairingParams; invite: KeykinInvite } {
  relayPolicy.loopback = true;        // a device, not a public page: its relays may be on this machine or a tailnet
  let params: PairingParams;
  try { params = parseUri(text.trim()); } catch { throw new Error('That is not a code for adding a device.'); }
  if (params.profile !== KEYKIN_DEVICE || params.mode !== 'offer') throw new Error('That is not a code for adding a device.');
  const invite = inviteOf(text) ?? (() => { throw new Error('That code has no device in it.'); })();
  return { params, invite };
}

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

export interface AnswerAddOptions {
  code: { params: PairingParams; invite: KeykinInvite };
  /** True only if this device's own camera read the code. Anything pasted or handed over compares five digits. */
  viaCamera: boolean;
  /** "Add <name>?" Nothing is added before a yes. */
  consent: (invite: KeykinInvite) => Promise<boolean>;
  /** Adds the device and returns the join text, or returns the whole key for an account with no box. After the yes only. */
  gift: (invite: KeykinInvite) => Promise<KeykinGift>;
  /** When the code was not read by camera: "Does the new device show these five digits?" */
  sameDigits: (digits: string) => Promise<boolean>;
  timeoutMs?: number;
}

/** The adding device's half. Resolves once the new device has what it was given. */
export async function answerAddCode(o: AnswerAddOptions): Promise<KeykinGift> {
  if (!(await o.consent(o.code.invite))) throw new Error('Not added.');
  allowLocal(o.code.params.relays);
  const check: CodeCheck = o.viaCamera ? 'none' : 'compare';
  const deps = { profile: keykinDevice, store: new Store(undefined, env.now, [], []), env, baseUrl: 'https://keykin.invalid/', origin: 'https://keykin.invalid', check, replenish: false };
  if (Transfer.refusal(deps, o.code.params)) throw new Error('That code cannot be used.');
  // The TypeScript session wants a payload when it is made. It gets a harmless stand-in (a join text naming no box,
  // nothing secret), replaced below before anything is released.
  const g = '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
  const t = Transfer.join(deps, o.code.params, { viaCamera: o.viaCamera }, { join: { addr: 'https://keykin.invalid', boxKey: g, npub: g } });
  try {
    const ms = o.timeoutMs ?? 60_000;
    const v = await until(t, (v) => v.session.phase === 'release' || v.stage === 'ended', ms);
    if (v.stage === 'ended') throw new Error('The new device did not answer.');
    // The digits come before anything is added: a code that is not the one on the new device adds nobody.
    if (v.session.check === 'compare' && !(await o.sameDigits(v.session.compare!))) { t.rejectMatch(); throw new Error('The digits did not match. Nothing was added.'); }
    if (v.session.check !== 'none' && v.session.check !== 'compare') throw new Error('That device asks for the digits to be typed, which this device does not do.');
    const gift = await o.gift(o.code.invite);
    // QRST's TypeScript session takes its payload when it is made; the Kotlin one takes it at release, which is
    // what this needs (nothing is added before the digits). So it is handed over here, the way Kotlin does it.
    const session = (t as any).session;
    if (!session || !('payloadContent' in session)) throw new Error('This QRST library cannot take the payload at release.');
    session.payloadContent = keykinDevice.encode(gift);
    if (v.session.check === 'none') t.release(); else t.confirmMatch();
    const end = await until(t, (v) => v.stage === 'ended', ms);
    if (end.session.outcome !== 'delivered') throw new Error('The new device did not take it.');
    return gift;
  } finally { t.dispose(); }
}

export interface AddCodeView { uri?: string; digits?: string; state: 'starting' | 'showing' | 'checking' | 'done' | 'failed'; problem?: string }

/** The new device's half: show the code, keep what arrives (no second tap, by the profile's departure from QRST §9.4). */
export function showAddCode(o: { invite: string; relays: string[]; baseUrl: string; onView: (v: AddCodeView) => void; timeoutMs?: number }): { done: Promise<KeykinGift>; cancel: () => void } {
  allowLocal(o.relays);
  const deps = { profile: keykinDevice, store: new Store(undefined, env.now, [], o.relays), env, baseUrl: o.baseUrl, origin: new URL(o.baseUrl).origin, check: 'none' as CodeCheck, replenish: false };
  const t = Transfer.show(deps, 'receiver');
  let stopped = false;
  const show = () => {
    const v = t.view();
    const state: AddCodeView['state'] = v.session.phase === 'code' && v.session.code ? 'checking' : v.uri ? 'showing' : 'starting';
    o.onView({ state, ...(v.uri ? { uri: withInvite(v.uri, o.invite) } : {}), ...(v.session.code ? { digits: v.session.code } : {}) });
  };
  t.onChange = () => { if (!stopped && t.view().session.phase !== 'accept' && t.view().stage !== 'ended') show(); };
  const done = (async () => {
    try {
      show();
      const v = await until(t, (v) => v.session.phase === 'accept' || v.stage === 'ended', o.timeoutMs ?? 600_000);
      if (v.stage === 'ended') throw new Error('The code ran out. Try again.');
      t.accept();
      const got = t.view().value ?? (() => { throw new Error('Nothing arrived.'); })();
      o.onView({ state: 'done' });
      return got;
    } catch (e: any) {
      if (!stopped) o.onView({ state: 'failed', problem: e?.message ?? String(e) });
      throw e;
    } finally { stopped = true; setTimeout(() => t.dispose(), 1500); }
  })();
  return { done, cancel: () => { stopped = true; t.cancel(); t.dispose(); } };
}
