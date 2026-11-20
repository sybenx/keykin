// A device's side of everything. `send` carries a signed request to the box and returns its reply;
// over HTTP, a tailnet or a test bus, this file does not care.

import * as F from './frost.ts';
import { ask, finish, type Piece } from './round.ts';
import { eventId, type UnsignedEvent } from './event.ts';
import { seal, type Signed, type Fingerprint } from './member.ts';
import { sealTo, openFrom } from './seal.ts';
import { commitmentFrom, scalarFrom, scalarHex, interpolate, mul, compHex, mod, derivePoint } from './curve.ts';
import { randomBytes, bytesToHex, hexToBytes, shaHex } from './bytes.ts';
import { ecdhPart, ecdhShared, nip44Key } from './ecdh.ts';
import { v2 as nip44 } from 'nostr-tools/nip44';
import { refuse } from './bytes.ts';
import { type Child, childPiece, childNpub, labelPoint, tweakFrom, tweakOf } from './child.ts';
export type { Child };

export type Send = (req: Signed) => Promise<any>;
/** This device: its member key, and its chip (fingerprint) if it has one. */
export interface Me { sk: string; key: string; name: string; chip?: string; fp?: Fingerprint }
/** What a device keeps once it is in an account. */
export interface Held { piece: Piece; npub: string; boxKey: string; epoch: number }

const call = async (send: Send, req: Signed) => { const r = await send(req); if (r?.error) refuse(r.error); return r; };

/**
 * A request that depends on the current pieces. If the keys were cycled while this device was away,
 * the box says `stale` and hands over the changes; the device applies them to `h` and asks again.
 * `h` is changed in place, so the caller saves it afterwards.
 */
async function current(me: Me, h: Held, send: Send, t: number, body: (h: Held) => object, fp?: Fingerprint) {
  for (let tries = 0; ; tries++) {
    const r = await send(await seal({ ...body(h), epoch: h.epoch, account: h.npub }, me.sk, t, fp));
    if (r?.error !== 'stale' || tries || !Array.isArray(r.catchups)) { if (r?.error) refuse(r.error); return r; }
    let share = h.piece.share;
    for (const c of r.catchups) share = mod(share + scalarFrom(openFrom(me.sk, c.from, 'cycle', c.sealed)));
    const C = commitmentFrom(r.commitment);
    if (compHex(C[0]).slice(2) !== h.npub || !mul(share).equals(derivePoint(C, BigInt(h.piece.i)))) refuse('bad_piece');
    h.piece = { C, i: h.piece.i, share }; h.epoch = r.epoch;
    await call(send, await seal({ op: 'caught_up', account: h.npub }, me.sk, t));
  }
}
const now = () => Math.floor(Date.now() / 1000);

/** What the QR on an empty box says. */
export function readQr(text: string): { addr: string; key: string; code: string } {
  let q: any; try { q = JSON.parse(text); } catch { return refuse('bad_qr'); }
  if (q?.keykin !== 2 || typeof q.addr !== 'string' || !/^[0-9a-f]{64}$/.test(q.key) || typeof q.code !== 'string') refuse('bad_qr');
  return q;
}

/** After scanning the box's QR: the device and the box make the key together. No whole key exists. */
export async function createWithBox(me: Me, qr: { key: string; code: string }, send: Send, t = now()): Promise<Held> {
  const one = F.dkg1(1, 2);
  const r1 = await call(send, await seal({ op: 'create1', request: qr.code, code: qr.code, pkg: one.pkg, name: me.name, chip: me.chip }, me.sk, t));
  const box: [number, string][] = [[2, r1.pkg]];
  const two = F.dkg2(one.secret, box);
  const r2 = await call(send, await seal({ op: 'create2', request: qr.code, pkg2: sealTo(me.sk, qr.key, 'keygen', two.pkgs.get(2)!) }, me.sk, t));
  const done = F.dkg3(two.secret, box, [[2, openFrom(me.sk, qr.key, 'keygen', r2.pkg2)]]);
  if (done.npub !== r2.npub) refuse('bad_keygen');
  return { piece: { C: done.C, i: 1, share: done.share }, npub: done.npub, boxKey: qr.key, epoch: 0 };
}

/** `grant` names the site or app this signature is for (SPEC 11.5); leave it out for the person's own use. */
/** `tapped`: the person said Yes on this device to a hard-to-undo event (see destructive.ts). Without it the box answers `needs_tap`. */
/**
 * Brings in a key the person already has (hex). This device splits it, keeps one piece and sends the
 * box the other, sealed. The caller KEEPS the whole key, encrypted at rest, as the tier 1 backup: it is
 * how the account comes back if the pieces are lost. It is forgotten only when the person chooses to.
 */
export async function importWithBox(me: Me, qr: { key: string; code: string }, nsecHex: string, send: Send, t = now()): Promise<Held> {
  if (!/^[0-9a-f]{64}$/.test(nsecHex)) refuse('bad_key');
  const { commitment: C, a0, a1 } = F.deal(BigInt('0x' + nsecHex));
  const npub = compHex(C[0]).slice(2);
  const r = await call(send, await seal({ op: 'import', request: qr.code, commitment: C.map(compHex), share: sealTo(me.sk, qr.key, 'import', scalarHex(F.pieceAt(a0, a1, 2))), name: me.name, chip: me.chip }, me.sk, t));
  if (r.npub !== npub) refuse('bad_keygen');
  return { piece: { C, i: 1, share: F.pieceAt(a0, a1, 1) }, npub, boxKey: qr.key, epoch: 0 };
}

/** The piece to use: the account's own, or this holder's piece of a child (SPEC 8k). Read after any catch-up. */
const pieceFor = (h: Held, child?: Child): Piece => (child ? childPiece(h.piece, tweakOf(child.t)) : h.piece);

/** `child`: sign as that child key instead of the account's. The event's `pubkey` must be the child's. */
export async function signEvent(me: Me, h: Held, ev: UnsignedEvent, send: Send, t = now(), grant?: string, tapped?: boolean, child?: Child) {
  const id = eventId(ev);
  let mine = ask(pieceFor(h, child), id);
  const r = await current(me, h, send, t, (h) => ({ op: 'sign', event: ev, commit: (mine = ask(pieceFor(h, child), id)).commit, grant, tapped, child: child?.t }));
  if (r.id !== id) refuse('wrong_id');
  return { ...ev, id, sig: finish(pieceFor(h, child), id, mine, { commit: r.commit, z: r.z }) };
}

/**
 * Makes (or makes again) the child key for a label (SPEC 8k). This device and the box work out the
 * tweak together; neither could alone, and any two pieces give the same child. Nothing is stored at
 * the box. The caller keeps the result to save asking again.
 */
export async function makeChild(me: Me, h: Held, label: string, send: Send, t = now()): Promise<Child> {
  const peer = labelPoint(label);
  const r = await current(me, h, send, t, () => ({ op: 'ecdh', peer }));
  const tweak = tweakFrom(ecdhShared(ecdhPart(h.piece.i, h.piece.share, r.i, peer), r.part), label);
  return { label, t: tweak, npub: childNpub(h.piece.C, BigInt('0x' + tweak)) };
}

export async function members(me: Me, send: Send, t = now(), account?: string) { return call(send, await seal({ op: 'members', account }, me.sk, t)); }
export async function block(me: Me, key: string, send: Send, t = now(), account?: string) { return call(send, await seal({ op: 'block', key, account }, me.sk, t)); }
/** Needs the fingerprint. */
export async function unblock(me: Me, key: string, send: Send, t = now(), account?: string) { return call(send, await seal({ op: 'unblock', key, account }, me.sk, t, me.fp)); }

/**
 * Adds a device (or a second box). Needs the fingerprint. This device and the box each give half
 * of the newcomer's piece; neither sees the piece, and the key is never whole.
 */
export async function addMember(me: Me, h: Held, m: { key: string; name: string; kind: 'device' | 'box'; chip?: string }, send: Send, t = now(), note?: string) {
  const list = await members(me, send, t, h.npub);
  const i: number = list.next;
  const boxI = list.members.find((x: any) => x.key === h.boxKey)?.i ?? refuse('no_box');
  const helpers = [h.piece.i, boxI].sort((a, b) => a - b);
  let mine = new Map<number, string>();
  const r = await current(me, h, send, t, (h) => {
    mine = F.repairDeltas(h.piece.C, helpers, h.piece.i, h.piece.share, i);
    return { op: 'add', member: { ...m, i }, delta: sealTo(me.sk, h.boxKey, 'repair-delta', mine.get(boxI)!), note };
  }, note ? undefined : me.fp);
  const sigma = F.repairSigma([mine.get(h.piece.i)!, openFrom(me.sk, h.boxKey, 'repair-delta', r.delta)]);
  await call(send, await seal({ op: 'welcome_put', account: h.npub, key: m.key, sigma: sealTo(me.sk, m.key, 'repair-sigma', sigma) }, me.sk, t));
  return i;
}

/**
 * The new device's side: collect both halves and build its piece. `npub` must be the one it was told. A device
 * added through the account page also shows the approval code the page gave (SPEC 11.6), and its PKCE verifier
 * when its invite came with a challenge.
 */
export async function join(me: Me, boxKey: string, npub: string, send: Send, t = now(), approval?: { code: string; verifier?: string }): Promise<Held> {
  const r = await call(send, await seal({ op: 'welcome', account: npub, ...(approval ? { code: approval.code, ...(approval.verifier ? { verifier: approval.verifier } : {}) } : {}) }, me.sk, t));
  if (r.npub !== npub) refuse('wrong_account');
  const C = commitmentFrom(r.commitment);
  if (compHex(C[0]).slice(2) !== npub) refuse('wrong_account');
  const sigmas = [openFrom(me.sk, boxKey, 'repair-sigma', r.box), openFrom(me.sk, r.from, 'repair-sigma', r.device)];
  return { piece: { C, i: r.i, share: F.repairShare(C, sigmas, r.i) }, npub, boxKey, epoch: r.epoch };
}

/**
 * Falls back to the nsec. Needs the fingerprint. The box hands over its piece, and this device
 * forms the nsec from the two. This is the only place a whole key ever exists.
 */
export async function formNsec(me: Me, h: Held, send: Send, t = now()): Promise<string> {
  const r = await current(me, h, send, t, () => ({ op: 'reveal' }), me.fp);
  const boxShare = scalarFrom(openFrom(me.sk, h.boxKey, 'reveal', r.share));
  const nsec = interpolate([[BigInt(h.piece.i), h.piece.share], [BigInt(r.i), boxShare]], 0n);
  if (compHex(mul(nsec)).slice(2) !== h.npub) refuse('bad_piece');
  return scalarHex(nsec);
}

/** The NIP-44 conversation key with `peer` (x-only hex), made with the box. The key is never whole. `child`: as that child key. */
export async function conversationKey(me: Me, h: Held, peer: string, send: Send, t = now(), grant?: string, child?: Child): Promise<Uint8Array> {
  const r = await current(me, h, send, t, () => ({ op: 'ecdh', peer, grant, child: child?.t }));
  const p = pieceFor(h, child);
  return nip44Key(ecdhShared(ecdhPart(p.i, p.share, r.i, peer), r.part));
}
export async function nip44Encrypt(me: Me, h: Held, peer: string, text: string, send: Send, t = now(), grant?: string, child?: Child) {
  return nip44.encrypt(text, await conversationKey(me, h, peer, send, t, grant, child));
}
/** A wrong part from the box cannot forge a message: NIP-44's MAC check fails instead. */
export async function nip44Decrypt(me: Me, h: Held, peer: string, payload: string, send: Send, t = now(), grant?: string, child?: Child) {
  return nip44.decrypt(payload, await conversationKey(me, h, peer, send, t, grant, child));
}

/**
 * Cycles the keys. Needs the fingerprint. Every blocked device is dropped for good and its piece
 * stops fitting with anyone's. The key itself, and so the npub, does not change.
 */
/** `note`: a signed-in account page asked for it and the person tapped Yes here, in place of the fingerprint. */
export async function cycle(me: Me, h: Held, send: Send, t = now(), note?: string) {
  const list = await members(me, send, t, h.npub);
  let b1 = 0n;
  const r = await current(me, h, send, t, () => {
    b1 = scalarFrom(bytesToHex(randomBytes(32)));
    const changes: Record<string, string> = {};
    for (const m of list.members) {
      if (m.blocked || m.key === me.key || m.key === h.boxKey) continue;
      changes[m.key] = sealTo(me.sk, m.key, 'cycle', scalarHex(mod(b1 * BigInt(m.i))));
    }
    return { op: 'cycle', b1: sealTo(me.sk, h.boxKey, 'cycle', scalarHex(b1)), changes, note };
  }, note ? undefined : me.fp);
  const C = commitmentFrom(r.commitment);
  const share = mod(h.piece.share + b1 * BigInt(h.piece.i));
  if (!mul(share).equals(derivePoint(C, BigInt(h.piece.i)))) refuse('bad_piece');
  h.piece = { C, i: h.piece.i, share }; h.epoch = r.epoch;
}

/** Logs a browser in to the box's page, from the code that page shows. Needs the fingerprint. */
export async function approveLogin(me: Me, h: Held, text: string, send: Send, t = now()) {
  let q: any; try { q = JSON.parse(text)?.login; } catch { return refuse('bad_qr'); }
  if (!q || typeof q.code !== 'string') refuse('bad_qr');
  if (q.key !== h.boxKey) refuse('wrong_box');          // only this account's own box
  await call(send, await seal({ op: 'login', account: h.npub, code: q.code }, me.sk, t, me.fp));
}

/** Tells the box where this device listens for other devices (see helper.ts), or with no address, that it stopped. */
export async function setAddress(me: Me, addr: string | undefined, send: Send, t = now(), account?: string) { return call(send, await seal({ op: 'address', addr, account }, me.sk, t)); }

/**
 * Asks the box first and, if it cannot be reached, other devices that listen. Only signing and message
 * keys can be done without the box; everything else needs it.
 */
export function withHelpers(box: Send, helpers: Send[]): Send {
  return async (req) => {
    try { return await box(req); }
    catch (e) {
      if (req.body?.op !== 'sign' && req.body?.op !== 'ecdh') throw e;
      let last: any = { error: 'no_box' };
      for (const h of helpers) { try { const r = await h(req); if (!r?.error) return r; last = r; } catch { /* try the next */ } }
      return last;
    }
  };
}

// --- Asking for an account on a box that needs the admin's yes (SPEC 11.4) --------------------------

/** Asks to make an account (or move one) on a box. Returns the request id to wait on. */
export async function askBox(me: Me, what: 'make' | 'transfer', note: string, send: Send, t = now(), account?: string): Promise<string> {
  return (await call(send, await seal({ op: 'ask', what, name: me.name, note, chip: me.chip, account }, me.sk, t))).request;
}
/** `waiting`, `approved`, `refused` or `gone`. Once approved, pass the id as the `code` to createWithBox. */
export async function asked(me: Me, request: string, send: Send, t = now()): Promise<string> {
  return (await call(send, await seal({ op: 'asked', request }, me.sk, t))).state;
}
/** The same, with the box's member key: `{ state, key }`. A device that only had the box's address needs the key to go on. */
export async function askedWithKey(me: Me, request: string, send: Send, t = now()): Promise<{ state: string; key: string }> {
  const r = await call(send, await seal({ op: 'asked', request }, me.sk, t));
  return { state: r.state, key: r.key };
}
/** Takes the request back. Only the device that asked can. */
export async function askCancel(me: Me, request: string, send: Send, t = now()) { await call(send, await seal({ op: 'ask_cancel', request }, me.sk, t)); }

// --- Username and password for the account page (SPEC 11.3) ----------------------------------------

/** The verifier for a password: PBKDF2-HMAC-SHA256, 600000 rounds, 32 bytes, over the NFKC form. Hex. */
export async function passwordVerifier(password: string, saltHex: string): Promise<string> {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  const salt = Uint8Array.from(saltHex.match(/../g)!.map((b) => parseInt(b, 16)));
  return bytesToHex(new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: 600000 }, key, 256)));
}
/** What the box stores for a verifier. */
export const passwordCheck = (verifierHex: string) => shaHex('keykin2-pw', hexToBytes(verifierHex));
/** Sets or changes the username and password. Needs the fingerprint. The box never sees the password. */
export async function passwordSet(me: Me, h: Held, username: string, password: string, send: Send, t = now()) {
  const salt = bytesToHex(randomBytes(16));
  const check = passwordCheck(await passwordVerifier(password, salt));
  await call(send, await seal({ op: 'password_set', account: h.npub, username, salt, check }, me.sk, t, me.fp));
}
export async function passwordClear(me: Me, h: Held, send: Send, t = now()) { await call(send, await seal({ op: 'password_clear', account: h.npub }, me.sk, t, me.fp)); }

// --- What this device has let in, and revoking (SPEC 11.5) -----------------------------------------

/** `client`, `device` and `via` are optional (SPEC 11.5): the site's NIP-46 key, its own label, and how it came in. */
export interface Grant { id: string; kind: 'site' | 'app'; name: string; since: number; client?: string; device?: string; via?: 'login' | 'scan' | 'paste' | 'bunker' }
export const newGrant = (kind: 'site' | 'app', name: string, t = now()): Grant => ({ id: bytesToHex(randomBytes(16)), kind, name, since: t });
/** Tells the box this device's whole list. Returns the ids that were revoked, to drop from the list. */
export async function reportGrants(me: Me, h: Held, grants: Grant[], send: Send, t = now()): Promise<string[]> {
  return (await call(send, await seal({ op: 'grants', account: h.npub, grants }, me.sk, t))).revoked;
}
export async function revoke(me: Me, h: Held, grant: string, send: Send, t = now()) { await call(send, await seal({ op: 'revoke', account: h.npub, grant }, me.sk, t)); }
/** Limits a grant to posting (`posts`): the box then signs only posts for it and gives it no message keys. `null` lifts the limit. */
export async function limit(me: Me, h: Held, grant: string, to: 'posts' | null, send: Send, t = now()) { await call(send, await seal({ op: 'limit', account: h.npub, grant, to: to ?? null }, me.sk, t)); }

// --- Things the account page started for a device to finish (SPEC 11.6) ----------------------------

/** `tap` is true when the device must ask the person Yes or No before doing it. */
/** For `nostrconnect`: `from` is the origin that sent the person to the login page (null if it could not tell),
 *  and `as` the key they chose, `main` or `site` (SPEC 11.6). A device that does not know `as` uses the main account. */
/** For `bunker`: `text` is an optional name for the site, and `lists` and `dms` the site's two switches (SPEC 11.6). */
export interface Note { id: string; kind: 'nostrconnect' | 'invite' | 'bunker' | 'cycle' | 'pointer'; text: string; at: number; tap: boolean; from?: string | null; as?: 'main' | 'site'; lists?: boolean; dms?: boolean }
/** A site's name as a person or the site gave it: no control characters, trimmed, at most 60 characters. Undefined when empty. */
export const siteName = (s: unknown): string | undefined => typeof s === 'string' ? s.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 60) || undefined : undefined;
export async function notes(me: Me, h: Held, send: Send, t = now()): Promise<Note[]> { return (await call(send, await seal({ op: 'notes', account: h.npub }, me.sk, t))).notes; }
/** Like `notes`, but the box holds the answer up to `wait` seconds (at most 25) until a note comes. Notes in `seen` alone do not answer at once. */
export async function notesWait(me: Me, h: Held, send: Send, wait: number, seen: string[] = [], t = now()): Promise<Note[]> {
  return (await call(send, await seal({ op: 'notes_wait', account: h.npub, wait, seen }, me.sk, t))).notes;
}
export async function noteDone(me: Me, h: Held, note: string, result: string, send: Send, t = now()) { await call(send, await seal({ op: 'note_done', account: h.npub, note, result }, me.sk, t)); }
/** The person tapped No. The note goes, and the browser that asked is signed out of the account page. */
export async function noteRefuse(me: Me, h: Held, note: string, send: Send, t = now()) { await call(send, await seal({ op: 'note_refuse', account: h.npub, note }, me.sk, t)); }

/**
 * Does what the account page asked, for every note waiting (SPEC 11.6). A signed-in account page has
 * the person's authority, so a device just does these; only a note marked `tap` asks first.
 *   `addr`         where the new device will reach the box, for the join text it is handed.
 *   `tap(text)`    asks the person Yes or No. Called only for hard-to-undo notes.
 *   `bunker(o)`    makes a bunker:// link, or null if this device runs no remote signer. `o.name` is the
 *                  site's name if the person gave one, and `o.lists`, `o.dms` the site's two switches.
 *   `connect(uri)` becomes the signer for a nostrconnect:// code, or false if this device cannot.
 *   `pointer(origin)` signs and publishes the sign-in-page pointer (both kinds, SPEC 11.1) naming `origin`,
 *                  true once a relay took it. Asked first with `tap`; No answers `declined`, not `note_refuse`.
 * Returns what it did, for the device to show or log.
 */
export async function answerNotes(me: Me, h: Held, send: Send, can: { addr: string; tap: (text: string) => Promise<boolean>; bunker?: (o: { name?: string; lists: boolean; dms: boolean }) => Promise<string | null>; connect?: (uri: string) => Promise<boolean>; pointer?: (origin: string) => Promise<boolean> }, t = now()): Promise<string[]> {
  const did: string[] = [];
  for (const n of await notes(me, h, send, t)) {
    try {
      if (n.kind === 'invite') {
        const inv = JSON.parse(n.text).invite;
        await addMember(me, h, { key: inv.key, name: String(inv.name ?? 'Device'), kind: 'device', chip: inv.chip }, send, t, n.id);
        await noteDone(me, h, n.id, JSON.stringify({ keykin: 2, join: { addr: can.addr, boxKey: h.boxKey, npub: h.npub } }), send, t);
        did.push(`added ${inv.name}`);
      } else if (n.kind === 'bunker') {
        const link = await can.bunker?.({ name: siteName(n.text), lists: n.lists === true, dms: n.dms === true });
        if (link) { await noteDone(me, h, n.id, link, send, t); did.push('gave a bunker link'); }
      } else if (n.kind === 'nostrconnect') {
        if (await can.connect?.(n.text)) { await noteDone(me, h, n.id, 'ok', send, t); did.push('signed a site in'); }
      } else if (n.kind === 'pointer') {
        if (!can.pointer || !/^https?:\/\/[^\s/?#]+$/.test(n.text)) continue;
        if (!(await can.tap(`Make ${new URL(n.text).host} your sign-in page?`))) { await noteDone(me, h, n.id, 'declined', send, t); did.push('said No to the sign-in page'); }
        else if (await can.pointer(n.text)) { await noteDone(me, h, n.id, 'ok', send, t); did.push(`published ${n.text} as the sign-in page`); }
      } else if (n.kind === 'cycle') {
        if (await can.tap('Remove blocked devices for good? Their pieces stop working. This cannot be undone.')) { await cycle(me, h, send, t, n.id); await noteDone(me, h, n.id, 'ok', send, t); did.push('removed blocked devices'); }
        else { await noteRefuse(me, h, n.id, send, t); did.push('said No to removing blocked devices'); }
      }
    } catch (e: any) { did.push(`could not do ${n.kind}: ${e?.code ?? e?.message ?? e}`); }
  }
  return did;
}

/**
 * Moves the account to another Keykin box (SPEC 11.4). Needs the fingerprint. The key is never whole:
 * this device and the old box give the new box its piece, then the keys are cycled on the new box so the
 * old box's piece stops fitting. `h` ends up pointing at the new box. Other devices then need the new
 * box's address and key (a join text) and catch up on their next request.
 */
export async function transferToBox(me: Me, h: Held, oldSend: Send, newBox: { key: string; code: string }, newSend: Send, t = now()) {
  const oldBox = h.boxKey;
  await addMember(me, h, { key: newBox.key, name: 'New box', kind: 'box' }, oldSend, t);
  const one = await call(newSend, await seal({ op: 'transfer1', request: newBox.code, account: h.npub }, me.sk, t));
  const welcome = await call(oldSend, one.welcome);
  const list = await members(me, oldSend, t, h.npub);
  await call(newSend, await seal({ op: 'transfer2', request: newBox.code, welcome, oldBox, members: list.members, next: list.next }, me.sk, t));
  h.boxKey = newBox.key;
  await cycle(me, h, newSend, t);          // the old box gets no change, so its piece is dead
}
