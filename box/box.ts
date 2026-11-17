// The box: one always-on machine holding one piece. It never starts a signature; it only helps a
// device that asks. It keeps the list of pieces and refuses blocked ones. No I/O here: `handle`
// takes a request and the time, and `state` is plain JSON the server file saves.

import * as F from '../src/frost.ts';
import { answer } from '../src/round.ts';
import { ecdhPart } from '../src/ecdh.ts';
import { eventId, type UnsignedEvent } from '../src/event.ts';
import { destructive } from '../src/destructive.ts';
import { open, fingerprintOk, newMemberKey, type Signed, MAX_SKEW } from '../src/member.ts';
import { sealTo, openFrom } from '../src/seal.ts';
import { commitmentFrom, commitmentHex, scalarHex, scalarFrom, mul, mod, type Commitment } from '../src/curve.ts';
import { KeykinError, refuse, randomBytes, bytesToHex, hexToBytes, sha, jcsBytes } from '../src/bytes.ts';
import { schnorr } from '@noble/curves/secp256k1.js';

/** `addr` is where a device that can listen answers other devices when the box is off. */
export interface Member { key: string; i: number; name: string; kind: 'device' | 'box'; chip?: string; addr?: string; blocked: boolean; added: number;
  /** When it last signed or made a message key, and when it was blocked. Unix seconds. */
  last?: number; blockedAt?: number }
/** What waits for a newly added member: the two values its piece is built from. */
export interface Welcome { by: string; box: string; device?: string; fetched?: boolean }
/** A change of piece waiting for a member that was not there when the keys were cycled. */
export interface Catchup { from: string; sealed: string }
export interface Account {
  commitment: string[]; npub: string;
  i: number; share: string;            // the box's own piece
  epoch: number;                       // goes up each time the keys are cycled
  next: number;                        // the next unused index
  members: Member[];
  welcomes: Record<string, Welcome>;
  catchups: Record<string, Catchup[]>;
  /** Username and password for the account page (SPEC 11.3). The box never has the password. */
  login?: { username: string; salt: string; check: string; fails?: number; lockedUntil?: number };
  /** What each device has let in (SPEC 11.5), by the device's member key. */
  grants?: Record<string, Grant[]>;
  /** Grants that were revoked. The box refuses any request naming one. */
  revoked?: string[];
  /** Grants the person limited (SPEC 11.5): `posts` lets that site or app post and nothing else. */
  limits?: Record<string, 'posts'>;
  /** Recent activity, newest last, at most 60 lines. */
  log?: Happened[];
}
export interface Grant { id: string; kind: 'site' | 'app'; name: string; since: number; last?: number }
/** Something the account page started for a device to finish (SPEC 11.6). */
/** `tap` is true for the hard-to-undo ones: a device asks the person Yes or No before doing it. */
export interface Note { id: string; kind: 'nostrconnect' | 'invite' | 'bunker' | 'cycle'; text: string; at: number; tap: boolean; result?: string }
/** One line of an account's recent activity. */
export interface Happened { at: number; text: string }
/** Someone asking to make an account here or move one here (SPEC 11.4). The admin decides. */
export interface Ask {
  id: string; what: 'make' | 'transfer';
  key?: string;                        // the asking device's member key; none for a code the admin made
  name?: string; note?: string; chip?: string; account?: string;
  only?: string;                       // a code made for one account (hex): good only for bringing that account in
  asked: number; state: 'waiting' | 'approved' | 'refused'; decided?: number;
}
/** `owner` is the hash of the owner secret that logs in to the admin page. Accounts are keyed by npub, hex. */
export interface BoxState { sk: string; key: string; owner?: string; pwSecret?: string; accounts: Record<string, Account>; requests: Record<string, Ask> }

const HEX64 = /^[0-9a-f]{64}$/, CHIP = /^0[23][0-9a-f]{64}$/;
const DEVICE_I = 1, BOX_I = 2;         // the first device and the box, at creation
const EPOCH_OPS = new Set(['sign', 'ecdh', 'add', 'reveal', 'cycle']);
const MAX_WAITING = 50, ASK_DAYS = 7, APPROVED_HOURS = 24;
export const USERNAME = /^[a-z0-9._-]{3,32}$/;
/** What a grant limited to `posts` may still sign: notes, reposts, reactions, comments, zap requests, media posts, and site logins (NIP-42). */
export const POST_KINDS = new Set([1, 6, 7, 16, 1111, 9734, 20, 21, 22, 22242]);

export class Box {
  state: BoxState;
  /** The code an empty box shows, so its first account needs no approval. A fresh one each start. */
  readonly setupCode = bytesToHex(randomBytes(16));
  #seen = new Map<string, number>();   // request id -> ts, for replay refusal
  #pending = new Map<string, { device: string; secret: string; pkg: string; name: string; chip?: string }>();   // by request id
  onChange: (s: BoxState) => void = () => {};
  /** Set by the server: approves a login to the box's page that a device scanned. Returns false if unknown or expired. */
  onLogin: (code: string, account: string, by: string) => boolean = () => false;
  /** Set by the page API: the notes waiting for an account's devices, and a device's answer to one. */
  onNotes: (account: string) => Note[] = () => [];
  onNoteDone: (account: string, note: string, result: string) => boolean = () => false;
  /** A device's person tapped No: the note goes, and so does the page session that left it. */
  onNoteRefused: (account: string, note: string) => boolean = () => false;

  constructor(state: BoxState | null = null) {
    const s: any = state ?? { ...newMemberKey() };
    // A state file from when a box held one account.
    if (!s.accounts) { s.accounts = s.account ? { [s.account.npub]: s.account } : {}; delete s.account; }
    s.requests ??= {};
    this.state = s;
  }

  /** The accounts, oldest first. */
  accounts(): Account[] { return Object.values(this.state.accounts); }
  /** The account when there is exactly one to speak of: the first, or null on an empty box. */
  only(): Account | null { return this.accounts()[0] ?? null; }

  /** What the QR on an empty box says. `addr` is where devices reach it. Null once it holds an account. */
  qr(addr: string) { return this.accounts().length ? null : JSON.stringify({ keykin: 2, addr, key: this.state.key, code: this.setupCode }); }

  /** The admin makes room for one more account: a request approved in advance, as a setup code. */
  newSetupCode(addr: string, now: number, only?: string): string {
    const id = bytesToHex(randomBytes(16));
    this.state.requests[id] = { id, what: 'make', asked: now, state: 'approved', decided: now, ...(only ? { only } : {}) };
    this.#save();
    return JSON.stringify({ keykin: 2, addr, key: this.state.key, code: id });
  }
  /** The admin's answer to someone asking (SPEC 11.4). */
  decide(id: string, approve: boolean, now: number) {
    const r = this.state.requests[id] ?? refuse('gone');
    if (r.state !== 'waiting') refuse('already_decided');
    r.state = approve ? 'approved' : 'refused'; r.decided = now;
    this.#save();
  }
  /** The admin removes an account and its piece, for good. */
  removeAccount(npub: string) {
    if (!this.state.accounts[npub]) refuse('unknown_account');
    delete this.state.accounts[npub];
    this.#save();
  }
  #tidyRequests(now: number) {
    let changed = false;
    for (const r of Object.values(this.state.requests)) {
      const dead = r.state === 'approved' ? now - (r.decided ?? r.asked) > APPROVED_HOURS * 3600 : now - r.asked > ASK_DAYS * 86400;
      if (dead) { delete this.state.requests[r.id]; this.#pending.delete(r.id); changed = true; }
    }
    if (changed) this.#save();
  }
  /** The request a `create` or `transfer` names, if it may be used by this device now. */
  #usable(id: unknown, device: string, what: 'make' | 'transfer', bringing?: '*'): string {
    if (typeof id !== 'string') refuse('bad_code');
    if (id === this.setupCode) { if (this.accounts().length) refuse('already_set_up'); return id as string; }
    const r = this.state.requests[id as string];
    if (r?.only && bringing !== '*') refuse('bad_code');      // made for one account, from the account page
    // A code the admin made (no asking device) is good for either; one that was asked for is good for what was asked.
    if (!r || (r.key && r.what !== what)) refuse('bad_code');
    if (r.state !== 'approved') refuse(r.state === 'waiting' ? 'not_approved' : 'refused');
    if (r.key && r.key !== device) refuse('bad_code');
    return id as string;
  }

  /** Every request comes through here. Returns `{ ok, ... }` or `{ error }`. */
  handle(req: Signed, now: number): any {
    try {
      const body = open(req, now);
      for (const [id, ts] of this.#seen) if (now - ts > 2 * MAX_SKEW) this.#seen.delete(id);
      if (this.#seen.has(body.id)) refuse('replay');
      this.#seen.set(body.id, body.ts);
      this.#tidyRequests(now);
      if (body.op === 'ask') return this.#ask(body, req.key, now);
      // `key` is the box's member key: what a device seals to when it goes on to make the account.
      if (body.op === 'asked') return { ok: true, state: this.state.requests[body.request]?.state ?? 'gone', key: this.state.key };
      if (body.op === 'ask_cancel') {
        const r = this.state.requests[body.request];
        if (!r || r.key !== req.key) refuse('gone');
        delete this.state.requests[r!.id]; this.#pending.delete(r!.id); this.#save();
        return { ok: true };
      }
      if (body.op === 'create1') return this.#create1(body, req.key);
      if (body.op === 'create2') return this.#create2(body, req.key, now);
      if (body.op === 'import') return this.#import(body, req.key, now);
      if (body.op === 'transfer1') return this.#transfer1(body, req.key, now);
      if (body.op === 'transfer2') return this.#transfer2(body, req, now);
      const s = this.#accountOf(body);
      const from = s.members.find((m) => m.key === req.key) ?? refuse('unknown_member');
      if (from.blocked) refuse('blocked');
      // A device still on the old pieces is told so, and handed what it needs to catch up.
      if (EPOCH_OPS.has(body.op) && body.epoch !== s.epoch) {
        return { error: 'stale', epoch: s.epoch, commitment: s.commitment, catchups: s.catchups[from.key] ?? [] };
      }
      if ((body.op === 'sign' || body.op === 'ecdh') && body.grant !== undefined) {
        if ((s.revoked ?? []).includes(body.grant)) refuse('revoked');
        // A grant limited to posting signs only posts, and gets no message keys: it cannot read messages.
        if (s.limits?.[body.grant] === 'posts' && (body.op === 'ecdh' || !POST_KINDS.has(body.event?.kind))) refuse('not_allowed');
      }
      switch (body.op) {
        case 'cycle': return this.#cycle(s, from, req, body);
        case 'caught_up': if (s.catchups[from.key]) { delete s.catchups[from.key]; this.#save(); } return { ok: true };
        case 'sign': return this.#sign(s, from, body);
        case 'ecdh': return this.#ecdh(s, from, body);
        case 'members': return { ok: true, npub: s.npub, commitment: s.commitment, epoch: s.epoch, next: s.next, boxKey: this.state.key, members: s.members };
        case 'block': return this.#block(s, body.key);
        case 'unblock': return this.#unblock(s, from, req, body.key);
        case 'add': return this.#add(s, from, req, body, now);
        case 'welcome_put': return this.#welcomePut(s, from, body);
        case 'welcome': return this.#welcome(s, from);
        case 'reveal': return this.#reveal(s, from, req);
        case 'address': {
          // A device that can listen says where; the others use it when the box is off.
          if (body.addr !== undefined && (typeof body.addr !== 'string' || body.addr.length > 200 || !/^https?:\/\//.test(body.addr))) refuse('bad_address');
          if (body.addr) from.addr = body.addr; else delete from.addr;
          this.#save();
          return { ok: true };
        }
        case 'password_set': {
          this.#needFingerprint(from, req);
          const u = body.username;
          if (typeof u !== 'string' || !USERNAME.test(u)) refuse('bad_username');
          if (!/^[0-9a-f]{32}$/.test(body.salt ?? '') || !HEX64.test(body.check ?? '')) refuse('bad_request');
          if (this.accounts().some((a) => a !== s && a.login?.username === u)) refuse('username_taken');
          s.login = { username: u, salt: body.salt, check: body.check };
          this.#save();
          return { ok: true };
        }
        case 'password_clear': this.#needFingerprint(from, req); delete s.login; this.#save(); return { ok: true };
        case 'grants': {
          const list = body.grants;
          if (!Array.isArray(list) || list.length > 200) refuse('bad_request');
          const clean: Grant[] = list.map((g: any) => {
            if (!/^[0-9a-f]{32}$/.test(g?.id ?? '') || (g.kind !== 'site' && g.kind !== 'app') || typeof g.name !== 'string' || !Number.isInteger(g.since)) refuse('bad_request');
            return { id: g.id, kind: g.kind, name: g.name.slice(0, 200), since: g.since };
          });
          const revoked = new Set(s.revoked ?? []);
          (s.grants ??= {})[from.key] = clean.filter((g) => !revoked.has(g.id));
          this.#save();
          return { ok: true, revoked: clean.filter((g) => revoked.has(g.id)).map((g) => g.id) };
        }
        case 'revoke': this.revokeGrant(s.npub, body.grant); return { ok: true };
        case 'limit': this.limitGrant(s.npub, body.grant, body.to); return { ok: true };
        case 'notes': return { ok: true, notes: this.onNotes(s.npub).filter((n) => n.result === undefined).map(({ id, kind, text, at, tap }) => ({ id, kind, text, at, tap })) };
        case 'note_refuse': if (from.kind !== 'device' || !this.onNoteRefused(s.npub, body.note)) refuse('gone'); this.happened(s.npub, `${from.name} said No to a request from the account page`, now); return { ok: true };
        case 'note_done': {
          if (from.kind !== 'device') refuse('devices_only');
          if (typeof body.result !== 'string' || body.result.length > 2000 || !this.onNoteDone(s.npub, body.note, body.result)) refuse('gone');
          return { ok: true };
        }
        case 'login': {
          // Logging in to the box's page gives the power to block and unblock anything, so it needs the fingerprint.
          this.#needFingerprint(from, req);
          if (typeof body.code !== 'string' || !this.onLogin(body.code, s.npub, from.name)) refuse('bad_code');
          return { ok: true };
        }
        default: return refuse('unknown_op');
      }
    } catch (e) {
      if (e instanceof KeykinError) return { error: e.code };
      throw e;
    }
  }

  // Which account a request is about (SPEC 11.2). A box with one account takes a request that names none.
  #accountOf(body: any): Account {
    if (body.account !== undefined) return (typeof body.account === 'string' ? this.state.accounts[body.account] : undefined) ?? refuse('unknown_account');
    const all = this.accounts();
    if (!all.length) refuse('not_set_up');
    if (all.length > 1) refuse('need_account');
    return all[0];
  }
  /** The account a member key is in, for the admin's buttons. `npub` picks one if the key is in several. */
  #holding(key: string, npub?: string): Account {
    const found = this.accounts().filter((a) => (!npub || a.npub === npub) && a.members.some((m) => m.key === key));
    return found[0] ?? refuse('unknown_member');
  }

  // Someone asks to make an account here, or to move one here. It waits for the admin.
  #ask(body: any, device: string, now: number) {
    if (body.what !== 'make' && body.what !== 'transfer') refuse('bad_request');
    if (body.what === 'transfer' && !HEX64.test(body.account ?? '')) refuse('bad_request');
    if (body.chip !== undefined && !CHIP.test(body.chip)) refuse('bad_chip_key');
    const all = Object.values(this.state.requests);
    const mine = all.find((r) => r.key === device && r.state === 'waiting');
    if (mine) return { ok: true, request: mine.id, key: this.state.key };
    if (all.filter((r) => r.state === 'waiting').length >= MAX_WAITING) refuse('too_many');
    const id = bytesToHex(randomBytes(16));
    this.state.requests[id] = { id, what: body.what, key: device, name: String(body.name ?? 'Device').slice(0, 60), note: String(body.note ?? '').slice(0, 200),
      chip: body.chip, account: body.account, asked: now, state: 'waiting' };
    this.#save();
    return { ok: true, request: id, key: this.state.key };
  }

  /** Ends a grant for good (SPEC 11.5): from a device, or from the account page. */
  revokeGrant(npub: string, grant: unknown) {
    const s = this.state.accounts[npub] ?? refuse('unknown_account');
    if (typeof grant !== 'string' || !/^[0-9a-f]{32}$/.test(grant)) refuse('bad_request');
    const r = (s.revoked ??= []);
    if (!r.includes(grant as string)) r.push(grant as string);
    if (r.length > 2000) r.splice(0, r.length - 2000);
    for (const k of Object.keys(s.grants ?? {})) s.grants![k] = s.grants![k].filter((g) => g.id !== grant);
    if (s.limits) delete s.limits[grant as string];
    this.#save();
  }
  /** Limits a grant to posting (`posts`), or lifts the limit (`null`). From a device or the account page. */
  limitGrant(npub: string, grant: unknown, to: unknown) {
    const s = this.state.accounts[npub] ?? refuse('unknown_account');
    if (typeof grant !== 'string' || !/^[0-9a-f]{32}$/.test(grant) || (to !== 'posts' && to !== null)) refuse('bad_request');
    const l = (s.limits ??= {});
    if (to === 'posts') { l[grant as string] = 'posts'; if (Object.keys(l).length > 2000) delete l[Object.keys(l)[0]]; }
    else delete l[grant as string];
    this.#save();
  }
  /** Saves after the page API changed something in the state (a password try count, say). */
  touch() { this.#save(); }
  /** Adds a line to an account's recent activity. */
  happened(npub: string, text: string, now: number) {
    const a = this.state.accounts[npub]; if (!a) return;
    (a.log ??= []).push({ at: now, text });
    if (a.log.length > 60) a.log.splice(0, a.log.length - 60);
    this.#save();
  }
  // Notes when a device and a grant were last used. Saved at most once a minute, so signing stays cheap.
  #lastSave = 0;
  #used(s: Account, from: Member, grant: unknown) {
    const t = Math.floor(Date.now() / 1000);
    from.last = t;
    if (typeof grant === 'string') for (const list of Object.values(s.grants ?? {})) for (const g of list) if (g.id === grant) g.last = t;
    if (t - this.#lastSave >= 60) { this.#lastSave = t; this.#save(); }
  }
  /** The account page's Unblock (a page session may do it) and the admin's. */
  unblockIn(npub: string, key: string) { return this.ownerUnblock(key, npub); }
  /** Sets the username and password for an account from a signed-in account page. */
  setLogin(npub: string, username: unknown, salt: unknown, check: unknown) {
    const s = this.state.accounts[npub] ?? refuse('unknown_account');
    if (typeof username !== 'string' || !USERNAME.test(username)) refuse('bad_username');
    if (typeof salt !== 'string' || !/^[0-9a-f]{32}$/.test(salt) || typeof check !== 'string' || !HEX64.test(check)) refuse('bad_request');
    if (this.accounts().some((a) => a !== s && a.login?.username === username)) refuse('username_taken');
    s.login = { username: username as string, salt: salt as string, check: check as string };
    this.#save();
  }

  /** The admin's Block button. */
  ownerBlock(key: string, npub?: string) { return this.#block(this.#holding(key, npub), key); }

  /**
   * The box owner's Unblock button. This is the way back when a thief with an unlocked phone has
   * blocked every other device: the owner logs in to the box, blocks the phone and unblocks the rest.
   */
  ownerUnblock(key: string, npub?: string) {
    const s = this.#holding(key, npub);
    const m = s.members.find((x) => x.key === key) ?? refuse('unknown_member');
    m.blocked = false; delete m.blockedAt;
    this.#save();
    return { ok: true };
  }

  #save() { this.onChange(this.state); }
  #C(s: Account): Commitment { return commitmentFrom(s.commitment); }

  // Account changes need the fingerprint: a signature by the asking device's chip key.
  #needFingerprint(from: Member, req: Signed) {
    if (from.kind !== 'device') refuse('devices_only');
    if (!from.chip) refuse('no_chip_key');
    if (!fingerprintOk(req, from.chip)) refuse('needs_fingerprint');
  }

  // --- Making the key with the first device. Neither side ever holds the whole key. ---------

  #create1(body: any, device: string) {
    // `request` is the name now; `code` is what older devices send for the same thing.
    const id = this.#usable(body.request ?? body.code, device, 'make');
    if (typeof body.pkg !== 'string') refuse('bad_keygen');
    if (body.chip !== undefined && !CHIP.test(body.chip)) refuse('bad_chip_key');
    const mine = F.dkg1(BOX_I, 2);
    this.#pending.set(id, { device, secret: mine.secret, pkg: body.pkg, name: String(body.name ?? 'First device'), chip: body.chip });
    return { ok: true, pkg: mine.pkg };
  }

  // Bringing in a key the person already has. The device split it; this is the box's piece. The whole
  // key existed on that device for a moment, which making a key together (create1, create2) avoids.
  #import(body: any, device: string, now: number) {
    const id = this.#usable(body.request ?? body.code, device, 'make', '*');     // which account it is for is checked below
    if (body.chip !== undefined && !CHIP.test(body.chip)) refuse('bad_chip_key');
    let C: Commitment, share: bigint;
    try { C = commitmentFrom(body.commitment); share = scalarFrom(openFrom(this.state.sk, device, 'import', body.share)); }
    catch (e) { if (e instanceof KeykinError && e.code === 'bad_seal') throw e; return refuse('bad_piece'); }
    // The piece must lie on the line the device says it is on: share·G = C0 + 2·C1.
    if (share === 0n || !mul(share).equals(C[0].add(C[1].multiply(BigInt(BOX_I))))) refuse('bad_piece');
    const npub = commitmentHex(C)[0].slice(2);
    if (commitmentHex(C)[0].slice(0, 2) !== '02') refuse('bad_piece');          // the key in its even-y form, as BIP-340 wants
    if (this.state.accounts[npub]) refuse('already_here');
    if (this.state.requests[id]?.only && this.state.requests[id].only !== npub) refuse('bad_code');
    delete this.state.requests[id];
    this.state.accounts[npub] = {
      commitment: commitmentHex(C), npub, i: BOX_I, share: scalarHex(share),
      members: [
        { key: device, i: DEVICE_I, name: String(body.name ?? 'First device').slice(0, 60), kind: 'device', chip: body.chip, blocked: false, added: now },
        { key: this.state.key, i: BOX_I, name: 'Box', kind: 'box', blocked: false, added: now },
      ],
      welcomes: {}, catchups: {}, epoch: 0, next: 3,
    };
    this.happened(npub, 'The account was brought here from an existing key', now);
    return { ok: true, npub };
  }

  // --- Moving an account here from another Keykin box (SPEC 11.4). The key is never whole. ----------
  //
  // On the old box the device has already added this box as a member (kind box), so the old box and the
  // device each hold half of this box's new piece, sealed to this box's key. Step 1 hands the device a
  // request, signed by this box, to collect those halves from the old box. Step 2 brings them here.

  #moving = new Map<string, { device: string; account: string }>();      // by request id
  #transfer1(body: any, device: string, now: number) {
    const id = this.#usable(body.request ?? body.code, device, 'transfer');
    if (!HEX64.test(body.account ?? '')) refuse('bad_request');
    if (this.state.accounts[body.account]) refuse('already_here');
    this.#moving.set(id, { device, account: body.account });
    // What this box asks the old one: "give me what is waiting for me in that account".
    const full = { op: 'welcome', account: body.account, ts: now, id: bytesToHex(randomBytes(16)) };
    return { ok: true, welcome: { body: full, key: this.state.key, sig: bytesToHex(schnorr.sign(sha(jcsBytes(full)), hexToBytes(this.state.sk))) } };
  }
  #transfer2(body: any, req: Signed, now: number) {
    const device = req.key;
    const id = this.#usable(body.request ?? body.code, device, 'transfer');
    const m = this.#moving.get(id);
    if (!m || m.device !== device) refuse('no_transfer');
    const w = body.welcome;
    if (!w || w.npub !== m!.account || !HEX64.test(body.oldBox ?? '')) refuse('bad_request');
    let C: Commitment, share: bigint;
    try {
      C = commitmentFrom(w.commitment);
      const sigmas = [openFrom(this.state.sk, body.oldBox, 'repair-sigma', w.box), openFrom(this.state.sk, w.from, 'repair-sigma', w.device)];
      share = F.repairShare(C, sigmas, w.i);                                // checked against the commitment
    } catch (e) { if (e instanceof KeykinError && e.code === 'bad_seal') throw e; return refuse('bad_piece'); }
    if (commitmentHex(C)[0].slice(2) !== m!.account) refuse('wrong_account');
    // The list as the old box had it, with the old box left out and this box in its place.
    const list: Member[] = (Array.isArray(body.members) ? body.members : []).filter((x: any) => x && HEX64.test(x.key) && Number.isInteger(x.i) && x.key !== body.oldBox && x.key !== this.state.key)
      .map((x: any) => ({ key: x.key, i: x.i, name: String(x.name ?? 'Device').slice(0, 60), kind: x.kind === 'box' ? 'box' : 'device', chip: CHIP.test(x.chip ?? '') ? x.chip : undefined, blocked: !!x.blocked, added: Number.isInteger(x.added) ? x.added : now }));
    const me = list.find((x) => x.key === device);
    if (!me || me.blocked || me.kind !== 'device' || list.some((x) => x.i === w.i)) refuse('bad_member');
    list.push({ key: this.state.key, i: w.i, name: 'Box', kind: 'box', blocked: false, added: now });
    this.#moving.delete(id); delete this.state.requests[id];
    this.state.accounts[m!.account] = {
      commitment: commitmentHex(C), npub: m!.account, i: w.i, share: scalarHex(share), members: list,
      welcomes: {}, catchups: {}, epoch: Number.isInteger(w.epoch) ? w.epoch : 0, next: Math.max(Number.isInteger(body.next) ? body.next : 0, ...list.map((x) => x.i + 1)),
    };
    this.happened(m!.account, 'The account was moved to this box', now);
    return { ok: true, npub: m!.account, i: w.i };
  }

  #create2(body: any, device: string, now: number) {
    // An older device sends no request id with the second step: it is the one keygen this device has open.
    const id = body.request ?? body.code ?? [...this.#pending].find(([, v]) => v.device === device)?.[0];
    const p = this.#pending.get(id);
    if (!p || p.device !== device) refuse('no_keygen');
    const theirs: [number, string][] = [[DEVICE_I, p!.pkg]];
    let out;
    try {
      const two = F.dkg2(p!.secret, theirs);
      const done = F.dkg3(two.secret, theirs, [[DEVICE_I, openFrom(this.state.sk, device, 'keygen', body.pkg2)]]);
      out = { done, forDevice: two.pkgs.get(DEVICE_I)! };
    } catch (e) { if (e instanceof KeykinError) throw e; return refuse('bad_keygen'); }
    this.#pending.delete(id);
    delete this.state.requests[id];
    this.state.accounts[out.done.npub] = {
      commitment: commitmentHex(out.done.C), npub: out.done.npub, i: BOX_I, share: scalarHex(out.done.share),
      members: [
        { key: device, i: DEVICE_I, name: p!.name, kind: 'device', chip: p!.chip, blocked: false, added: now },
        { key: this.state.key, i: BOX_I, name: 'Box', kind: 'box', blocked: false, added: now },
      ],
      welcomes: {}, catchups: {}, epoch: 0, next: 3,
    };
    this.#save();
    return { ok: true, npub: out.done.npub, pkg2: sealTo(this.state.sk, device, 'keygen', out.forDevice) };
  }

  // --- Signing ------------------------------------------------------------------------------

  #sign(s: Account, from: Member, body: any) {
    if (from.kind !== 'device') refuse('devices_only');
    const ev = body.event as UnsignedEvent;
    const msg = eventId(ev);
    if (ev.pubkey !== s.npub) refuse('wrong_account');
    // Hard to undo: the device must have asked the person, and says so.
    if (destructive(ev) && body.tapped !== true) refuse('needs_tap');
    const c = body.commit;
    if (!c || c.i !== from.i || typeof c.D !== 'string' || typeof c.E !== 'string') refuse('bad_commit');
    const a = answer({ C: this.#C(s), i: s.i, share: BigInt('0x' + s.share) }, msg, c);
    this.#used(s, from, body.grant);
    if (s.welcomes[from.key]) { delete s.welcomes[from.key]; this.#save(); }   // it has its piece
    return { ok: true, id: msg, commit: a.commit, z: a.z };
  }

  // The box's part of a shared secret with another person's key, for encrypting and decrypting
  // messages. It is useless without the asking device's own part.
  #ecdh(s: Account, from: Member, body: any) {
    if (from.kind !== 'device') refuse('devices_only');
    const part = ecdhPart(s.i, BigInt('0x' + s.share), from.i, body.peer);
    this.#used(s, from, body.grant);
    return { ok: true, i: s.i, part };
  }

  // --- The list -----------------------------------------------------------------------------

  // Blocking is one press and anyone on the list may do it. Undoing it is the hard direction. Another box
  // in the account (a backup, say) can be blocked and then cycled away like a device; this box cannot.
  #block(s: Account, key: string) {
    const m = s.members.find((x) => x.key === key) ?? refuse('unknown_member');
    if (m.key === this.state.key) refuse('cannot_block_box');
    m.blocked = true; m.blockedAt = Math.floor(Date.now() / 1000);
    delete s.welcomes[m.key];
    this.#save();
    return { ok: true };
  }

  #unblock(s: Account, from: Member, req: Signed, key: string) {
    this.#needFingerprint(from, req);
    const m = s.members.find((x) => x.key === key) ?? refuse('unknown_member');
    m.blocked = false; delete m.blockedAt;
    this.#save();
    return { ok: true };
  }

  // Adding a member. The asking device and the box each hold a piece; together they make the piece
  // for a new index without either seeing it and without the key ever being whole. The box's half
  // waits here, sealed to the new member; the device's half arrives with `welcome_put`.
  #add(s: Account, from: Member, req: Signed, body: any, now: number) {
    const m = body.member;
    // Either the person asked on this device (fingerprint), or a signed-in account page asked (its note).
    if (body.note !== undefined) {
      const n = this.onNotes(s.npub).find((x) => x.id === body.note && x.kind === 'invite' && x.result === undefined) ?? refuse('gone');
      let inv: any; try { inv = JSON.parse(n.text).invite; } catch { inv = null; }
      if (!inv || inv.key !== m?.key) refuse('bad_member');
      if (from.kind !== 'device') refuse('devices_only');
    } else this.#needFingerprint(from, req);
    if (!m || !HEX64.test(m.key) || !Number.isInteger(m.i) || m.i < 1) refuse('bad_member');
    if (m.kind !== 'device' && m.kind !== 'box') refuse('bad_member');
    if (m.chip !== undefined && !CHIP.test(m.chip)) refuse('bad_chip_key');
    if (m.i !== s.next || s.members.some((x) => x.key === m.key)) refuse('already_listed');   // indices are never reused
    s.next++;
    const helpers = [from.i, s.i].sort((a, b) => a - b);
    const mine = F.repairDeltas(this.#C(s), helpers, s.i, BigInt('0x' + s.share), m.i);
    const sigma = F.repairSigma([mine.get(s.i)!, openFrom(this.state.sk, from.key, 'repair-delta', body.delta)]);
    s.members.push({ key: m.key, i: m.i, name: String(m.name ?? 'Device'), kind: m.kind, chip: m.chip, blocked: false, added: now });
    s.welcomes[m.key] = { by: from.key, box: sealTo(this.state.sk, m.key, 'repair-sigma', sigma) };
    this.#save();
    return { ok: true, delta: sealTo(this.state.sk, from.key, 'repair-delta', mine.get(from.i)!) };
  }

  #welcomePut(s: Account, from: Member, body: any) {
    const w = s.welcomes[body.key] ?? refuse('no_welcome');
    if (w.by !== from.key) refuse('not_yours');
    if (typeof body.sigma !== 'string') refuse('bad_request');
    w.device = body.sigma;
    this.#save();
    return { ok: true };
  }

  #welcome(s: Account, from: Member) {
    const w = s.welcomes[from.key] ?? refuse('no_welcome');
    if (!w.device) refuse('not_ready');
    if (!w.fetched) { w.fetched = true; this.#save(); }
    return { ok: true, npub: s.npub, commitment: s.commitment, epoch: s.epoch, i: from.i, box: w.box, from: w.by, device: w.device };
  }

  // --- Cycling the keys --------------------------------------------------------------------------

  // After a block, the pieces are moved to a new line through the same key. Every member still
  // welcome gets a small change to its piece; a blocked member gets none, so its old piece no
  // longer fits with anyone's and it is dropped from the list. The asking device picks the change
  // (one number, `b1`): it sends it to the box sealed, and each other member's share of it sealed
  // to that member. Nobody learns anything about the key from it.
  #cycle(s: Account, from: Member, req: Signed, body: any) {
    // Either a fingerprint on this device, or a signed-in account page asked and the person tapped Yes here.
    if (body.note !== undefined) {
      if (!this.onNotes(s.npub).some((x) => x.id === body.note && x.kind === 'cycle' && x.result === undefined)) refuse('gone');
      if (from.kind !== 'device') refuse('devices_only');
    } else this.#needFingerprint(from, req);
    // A newcomer that has not collected its piece yet would be left with halves of the old line.
    if (Object.values(s.welcomes).some((w) => !w.fetched)) refuse('pending_welcome');
    s.welcomes = {};
    const others = s.members.filter((m) => !m.blocked && m.key !== from.key && m.key !== this.state.key);
    const given = body.changes ?? {};
    if (Object.keys(given).length !== others.length || others.some((m) => typeof given[m.key] !== 'string')) refuse('bad_cycle');
    const b1 = scalarFrom(openFrom(this.state.sk, from.key, 'cycle', body.b1));
    if (b1 === 0n) refuse('bad_cycle');
    const C = this.#C(s);
    s.share = scalarHex(mod(BigInt('0x' + s.share) + b1 * BigInt(s.i)));
    s.commitment = commitmentHex([C[0], C[1].add(mul(b1))]);
    s.epoch++;
    s.members = s.members.filter((m) => !m.blocked);
    for (const k of Object.keys(s.catchups)) if (!s.members.some((m) => m.key === k)) delete s.catchups[k];
    for (const m of others) (s.catchups[m.key] ??= []).push({ from: from.key, sealed: given[m.key] });
    this.#save();
    return { ok: true, epoch: s.epoch, commitment: s.commitment };
  }

  // --- Falling back to the nsec --------------------------------------------------------------

  // With a fingerprint, the box hands its piece to that device, sealed. Two pieces are the nsec,
  // so this is the one request that lets a whole key exist, and only on the device that asked.
  #reveal(s: Account, from: Member, req: Signed) {
    this.#needFingerprint(from, req);
    return { ok: true, i: s.i, share: sealTo(this.state.sk, from.key, 'reveal', s.share) };
  }
}
