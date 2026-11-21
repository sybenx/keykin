// The box: one always-on machine holding one piece. It never starts a signature; it only helps a
// device that asks. It keeps the list of pieces and refuses blocked ones. No I/O here: `handle`
// takes a request and the time, and `state` is plain JSON the server file saves.

import * as F from '../src/frost.ts';
import { answer, type Piece } from '../src/round.ts';
import { childPiece, tweakOf } from '../src/child.ts';
import { ecdhPart } from '../src/ecdh.ts';
import { eventId, type UnsignedEvent } from '../src/event.ts';
import { judge, KEPT, AHEAD } from '../src/destructive.ts';
import { Lists, KEPT_SETS } from './lists.ts';
import { open, fingerprintOk, newMemberKey, type Signed, MAX_SKEW } from '../src/member.ts';
import { sealTo, openFrom } from '../src/seal.ts';
import { commitmentFrom, commitmentHex, scalarHex, scalarFrom, mul, mod, xOnly, type Commitment } from '../src/curve.ts';
import { KeykinError, refuse, refuseWhy, randomBytes, bytesToHex, hexToBytes, sha, jcsBytes } from '../src/bytes.ts';
import { randomInt, timingSafeEqual } from 'node:crypto';

/** How long an approval code lasts, and how many wrong tries a member gets (SPEC 11.6). */
const GATE_SECONDS = 600, GATE_TRIES = 5;
const b64url = (b: Uint8Array) => Buffer.from(b).toString('base64url');
const same = (h: Uint8Array, hex: string) => { const o = hexToBytes(hex); return o.length === h.length && timingSafeEqual(h, o); };
import { schnorr } from '@noble/curves/secp256k1.js';

/** `addr` is where a device that can listen answers other devices when the box is off. */
export interface Member { key: string; i: number; name: string; kind: 'device' | 'box'; chip?: string; addr?: string; blocked: boolean; added: number;
  /** When it last signed or made a message key, and when it was blocked. Unix seconds. */
  last?: number; blockedAt?: number }
/** What waits for a newly added member: the two values its piece is built from. */
export interface Welcome { by: string; box: string; device?: string; fetched?: boolean }
/**
 * A member added through an account-page note (SPEC 11.6, `add=` and Devices, Add a device): its welcome is held
 * until it shows the approval code the page was given, and the PKCE verifier when the note carried a challenge.
 * Codes are kept as SHA-256 only. `until` and `tries` bound the guessing; the member goes when they run out.
 */
export interface Gate { note: string; at: number; challenge: string | null; code?: string; short?: string; until?: number; tries: number }
/** A change of piece waiting for a member that was not there when the keys were cycled. */
export interface Catchup { from: string; sealed: string }
export interface Passkey { id: string; key: string; counter: number; rpId: string; origin: string; added: number; last?: number }

export interface Account {
  commitment: string[]; npub: string;
  i: number; share: string;            // the box's own piece
  epoch: number;                       // goes up each time the keys are cycled
  next: number;                        // the next unused index
  members: Member[];
  welcomes: Record<string, Welcome>;
  catchups: Record<string, Catchup[]>;
  /** Members added through a page note, waiting for their approval code, by member key (SPEC 11.6). */
  gates?: Record<string, Gate>;
  /** Username and password for the account page (SPEC 11.3). The box never has the password. */
  login?: { username: string; salt: string; check: string; fails?: number; lockedUntil?: number };
  /** Passkeys that sign in to the account page (SPEC 11.3): WebAuthn credentials, each bound to the page's host. */
  passkeys?: Passkey[];
  /** What each device has let in (SPEC 11.5), by the device's member key. */
  grants?: Record<string, Grant[]>;
  /** Grants that were revoked. The box refuses any request naming one. */
  revoked?: string[];
  /** When each grant was last used (SPEC 11.5), by grant id. A grant unused for 90 days ends. */
  used?: Record<string, number>;
  /** The last event kind signed for each grant (SPEC 11.5), by grant id. */
  kinds?: Record<string, number>;
  /** Account-page browsers that left a nostrconnect note, by the code's client key (SPEC 11.5): the browser label and when. */
  connects?: Record<string, { browser: string; at: number }>;
  /** Grants the person limited (SPEC 11.5): `posts` lets that site or app post and nothing else. */
  limits?: Record<string, Limit>;
  /** Switches the account page turned on or off for a site (SPEC 11.5), by grant id, waiting for the device that let it in. */
  wants?: Record<string, Scopes>;
  /** Recent activity, newest last, at most 60 lines. */
  log?: Happened[];
}
/** `client`, `device`, `via` come from the device; `browser` is set by the box from the page session that left the nostrconnect note (SPEC 11.5). */
export interface Grant { id: string; kind: 'site' | 'app'; name: string; since: number; last?: number; client?: string; device?: string; via?: Via; browser?: string;
  /** The device's own switches for a site (SPEC 11.5): may it read the private lists, may it read and send DMs. Absent: it has none. */
  lists?: boolean; dms?: boolean }
/** What the account page wants a site's switches to be (SPEC 11.5). */
export interface Scopes { lists?: boolean; dms?: boolean }
export const SCOPES = ['lists', 'dms'] as const;
export type Via = 'login' | 'scan' | 'paste' | 'bunker';
const VIAS = new Set(['login', 'scan', 'paste', 'bunker']);
/** A short label for a browser from its User-Agent, e.g. "Chrome on Windows" (the account page's browserOf). */
export function browserLabel(agent: string | undefined): string {
  const a = agent ?? '';
  const b = /Edg(e|A|iOS)?\//.test(a) ? 'Edge' : /OPR\/|Opera/.test(a) ? 'Opera' : /SamsungBrowser/.test(a) ? 'Samsung Internet' : /Firefox\/|FxiOS/.test(a) ? 'Firefox'
    : /Chrome\/|CriOS|Chromium/.test(a) ? 'Chrome' : /Safari\//.test(a) ? 'Safari' : null;
  const os = /Windows/.test(a) ? 'Windows' : /Android/.test(a) ? 'Android' : /iPhone/.test(a) ? 'iPhone' : /iPad/.test(a) ? 'iPad' : /CrOS/.test(a) ? 'ChromeOS'
    : /Macintosh|Mac OS X/.test(a) ? 'macOS' : /Linux/.test(a) ? 'Linux' : null;
  return b && os ? `${b} on ${os}` : b ?? (os ? `A browser on ${os}` : 'A browser');
}
/** The client key of a nostrconnect:// code, hex, or null. */
export function clientOf(code: string): string | null {
  const m = /^nostrconnect:\/\/([0-9a-fA-F]{64})(?:[?/]|$)/.exec(code.trim());
  return m ? m[1].toLowerCase() : null;
}
/** Something the account page started for a device to finish (SPEC 11.6). */
/** `tap` is true for the hard-to-undo ones: a device asks the person Yes or No before doing it. */
/** For `nostrconnect`, `from` is the origin that sent the person to the login page (or null), and `as` is the key the person chose.
 *  For `pointer`, `text` is the box's own login page address, never anything the page sent.
 *  For `bunker`, `text` is an optional name for the site. `bunker` and `nostrconnect` carry `lists`, `dms`, the site's two switches. */
export interface Note { id: string; kind: 'nostrconnect' | 'invite' | 'bunker' | 'cycle' | 'pointer'; text: string; at: number; tap: boolean; result?: string; weak?: boolean; from?: string | null; as?: 'main' | 'site'; challenge?: string | null; lists?: boolean; dms?: boolean }
/** A signed-in account page (SPEC 11.6), kept by SHA-256 of its token, never the token. Unix seconds. */
export interface PageSession { account: string; how: 'password' | 'passkey' | 'scan'; made: number; last: number; agent: string }
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
export interface BoxState { sk: string; key: string; owner?: string; pwSecret?: string; accounts: Record<string, Account>; requests: Record<string, Ask>;
  /** The box's public login page (Keykin Login in front of it), set on the admin page. KEYKIN_LOGIN_URL overrides it. */
  loginPage?: string
  /** How many named sets the list store keeps per account (box/lists.ts), set on the admin page. KEYKIN_KEPT_SETS overrides it. */
  keptSets?: number
  /** How many accounts an open box lets in from the account page ([OPEN_ACCOUNTS]), set on the admin page. KEYKIN_OPEN_ACCOUNTS overrides it. */
  openAccounts?: number
  /** The account page's sessions, by SHA-256(token) in hex. */
  sessions?: Record<string, PageSession> }

/** A login page address as a box takes it: https, a host and maybe a port, nothing after. Trailing slashes
 *  are dropped. Null if it is anything else. The same rule for the admin setting and KEYKIN_LOGIN_URL. */
export function loginOrigin(s: unknown): string | null {
  const v = String(s ?? '').trim().replace(/\/+$/, '');
  return /^https:\/\/[a-z0-9.-]+(:[0-9]+)?$/.test(v) ? v : null;
}

const HEX64 = /^[0-9a-f]{64}$/, CHIP = /^0[23][0-9a-f]{64}$/;
const DEVICE_I = 1, BOX_I = 2;         // the first device and the box, at creation
const EPOCH_OPS = new Set(['sign', 'ecdh', 'add', 'reveal', 'cycle']);
const MAX_WAITING = 50, ASK_DAYS = 7, APPROVED_HOURS = 24;

// How much the box keeps (SPEC 6). A box is run for people its admin knows, so these guard against bugs and
// accidents, not strangers: far above real use, the oldest going first where something can go, and none of
// them ever refuses a signature. The state file is rewritten whole on every change, so nothing in it may grow
// without end.
/**
 * Devices and boxes in one account, blocked ones included: a person has a handful. Past it `add` is refused
 * (`too_many_members`). Nothing is dropped to make room: a blocked member's entry is what keeps it refused,
 * here and at a device that helps while the box is off (SPEC 8g), until a cycle leaves its piece useless.
 * Removing blocked devices (the cycle) makes room.
 */
export const MAX_MEMBERS = 50;
/**
 * Setup codes approved in advance and not used yet, in all: the admin's "Make a setup code" and the account
 * page's `protect`. Each lasts 24 hours anyway; 50 in a day is far more than anyone makes. Past it the oldest
 * goes. Asks the admin approved are not counted: there are at most 50 waiting, and each is the admin's own yes.
 */
export const MAX_CODES = 50;
/**
 * The accounts an open box (KEYKIN_OPEN=1) lets in from the account page: it stops once it holds this many,
 * counting every account. Set on the admin page; KEYKIN_OPEN_ACCOUNTS overrides it. Past it `protect` is
 * refused (`box_full`): nothing older can go, since each account is someone's piece. The admin's own codes
 * and approvals still work.
 */
export const OPEN_ACCOUNTS = 500;
/** `notes_wait` (SPEC 11.6): the longest a device's request is held, in seconds, and how many may be held at once for one account. */
export const WAIT_MOST = 25, WAITS_PER_ACCOUNT = 4;
/** On a `notes_wait` answer with nothing new yet: the server holds the reply and asks [Box.heldNotes] again later. JSON leaves it out. */
export const HOLD = Symbol('hold');
export interface Hold { account: string; member: string; seconds: number }
/** A grant nobody has used for this long ends (SPEC 11.5). */
export const GRANT_UNUSED = 90 * 86400;
export const USERNAME = /^[a-z0-9._-]{3,32}$/;
/** What a grant limited to `posts` may still sign: notes, reposts, reactions, comments, zap requests, media posts, and site logins (NIP-42). */
export const POST_KINDS = new Set([1, 6, 7, 16, 1111, 9734, 20, 21, 22, 22242]);
/** Direct messages: NIP-04 (4), NIP-17 seals, chat and files (13, 14, 15), and gift wraps (1059). */
export const DM_KINDS = new Set([4, 13, 14, 15, 1059]);
/** A grant's limit (SPEC 11.5): `posts` signs posts only and gets no message keys; `dms` also signs and
 *  reads direct messages, with other people's keys only, so not the account's own private lists. */
export type Limit = 'posts' | 'dms';
export const LIMITS = new Set<Limit>(['posts', 'dms']);
const sameKey = (peer: unknown, npub: string) => typeof peer === 'string' && peer.toLowerCase().slice(-64) === npub;
export function allowedBy(limit: Limit | undefined, op: string, kind: unknown, peer: unknown, npub: string) {
  if (!limit) return true;
  if (op === 'ecdh') return limit === 'dms' && !sameKey(peer, npub);
  return POST_KINDS.has(kind as number) || (limit === 'dms' && DM_KINDS.has(kind as number));
}

/** A named-set cap as the admin page and KEYKIN_KEPT_SETS take it: a whole number from 0 to 100000. Null if anything else. */
export function keptSetsOf(v: unknown): number | null {
  const n = typeof v === 'number' ? v : /^\s*[0-9]{1,6}\s*$/.test(String(v ?? '')) ? Number(v) : NaN;
  return Number.isInteger(n) && n >= 0 && n <= 100000 ? n : null;
}
/** The open box's account cap as the admin page and KEYKIN_OPEN_ACCOUNTS take it: the same rule, a whole number from 0 to 100000. */
export const openAccountsOf = keptSetsOf;
const SET_NAMES: Record<string, string> = { 30000: 'follow set', 30001: 'list', 30002: 'relay set', 30003: 'bookmark set', 30004: 'curation set', 30015: 'interest set', 30030: 'emoji set' };
/** "bookmark set "reading"", for the activity list. */
function setName(key: string) {
  const i = key.indexOf(':'), d = key.slice(i + 1).replace(/[\u0000-\u001f\u007f]/g, '');
  return `${SET_NAMES[key.slice(0, i)] ?? 'set'} "${d.length > 40 ? d.slice(0, 40) + '...' : d}"`;
}

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
  onNoteDone: (account: string, note: string, result: string, device: string) => boolean = () => false;
  /** A device's person tapped No: the note goes, and so does the page session that left it. */
  onNoteRefused: (account: string, note: string) => boolean = () => false;

  constructor(state: BoxState | null = null) {
    const s: any = state ?? { ...newMemberKey() };
    // A state file from when a box held one account.
    if (!s.accounts) { s.accounts = s.account ? { [s.account.npub]: s.account } : {}; delete s.account; }
    s.requests ??= {};
    this.state = s;
    // A state file from before the growth limits: bookkeeping they now keep tidy is tidied once, here. Nothing
    // a person would miss goes, and nothing over a cap that is refused rather than pruned (members, accounts).
    for (const a of Object.values(this.state.accounts)) this.#forgetRemoved(a);
  }

  /**
   * What stays of a member after it left the list (a cycle dropped it): its grants, and the last kind of any
   * grant whose use is no longer kept. Neither can sign anything: the member is gone, and a grant is refused
   * by `revoked` and `limits`, which stay as they are. Nothing is added to `revoked`, so no older revoke is
   * pushed out of its 2000.
   */
  #forgetRemoved(a: Account) {
    const here = new Set(a.members.map((m) => m.key));
    for (const k of Object.keys(a.grants ?? {})) if (!here.has(k)) delete a.grants![k];
    for (const id of Object.keys(a.kinds ?? {})) if (a.used?.[id] === undefined) delete a.kinds![id];
  }

  /** The accounts, oldest first. */
  accounts(): Account[] { return Object.values(this.state.accounts); }
  /** The account when there is exactly one to speak of: the first, or null on an empty box. */
  only(): Account | null { return this.accounts()[0] ?? null; }

  /** What the QR on an empty box says. `addr` is where devices reach it. Null once it holds an account. */
  /** The login page's origin set by KEYKIN_LOGIN_URL. When set it wins over the admin setting. */
  fixedLogin: string | undefined;
  /** The login page's origin (Keykin Login in front of this box), if set. Codes carry it so the device can publish the pointer (SPEC 11.1). */
  get login(): string | undefined { return this.fixedLogin ?? this.state.loginPage; }
  /** The admin sets or clears (null) the login page address. A bad address is refused and nothing changes. */
  setLoginPage(addr: string | null) {
    if (addr === null) delete this.state.loginPage;
    else this.state.loginPage = loginOrigin(addr) ?? refuse('bad_login_page');
    this.#save();
  }
  #login() { return this.login ? { loginPage: this.login } : {}; }

  /** The latest version the box signed of each kept list, beside the state file, never in it. In memory until the server gives it a directory. */
  lists = new Lists();
  /** The named-set cap set by KEYKIN_KEPT_SETS. When set it wins over the admin setting. */
  fixedKeptSets: number | undefined;
  /** How many named sets are kept per account (a soft cap: past it a set is not compared, never refused). */
  get keptSets(): number { return this.fixedKeptSets ?? this.state.keptSets ?? KEPT_SETS; }
  /** The admin sets the cap, or goes back to the default (null). */
  setKeptSets(n: number | null) {
    if (n === null) delete this.state.keptSets;
    else this.state.keptSets = keptSetsOf(n) ?? refuse('bad_number');
    this.#save();
  }
  /** The open-door account cap set by KEYKIN_OPEN_ACCOUNTS. When set it wins over the admin setting. */
  fixedOpenAccounts: number | undefined;
  /** How many accounts the box may hold and still let one in from the account page ([OPEN_ACCOUNTS]). */
  get openAccounts(): number { return this.fixedOpenAccounts ?? this.state.openAccounts ?? OPEN_ACCOUNTS; }
  /** The admin sets the cap, or goes back to the default (null). */
  setOpenAccounts(n: number | null) {
    if (n === null) delete this.state.openAccounts;
    else this.state.openAccounts = openAccountsOf(n) ?? refuse('bad_number');
    this.#save();
  }
  /** Refuses (`box_full`) when the box holds as many accounts as it lets in from the account page. */
  roomFromPage() {
    const n = this.accounts().length;
    if (n >= this.openAccounts) refuseWhy('box_full', `This box holds ${n} account${n === 1 ? '' : 's'}, as many as its admin lets in from the account page. Ask the admin to make room.`);
  }
  qr(addr: string) { return this.accounts().length ? null : JSON.stringify({ keykin: 2, addr, key: this.state.key, code: this.setupCode, ...this.#login() }); }

  /**
   * The admin makes room for one more account: a request approved in advance, as a setup code. `only` is the
   * account page's `protect`: a new code for an account replaces its earlier one. Past MAX_CODES unused codes
   * the oldest goes. A state from before the cap is brought under it here, all at once.
   */
  newSetupCode(addr: string, now: number, only?: string): string {
    if (only) for (const r of Object.values(this.state.requests)) if (r.only === only) this.#dropRequest(r.id);
    const codes = Object.values(this.state.requests).filter((r) => r.state === 'approved' && !r.key).sort((x, y) => (x.decided ?? x.asked) - (y.decided ?? y.asked));
    for (const r of codes.slice(0, Math.max(0, codes.length - MAX_CODES + 1))) this.#dropRequest(r.id);
    const id = bytesToHex(randomBytes(16));
    this.state.requests[id] = { id, what: 'make', asked: now, state: 'approved', decided: now, ...(only ? { only } : {}) };
    this.#save();
    return JSON.stringify({ keykin: 2, addr, key: this.state.key, code: id, ...this.#login() });
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
    this.lists.forget(npub);
    this.#save();
  }
  #tidyRequests(now: number) {
    let changed = false;
    for (const r of Object.values(this.state.requests)) {
      const dead = r.state === 'approved' ? now - (r.decided ?? r.asked) > APPROVED_HOURS * 3600 : now - r.asked > ASK_DAYS * 86400;
      if (dead) { delete this.state.requests[r.id]; this.#pending.delete(r.id); changed = true; }
    }
    // A move started with a code that is gone (ran out, used, taken back) can never finish.
    for (const id of this.#moving.keys()) if (!this.state.requests[id]) this.#moving.delete(id);
    if (changed) this.#save();
  }
  /** A request goes, and anything begun with it. The caller saves. */
  #dropRequest(id: string) { delete this.state.requests[id]; this.#pending.delete(id); this.#moving.delete(id); }
  /** How many moves (`transfer1`) are open, for tests. */
  get movesOpen() { return this.#moving.size; }
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
      // A member added through a page note may not know its account yet: the typed code (SPEC 11.6) names only the box.
      const s = body.op === 'welcome' && body.account === undefined ? this.#gatedAccount(req.key) : this.#accountOf(body);
      this.#sweepGates(s, now);
      const from = s.members.find((m) => m.key === req.key) ?? refuse('unknown_member');
      if (from.blocked) refuse('blocked');
      // Until it shows its approval code, a member added through a page note can do nothing but ask for its welcome.
      if (s.gates?.[from.key] && body.op !== 'welcome') refuse('not_approved');
      // A device still on the old pieces is told so, and handed what it needs to catch up.
      if (EPOCH_OPS.has(body.op) && body.epoch !== s.epoch) {
        return { error: 'stale', epoch: s.epoch, commitment: s.commitment, catchups: s.catchups[from.key] ?? [] };
      }
      if ((body.op === 'sign' || body.op === 'ecdh') && body.grant !== undefined) {
        this.expireGrants(s, now);
        if ((s.revoked ?? []).includes(body.grant)) refuse('revoked');
        // A site let in from a password-only page session is limited to posting from its first request on.
        if (typeof body.grant === 'string' && /^[0-9a-f]{32}$/.test(body.grant) && !s.limits?.[body.grant] && this.#limitNext(s.npub, from.key, now)
          && !Object.values(s.grants ?? {}).flat().some((g) => g.id === body.grant)) this.limitGrant(s.npub, body.grant, this.#limited.get(`${s.npub}/${from.key}`)!.to);
        // A grant limited to posting signs only posts, and gets no message keys: it cannot read messages.
        if (!allowedBy(s.limits?.[body.grant], body.op, body.event?.kind, body.peer, s.npub)) refuse('not_allowed');
      }
      switch (body.op) {
        case 'cycle': return this.#cycle(s, from, req, body);
        case 'caught_up': if (s.catchups[from.key]) { delete s.catchups[from.key]; this.#save(); } return { ok: true };
        case 'sign': return this.#sign(s, from, req, body, now);
        case 'ecdh': return this.#ecdh(s, from, body, now);
        case 'members': return { ok: true, npub: s.npub, commitment: s.commitment, epoch: s.epoch, next: s.next, boxKey: this.state.key, members: s.members, password: !!s.login };
        case 'block': return this.#block(s, body.key);
        case 'unblock': return this.#unblock(s, from, req, body.key);
        case 'add': return this.#add(s, from, req, body, now);
        case 'welcome_put': return this.#welcomePut(s, from, body);
        case 'welcome': return this.#welcome(s, from, body, now);
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
        // A password is always required (SPEC 11.3): it can be changed, never removed.
        case 'password_clear': refuse('password_required');
        case 'grants': {
          const list = body.grants;
          if (!Array.isArray(list) || list.length > 200) refuse('bad_request');
          const clean: Grant[] = list.map((g: any) => {
            if (!/^[0-9a-f]{32}$/.test(g?.id ?? '') || (g.kind !== 'site' && g.kind !== 'app') || typeof g.name !== 'string' || !Number.isInteger(g.since)) refuse('bad_request');
            const out: Grant = { id: g.id, kind: g.kind, name: g.name.slice(0, 200), since: g.since };
            if (typeof g.client === 'string' && /^[0-9a-f]{64}$/.test(g.client)) out.client = g.client;
            const label = typeof g.device === 'string' ? g.device.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 60) : '';
            if (label) out.device = label;
            if (VIAS.has(g.via)) out.via = g.via;
            for (const k of SCOPES) if (typeof g[k] === 'boolean') out[k] = g[k];
            // The browser is the box's own word, from the page session whose note carried this client key.
            const c = out.client && s.connects?.[out.client];
            if (c) out.browser = c.browser;
            return out;
          });
          const revoked = new Set(s.revoked ?? []);
          const known = new Set((s.grants?.[from.key] ?? []).map((g) => g.id));
          if (this.#limitNext(s.npub, from.key, now)) {
            const fresh = clean.filter((g) => g.kind === 'site' && !known.has(g.id));
            const to = this.#limited.get(`${s.npub}/${from.key}`)!.to;
            for (const g of fresh) this.limitGrant(s.npub, g.id, to);
            if (fresh.length) this.#limited.delete(`${s.npub}/${from.key}`);
          }
          (s.grants ??= {})[from.key] = clean.filter((g) => !revoked.has(g.id));
          this.expireGrants(s, now);
          const scopes = this.#scopesFor(s, from.key);
          this.#save();
          const gone = new Set(s.revoked ?? []);
          return { ok: true, revoked: clean.filter((g) => gone.has(g.id)).map((g) => g.id), ...(Object.keys(scopes).length ? { scopes } : {}) };
        }
        case 'revoke': this.revokeGrant(s.npub, body.grant); return { ok: true };
        case 'limit': this.limitGrant(s.npub, body.grant, body.to); return { ok: true };
        case 'notes': return { ok: true, notes: this.#waitingNotes(s.npub) };
        case 'notes_wait': {
          // The same answer as `notes`, but with nothing new waiting, the reply is held until a note comes or
          // `wait` seconds pass. `seen` lists notes this device already has (one waiting for the person's
          // Yes or No, say), so those alone do not answer at once.
          const wait = body.wait, seen = body.seen ?? [];
          if (!Number.isInteger(wait) || wait < 0 || !Array.isArray(seen) || seen.length > 50) refuse('bad_request');
          const notes = this.#waitingNotes(s.npub), known = new Set(seen);
          const out: any = { ok: true, notes };
          if (wait > 0 && !notes.some((n) => !known.has(n.id))) out[HOLD] = { account: s.npub, member: from.key, seconds: Math.min(wait, WAIT_MOST) } satisfies Hold;
          return out;
        }
        case 'note_refuse': if (from.kind !== 'device' || !this.onNoteRefused(s.npub, body.note)) refuse('gone'); this.happened(s.npub, `${from.name} said No to a request from the account page`, now); return { ok: true };
        case 'note_done': {
          if (from.kind !== 'device') refuse('devices_only');
          if (typeof body.result !== 'string' || body.result.length > 2000 || !this.onNoteDone(s.npub, body.note, body.result, from.key)) refuse('gone');
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
      if (e instanceof KeykinError) return { error: e.code, ...(e.why ? { why: e.why } : {}) };
      throw e;
    }
  }

  #waitingNotes(npub: string) {
    return this.onNotes(npub).filter((n) => n.result === undefined).map(({ id, kind, text, at, tap, from, as, lists, dms }) => ({ id, kind, text, at, tap, ...(kind === 'nostrconnect' ? { from: from ?? null, as: as ?? 'main' } : {}), ...(kind === 'bunker' || kind === 'nostrconnect' ? { lists: lists === true, dms: dms === true } : {}) }));
  }

  // --- Holding a `notes_wait` (SPEC 11.6). The request was checked once, in `handle`; this only waits. ---

  #waits = new Map<string, Set<() => void>>();     // by account npub, oldest first
  /**
   * Resolves when a note is put for the account ([noteCame]), after `ms`, or when `signal` aborts (the
   * device went away). At most WAITS_PER_ACCOUNT are held for one account: one more ends the oldest early.
   */
  waitForNote(account: string, ms: number, signal?: AbortSignal): Promise<void> {
    return new Promise((done) => {
      const set = this.#waits.get(account) ?? new Set<() => void>();
      this.#waits.set(account, set);
      const end = () => {
        clearTimeout(timer); signal?.removeEventListener('abort', end);
        set.delete(end); if (!set.size && this.#waits.get(account) === set) this.#waits.delete(account);
        done();
      };
      const timer = setTimeout(end, ms);
      signal?.addEventListener('abort', end);
      if (signal?.aborted) return end();
      set.add(end);
      while (set.size > WAITS_PER_ACCOUNT) set.values().next().value!();
    });
  }
  /** How many requests are held for an account now, for tests. */
  waitsFor(account: string) { return this.#waits.get(account)?.size ?? 0; }
  /** A note was put for the account: every held `notes_wait` of it answers now. */
  noteCame(account: string) { for (const end of [...(this.#waits.get(account) ?? [])]) end(); }
  /** The answer to a held `notes_wait`, read again from the state. A device blocked or removed meanwhile gets no notes. */
  heldNotes(h: Hold) {
    const m = this.state.accounts[h.account]?.members.find((x) => x.key === h.member);
    if (!m) return { error: 'unknown_member' };
    if (m.blocked) return { error: 'blocked' };
    return { ok: true, notes: this.#waitingNotes(h.account) };
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
    if (s.wants) { delete s.wants[grant as string]; if (!Object.keys(s.wants).length) delete s.wants; }
    if (s.used) delete s.used[grant as string];
    if (s.kinds) delete s.kinds[grant as string];
    this.#save();
  }
  /** Remembers which account-page browser left a nostrconnect note, so the grant it becomes can say so (SPEC 11.5). */
  rememberConnect(s: Account, code: string, agent: string | undefined, now: number) {
    const client = clientOf(code);
    if (!client) return;
    const all = (s.connects ??= {});
    for (const [k, v] of Object.entries(all)) if (v.at < now - 30 * 86400) delete all[k];
    all[client] = { browser: browserLabel(agent), at: now };
    const keys = Object.keys(all);
    if (keys.length > 20) for (const k of keys.sort((x, y) => all[x].at - all[y].at).slice(0, keys.length - 20)) delete all[k];
    this.#save();
  }
  /** A grant's last use: when a request last named it, else its `since` (SPEC 11.5). */
  lastUse(s: Account, g: Grant) { return Math.max(s.used?.[g.id] ?? 0, g.last ?? 0, g.since); }
  /** Ends every grant of the account unused for 90 days, as if revoked, and says so in the activity list. */
  expireGrants(s: Account, now: number) {
    const cut = now - GRANT_UNUSED, ended = new Map<string, string>();
    for (const list of Object.values(s.grants ?? {})) for (const g of list) if (this.lastUse(s, g) < cut) ended.set(g.id, g.name);
    // A grant used but never reported by its device still ends; it has no name to show.
    for (const [id, t] of Object.entries(s.used ?? {})) if (t < cut && !ended.has(id)) ended.set(id, '');
    for (const [id, name] of ended) {
      this.revokeGrant(s.npub, id);
      if (name) this.happened(s.npub, `${name} signed out after 90 days unused`, now);
    }
    return ended.size > 0;
  }
  // Sites a device lets in for a password-only page session (SPEC 11.6): the next new site grant that
  // device reports, or first uses, within ten minutes is limited to posting.
  #limited = new Map<string, { until: number; to: Limit }>();
  limitNextSiteOf(npub: string, device: string, until: number, to: Limit) { this.#limited.set(`${npub}/${device}`, { until, to }); }
  #limitNext(npub: string, device: string, now: number) {
    const k = `${npub}/${device}`, x = this.#limited.get(k);
    if (x === undefined) return false;
    if (x.until < now) { this.#limited.delete(k); return false; }
    return true;
  }
  /** Limits a grant to posting (`posts`), or lifts the limit (`null`). From a device or the account page. */
  limitGrant(npub: string, grant: unknown, to: unknown) {
    const s = this.state.accounts[npub] ?? refuse('unknown_account');
    if (typeof grant !== 'string' || !/^[0-9a-f]{32}$/.test(grant) || (to !== null && !LIMITS.has(to as Limit))) refuse('bad_request');
    const l = (s.limits ??= {});
    if (to !== null) { l[grant as string] = to as Limit; if (Object.keys(l).length > 2000) delete l[Object.keys(l)[0]]; }
    else delete l[grant as string];
    this.#save();
  }
  /**
   * The account page turns a site's switches on or off (SPEC 11.5). The box keeps it as a want, merged with
   * any earlier one, until the device that let the site in reports the same values.
   */
  wantScopes(npub: string, grant: string, want: Scopes) {
    const s = this.state.accounts[npub] ?? refuse('unknown_account');
    const w = ((s.wants ??= {})[grant] ??= {});
    for (const k of SCOPES) if (typeof want[k] === 'boolean') w[k] = want[k];
    this.#save();
  }
  // After a device reports: a want its report now matches is done, and a want for a grant no device lists
  // any more goes. What is still wanted for this device's grants goes back to it.
  #scopesFor(s: Account, device: string): Record<string, Scopes> {
    if (!s.wants) return {};
    const listed = new Set(Object.values(s.grants ?? {}).flat().map((g) => g.id));
    for (const id of Object.keys(s.wants)) if (!listed.has(id)) delete s.wants[id];
    const out: Record<string, Scopes> = {};
    for (const g of s.grants?.[device] ?? []) {
      const w = s.wants[g.id];
      if (!w) continue;
      for (const k of SCOPES) if (w[k] !== undefined && g[k] === w[k]) delete w[k];
      if (Object.keys(w).length) out[g.id] = { ...w }; else delete s.wants[g.id];
    }
    if (!Object.keys(s.wants).length) delete s.wants;
    return out;
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
  #used(s: Account, from: Member, grant: unknown, t: number) {
    from.last = t;
    if (typeof grant === 'string' && /^[0-9a-f]{32}$/.test(grant)) {
      const u = (s.used ??= {}); u[grant] = t;
      // The grant's last kind goes with its use, so `kinds` stays within the same 2000.
      const ids = Object.keys(u); if (ids.length > 2000) { delete u[ids[0]]; if (s.kinds) delete s.kinds[ids[0]]; }
    }
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
    // A code from the account page made before the box filled up waits (it lasts 24 hours) until there is room.
    if (this.state.requests[id]?.only) this.roomFromPage();
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
    // The list comes from the device. The old box is in it and this box takes its place, so its length is the account's.
    if (Array.isArray(body.members) && body.members.length > MAX_MEMBERS) this.#tooMany();
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

  /** The box's piece for this request: of the account, or of the child the request names (SPEC 8k). */
  #piece(s: Account, body: any): Piece {
    const mine = { C: this.#C(s), i: s.i, share: BigInt('0x' + s.share) };
    return body.child === undefined ? mine : childPiece(mine, tweakOf(body.child));
  }

  #sign(s: Account, from: Member, req: Signed, body: any, now: number) {
    if (from.kind !== 'device') refuse('devices_only');
    const ev = body.event as UnsignedEvent;
    const msg = eventId(ev);
    const piece = this.#piece(s, body);
    // The event must be by the key being asked for: the account's, or the child's.
    if (ev.pubkey !== xOnly(piece.C[0])) refuse('wrong_account');
    // The box decides what is hard to undo (src/destructive.ts), against the last version of that list it signed.
    // A refusal is final. A level 1 question needs the device to have asked the person, and say so with `tapped`.
    // Level 2 is never done by accident: it needs the fingerprint, checked as for an account change, and `tapped`
    // alone is not enough. A child's lists are not kept here, so its changes are judged on their own.
    const mine = body.child === undefined && KEPT.has(ev.kind);
    const j = judge(ev, mine ? this.lists.latest(s.npub, ev) : null, now, body.child !== undefined);
    if (j.decision === 'refuse') refuseWhy('dated_ahead', j.says!);
    if (j.decision === 'ask' && j.level === 2) {
      if (!from.chip) refuseWhy('no_chip_key', j.says!);
      if (!fingerprintOk(req, from.chip)) refuseWhy('needs_fingerprint', j.says!);
    } else if (j.decision === 'ask' && body.tapped !== true) refuseWhy('needs_tap', j.says!);
    const c = body.commit;
    if (!c || c.i !== from.i || typeof c.D !== 'string' || typeof c.E !== 'string') refuse('bad_commit');
    const a = answer(piece, msg, c);
    if (mine && ev.created_at <= now + AHEAD) this.#keep(s, { ...ev, id: msg }, now);
    this.#used(s, from, body.grant, now);
    if (typeof body.grant === 'string' && /^[0-9a-f]{32}$/.test(body.grant) && Number.isInteger(ev.kind)) (s.kinds ??= {})[body.grant] = ev.kind;
    if (s.welcomes[from.key]) { delete s.welcomes[from.key]; this.#save(); }   // it has its piece
    return { ok: true, id: msg, commit: a.commit, z: a.z };
  }

  /** Keeps what was just signed as the latest version of that list. Sets dropped past the cap are said in the activity. */
  #keep(s: Account, e: UnsignedEvent & { id: string }, now: number) {
    let dropped: string[];
    // A list that cannot be written (a full disk) never fails the signature: the next change is compared with an older version.
    try { dropped = this.lists.keep(s.npub, e, this.keptSets, now).dropped; } catch { return; }
    for (const key of dropped) this.happened(s.npub, `Your ${setName(key)} is no longer compared before signing: this box keeps the ${this.keptSets} most recently changed sets`, now);
  }

  // The box's part of a shared secret with another person's key, for encrypting and decrypting
  // messages. It is useless without the asking device's own part.
  #ecdh(s: Account, from: Member, body: any, now: number) {
    if (from.kind !== 'device') refuse('devices_only');
    const piece = this.#piece(s, body);
    const part = ecdhPart(piece.i, piece.share, from.i, body.peer);
    this.#used(s, from, body.grant, now);
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
    let gate: Gate | null = null;
    // Either the person asked on this device (fingerprint), or a signed-in account page asked (its note).
    if (body.note !== undefined) {
      const n = this.onNotes(s.npub).find((x) => x.id === body.note && x.kind === 'invite' && x.result === undefined) ?? refuse('gone');
      let inv: any; try { inv = JSON.parse(n.text).invite; } catch { inv = null; }
      if (!inv || inv.key !== m?.key) refuse('bad_member');
      if (from.kind !== 'device') refuse('devices_only');
      gate = { note: n.id, at: now, challenge: n.challenge ?? null, tries: 0 };
    } else this.#needFingerprint(from, req);
    if (!m || !HEX64.test(m.key) || !Number.isInteger(m.i) || m.i < 1) refuse('bad_member');
    if (m.kind !== 'device' && m.kind !== 'box') refuse('bad_member');
    if (m.chip !== undefined && !CHIP.test(m.chip)) refuse('bad_chip_key');
    if (m.i !== s.next || s.members.some((x) => x.key === m.key)) refuse('already_listed');   // indices are never reused
    if (s.members.length >= MAX_MEMBERS) this.#tooMany();      // before the index is used up
    s.next++;
    const helpers = [from.i, s.i].sort((a, b) => a - b);
    const mine = F.repairDeltas(this.#C(s), helpers, s.i, BigInt('0x' + s.share), m.i);
    const sigma = F.repairSigma([mine.get(s.i)!, openFrom(this.state.sk, from.key, 'repair-delta', body.delta)]);
    s.members.push({ key: m.key, i: m.i, name: String(m.name ?? 'Device'), kind: m.kind, chip: m.chip, blocked: false, added: now });
    s.welcomes[m.key] = { by: from.key, box: sealTo(this.state.sk, m.key, 'repair-sigma', sigma) };
    if (gate) (s.gates ??= {})[m.key] = gate;
    this.#save();
    return { ok: true, delta: sealTo(this.state.sk, from.key, 'repair-delta', mine.get(from.i)!) };
  }

  #tooMany(): never { return refuseWhy('too_many_members', `An account has at most ${MAX_MEMBERS} devices and boxes, blocked ones included. Removing blocked devices makes room.`); }

  #welcomePut(s: Account, from: Member, body: any) {
    const w = s.welcomes[body.key] ?? refuse('no_welcome');
    if (w.by !== from.key) refuse('not_yours');
    if (typeof body.sigma !== 'string') refuse('bad_request');
    w.device = body.sigma;
    this.#save();
    return { ok: true };
  }

  #welcome(s: Account, from: Member, body: any, now: number) {
    const w = s.welcomes[from.key] ?? refuse('no_welcome');
    if (!w.device) refuse('not_ready');
    const g = s.gates?.[from.key];
    if (g) {
      // Added through a page note: the approval code the page was given, and the verifier when the note carried
      // a challenge (SPEC 11.6). A wrong try counts; after GATE_TRIES the member goes.
      if (!g.code || !g.short) refuse('not_approved');
      const code = typeof body.code === 'string' ? body.code : '';
      const codeOk = /^\d{6}$/.test(code) ? same(sha(new TextEncoder().encode('short:' + code)), g.short!) : code.length >= 16 && code.length <= 100 && same(sha(new TextEncoder().encode(code)), g.code!);
      const verifierOk = g.challenge === null || (typeof body.verifier === 'string' && /^[A-Za-z0-9_-]{43,128}$/.test(body.verifier) && b64url(sha(new TextEncoder().encode(body.verifier))) === g.challenge);
      if (!codeOk || !verifierOk) {
        g.tries++;
        if (g.tries >= GATE_TRIES) this.#dropGated(s, from.key);
        this.#save();
        refuse('wrong_code');
      }
      delete s.gates![from.key];                 // one use
    }
    if (!w.fetched) w.fetched = true;
    this.#save();
    return { ok: true, npub: s.npub, commitment: s.commitment, epoch: s.epoch, i: from.i, box: w.box, from: w.by, device: w.device, boxKey: this.state.key };
  }

  /**
   * The page that left the note gets its approval codes once, when a device has added the member (SPEC 11.6): a
   * long one (128 bits) for the app to redeem through the browser, and six digits to type. Null if there is no
   * member for the note, or the codes were given already.
   */
  approve(npub: string, note: string, now: number): { code: string; short: string; until: number } | null {
    const s = this.state.accounts[npub];
    const entry = s && Object.entries(s.gates ?? {}).find(([, g]) => g.note === note);
    if (!entry || entry[1].code) return null;
    const g = entry[1];
    const code = b64url(randomBytes(18)), short = String(randomInt(0, 1_000_000)).padStart(6, '0');
    g.code = bytesToHex(sha(new TextEncoder().encode(code)));
    g.short = bytesToHex(sha(new TextEncoder().encode('short:' + short)));
    g.until = now + GATE_SECONDS; g.tries = 0;
    this.#save();
    return { code, short, until: g.until };
  }
  /** The account a member waiting for its approval code is in. */
  #gatedAccount(key: string): Account {
    return this.accounts().find((a) => a.gates?.[key]) ?? refuse('no_welcome');
  }
  /** Members whose approval ran out (10 minutes after the codes, or never approved) go, as if never added. */
  #sweepGates(s: Account, now: number) {
    let changed = false;
    for (const [key, g] of Object.entries(s.gates ?? {})) {
      if (g.until !== undefined ? now > g.until : now - g.at > 2 * GATE_SECONDS) { this.#dropGated(s, key); changed = true; }
    }
    if (changed) this.#save();
  }
  #dropGated(s: Account, key: string) {
    s.members = s.members.filter((m) => m.key !== key);
    delete s.welcomes[key];
    delete s.gates![key];
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
    this.#forgetRemoved(s);                  // the sign-ins of the devices just dropped go with them
    // No cap on these (SPEC 8f): a member that stays away needs every change since, sealed to it so the box cannot
    // add them up, and missing one leaves its piece useless for good. Each one is a cycle a person asked for.
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
