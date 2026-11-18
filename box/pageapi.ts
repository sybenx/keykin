// What the account page may ask of the box (SPEC 11.6). The page itself (Keykin Login) holds no piece
// and no list: it passes these calls through, and the box decides. Nothing here can sign, add a device,
// unblock one or form the key. Those need a device's fingerprint and go through /keykin.

import { Box, type Limit, type Account, type Note, type Passkey, USERNAME } from './box.ts';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { KeykinError, refuse, randomBytes, bytesToHex, hexToBytes, sha } from '../src/bytes.ts';
import { timingSafeEqual } from 'node:crypto';
import { schnorr } from '@noble/curves/secp256k1.js';
import { eventId } from '../src/event.ts';

const SESSION_SECONDS = 12 * 3600, LOGIN_SECONDS = 180, NOTE_SECONDS = 600, CHALLENGE_SECONDS = 900, PROOF_SKEW = 600;
/** The kind of the event that proves who is signing in: a login event (NIP-42's kind), which signers sign without asking. */
export const PROOF_KIND = 22242;
const FREE_TRIES = 5, FIRST_LOCK = 15 * 60, LONGEST_LOCK = 24 * 3600, TRIES_A_MINUTE = 30;
const HEX32 = /^[0-9a-f]{32}$/, HEX64 = /^[0-9a-f]{64}$/;
/** How a page session was made (SPEC 11.6). A passkey or a scan is strong; a password alone is weak. */
export type How = 'password' | 'passkey' | 'scan';
// Sign-in strength (SPEC 11.6). A password, a passkey and a scan all give the same full session
// ("the password *is* the auth", 2026-11-17). Tiers are a possible later idea, not adopted: switching
// one on is a row here, `call` (or `note_put:<kind>`, `limit:<to|none>`) -> 'strong', plus a ceiling
// for sites a weak session signs in. A box owner can set them with KEYKIN_POLICY, e.g.
// {"calls":{"note_put:invite":"strong","limit:none":"strong"},"weakSiteLimit":"dms"}.
export type Need = 'any' | 'strong';
export const POLICY: Record<string, Need> = {};
/** The most a site signed in from a weak session gets (`dms`, `posts`), or null: no ceiling. */
export const WEAK_SITE_LIMIT: Limit | null = null;
const B64URL = /^[A-Za-z0-9_-]{1,1400}$/;

export class PageApi {
  #sessions = new Map<string, { account: string; until: number; how: How }>();
  #pkChallenges = new Map<string, { until: number; rpId: string; origin: string; account?: string }>();
  #noteBy = new Map<string, string>();      // note id -> the session that left it
  #logins = new Map<string, { until: number; browser: string; account?: string }>();
  #notes = new Map<string, Note[]>();
  #challenges = new Map<string, number>();   // challenge -> good until
  #tries: number[] = [];
  readonly box: Box;
  /** The address devices reach the box at, for the login codes the page shows. */
  readonly addr: () => string;

  /** Whether anyone who signs in may bring their account onto this box without the admin approving. */
  readonly open: () => boolean;

  readonly policy: Record<string, Need>;
  readonly weakSiteLimit: Limit | null;
  constructor(box: Box, addr: () => string, open: () => boolean = () => false, policy: { calls?: Record<string, Need>; weakSiteLimit?: Limit | null } = {}) {
    this.box = box; this.addr = addr; this.open = open;
    this.policy = { ...POLICY, ...policy.calls }; this.weakSiteLimit = policy.weakSiteLimit === undefined ? WEAK_SITE_LIMIT : policy.weakSiteLimit;
    box.onLogin = (code, account) => {
      const l = this.#logins.get(code);
      if (!l || l.account) return false;
      l.account = account; this.box.happened(account, 'A browser was signed in to the account page by a device', Math.floor(Date.now() / 1000)); return true;
    };
    box.onNoteRefused = (account, id) => {
      const list = this.#notes.get(account) ?? [];
      if (!list.some((x) => x.id === id && x.result === undefined)) return false;
      this.#notes.set(account, list.filter((x) => x.id !== id));
      const by = this.#noteBy.get(id); if (by) this.#sessions.delete(by);      // No ends that browser's session
      this.#noteBy.delete(id);
      return true;
    };
    box.onNotes = (account) => this.#notes.get(account) ?? [];
    box.onNoteDone = (account, id, result, device) => {
      const n = (this.#notes.get(account) ?? []).find((x) => x.id === id);
      if (!n || n.result !== undefined) return false;
      if (n.kind === 'nostrconnect' && n.weak && this.weakSiteLimit) this.box.limitNextSiteOf(account, device, Math.floor(Date.now() / 1000) + NOTE_SECONDS, this.weakSiteLimit);
      n.result = result; return true;
    };
  }

  /** Every call from the page comes through here. Returns `{ ok, ... }` or `{ error }`. */
  call(body: any, now: number): any {
    try {
      this.#tidy(now); this.lastCall = now;
      switch (body?.call) {
        case 'pw_salt': return { ok: true, salt: this.#saltFor(String(body.username ?? '')) };
        case 'pw_login': return this.#pwLogin(body, now);
        // Signing in the way any site does: the page gets a signer for the account (by a scanned code), and
        // that signer signs this challenge. The box only checks the signature. It need not hold the account.
        case 'signin_start': {
          if (this.#challenges.size > 2000) refuse('too_many');
          const challenge = bytesToHex(randomBytes(16));
          this.#challenges.set(challenge, now + CHALLENGE_SECONDS);
          return { ok: true, challenge };
        }
        case 'signin': {
          const e = body.event;
          if (!e || typeof e !== 'object' || !HEX64.test(e.pubkey ?? '') || !HEX64.test(e.id ?? '') || typeof e.sig !== 'string' || !/^[0-9a-f]{128}$/.test(e.sig)
            || e.kind !== PROOF_KIND || !Number.isInteger(e.created_at) || !Array.isArray(e.tags) || typeof e.content !== 'string') refuse('bad_request');
          const challenge = e.tags.find((t: any) => Array.isArray(t) && t[0] === 'challenge')?.[1];
          if (typeof challenge !== 'string' || !this.#challenges.has(challenge)) refuse('gone');
          if (Math.abs(now - e.created_at) > PROOF_SKEW) refuse('gone');
          let good = false;
          try { good = eventId({ pubkey: e.pubkey, created_at: e.created_at, kind: e.kind, tags: e.tags, content: e.content }) === e.id && schnorr.verify(hexToBytes(e.sig), hexToBytes(e.id), hexToBytes(e.pubkey)); } catch { good = false; }
          if (!good) refuse('wrong');
          this.#challenges.delete(challenge);                    // a challenge works once
          if (this.box.state.accounts[e.pubkey]) this.box.happened(e.pubkey, 'A browser was signed in to the account page by a device', now);
          return { ok: true, session: this.#newSession(e.pubkey, now, 'scan', body.session) };
        }
        case 'login_start': {
          if (!HEX32.test(body.browser ?? '')) refuse('bad_request');
          if (this.#logins.size > 500) refuse('too_many');
          const code = bytesToHex(randomBytes(16));
          this.#logins.set(code, { until: now + LOGIN_SECONDS, browser: body.browser });
          return { ok: true, code, text: JSON.stringify({ keykin: 2, login: { addr: this.addr(), key: this.box.state.key, code } }) };
        }
        case 'login_wait': {
          const l = this.#logins.get(body.code);
          if (!l || l.browser !== body.browser) refuse('gone');
          if (!l!.account) return { ok: true, waiting: true };
          this.#logins.delete(body.code);
          return { ok: true, session: this.#newSession(l!.account!, now, 'scan', body.session) };
        }
      }
      // Everything below needs a session.
      const ses = this.#sessions.get(body?.session) ?? refuse('login');
      const a = this.box.state.accounts[ses.account];
      if (!a) {
        // Signed in, but this box holds no piece of the account yet. All it can do here is come in.
        switch (body.call) {
          case 'me': return { ok: true, how: ses.how, npub: ses.account, held: false, open: this.open() };
          case 'protect': {
            if (!this.open()) refuse('not_open');
            return { ok: true, text: this.box.newSetupCode(this.addr(), now, ses.account) };
          }
          case 'logout': case 'logout_all': this.#sessions.delete(body.session); return { ok: true };
          default: return refuse('not_here');
        }
      }
      const strong = ses.how !== 'password';
      if (!strong && this.#needs(body) === 'strong') refuse('need_strong');
      switch (body.call) {
        case 'me': return { ok: true, how: ses.how, strong, held: true, ...this.#view(a) };
        case 'block': { const n = this.#name(a, body.key); this.box.ownerBlock(body.key, a.npub); this.box.happened(a.npub, `${n} was blocked from the account page`, now); return { ok: true }; }
        case 'unblock': { const n = this.#name(a, body.key); this.box.unblockIn(a.npub, body.key); this.box.happened(a.npub, `${n} was unblocked from the account page`, now); return { ok: true }; }
        case 'revoke': {
          const g = Object.values(a.grants ?? {}).flat().find((x) => x.id === body.grant);
          this.box.revokeGrant(a.npub, body.grant); this.box.happened(a.npub, `${g?.name ?? 'A sign-in'} was revoked from the account page`, now); return { ok: true };
        }
        case 'limit': {
          const g = Object.values(a.grants ?? {}).flat().find((x) => x.id === body.grant) ?? refuse('gone');
          this.box.limitGrant(a.npub, body.grant, body.to ?? null);
          this.box.happened(a.npub, body.to === 'posts' ? `${g.name} was limited to posting from the account page` : body.to === 'dms' ? `${g.name} was limited to posts and direct messages from the account page` : `${g.name} may do everything again, from the account page`, now);
          return { ok: true };
        }
        case 'pw_set': this.box.setLogin(a.npub, body.username, body.salt, body.check); this.box.happened(a.npub, 'The password was changed from the account page', now); return { ok: true };
        case 'pw_clear': delete a.login; this.box.touch(); this.box.happened(a.npub, 'Password sign-in was turned off from the account page', now); return { ok: true };
        case 'logout': this.#sessions.delete(body.session); return { ok: true };
        case 'logout_all': for (const [t, s] of this.#sessions) if (s.account === a.npub) this.#sessions.delete(t); return { ok: true };
        case 'note_put': {
          if (!['nostrconnect', 'invite', 'bunker', 'cycle'].includes(body.kind) || typeof body.text !== 'string' || body.text.length > 4000) refuse('bad_request');
          const list = this.#notes.get(a.npub) ?? [];
          if (list.length >= 10) refuse('too_many');
          // Only the hard-to-undo one asks the person on a device. The rest a device just does.
          const note: Note = { id: bytesToHex(randomBytes(16)), kind: body.kind, text: body.text, at: now, tap: body.kind === 'cycle', ...(body.kind === 'nostrconnect' && !strong && this.weakSiteLimit ? { weak: true } : {}) };
          this.#notes.set(a.npub, [...list, note]); this.#noteBy.set(note.id, body.session);
          this.box.happened(a.npub, { nostrconnect: 'A site sign-in was started from the account page', invite: 'Adding a device was started from the account page', bunker: 'A bunker link was asked for from the account page', cycle: 'Removing blocked devices was asked for from the account page' }[body.kind as Note['kind']], now);
          return { ok: true, note: note.id, ...(note.weak ? { limit: this.weakSiteLimit } : {}) };
        }
        case 'note_get': {
          const n = (this.#notes.get(a.npub) ?? []).find((x) => x.id === body.note);
          return n ? { ok: true, state: n.result === undefined ? 'waiting' : 'done', result: n.result } : { ok: true, state: 'gone' };
        }
        default: return refuse('unknown_call');
      }
    } catch (e) {
      if (e instanceof KeykinError) return { error: e.code };
      throw e;
    }
  }

  // ---- Passkeys (SPEC 11.3) --------------------------------------------------------------------------
  // WebAuthn with the page's host as the relying party, a resident key, and user verification required.
  // `origin` is put in by Keykin Login from the request it served, never taken from the page.
  async request(body: any, now: number): Promise<any> {
    if (typeof body?.call !== 'string' || !body.call.startsWith('pk_')) return this.call(body, now);
    try { this.#tidy(now); this.lastCall = now; return await this.#passkey(body, now); }
    catch (e) { if (e instanceof KeykinError) return { error: e.code }; return { error: 'wrong' }; }
  }
  #needs(body: any): Need {
    const row = body.call === 'note_put' ? `note_put:${body.kind}` : body.call === 'limit' ? `limit:${body.to ?? 'none'}` : body.call;
    return this.policy[row] ?? this.policy[body.call] ?? 'any';
  }
  #place(body: any) {
    let u: URL; try { u = new URL(String(body.origin ?? '')); } catch { return refuse('bad_request'); }
    if (u.protocol !== 'https:' && !['localhost', '127.0.0.1'].includes(u.hostname)) refuse('bad_request');
    return { rpId: u.hostname, origin: u.origin };
  }
  #challengeOf(response: any) {
    try { return JSON.parse(Buffer.from(String(response?.response?.clientDataJSON ?? ''), 'base64url').toString('utf8')).challenge as string; } catch { return ''; }
  }
  async #passkey(body: any, now: number): Promise<any> {
    if (this.#pkChallenges.size > 2000) refuse('too_many');
    switch (body.call) {
      case 'pk_login_start': {
        const { rpId, origin } = this.#place(body);
        const o = await generateAuthenticationOptions({ rpID: rpId, userVerification: 'required', allowCredentials: [] });
        this.#pkChallenges.set(o.challenge, { until: now + LOGIN_SECONDS, rpId, origin });
        return { ok: true, options: o };
      }
      case 'pk_login': {
        const { rpId, origin } = this.#place(body);
        const r = body.response, ch = this.#challengeOf(r), c = this.#pkChallenges.get(ch);
        if (!c || c.account || c.rpId !== rpId || c.origin !== origin) refuse('gone');
        this.#pkChallenges.delete(ch);
        if (!B64URL.test(r?.id ?? '')) refuse('wrong');
        const a = this.box.accounts().find((x) => x.passkeys?.some((p) => p.id === r.id));
        const pk = a?.passkeys?.find((p) => p.id === r.id);
        if (!a || !pk || pk.rpId !== rpId) refuse('wrong');
        const v = await verifyAuthenticationResponse({ response: r, expectedChallenge: ch, expectedOrigin: pk!.origin, expectedRPID: pk!.rpId, requireUserVerification: true,
          credential: { id: pk!.id, publicKey: Buffer.from(pk!.key, 'base64url'), counter: pk!.counter } });
        if (!v.verified) refuse('wrong');
        pk!.counter = v.authenticationInfo.newCounter; pk!.last = now; this.box.touch();
        this.box.happened(a!.npub, 'A browser signed in to the account page with a passkey', now);
        return { ok: true, session: this.#newSession(a!.npub, now, 'passkey', body.session) };
      }
    }
    // Adding and removing passkeys needs a strong session.
    const ses = this.#sessions.get(body.session) ?? refuse('login');
    const a = this.box.state.accounts[ses.account] ?? refuse('not_here');
    if (ses.how === 'password' && this.#needs(body) === 'strong') refuse('need_strong');
    switch (body.call) {
      case 'pk_add_start': {
        const { rpId, origin } = this.#place(body);
        if ((a.passkeys ?? []).length >= 20) refuse('too_many');
        const o = await generateRegistrationOptions({ rpName: 'Keykin', rpID: rpId, userName: a.login?.username ?? `${a.npub.slice(0, 12)}…`, userID: hexToBytes(a.npub),
          attestationType: 'none', authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
          excludeCredentials: (a.passkeys ?? []).filter((p) => p.rpId === rpId).map((p) => ({ id: p.id })) });
        this.#pkChallenges.set(o.challenge, { until: now + LOGIN_SECONDS, rpId, origin, account: a.npub });
        return { ok: true, options: o };
      }
      case 'pk_add': {
        const { rpId, origin } = this.#place(body);
        const ch = this.#challengeOf(body.response), c = this.#pkChallenges.get(ch);
        if (!c || c.account !== a.npub || c.rpId !== rpId || c.origin !== origin) refuse('gone');
        this.#pkChallenges.delete(ch);
        const v = await verifyRegistrationResponse({ response: body.response, expectedChallenge: ch, expectedOrigin: origin, expectedRPID: rpId, requireUserVerification: true });
        if (!v.verified || !v.registrationInfo) refuse('wrong');
        const cred = v.registrationInfo!.credential;
        if (this.box.accounts().some((x) => x.passkeys?.some((p) => p.id === cred.id))) refuse('bad_request');
        const p: Passkey = { id: cred.id, key: Buffer.from(cred.publicKey).toString('base64url'), counter: cred.counter, rpId, origin, added: now };
        (a.passkeys ??= []).push(p); this.box.touch();
        this.box.happened(a.npub, 'A passkey was added from the account page', now);
        return { ok: true };
      }
      case 'pk_remove': {
        const before = (a.passkeys ?? []).length;
        a.passkeys = (a.passkeys ?? []).filter((p) => p.id !== body.id);
        if (a.passkeys.length === before) refuse('gone');
        this.box.touch(); this.box.happened(a.npub, 'A passkey was removed from the account page', now);
        return { ok: true };
      }
      default: return refuse('unknown_call');
    }
  }

  #tidy(now: number) {
    for (const [c, x] of this.#pkChallenges) if (x.until < now) this.#pkChallenges.delete(c);
    for (const [t, s] of this.#sessions) if (s.until < now) this.#sessions.delete(t);
    for (const [c, l] of this.#logins) if (l.until < now) this.#logins.delete(c);
    for (const [c, until] of this.#challenges) if (until < now) this.#challenges.delete(c);
    for (const id of this.#noteBy.keys()) if (![...this.#notes.values()].some((l) => l.some((n) => n.id === id))) this.#noteBy.delete(id);
    for (const [a, list] of this.#notes) { const keep = list.filter((n) => now - n.at < NOTE_SECONDS); if (keep.length) this.#notes.set(a, keep); else this.#notes.delete(a); }
  }
  #newSession(account: string, now: number, how: How, old?: unknown) {
    // Confirming with a passkey or a scan replaces a weaker session of the same account (an upgrade in place).
    if (typeof old === 'string' && this.#sessions.get(old)?.account === account) this.#sessions.delete(old);
    const token = bytesToHex(randomBytes(32));
    this.#sessions.set(token, { account, until: now + SESSION_SECONDS, how });
    return token;
  }
  #name(a: Account, key: unknown) { return a.members.find((m) => m.key === key)?.name ?? 'A device'; }
  /** When the account page last reached the box, for the admin page's "outside door" card. */
  lastCall = 0;
  #byUsername(u: string): Account | undefined { return this.box.accounts().find((a) => a.login?.username === u); }
  // A username that does not exist still gets a salt, the same one every time, so asking tells nothing.
  #saltFor(username: string): string {
    const a = this.#byUsername(username);
    if (a) return a.login!.salt;
    if (!this.box.state.pwSecret) { this.box.state.pwSecret = bytesToHex(randomBytes(32)); this.box.touch(); }
    return bytesToHex(sha('keykin2-nosalt', this.box.state.pwSecret, username)).slice(0, 32);
  }
  #pwLogin(body: any, now: number) {
    this.#tries = this.#tries.filter((t) => now - t < 60);
    if (this.#tries.length >= TRIES_A_MINUTE) refuse('slow_down');
    this.#tries.push(now);
    const u = String(body.username ?? '');
    if (!USERNAME.test(u) || !HEX64.test(body.verifier ?? '')) refuse('wrong');
    const a = this.#byUsername(u);
    if (!a) refuse('wrong');
    const l = a!.login!;
    if ((l.lockedUntil ?? 0) > now) return { error: 'locked', wait: l.lockedUntil! - now };
    const given = sha('keykin2-pw', hexToBytes(body.verifier));
    if (!timingSafeEqual(given, hexToBytes(l.check))) {
      l.fails = (l.fails ?? 0) + 1;
      if (l.fails >= FREE_TRIES) l.lockedUntil = now + Math.min(LONGEST_LOCK, FIRST_LOCK * 2 ** (l.fails - FREE_TRIES));
      this.box.touch();
      return refuse('wrong');
    }
    if (l.fails || l.lockedUntil) { delete l.fails; delete l.lockedUntil; this.box.touch(); }
    this.box.happened(a!.npub, 'A browser signed in to the account page with the password', now);
    return { ok: true, session: this.#newSession(a!.npub, now, 'password') };
  }
  #view(a: Account) {
    const name = (key: string) => a.members.find((m) => m.key === key)?.name ?? 'A device that was removed';
    return {
      npub: a.npub, username: a.login?.username ?? null, boxKey: this.box.state.key,
      passkeys: (a.passkeys ?? []).map((p) => ({ id: p.id, host: p.rpId, added: p.added, last: p.last ?? null })),
      devices: a.members.map((m) => ({ key: m.key, name: m.name, kind: m.kind, blocked: m.blocked, blockedAt: m.blockedAt ?? null, added: m.added, last: m.last ?? null, fingerprint: !!m.chip })),
      log: [...(a.log ?? [])].reverse(),
      grants: Object.entries(a.grants ?? {}).flatMap(([key, list]) => list.map((g) => ({ ...g, device: key, deviceName: name(key), limit: a.limits?.[g.id] ?? null }))),
    };
  }
}
