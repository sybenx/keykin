// What the account page may ask of the box (SPEC 11.6). The page itself (Keykin Login) holds no piece
// and no list: it passes these calls through, and the box decides. Nothing here can sign, add a device,
// unblock one or form the key. Those need a device's fingerprint and go through /keykin.

import { Box, type Account, type Note, USERNAME } from './box.ts';
import { KeykinError, refuse, randomBytes, bytesToHex, hexToBytes, sha } from '../src/bytes.ts';
import { timingSafeEqual } from 'node:crypto';

const SESSION_SECONDS = 12 * 3600, LOGIN_SECONDS = 180, NOTE_SECONDS = 600;
const FREE_TRIES = 5, FIRST_LOCK = 15 * 60, LONGEST_LOCK = 24 * 3600, TRIES_A_MINUTE = 30;
const HEX32 = /^[0-9a-f]{32}$/, HEX64 = /^[0-9a-f]{64}$/;

export class PageApi {
  #sessions = new Map<string, { account: string; until: number; how: 'password' | 'device' }>();
  #noteBy = new Map<string, string>();      // note id -> the session that left it
  #logins = new Map<string, { until: number; browser: string; account?: string }>();
  #notes = new Map<string, Note[]>();
  #tries: number[] = [];
  readonly box: Box;
  /** The address devices reach the box at, for the login codes the page shows. */
  readonly addr: () => string;

  constructor(box: Box, addr: () => string) {
    this.box = box; this.addr = addr;
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
    box.onNoteDone = (account, id, result) => {
      const n = (this.#notes.get(account) ?? []).find((x) => x.id === id);
      if (!n || n.result !== undefined) return false;
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
          return { ok: true, session: this.#newSession(l!.account!, now, 'device') };
        }
      }
      // Everything below needs a session.
      const ses = this.#sessions.get(body?.session) ?? refuse('login');
      const a = this.box.state.accounts[ses.account] ?? refuse('login');
      switch (body.call) {
        case 'me': return { ok: true, how: ses.how, ...this.#view(a) };
        case 'block': { const n = this.#name(a, body.key); this.box.ownerBlock(body.key, a.npub); this.box.happened(a.npub, `${n} was blocked from the account page`, now); return { ok: true }; }
        case 'unblock': { const n = this.#name(a, body.key); this.box.unblockIn(a.npub, body.key); this.box.happened(a.npub, `${n} was unblocked from the account page`, now); return { ok: true }; }
        case 'revoke': {
          const g = Object.values(a.grants ?? {}).flat().find((x) => x.id === body.grant);
          this.box.revokeGrant(a.npub, body.grant); this.box.happened(a.npub, `${g?.name ?? 'A sign-in'} was revoked from the account page`, now); return { ok: true };
        }
        case 'limit': {
          const g = Object.values(a.grants ?? {}).flat().find((x) => x.id === body.grant) ?? refuse('gone');
          this.box.limitGrant(a.npub, body.grant, body.to ?? null);
          this.box.happened(a.npub, body.to === 'posts' ? `${g.name} was limited to posting from the account page` : `${g.name} may do everything again, from the account page`, now);
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
          const note: Note = { id: bytesToHex(randomBytes(16)), kind: body.kind, text: body.text, at: now, tap: body.kind === 'cycle' };
          this.#notes.set(a.npub, [...list, note]); this.#noteBy.set(note.id, body.session);
          this.box.happened(a.npub, { nostrconnect: 'A site sign-in was started from the account page', invite: 'Adding a device was started from the account page', bunker: 'A bunker link was asked for from the account page', cycle: 'Removing blocked devices was asked for from the account page' }[body.kind as Note['kind']], now);
          return { ok: true, note: note.id };
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

  #tidy(now: number) {
    for (const [t, s] of this.#sessions) if (s.until < now) this.#sessions.delete(t);
    for (const [c, l] of this.#logins) if (l.until < now) this.#logins.delete(c);
    for (const id of this.#noteBy.keys()) if (![...this.#notes.values()].some((l) => l.some((n) => n.id === id))) this.#noteBy.delete(id);
    for (const [a, list] of this.#notes) { const keep = list.filter((n) => now - n.at < NOTE_SECONDS); if (keep.length) this.#notes.set(a, keep); else this.#notes.delete(a); }
  }
  #newSession(account: string, now: number, how: 'password' | 'device') {
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
      devices: a.members.map((m) => ({ key: m.key, name: m.name, kind: m.kind, blocked: m.blocked, blockedAt: m.blockedAt ?? null, added: m.added, last: m.last ?? null, fingerprint: !!m.chip })),
      log: [...(a.log ?? [])].reverse(),
      grants: Object.entries(a.grants ?? {}).flatMap(([key, list]) => list.map((g) => ({ ...g, device: key, deviceName: name(key), limit: a.limits?.[g.id] ?? null }))),
    };
  }
}
