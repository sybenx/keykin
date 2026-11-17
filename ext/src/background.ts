// The extension's worker: this browser as a Keykin device. It holds the browser's piece, talks to the
// box, and answers sites the person has allowed. A browser has no fingerprint chip, so it has no chip
// key: it signs, and leaves adding devices, unblocking and forming the whole key to a phone.

import init, * as frost from '../../frost-wasm-web/keykin_frost.js';
import { useWasm } from '../../src/wasm.ts';
import * as D from '../../src/device.ts';
import { newMemberKey } from '../../src/member.ts';
import { commitmentFrom, commitmentHex, scalarFrom, scalarHex } from '../../src/curve.ts';
import { npubEncode } from 'nostr-tools/nip19';

const ready = init({ module_or_path: chrome.runtime.getURL('keykin_frost_bg.wasm') }).then(() => useWasm(frost));

interface Saved {
  me?: { sk: string; key: string; name: string };
  held?: { commitment: string[]; i: number; share: string; npub: string; boxKey: string; epoch: number };
  addr?: string;
  sites?: string[];
  /** Each allowed site is a grant at the box (SPEC 11.5), by origin, so the account page lists it and can revoke or limit it. */
  grants?: Record<string, D.Grant>;
}
const load = async (): Promise<Saved> => (await chrome.storage.local.get('keykin')).keykin ?? {};
const save = (s: Saved) => chrome.storage.local.set({ keykin: s });
const sender = (addr: string): D.Send => async (r) => (await fetch(`${addr}/keykin`, { method: 'POST', body: JSON.stringify(r) })).json();
const heldOf = (s: Saved): D.Held => {
  if (!s.held) throw new Error('This browser is not in an account yet. Open Keykin to set it up.');
  return { piece: { C: commitmentFrom(s.held.commitment), i: s.held.i, share: scalarFrom(s.held.share) }, npub: s.held.npub, boxKey: s.held.boxKey, epoch: s.held.epoch };
};
const keep = (s: Saved, h: D.Held, addr: string) => {
  s.addr = addr;
  s.held = { commitment: commitmentHex(h.piece.C), i: h.piece.i, share: scalarHex(h.piece.share), npub: h.npub, boxKey: h.boxKey, epoch: h.epoch };
};
async function meOf(s: Saved): Promise<D.Me> {
  if (!s.me) { s.me = { ...newMemberKey(), name: 'Browser' }; await save(s); }
  return { sk: s.me.sk, key: s.me.key, name: s.me.name };
}
const say = (e: any): string => {
  const code = e?.code ?? '';
  return ({
    blocked: 'This browser is blocked.', bad_code: 'That code is no longer valid. Reload the box page and copy it again.',
    already_set_up: 'That box already has an account.', bad_qr: 'That is not a Keykin code.', not_ready: 'The other device has not finished adding this browser yet.',
    no_welcome: 'The other device has not finished adding this browser yet.', unknown_member: 'This browser is no longer in the account.',
    revoked: 'This site was signed out from your account page.', not_allowed: 'This site may only post. That is set on your account page.',
  } as Record<string, string>)[code] ?? (e?.message?.includes('fetch') ? 'Cannot reach the box.' : String(e?.message ?? e));
};

// Sites waiting for the person to allow or deny them: origin -> the callbacks of every request waiting on it.
const asking = new Map<string, ((ok: boolean) => void)[]>();
function allowSite(origin: string): Promise<boolean> {
  return new Promise((done) => {
    const list = asking.get(origin);
    if (list) { list.push(done); return; }
    asking.set(origin, [done]);
    chrome.windows.create({ url: chrome.runtime.getURL(`approve.html?origin=${encodeURIComponent(origin)}`), type: 'popup', width: 420, height: 360 });
  });
}

/** Forgets a site here: it is asked about again next time. */
const dropSite = (s: Saved, origin: string) => { s.sites = (s.sites ?? []).filter((o) => o !== origin); if (s.grants) delete s.grants[origin]; };

/**
 * Tells the box the whole list of allowed sites, and forgets any the box says were revoked. A site allowed
 * before grants existed gets one here. If the box cannot be reached, the list is sent next time.
 */
async function reportSites(): Promise<void> {
  const s = await load();
  if (!s.held || !s.addr) return;
  const grants = (s.grants ??= {});
  for (const o of s.sites ?? []) grants[o] ??= D.newGrant('site', o);
  for (const o of Object.keys(grants)) if (!(s.sites ?? []).includes(o)) delete grants[o];
  await save(s);
  let revoked: string[];
  try { revoked = await D.reportGrants(await meOf(s), heldOf(s), Object.values(grants), sender(s.addr)); } catch { return; }
  if (!revoked.length) return;
  const now = await load();
  for (const [o, g] of Object.entries(now.grants ?? {})) if (revoked.includes(g.id)) dropSite(now, o);
  await save(now);
}

async function fromSite(origin: string, method: string, params: any[]): Promise<unknown> {
  await ready;
  let s = await load();
  const h = heldOf(s);
  if (!(s.sites ?? []).includes(origin)) {
    if (!(await allowSite(origin))) throw new Error('Not allowed.');
    s = await load();
  }
  if (!s.grants?.[origin]) { await reportSites(); s = await load(); }
  const grant = s.grants?.[origin]?.id;
  const me = await meOf(s), send = sender(s.addr!);
  try {
    switch (method) {
      case 'getPublicKey': return h.npub;
      case 'signEvent': {
        const e = params[0] ?? {};
        return await D.signEvent(me, h, { pubkey: h.npub, created_at: e.created_at ?? Math.floor(Date.now() / 1000), kind: e.kind, tags: e.tags ?? [], content: e.content ?? '' }, send, undefined, grant);
      }
      case 'nip44.encrypt': return await D.nip44Encrypt(me, h, params[0], params[1], send, undefined, grant);
      case 'nip44.decrypt': return await D.nip44Decrypt(me, h, params[0], params[1], send, undefined, grant);
      default: throw new Error('Keykin does not do that.');
    }
  } catch (e: any) {
    // Revoked at the box (from the account page or another device): this site is asked about again next time.
    if (e?.code === 'revoked') { const now = await load(); dropSite(now, origin); await save(now); reportSites().catch(() => {}); }
    throw e;
  } finally { const now = await load(); keep(now, h, s.addr!); await save(now); }   // a catch-up after a cycle is kept
}

async function fromUi(m: any): Promise<unknown> {
  await ready;
  const s = await load();
  const me = await meOf(s);
  switch (m.cmd) {
    case 'state': {
      if (!s.held) return { account: false, invite: JSON.stringify({ keykin: 2, invite: { key: me.key, name: me.name } }) };
      let members: any[] = [], problem: string | undefined;
      try { members = (await D.members(me, sender(s.addr!), undefined, s.held.npub)).members; } catch (e) { problem = say(e); }
      if (!problem) await reportSites();           // picks up revokes made on the account page
      return { account: true, npub: npubEncode(s.held.npub), me: me.key, members, sites: (await load()).sites ?? [], problem };
    }
    case 'create': {
      const qr = D.readQr(m.text);
      const h = await D.createWithBox(me, qr, sender(qr.addr));
      keep(s, h, qr.addr); await save(s); return {};
    }
    case 'join': {
      let j: any; try { j = JSON.parse(m.text).join; } catch { j = null; }
      if (!j) throw Object.assign(new Error('bad'), { code: 'bad_qr' });
      const h = await D.join(me, j.boxKey, j.npub, sender(j.addr));
      keep(s, h, j.addr); await save(s); return {};
    }
    case 'block': await D.block(me, m.key, sender(s.addr!), undefined, s.held?.npub); return {};
    case 'signout': dropSite(s, m.origin); await save(s); await reportSites(); return {};
    case 'decide': {
      if (m.allow) {
        s.sites = [...new Set([...(s.sites ?? []), m.origin])];
        (s.grants ??= {})[m.origin] ??= D.newGrant('site', m.origin);
        await save(s); await reportSites();
      }
      for (const done of asking.get(m.origin) ?? []) done(!!m.allow);
      asking.delete(m.origin); return {};
    }
    default: throw new Error('unknown');
  }
}

chrome.runtime.onMessage.addListener((m, from, reply) => {
  const run = m?.kind === 'nostr'
    ? fromSite(from.origin ?? new URL(from.url ?? '').origin, m.method, m.params ?? []).then((result) => ({ result }))
    : m?.kind === 'ui' && from.id === chrome.runtime.id && !from.tab?.url?.startsWith('http')
      ? fromUi(m).then((result) => ({ result }))
      : Promise.reject(new Error('unknown'));
  run.catch((e) => ({ error: say(e) })).then(reply);
  return true;   // the answer comes later
});
