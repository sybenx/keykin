// Stand-ins for a DMs home (bothy) and its file server (Keykin Storage), for the account page's Home section.
// They follow the written contracts: bothy's in ~/dms/docs/bothy-members-contract.md (v0.20 admins to v0.28
// location trust and removal), storage's /manage as agreed with the DMs coordinating session on 2026-11-22.
// Each checks every NIP-98 header the way the contracts say: kind 27235, `u` the exact URL, `method` POST,
// `payload` the body's SHA-256, `created_at` within 60 seconds, a good signature.
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { connect } from 'node:net';
import { createHash } from 'node:crypto';
import { verifyEvent } from 'nostr-tools/pure';

type Member = { pubkey: string; invitedBy: string | null; joinedAt: number; source: string; role: 'admin' | 'member'; close: boolean; lastSeen?: number | null; inviterUnknown?: boolean };
const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-allow-headers': 'Authorization, Content-Type, Accept' };

const body = (req: IncomingMessage) => new Promise<string>((ok) => { const c: Buffer[] = []; req.on('data', (b) => c.push(b)); req.on('end', () => ok(Buffer.concat(c).toString('utf8'))); });
const send = (res: ServerResponse, status: number, j: unknown, type = 'application/json') => { res.writeHead(status, { 'content-type': type, ...CORS }); res.end(JSON.stringify(j)); };

/** The signer of a NIP-98 request, or why it is refused. */
export function nip98(req: IncomingMessage, url: string, text: string, now = Math.floor(Date.now() / 1000)): { pubkey: string } | { bad: string } {
  const h = String(req.headers.authorization ?? '');
  if (!h.startsWith('Nostr ')) return { bad: 'no auth' };
  let e: any; try { e = JSON.parse(Buffer.from(h.slice(6), 'base64').toString('utf8')); } catch { return { bad: 'bad auth' }; }
  const tag = (n: string) => e.tags?.find((t: string[]) => t[0] === n)?.[1];
  if (e.kind !== 27235) return { bad: 'kind' };
  if (tag('u') !== url) return { bad: `u ${tag('u')} != ${url}` };
  if (tag('method') !== 'POST') return { bad: 'method' };
  if (tag('payload') !== createHash('sha256').update(text).digest('hex')) return { bad: 'payload' };
  if (Math.abs(now - e.created_at) > 60) return { bad: 'time' };
  if (!verifyEvent(e)) return { bad: 'signature' };
  return { pubkey: e.pubkey };
}

export async function fakeBothy(o: { owner: string; name?: string; members?: Partial<Member>[]; relayPort?: number }) {
  const members = new Map<string, Member>();
  const t0 = 1_760_000_000;
  (o.members ?? []).forEach((m, i) => members.set(m.pubkey!, { invitedBy: o.owner, joinedAt: t0 + i, source: 'invite', role: 'member', close: true, ...m } as Member));
  const removed: { pubkey: string; removedAt: number; deletesAt: number; reason: string }[] = [];
  let storage: { url: string; pubkey: string } | null = null;
  const calls: { method: string; params: any[]; by: string }[] = [];
  let url = '';
  const roleOf = (pk: string) => (pk === o.owner ? 'owner' : members.get(pk)?.role ?? (members.has(pk) ? 'member' : 'none'));
  const below = (pk: string): string[] => [...members.values()].filter((m) => m.invitedBy === pk).flatMap((m) => [m.pubkey, ...below(m.pubkey)]);
  const drop = (pk: string) => { members.delete(pk); const at = Math.floor(Date.now() / 1000); removed.unshift({ pubkey: pk, removedAt: at, deletesAt: at + 14 * 86400, reason: 'removed' }); };

  function run(by: string, method: string, params: any[]): { result?: unknown; error?: string; status?: number } {
    const role = roleOf(by);
    const staff = role === 'owner' || role === 'admin';
    switch (method) {
      case 'myrole': return { result: { role, close: role === 'owner' || !!members.get(by)?.close } };
      case 'listmembers':
        if (!staff) return { status: 401, error: 'you are not allowed' };
        return { result: { members: [...members.values()], removed } };
      case 'setclose': {
        if (!staff) return { status: 401, error: 'setclose is for this relay\'s owner and admins' };
        const [pk, on] = params;
        if (pk === o.owner) return { error: 'setclose: the owner always sees where photos were taken' };
        if (!members.has(pk)) return { error: 'setclose: that pubkey is not a member of this home' };
        if (typeof on !== 'boolean') return { error: 'setclose takes a pubkey, as npub or hex, and true or false' };
        members.get(pk)!.close = on; return { result: true };
      }
      case 'unallowpubkey': {
        if (!staff) return { status: 401, error: 'not allowed' };
        const [pk, opt] = params; const invitees = opt?.invitees ?? 'keep';
        const m = members.get(pk);
        if (!m) return { error: 'unallowpubkey: not a member' };
        const sub = below(pk);
        if (role === 'admin' && m.role === 'admin') return { error: 'unallowpubkey: that member is an admin, and only the owner can remove an admin' };
        if (role === 'admin' && invitees === 'remove' && sub.some((k) => members.get(k)?.role === 'admin')) return { error: 'unallowpubkey: someone they invited is an admin, and only the owner can remove an admin' };
        if (invitees === 'remove') { for (const k of sub) drop(k); drop(pk); return { result: true }; }
        for (const k of [...members.values()].filter((x) => x.invitedBy === pk)) k.invitedBy = o.owner;
        drop(pk); return { result: true };
      }
      case 'allowpubkey': {
        if (!staff) return { status: 401, error: 'not allowed' };
        const [pk] = params;
        const i = removed.findIndex((r) => r.pubkey === pk); if (i >= 0) removed.splice(i, 1);
        members.set(pk, { pubkey: pk, invitedBy: by, joinedAt: Math.floor(Date.now() / 1000), source: 'member', role: 'member', close: true });
        return { result: true };
      }
      case 'getstorage': return role === 'owner' ? { result: storage } : { status: 401, error: 'not allowed' };
      case 'setstorage': {
        if (role !== 'owner') return { status: 401, error: 'not allowed' };
        const [u, pk] = params;
        if (u === '') { storage = null; return { result: true }; }
        if (typeof u !== 'string' || !/^https?:\/\//.test(u)) return { error: 'setstorage takes the storage server\'s https URL and its pubkey; "" as the URL clears both' };
        if (!/^[0-9a-f]{64}$/.test(pk ?? '')) return { error: 'setstorage: the second parameter is the storage service\'s pubkey, as npub or hex' };
        storage = { url: u, pubkey: pk }; return { result: true };
      }
      default: return { error: `unknown method ${method}` };
    }
  }

  const server = createServer(async (req, res) => {
    if (req.method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }
    if (req.method === 'GET') {
      return send(res, 200, { name: o.name ?? 'The Herbst home', pubkey: o.owner, software: 'bothy', ...(storage ? { storage: { url: storage.url } } : {}) }, 'application/nostr+json');
    }
    const text = await body(req);
    const who = nip98(req, url, text);
    if ('bad' in who) return send(res, 401, { error: `auth: ${who.bad}` });
    let j: any; try { j = JSON.parse(text); } catch { return send(res, 400, { error: 'bad json' }); }
    calls.push({ method: j.method, params: j.params, by: who.pubkey });
    const r = run(who.pubkey, j.method, j.params ?? []);
    return send(res, r.status ?? 200, 'result' in r ? { result: r.result } : { error: r.error });
  });
  // The home is also a relay: a websocket here is passed to a real test relay, for names and photos (kind 0).
  server.on('upgrade', (req, sock, head) => {
    if (!o.relayPort) return sock.destroy();
    const up = connect(o.relayPort, '127.0.0.1', () => {
      up.write(`${req.method} / HTTP/1.1\r\n` + Object.entries(req.headers).map(([k, v]) => `${k}: ${v}`).join('\r\n') + '\r\n\r\n');
      if (head.length) up.write(head);
      sock.pipe(up).pipe(sock);
    });
    up.on('error', () => sock.destroy()); sock.on('error', () => up.destroy());
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  url = `http://127.0.0.1:${(server.address() as any).port}/`;
  return { url, members, removed, calls, get storage() { return storage; }, set storage(v) { storage = v; }, close: () => new Promise<void>((r) => { server.close(() => r()); server.closeAllConnections(); }) };
}

type Blob = { sha256: string; size: number; type: string; owners: Set<string>; charged: string | null; binnedAt: number | null };
export async function fakeStorage(o: { owner: string; admins?: string[]; home: string; key?: string; blobs?: { sha256: string; size: number; owner: string; binned?: boolean }[]; parked?: any[]; disk?: { used: number; free: number } }) {
  const key = o.key ?? 'c'.repeat(64);
  const blobs = new Map<string, Blob>();
  for (const b of o.blobs ?? []) blobs.set(b.sha256, { sha256: b.sha256, size: b.size, type: 'image/jpeg', owners: b.binned ? new Set() : new Set([b.owner]), charged: b.owner, binnedAt: b.binned ? Math.floor(Date.now() / 1000) - 86400 : null });
  const calls: { method: string; params: any[]; by: string }[] = [];
  let base = '';
  const staff = (pk: string) => pk === o.owner || (o.admins ?? []).includes(pk);
  const hashes = (p: any) => (Array.isArray(p?.[0]) && p[0].length >= 1 && p[0].length <= 500 && p[0].every((x: any) => /^[0-9a-f]{64}$/.test(x)) ? p[0] as string[] : null);
  function run(by: string, method: string, params: any[]): { result?: unknown; error?: string; status?: number } {
    const no = { status: 401, error: 'this key may not manage this box' };
    if (!staff(by)) return no;
    switch (method) {
      case 'usage': {
        const acc = new Map<string, { used: number; blobs: number }>();
        for (const b of blobs.values()) if (b.charged) { const a = acc.get(b.charged) ?? { used: 0, blobs: 0 }; a.used += Math.max(4096, b.size); a.blobs++; acc.set(b.charged, a); }
        const total = [...acc.values()].reduce((s, a) => ({ bytes: s.bytes + a.used, blobs: s.blobs + a.blobs }), { bytes: 0, blobs: 0 });
        return { result: { disk: o.disk ?? { used: 40e9, free: 960e9 }, total, accounts: [...acc].map(([pubkey, a]) => ({ pubkey, ...a, quota: pubkey === o.owner ? null : 5e9, member: true, hand: false })) } };
      }
      case 'bin':
        return { result: { items: [...blobs.values()].filter((b) => b.binnedAt).map((b) => ({ sha256: b.sha256, size: b.size, type: b.type, charged: b.charged, binnedAt: b.binnedAt, erasesAt: b.binnedAt! + 30 * 86400 })), more: false, parked: o.parked ?? [] } };
      case 'restore': {
        const h = hashes(params); if (!h) return { error: 'restore takes an array of 1 to 500 sha256' };
        let n = 0; for (const s of h) { const b = blobs.get(s); if (b?.binnedAt && b.charged) { b.binnedAt = null; b.owners.add(b.charged); n++; } }
        return { result: { restored: n } };
      }
      case 'erase': {
        if (by !== o.owner) return no;
        const h = hashes(params); if (!h) return { error: 'erase takes an array of 1 to 500 sha256' };
        let n = 0; for (const s of h) if (blobs.delete(s)) n++;          // any file, like the box's own erase command
        return { result: { erased: n } };
      }
      default: return { error: `unknown method ${method}` };
    }
  }
  const server = createServer(async (req, res) => {
    const path = new URL(req.url ?? '/', 'http://x').pathname;
    if (req.method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }
    if (req.method === 'GET' && path === '/manage/info') return send(res, 200, { result: { pubkey: key, home: o.home } });
    if (req.method === 'POST' && path === '/manage' && req.headers['content-type'] !== 'application/nostr+json+rpc') return send(res, 415, { error: 'content type' });
    if (req.method !== 'POST' || path !== '/manage') return send(res, 404, { error: 'not found' });
    const text = await body(req);
    const who = nip98(req, base + '/manage', text);
    if ('bad' in who) return send(res, 401, { error: `auth: ${who.bad}` });
    const j = JSON.parse(text);
    calls.push({ method: j.method, params: j.params, by: who.pubkey });
    const r = run(who.pubkey, j.method, j.params ?? []);
    return send(res, r.status ?? 200, 'result' in r ? { result: r.result } : { error: r.error });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as any).port}`;
  return { url: base, key, blobs, calls, close: () => new Promise<void>((r) => { server.close(() => r()); server.closeAllConnections(); }) };
}
