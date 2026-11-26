// A stand-in for the sign-in app on someone's phone (a NIP-46 remote signer), with a throwaway account, talking over
// a local relay only. Ported from ~/archive/signin/test/signer-sim.mjs, run in the test's own process (no child
// process to leave behind). It answers a nostrconnect:// code, or gives a bunker:// link and answers that, then
// answers get_public_key, sign_event, nip44_encrypt and nip44_decrypt as a real one does. Use:
//
//   import { standInPhone } from './standins/phone.ts';
//   const phone = standInPhone();                      // answers everything
//   await phone.answerCode(code);                      // the code the page shows (data-code of "Copy the code")
//   const link = await phone.bunker(relay.url);        // or a bunker link to paste
//   ...
//   await phone.stop();                                // always, in a finally
//
// Told otherwise:
//   standInPhone({ refuse: 'Not now' })                // every request answered with that error
//   standInPhone({ silent: true })                     // never answers anything (not even a code)
//   standInPhone({ approveFirst: true })               // the first request is answered with auth_url: a page on
//                                                      // 127.0.0.1 run here; opening it (GET) sends the real answer
//   standInPhone({ approveFirst: { url: 'javascript:alert(1)', answerAfter: 1500 } })
//                                                      // that address as the auth_url, the real answer after 1.5 s
//   standInPhone({ approveFirst: { on: 'sign_event' } })
//                                                      // not the first request: the first one of that method
//
// phone.pubkey is the account, phone.asked the methods asked so far, phone.approvalUrl the local page once it runs.
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure';
import * as nip44 from 'nostr-tools/nip44';

export type PhoneOptions = {
  refuse?: string;
  silent?: boolean;
  approveFirst?: boolean | { url?: string; answerAfter?: number; on?: string };
  user?: Uint8Array;
};

export function standInPhone(opts: PhoneOptions = {}) {
  const user = opts.user ?? generateSecretKey(), signer = generateSecretKey();
  const signerPk = getPublicKey(signer);
  const asked: string[] = [];
  const sockets: WebSocket[] = [];
  const heard = new Set<WebSocket>(); // connections a request came in on
  const timers = new Set<ReturnType<typeof setTimeout>>();
  const waitingApproval = new Map<string, () => void>(); // request id → send its real answer
  let server: Server | null = null, approvalBase = '';
  let secret = '', approvalAsked = false, stoppedNow = false;

  const later = (fn: () => void, ms: number) => { const t = setTimeout(() => { timers.delete(t); fn(); }, ms); timers.add(t); return t; };
  const now = () => Math.floor(Date.now() / 1000);
  const send = (ws: WebSocket, to: string, body: object) => {
    if (stoppedNow || ws.readyState !== WebSocket.OPEN) return;
    const content = nip44.v2.encrypt(JSON.stringify(body), nip44.v2.utils.getConversationKey(signer, to));
    ws.send(JSON.stringify(['EVENT', finalizeEvent({ kind: 24133, created_at: now(), tags: [['p', to]], content }, signer)]));
  };

  async function approvalPage(): Promise<string> {
    if (server) return approvalBase;
    server = createServer((req, res) => {
      const id = new URL(req.url!, 'http://x').pathname.split('/').pop()!;
      const answer = waitingApproval.get(id);
      waitingApproval.delete(id);
      answer?.();
      res.writeHead(answer ? 200 : 404, { 'content-type': 'text/html' }).end(`<!doctype html><title>Approve</title><p>${answer ? 'Approved. You can close this tab.' : 'Nothing to approve.'}</p>`);
    });
    await new Promise<void>((ok) => server!.listen(0, '127.0.0.1', ok));
    approvalBase = `http://127.0.0.1:${(server.address() as AddressInfo).port}/approve/`;
    return approvalBase;
  }

  function answer(req: { id: string; method: string; params: any[] }): object {
    if (opts.refuse) return { id: req.id, error: opts.refuse };
    const p = req.params || [];
    switch (req.method) {
      case 'connect': return !secret || p[1] === secret ? { id: req.id, result: 'ack' } : { id: req.id, error: 'bad secret' };
      case 'get_public_key': return { id: req.id, result: getPublicKey(user) };
      case 'sign_event': return { id: req.id, result: JSON.stringify(finalizeEvent(JSON.parse(p[0]), user)) };
      case 'nip44_encrypt': return { id: req.id, result: nip44.v2.encrypt(p[1], nip44.v2.utils.getConversationKey(user, p[0])) };
      case 'nip44_decrypt': return { id: req.id, result: nip44.v2.decrypt(p[1], nip44.v2.utils.getConversationKey(user, p[0])) };
      default: return { id: req.id, result: 'ack' };
    }
  }

  async function onRequest(ws: WebSocket, from: string, req: { id: string; method: string; params: any[] }) {
    asked.push(req.method);
    if (opts.silent) return;
    const real = () => send(ws, from, answer(req));
    const a = typeof opts.approveFirst === 'object' ? opts.approveFirst : {};
    if (opts.approveFirst && !approvalAsked && (!a.on || a.on === req.method)) {
      approvalAsked = true;
      const url = a.url ?? (await approvalPage()) + req.id;
      if (!a.url) waitingApproval.set(req.id, real);
      send(ws, from, { id: req.id, result: 'auth_url', error: url });
      if (a.answerAfter !== undefined) later(real, a.answerAfter);
      return;
    }
    real();
  }

  /** Connects to the relay and listens for requests to this signer; onOpen runs once it is connected. */
  function connect(relay: string, onOpen: (ws: WebSocket) => void): Promise<WebSocket> {
    return new Promise((ok, no) => {
      const ws = new WebSocket(relay);
      sockets.push(ws);
      const seen = new Set<string>();
      ws.onerror = () => no(new Error('stand-in phone: no relay at ' + relay));
      ws.onopen = () => {
        // (no since: the relay keeps none of these, and a page whose clock a test moved may be behind or ahead)
        ws.send(JSON.stringify(['REQ', 'phone', { kinds: [24133], '#p': [signerPk] }]));
        onOpen(ws);
        ok(ws);
      };
      ws.onmessage = (m) => {
        const d = JSON.parse(String(m.data));
        if (d[0] !== 'EVENT' || seen.has(d[2]?.id)) return;
        seen.add(d[2].id);
        heard.add(ws);
        let req;
        try { req = JSON.parse(nip44.v2.decrypt(d[2].content, nip44.v2.utils.getConversationKey(signer, d[2].pubkey))); } catch { return; }
        onRequest(ws, d[2].pubkey, req);
      };
    });
  }

  return {
    pubkey: getPublicKey(user),
    signerPubkey: signerPk,
    asked,
    get approvalUrl() { return approvalBase || null; },
    /**
     * Answers a nostrconnect:// code: says its secret back from this signer. Kind 24133 is not kept by relays, so it
     * says it again each second until the page asks something (a real phone is seconds behind anyway).
     */
    async answerCode(uri: string) {
      const u = new URL(uri.replace(/^nostrconnect:\/\//, 'http://'));
      const client = u.hostname, relay = u.searchParams.get('relay')!;
      secret = u.searchParams.get('secret') || '';
      await connect(relay, (ws) => {
        if (opts.silent) return;
        const hello = () => { if (!heard.has(ws) && !stoppedNow) { send(ws, client, { id: 'hello' + Date.now(), result: secret }); later(hello, 1000); } };
        hello();
      });
    },
    /** Listens on the relay as a bunker and gives its link (the secret is checked on connect). */
    async bunker(relay: string, s = 's3cret') {
      secret = s;
      await connect(relay, () => {});
      return `bunker://${signerPk}?relay=${encodeURIComponent(relay)}&secret=${s}`;
    },
    async stop() {
      stoppedNow = true;
      for (const t of timers) clearTimeout(t);
      timers.clear();
      for (const ws of sockets) try { ws.close(); } catch {}
      if (server) { server.closeAllConnections?.(); await new Promise((ok) => server!.close(() => ok(null))); }
    },
  };
}
export type StandInPhone = ReturnType<typeof standInPhone>;
