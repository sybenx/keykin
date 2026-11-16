// Runs in the page: gives sites `window.nostr` (NIP-07). Each call is passed to the extension and
// answered there; nothing secret is ever in the page.
(() => {
  let n = 0;
  const waiting = new Map<number, { ok: (v: unknown) => void; no: (e: Error) => void }>();
  window.addEventListener('message', (e) => {
    if (e.source !== window || e.data?.keykin !== 'answer') return;
    const w = waiting.get(e.data.id); if (!w) return;
    waiting.delete(e.data.id);
    if (e.data.error) w.no(new Error(e.data.error)); else w.ok(e.data.result);
  });
  const ask = (method: string, params: unknown[] = []) => new Promise((ok, no) => {
    const id = ++n; waiting.set(id, { ok, no });
    window.postMessage({ keykin: 'ask', id, method, params }, window.location.origin);
  });
  (window as any).nostr = {
    getPublicKey: () => ask('getPublicKey'),
    signEvent: (event: unknown) => ask('signEvent', [event]),
    nip44: {
      encrypt: (peer: string, text: string) => ask('nip44.encrypt', [peer, text]),
      decrypt: (peer: string, payload: string) => ask('nip44.decrypt', [peer, payload]),
    },
  };
})();
