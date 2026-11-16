// The box as a process: one HTTP endpoint and one state file.
//   KEYKIN_DIR   where state.json lives (default ./box-data)
//   KEYKIN_ADDR  address to listen on (default 127.0.0.1; use the tailnet address to be reachable)
//   KEYKIN_PORT  port (default 7460)
// Until it has an account it prints what its QR says; the first device scans that.

import { createServer } from 'node:http';
import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Box, type BoxState } from './box.ts';

export function startBox(o: { dir: string; addr?: string; port?: number; log?: (s: string) => void }) {
  const log = o.log ?? console.log;
  mkdirSync(o.dir, { recursive: true, mode: 0o700 });
  const file = join(o.dir, 'state.json');
  const state: BoxState | null = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : null;
  const box = new Box(state);
  const save = (s: BoxState) => { writeFileSync(file + '.tmp', JSON.stringify(s, null, 2), { mode: 0o600 }); renameSync(file + '.tmp', file); };
  box.onChange = save;
  if (!state) save(box.state);          // keep the box's own member key across restarts
  const where = () => `http://${o.addr ?? '127.0.0.1'}:${(server.address() as any).port}`;

  const server = createServer((req, res) => {
    const reply = (status: number, body: unknown) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
    if (req.method === 'GET' && req.url === '/') {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      return res.end(`Keykin box. ${box.state.account ? 'Set up.' : 'Not set up.'} The login page is not built yet.\n`);
    }
    if (req.method !== 'POST' || req.url !== '/keykin') return reply(404, { error: 'not_found' });
    const chunks: Buffer[] = []; let size = 0;
    req.on('data', (c: Buffer) => { size += c.length; if (size > 256 * 1024) req.destroy(); else chunks.push(c); });
    req.on('end', () => {
      let parsed: any;
      try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return reply(400, { error: 'bad_json' }); }
      try { reply(200, box.handle(parsed, Math.floor(Date.now() / 1000))); }
      catch (e) { log(`keykin box: ${String(e)}`); reply(500, { error: 'internal' }); }
    });
  });
  return new Promise<{ server: typeof server; box: Box; port: number; qr: () => string | null }>((resolve) => {
    server.listen(o.port ?? 7460, o.addr ?? '127.0.0.1', () => {
      const port = (server.address() as any).port;
      log(`keykin box: listening on ${o.addr ?? '127.0.0.1'}:${port}`);
      if (!box.state.account) log(`keykin box: no account yet. QR: ${box.qr(where())}`);
      resolve({ server, box, port, qr: () => box.qr(where()) });
    });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startBox({ dir: process.env.KEYKIN_DIR ?? './box-data', addr: process.env.KEYKIN_ADDR, port: Number(process.env.KEYKIN_PORT ?? 7460) });
}
