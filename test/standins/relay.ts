// A local relay for a test: `nak serve` on 127.0.0.1 and a free port, as the other tests here start one. Nothing
// leaves this machine. Use:
//
//   import { hasNak, startRelay } from './standins/relay.ts';
//   test('…', { skip: !hasNak && 'nak is not installed' }, async () => {
//     const relay = await startRelay();
//     try { /* relay.url is ws://127.0.0.1:<port> */ } finally { await relay.stop(); }
//   });
//
// stop() kills it and waits until it has exited.
import { spawn, execFileSync, type ChildProcess } from 'node:child_process';

export let hasNak = false;
try { execFileSync('which', ['nak'], { stdio: 'ignore' }); hasNak = true; } catch {}

export type LocalRelay = { url: string; stop: () => Promise<void> };

function stopped(proc: ChildProcess): Promise<void> {
  if (proc.exitCode !== null || proc.signalCode !== null) return Promise.resolve();
  return new Promise((done) => {
    const t = setTimeout(() => proc.kill('SIGKILL'), 3000);
    proc.once('exit', () => { clearTimeout(t); done(); });
    proc.kill();
  });
}

async function answers(url: string): Promise<boolean> {
  try {
    const ws = new WebSocket(url);
    await new Promise((ok, no) => { ws.onopen = ok; ws.onerror = no; });
    ws.close();
    return true;
  } catch { return false; }
}

export async function startRelay(): Promise<LocalRelay> {
  for (let tries = 0; tries < 5; tries++) {
    const port = 20000 + Math.floor(Math.random() * 20000);
    const proc = spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', String(port)], { stdio: 'ignore' });
    const url = `ws://127.0.0.1:${port}`;
    for (let i = 0; i < 50 && proc.exitCode === null; i++) {
      if (await answers(url)) return { url, stop: () => stopped(proc) };
      await new Promise((r) => setTimeout(r, 100));
    }
    await stopped(proc);
  }
  throw new Error('nak serve did not start');
}
