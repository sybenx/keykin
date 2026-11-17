// The box page signs in the way any site does: it shows a QRST code, a device in the account answers
// it, and the account's signature on the box's challenge logs the browser in. Real Chromium, real relay.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir, homedir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { startBox } from '../box/server.ts';
import { main } from '../cli/keykin.ts';

const relayTool = process.env.QRST_REPO ? join(process.env.QRST_REPO, 'tools/test-relay.mjs') : join(homedir(), 'qr-secret-transfer/tools/test-relay.mjs');
function chromium(): string | null {
  if (process.env.KEYKIN_CHROMIUM) return process.env.KEYKIN_CHROMIUM;
  const cache = join(homedir(), 'Library/Caches/ms-playwright');
  if (!existsSync(cache)) return null;
  for (const d of readdirSync(cache).filter((n) => /^chromium-\d+$/.test(n)).sort().reverse()) {
    try { const p = execFileSync('find', [join(cache, d), '-maxdepth', '5', '-type', 'f', '-perm', '+111', '-path', '*MacOS*'], { encoding: 'utf8' }).split('\n')[0]; if (p) return p; } catch {}
  }
  return null;
}
const exe = chromium();
const tmp = (n: string) => mkdtempSync(join(tmpdir(), n));
async function cli(home: string, ...argv: string[]) { const lines: string[] = []; const r = await main(argv, (s) => lines.push(s), home); return { text: lines.join('\n'), run: r as any }; }

test('the box page: sign in by a scanned code, and only this box’s account gets in',
  { skip: (!exe && 'no Chromium found') || (!existsSync(relayTool) && 'the qr-secret-transfer repo is not beside this one'), timeout: 90_000 }, async () => {
  execFileSync('node', ['tools/build-site.mjs'], { stdio: 'ignore' });
  const { chromium: pw } = await import('playwright-core');
  const relay = await (await import(relayTool)).startRelay({});
  const b = await startBox({ dir: tmp('kk-box-'), port: 0, relays: [relay.url], log: () => {} });
  const other = await startBox({ dir: tmp('kk-box-'), port: 0, log: () => {} });        // somebody else's box and account
  const browser = await pw.launch({ executablePath: exe!, headless: true });
  const bunkers: any[] = [];
  try {
    const [mine, theirs] = [tmp('kk-mine-'), tmp('kk-theirs-')];
    await cli(mine, 'create', b.qr()!, 'MacBook');
    await cli(theirs, 'create', other.qr()!, 'Stranger');
    bunkers.push((await cli(mine, 'bunker', relay.url)).run, (await cli(theirs, 'bunker', relay.url)).run);
    const base = `http://localhost:${b.port}`;

    // A stranger's signer answers the code: the sign-in itself works, but the box refuses the account.
    const p1 = await (await browser.newContext()).newPage();
    await p1.goto(base + '/');
    await p1.waitForSelector('#kk-uri', { state: 'attached' });
    assert.match((await p1.textContent('body'))!, /Sign in with your signer/);
    const stranger = cli(theirs, 'scan', (await p1.textContent('#kk-uri'))!, '--yes');
    await p1.waitForSelector('#kk-yes');
    assert.match((await p1.textContent('#kk-asking'))!, /^Sign in as [0-9a-f]{8}…, through your signer/);
    await p1.click('#kk-yes');
    await stranger;
    await p1.waitForSelector('text=That is not this box’s account.');

    // The account's own device: the browser ends up logged in, on the device list.
    const p2 = await (await browser.newContext()).newPage();
    await p2.goto(base + '/');
    await p2.waitForSelector('#kk-uri', { state: 'attached' });
    const me = cli(mine, 'scan', (await p2.textContent('#kk-uri'))!, '--yes');
    await p2.waitForSelector('#kk-yes');
    await p2.click('#kk-yes');
    await me;
    await p2.waitForSelector('text=Devices');
    assert.match((await p2.textContent('body'))!, /MacBook/);
    assert.match((await cli(mine, 'sites')).text, new RegExp(base.replace(/[.]/g, '\\.')));

    // Cancelling on the page signs nobody in.
    const p3 = await (await browser.newContext()).newPage();
    await p3.goto(base + '/');
    await p3.waitForSelector('#kk-uri', { state: 'attached' });
    const again = cli(mine, 'scan', (await p3.textContent('#kk-uri'))!, '--yes').catch((e) => e.message);
    await p3.waitForSelector('#kk-no');
    await p3.click('#kk-no');
    await p3.waitForSelector('text=Cancelled.');
    assert.match(await again, /did not take the sign-in/);
    assert.match((await p3.textContent('body'))!, /Or use the owner secret/);
  } finally {
    for (const k of bunkers) k?.close();
    await browser.close();
    for (const x of [b, other]) await new Promise((done) => { x.server.close(done); x.server.closeAllConnections(); });
    await relay.close();
  }
});
