// Runs the Kotlin core's tests (android/app/src/test) against real boxes.
//
//   node tools/kotlin-test.ts           start two boxes and a relay, run the tests, print the results, stop
//   node tools/kotlin-test.ts --env     start them and print the environment instead, for running gradle by hand
//
// Every Kotlin test that makes an account gets its own setup code (an approved request), so the tests do not
// depend on the order they run in. The relay is `nak serve`; without nak the site-signer test is skipped.
// Needs Java 17 and the FROST library built for this computer:
//   cd frost && cargo build --release --features jni

import { mkdtempSync, readdirSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { v2 as nip44 } from 'nostr-tools/nip44';
import { startBox } from '../box/server.ts';
import { bytesToHex, randomBytes } from '../src/bytes.ts';

const root = join(import.meta.dirname, '..');
if (!existsSync(join(root, 'frost/target/release/libkeykin_frost.dylib'))) {
  console.error('Build the FROST library first: cd frost && cargo build --release --features jni'); process.exit(1);
}
const box = async () => startBox({ dir: mkdtempSync(join(tmpdir(), 'kk-kotlin-')), port: 0, sidePort: 0, log: () => {} });
const [a, b] = [await box(), await box()];
const addr = (x: { port: number }) => `http://127.0.0.1:${x.port}`;
const now = () => Math.floor(Date.now() / 1000);
const code = (x: typeof a) => x.box.newSetupCode(addr(x), now());

let relay: ReturnType<typeof spawn> | null = null, relayUrl = '';
if (spawnSync('which', ['nak']).status === 0) {
  const port = 20000 + Math.floor(Math.random() * 20000);
  relay = spawn('nak', ['serve', '--hostname', '127.0.0.1', '--port', String(port)], { stdio: 'ignore' });
  relayUrl = `ws://127.0.0.1:${port}`;
  for (let k = 0; k < 50; k++) {
    try { const w = new WebSocket(relayUrl); await new Promise((ok, no) => { w.onopen = ok; w.onerror = no; }); w.close(); break; }
    catch { await new Promise((r) => setTimeout(r, 100)); }
  }
}

// A NIP-44 test vector from nostr-tools, for the Kotlin implementation to match.
const convKey = randomBytes(32), nonce = randomBytes(32), plain = 'Keykin é😀 ' + bytesToHex(randomBytes(8));
const env: Record<string, string> = {
  KEYKIN_BOX_QR: code(a),
  KEYKIN_BOX_MANY: `${code(a)}|${addr({ port: a.sidePort! })}/page`,
  KEYKIN_BOX_IMPORT: code(a),
  KEYKIN_BOX_TRANSFER: `${code(a)}|${code(b)}`,
  KEYKIN_BOX_SITE: relayUrl ? `${code(a)}|${relayUrl}` : '',
  KEYKIN_NIP44_VECTOR: `${bytesToHex(convKey)}|${bytesToHex(nonce)}|${plain}|${nip44.encrypt(plain, convKey, nonce)}`,
};
const stop = async () => { relay?.kill(); await a.close(); await b.close(); };

if (process.argv.includes('--env')) {
  for (const [k, v] of Object.entries(env)) console.log(`export ${k}='${v}'`);
  console.log('# Running. Ctrl-C stops the boxes and the relay.');
  process.on('SIGINT', () => stop().then(() => process.exit(0)));
} else {
  const javaHome = spawnSync('/usr/libexec/java_home', ['-v', '17'], { encoding: 'utf8' }).stdout.trim();
  const gradle = spawn('./gradlew', [':app:testDebugUnitTest', '--console=plain', '-q'], { cwd: join(root, 'android'), stdio: 'inherit', env: { ...process.env, ...env, ...(javaHome ? { JAVA_HOME: javaHome } : {}) } });
  const status: number = await new Promise((done) => gradle.on('exit', (c) => done(c ?? 1)));
  await stop();
  const dir = join(root, 'android/app/build/test-results/testDebugUnitTest');
  let tests = 0, failed = 0, skipped = 0;
  for (const f of existsSync(dir) ? readdirSync(dir).filter((n) => n.endsWith('.xml')) : []) {
    const head = /<testsuite [^>]*>/.exec(readFileSync(join(dir, f), 'utf8'))?.[0] ?? '';
    const n = (k: string) => Number(new RegExp(`${k}="(\\d+)"`).exec(head)?.[1] ?? 0);
    tests += n('tests'); failed += n('failures') + n('errors'); skipped += n('skipped');
  }
  console.log(`Kotlin: ${tests} tests, ${tests - failed - skipped} passed, ${failed} failed, ${skipped} skipped`);
  process.exit(status);
}
