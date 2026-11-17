// Bundles the QRST library (../qr-secret-transfer, the protocol core and its relay layer) into
// vendor/qrst.js, so Keykin carries a fixed copy and Node can load it without a TypeScript step.
//   node tools/build-qrst.mjs [path to qr-secret-transfer]
import { build } from 'esbuild';
import { writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

const here = import.meta.dirname, src = process.argv[2] ?? join(here, '../../qr-secret-transfer');
const entry = join(here, '../vendor/.qrst-entry.ts');
writeFileSync(entry, `export * from ${JSON.stringify(join(src, 'src/core/index.ts'))};\nexport * from ${JSON.stringify(join(src, 'src/web/index.ts'))};\n`);
const commit = execFileSync('git', ['-C', src, 'rev-parse', '--short', 'HEAD'], { encoding: 'utf8' }).trim();
await build({ entryPoints: [entry], bundle: true, format: 'esm', platform: 'neutral', target: 'es2022', mainFields: ['module', 'main'], conditions: ['import', 'default'],
  outfile: join(here, '../vendor/qrst.js'), banner: { js: `// QRST (qr-secret-transfer) at commit ${commit}. Built by tools/build-qrst.mjs. Do not edit.` }, logLevel: 'warning' });
console.log('vendor/qrst.js from', src, 'at', commit);
