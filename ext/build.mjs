// Builds the extension into ext/dist. Load that folder in Chrome with "Load unpacked".
//   node ext/build.mjs
import { build } from 'esbuild';
import { cpSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';

const here = import.meta.dirname, src = join(here, 'src'), out = join(here, 'dist');
rmSync(out, { recursive: true, force: true }); mkdirSync(out, { recursive: true });
const noNode = { name: 'no-node', setup(b) { b.onResolve({ filter: /^node:/ }, (a) => ({ errors: [{ text: `${a.path} imported by ${a.importer}: a browser has no Node modules` }] })); } };
const common = { bundle: true, platform: 'browser', target: 'es2022', plugins: [noNode], logLevel: 'warning' };
await build({ ...common, format: 'esm', entryPoints: [join(src, 'background.ts'), join(src, 'popup.ts'), join(src, 'approve.ts')], outdir: out });
await build({ ...common, format: 'iife', entryPoints: [join(src, 'inject.ts'), join(src, 'content.ts')], outdir: out });
for (const f of ['popup.html', 'approve.html', 'ui.css']) cpSync(join(src, f), join(out, f));
cpSync(join(here, 'manifest.json'), join(out, 'manifest.json'));
cpSync(join(here, '../frost-wasm-web/keykin_frost_bg.wasm'), join(out, 'keykin_frost_bg.wasm'));
console.log('built', out);
