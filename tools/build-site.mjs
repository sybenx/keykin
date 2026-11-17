// Builds the browser side of sign-in by code:
//   box/static/signin.js   the box page's login (site/box-login.ts)
//   site/dist/keykin-signin.js   the widget for any site, as window.KeykinSignIn (site/signin.ts)
import { build } from 'esbuild';
import { join } from 'node:path';
const here = import.meta.dirname, root = join(here, '..');
const noNode = { name: 'no-node', setup(b) { b.onResolve({ filter: /^node:/ }, (a) => ({ errors: [{ text: `${a.path} imported by ${a.importer}: a browser has no Node modules` }] })); } };
const common = { bundle: true, platform: 'browser', target: 'es2022', format: 'iife', plugins: [noNode], logLevel: 'warning', minify: true };
await build({ ...common, entryPoints: [join(root, 'site/box-login.ts')], outfile: join(root, 'box/static/signin.js') });
await build({ ...common, entryPoints: [join(root, 'site/signin.ts')], globalName: 'KeykinSignIn', outfile: join(root, 'site/dist/keykin-signin.js') });
console.log('built box/static/signin.js and site/dist/keykin-signin.js');
