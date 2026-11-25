// Copying a shared folder of this repo into an app, and checking the copy later. Used by signin-copy.mjs and
// calendar-copy.mjs. A copy gets a SOURCE file: "keykin <commit>", then "<sha256>  <path>" per file, so an edit
// made in the app shows. A folder that has files and no SOURCE is left alone.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, copyFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');

const sha = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');
function files(root, dir = root) {
  const out = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...files(root, p));
    else out.push(relative(root, p).split(sep).join('/'));
  }
  return out;
}
function commit(from, label) {
  try {
    const head = execFileSync('git', ['-C', repo, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
    const dirty = execFileSync('git', ['-C', repo, 'status', '--porcelain', '--', from], { encoding: 'utf8' }).trim();
    return head + (dirty ? ` (with uncommitted changes in ${label})` : '');
  } catch { return 'unknown'; }
}
function readSource(dest) {
  const p = join(dest, 'SOURCE');
  if (!existsSync(p)) return null;
  const lines = readFileSync(p, 'utf8').split('\n').filter(Boolean);
  const list = new Map();
  for (const l of lines.slice(1)) { const m = /^([0-9a-f]{64})  (.+)$/.exec(l); if (m) list.set(m[2], m[1]); }
  return { commit: (lines[0] || '').replace(/^keykin /, ''), list };
}

/** Copies the folder `from` (absolute) to `dest`, replacing an earlier copy. `label` names it in messages. */
export function copy(from, dest, label) {
  const old = readSource(dest);
  if (!old && existsSync(dest) && readdirSync(dest).length) throw new Error(`${dest} has files and no SOURCE: not a copy of ${label}, left alone`);
  for (const f of old?.list.keys() ?? []) rmSync(join(dest, f), { force: true });
  const list = files(from);
  for (const f of list) { mkdirSync(dirname(join(dest, f)), { recursive: true }); copyFileSync(join(from, f), join(dest, f)); }
  const at = commit(from, label);
  writeFileSync(join(dest, 'SOURCE'), `keykin ${at}\n` + list.map((f) => `${sha(join(dest, f))}  ${f}\n`).join(''));
  console.log(`copied ${list.length} files to ${dest} (keykin ${at})`);
}

/** 0 when `dest` is an unedited copy of `from` as it is now; else 1, naming the files. */
export function check(from, dest, label) {
  const src = readSource(dest);
  if (!src) { console.error(`${dest}: no SOURCE, so not a copy made by this tool`); return 1; }
  const problems = [];
  const have = existsSync(dest) ? files(dest).filter((f) => f !== 'SOURCE') : [];
  for (const [f, want] of src.list) {
    const p = join(dest, f);
    if (!existsSync(p)) problems.push(`missing from the copy: ${f}`);
    else if (sha(p) !== want) problems.push(`edited in the copy: ${f}`);
  }
  for (const f of have) if (!src.list.has(f)) problems.push(`added to the copy: ${f}`);
  const here = files(from);
  for (const f of here) {
    if (!src.list.has(f)) problems.push(`not in the copy, new in this checkout: ${f}`);
    else if (sha(join(from, f)) !== src.list.get(f)) problems.push(`differs from this checkout: ${f}`);
  }
  for (const f of src.list.keys()) if (!here.includes(f)) problems.push(`gone from this checkout: ${f}`);
  if (problems.length) {
    console.error(`${dest} (from keykin ${src.commit}):\n` + problems.map((p) => '  ' + p).join('\n'));
    return 1;
  }
  console.log(`${dest}: the same as this checkout's ${label} (${src.list.size} files, from keykin ${src.commit})`);
  return 0;
}
