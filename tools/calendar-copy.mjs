#!/usr/bin/env node
// An app's copy of the shared calendar module, and a check that it is still the same. Each part goes to its own folder:
//
//   node tools/calendar-copy.mjs js <dest folder>        calendar/js/ (calendar.js, sha256.js), for a web app or Node
//   node tools/calendar-copy.mjs kotlin <dest folder>    calendar/kotlin/ (Calendar.kt), into an Android source tree
//   node tools/calendar-copy.mjs vectors <dest folder>   calendar/vectors/ (the shared cases), for an app's own tests
//   node tools/calendar-copy.mjs --check <part> <dest>   exits 1, naming the files, if the copy was edited or differs
//
// SOURCE holds the Keykin commit the copy came from and a sha256 per file. Edit here, then copy again.
import { join, resolve } from 'node:path';
import { repo, copy, check } from './module-copy.mjs';

const PARTS = ['js', 'kotlin', 'vectors'];
const usage = 'usage: node tools/calendar-copy.mjs <js|kotlin|vectors> <dest folder>\n       node tools/calendar-copy.mjs --check <js|kotlin|vectors> <dest folder>';
const args = process.argv.slice(2);
const checking = args[0] === '--check';
const [part, dest] = checking ? args.slice(1) : args;
try {
  if (args.length !== (checking ? 3 : 2) || !PARTS.includes(part)) { console.error(usage); process.exitCode = 2; }
  else {
    const from = join(repo, 'calendar', part), label = `calendar/${part}/`;
    if (checking) process.exitCode = check(from, resolve(dest), label);
    else copy(from, resolve(dest), label);
  }
} catch (err) { console.error(String(err?.message || err)); process.exitCode = 1; }
