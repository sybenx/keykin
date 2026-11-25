#!/usr/bin/env node
// A site's copy of signin/ (the shared name-first sign-in), and a check that it is still the same.
//
//   node tools/signin-copy.mjs <dest folder>           copies signin/ there and writes <dest>/SOURCE
//   node tools/signin-copy.mjs --check <dest folder>   exits 1, naming the files, if the copy was edited or differs
//                                                      from this checkout
//
// SOURCE holds the Keykin commit the copy came from and a sha256 per file, so an edit in the site shows.
import { join, resolve } from 'node:path';
import { repo, copy, check } from './module-copy.mjs';

const from = join(repo, 'signin');
const args = process.argv.slice(2);
try {
  if (args[0] === '--check' && args.length === 2) process.exitCode = check(from, resolve(args[1]), 'signin/');
  else if (args.length === 1 && !args[0].startsWith('-')) copy(from, resolve(args[0]), 'signin/');
  else { console.error('usage: node tools/signin-copy.mjs <dest folder>\n       node tools/signin-copy.mjs --check <dest folder>'); process.exitCode = 2; }
} catch (err) { console.error(String(err?.message || err)); process.exitCode = 1; }
