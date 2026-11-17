// A command-line device's saved state: one file, readable only by its owner.

import { mkdirSync, readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import { softwareChip, newMemberKey } from '../src/member.ts';
import { commitmentFrom, commitmentHex, scalarFrom, scalarHex } from '../src/curve.ts';
import type { Me, Held, Send } from '../src/device.ts';
import type { BunkerState } from '../src/nip46.ts';

export interface Saved {
  me: { sk: string; key: string; name: string; chip: string; chipSk: string };
  addr?: string;
  held?: { commitment: string[]; i: number; share: string; npub: string; boxKey: string; epoch?: number };
  bunker?: BunkerState;
  /** The whole key (hex), kept as a backup after `import` until the person runs `forget-key`. */
  nsec?: string;
  /** The device list as last seen at the box, for when the box is off. */
  list?: { key: string; i: number; name: string; kind: string; blocked: boolean; addr?: string }[];
}

export function load(file: string, name = 'This computer'): Saved {
  if (existsSync(file)) return JSON.parse(readFileSync(file, 'utf8'));
  const c = softwareChip();
  return { me: { ...newMemberKey(), name, chip: c.chip, chipSk: c.chipSk } };
}
export function save(file: string, s: Saved) {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(file + '.tmp', JSON.stringify(s, null, 2), { mode: 0o600 });
  renameSync(file + '.tmp', file);
}
// The fingerprint here is the easy kind: a software key in the state file, no prompt (SPEC §4).
export const meOf = (s: Saved): Me => ({ sk: s.me.sk, key: s.me.key, name: s.me.name, chip: s.me.chip, fp: softwareChip(s.me.chipSk).fp });
export const heldOf = (s: Saved): Held => {
  if (!s.held) throw new Error('This device is not in an account yet. Run create or join.');
  const C = commitmentFrom(s.held.commitment);
  return { piece: { C, i: s.held.i, share: scalarFrom(s.held.share) }, npub: s.held.npub, boxKey: s.held.boxKey, epoch: s.held.epoch ?? 0 };
};
export const keep = (s: Saved, h: Held, addr: string) => {
  s.addr = addr;
  s.held = { commitment: commitmentHex(h.piece.C), i: h.piece.i, share: scalarHex(h.piece.share), npub: h.npub, boxKey: h.boxKey, epoch: h.epoch };
};
export const sender = (addr: string): Send => async (r) =>
  (await fetch(`${addr}/keykin`, { method: 'POST', body: JSON.stringify(r), headers: { connection: 'close' }, signal: AbortSignal.timeout(6000) })).json();
