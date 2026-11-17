// The few signatures that are hard to undo. Signing one needs the person to tap Yes on a device
// (Aaron, 2026-11-17). The device asks; the box refuses such an event unless the device says it asked.

import type { UnsignedEvent } from './event.ts';

/** Why an event is hard to undo, in a few words, or null if it is ordinary. */
export function destructive(e: UnsignedEvent): string | null {
  if (e.kind === 62) return 'asks every relay to erase the whole account';
  if (e.kind === 5 && e.tags.filter((t) => t[0] === 'e' || t[0] === 'a').length >= 5) return 'deletes five or more posts at once';
  if (e.kind === 3 && !e.tags.some((t) => t[0] === 'p')) return 'empties the follow list';
  if (e.kind === 0) {
    let p: any; try { p = JSON.parse(e.content); } catch { p = null; }
    if (!p || typeof p !== 'object' || !['name', 'display_name', 'about', 'picture', 'nip05', 'lud16'].some((k) => typeof p[k] === 'string' && p[k].trim())) return 'empties the profile';
  }
  return null;
}
