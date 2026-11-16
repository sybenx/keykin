// The Nostr event id (NIP-01), computed from the event itself so a helper never signs a bare hash.

import { shaHex, refuse } from './bytes.ts';

export interface UnsignedEvent { pubkey: string; created_at: number; kind: number; tags: string[][]; content: string }

export function eventId(e: UnsignedEvent): string {
  if (typeof e?.pubkey !== 'string' || !/^[0-9a-f]{64}$/.test(e.pubkey)) refuse('bad_event', 'pubkey');
  if (!Number.isInteger(e.created_at) || !Number.isInteger(e.kind)) refuse('bad_event', 'created_at or kind');
  if (typeof e.content !== 'string') refuse('bad_event', 'content');
  if (!Array.isArray(e.tags) || !e.tags.every((t) => Array.isArray(t) && t.every((v) => typeof v === 'string'))) refuse('bad_event', 'tags');
  return shaHex(JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content]));
}
