// A device's side of signing with a helper. `send` carries a signed request to the helper and
// returns its reply; over HTTP, a tailnet or a test bus, this file does not care.

import { ask, finish, type Piece } from './round.ts';
import { eventId, type UnsignedEvent } from './event.ts';
import { seal, type Signed } from './member.ts';
import { refuse } from './bytes.ts';

export type Send = (req: Signed) => Promise<any>;

export async function signEvent(p: Piece, sk: string, ev: UnsignedEvent, send: Send, now: number) {
  const id = eventId(ev);
  const mine = ask(p, id);
  const r = await send(seal({ op: 'sign', event: ev, commit: mine.commit }, sk, now));
  if (r?.error) refuse(r.error);
  if (r?.id !== id) refuse('wrong_id');
  return { ...ev, id, sig: finish(p, id, mine, { commit: r.commit, z: r.z }) };
}
