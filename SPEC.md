# Keykin v2

Draft 0.1, 2026-11-16. The direction and the reasons are in `DIRECTION.md`. This file says what
the code does. It replaces Keykin Core draft 14.26 (weights, seats, paper, helper), which stays
in the `cosign` repo's history.

## 1. Pieces

- The key is a secp256k1 Nostr key. It is split on a line `f(x) = a0 + a1·x`, where `a0` is the
  nsec, negated if needed so the public key has even y (BIP-340).
- A **piece** is `f(i)` for an index `i ≥ 1`. Every device holds one piece. Every box holds one.
- **Any two pieces sign.** One piece alone can do nothing.
- The **commitment** is `[a0·G, a1·G]`. The npub is the x of `a0·G`.
- Indices are handed out in order and never reused.

## 2. The primary device

- The first device makes the nsec or imports one, and splits it. It keeps `a0` and `a1`, so it
  can hand out a piece at any new index.
- It keeps the whole nsec as the tier 1 QRST backup until the person chooses to forget it.
  After that, new pieces need two existing pieces to help (not built).

## 3. Signing

FROST (FROST-secp256k1-SHA256-TR, the Zcash Foundation crate) between two pieces. One round trip.

1. The asking device computes the event id from the event (NIP-01), makes fresh nonces and sends
   its commitment with the whole event.
2. The helper recomputes the id from the event, makes its own nonces, and replies with its
   commitment and its partial signature.
3. The asker checks the partial, adds its own, and has an ordinary BIP-340 signature.

A helper never signs a bare hash. Nonces are made per request and used once.

## 4. Member keys and requests

- Every piece holder has a **member key** (secp256k1, x-only), separate from its piece.
- A request is `{ body, key, sig }`. `sig` is BIP-340 by `key` over `SHA-256(JCS(body))`.
- `body.ts` is unix seconds and must be within 60 s. `body.id` is random and is refused twice.

## 5. The box

One always-on machine. It holds one piece and the list of members: `{ key, i, name, kind,
blocked, added }`, with `kind` either `device` or `box`. It never starts a signature.

One endpoint, `POST /keykin`, taking a request and answering `{ ok: true, … }` or `{ error }`.

| `op` | From | Does |
|---|---|---|
| `setup` | The first device, with the setup code the box printed | Stores the commitment, the box's piece and the first two members. Once only |
| `sign` | An unblocked device | Answers a signing round for an event of this account |
| `members` | Any unblocked member | Returns the list |
| `block` | Any unblocked member | Blocks a device. One press |
| `unblock` | Another unblocked device | Unblocks a device |
| `add` | An unblocked device | Adds a device or a box to the list |

A blocked member is refused everything. A box cannot be blocked through this endpoint and a box
may not ask for a signature.

## 6. Not built yet

- **The login page** and its QRST login, with the device list and Block buttons. The box has
  the owner's block function ready for it.
- **The fingerprint (chip key) check** on `add` and `unblock`. Today a device's member key is
  enough for both, which is weaker than `DIRECTION.md` requires.
- **Devices refusing to help a blocked device.** Devices can read the list from the box, but
  device-to-device transport is not written.
- **Cycling the keys** after a block, so the blocked piece is worthless.
- **Encryption and decryption** (NIP-44, NIP-04) with two pieces.
- **Apps:** Android, the browser extension, NIP-46, NIP-07, NIP-55.
- **Tier 3.** Not planned for now.

## 7. Known weak spots

- A thief with an unlocked phone can block every other device before the owner blocks the
  phone. The owner then needs the box's login page to undo it.
- Requests travel as plain HTTP. The address is meant to be a tailnet one. Nothing in a request
  is secret except the piece sent once in `setup`, which must not cross an open network.
