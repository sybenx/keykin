# Keykin v2

Draft 0.1, 2026-11-16. The direction and the reasons are in `DIRECTION.md`. This file says what
the code does. It replaces Keykin Core draft 14.26 (weights, seats, paper, helper), which stays
in the `cosign` repo's history.

## 1. Pieces

- The key is a secp256k1 Nostr key, split on a line `f(x) = a0 + a1·x`. `a0` is the nsec, in
  the form whose public key has even y (BIP-340).
- A **piece** is `f(i)` for an index `i ≥ 1`. Every device holds one piece. Every box holds one.
- **Any two pieces sign.** One piece alone can do nothing.
- The **commitment** is `[a0·G, a1·G]`. The npub is the x of `a0·G`.
- Indices only go up and are never reused. The first device is 1 and the box is 2.

## 2. Creating the account

**The nsec is never raw on any device.** Nobody generates it. The first device and the box
make their pieces together (FROST distributed key generation, two parties, threshold two).

1. An empty box shows a QR: `{ keykin: 2, addr, key, code }`. `key` is the box's member key and
   `code` is a one-time setup code, new each time the box starts.
2. The device scans it and sends `create1` with the code, its part-1 package, its name and its
   chip key. The box answers with its own part-1 package.
3. The device sends `create2` with its part-2 package, sealed to the box (section 5). The box
   finishes, stores the account, and answers with its part-2 package, sealed to the device.
4. The device finishes and checks it got the npub the box reported.

A device that was shown the wrong box key cannot finish, because it cannot open the box's
sealed package.

## 3. Signing

FROST (FROST-secp256k1-SHA256-TR, the Zcash Foundation crate) between two pieces. One round trip.

1. The asking device computes the event id from the event (NIP-01), makes fresh nonces and sends
   its commitment with the whole event.
2. The helper recomputes the id from the event, makes its own nonces, and replies with its
   commitment and its partial signature.
3. The asker checks the partial, adds its own, and has an ordinary BIP-340 signature.

A helper never signs a bare hash. Nonces are made per request and used once.

## 4. Member keys, requests and the fingerprint

- Every piece holder has a **member key** (secp256k1, x-only), separate from its piece.
- A request is `{ body, key, sig }`. `sig` is BIP-340 by `key` over `SHA-256(JCS(body))`.
- `body.ts` is unix seconds and must be within 60 s. `body.id` is random and is refused twice.
- A device may have a **chip key**: a P-256 key in the phone's secure chip that signs only
  after a fingerprint or face check. Its public key is on the member list.
- An **account change** also carries `fp`: an ECDSA (SHA-256) signature by the asker's chip key
  over the same `JCS(body)`. Without a valid one the box answers `needs_fingerprint`. A device
  with no chip key gets `no_chip_key` and cannot make account changes.
- **Fallback (Aaron, 2026-11-16).** Where this checked fingerprint hits a blocker (a platform
  whose chip cannot do it, the browser extension, a device with no chip), that spot may use the
  easy kind instead: the app shows a fingerprint prompt and then proceeds, with nothing the box
  can verify. Spots using the easy kind:
  - **The command-line device** (`cli/`). Its chip key is a software key in its state file, and
    nothing prompts. The box still checks the signature, so the rule that a device with no chip
    key cannot make account changes holds; what is missing is the fingerprint itself.

## 5. Sealed values

The few secrets that cross the wire are sealed between two member keys: ECDH on the member
keys, `SHA-256("keykin2-seal" ‖ x)` as the key, XChaCha20-Poly1305 with a random 24-byte nonce,
and the purpose (`keygen`, `repair-delta`, `repair-sigma`, `reveal`) as associated data.

## 6. The box

One always-on machine. It holds one piece and the list of members: `{ key, i, name, kind, chip,
blocked, added }`, with `kind` either `device` or `box`. It never starts a signature.

One endpoint, `POST /keykin`, taking a request and answering `{ ok: true, … }` or `{ error }`.

| `op` | From | Fingerprint | Does |
|---|---|---|---|
| `create1`, `create2` | The first device, with the code from the QR | No | Makes the key with the device. Once only |
| `sign` | An unblocked device | No | Answers a signing round for an event of this account |
| `ecdh` | An unblocked device | No | The box's part of a shared secret with another person's key (section 8a) |
| `members` | Any unblocked member | No | Returns the list |
| `block` | Any unblocked member | No | Blocks a device. One press |
| `unblock` | An unblocked device | **Yes** | Unblocks a device |
| `add` | An unblocked device | **Yes** | Adds a device or a box, and makes the box's half of its piece |
| `welcome_put` | The device that did the `add` | No | Leaves the device's half for the newcomer |
| `welcome` | The newcomer | No | Collects both halves |
| `reveal` | An unblocked device | **Yes** | Hands the box's piece to that device, sealed |

A blocked member is refused everything. A box cannot be blocked through this endpoint and a box
may not ask for a signature.

**The box owner can block and unblock any device** from the box's page (section 6a). This is the way back when a thief with an unlocked phone blocks every other device
first: the owner blocks the phone and unblocks the rest. A stolen phone could always do that,
and the box is what recovers from it.

## 6a. The box's page

What the person who runs the box sees in a browser, at the box's address. Plain HTML from the
box itself, nothing loaded from elsewhere.

- **Log in** with the owner secret. The box prints it once, on its first start, and keeps only
  its hash. Five wrong tries in a minute are refused for the rest of that minute. A session lasts
  12 hours, in a cookie scripts cannot read.
- **No account yet:** the setup QR of section 2, with the same text available to copy for a
  device with no camera. The QR names the address the browser used. The page moves on by itself
  once a device has created the account.
- **With an account:** the npub and the list of devices, each with Block or Unblock. The box
  itself has no button. Every button carries a per-session token.

## 7. Adding a member

The key is never whole here either. The asking device and the box each hold a piece. Using
FROST's share repair, each computes a half of the piece for the new index. The box's half
waits at the box, sealed to the newcomer. The device's half follows with `welcome_put`. The
newcomer opens both, adds them, and checks the result against the commitment and against the
npub it was told. The halves are dropped once the newcomer has signed.

## 8. Falling back to the nsec

With a fingerprint, `reveal` hands the box's piece to the asking device. That device forms the
nsec from its own piece and the box's. This is the only place a whole key ever exists, and it
exists only on the device that asked.

## 8a. Messages

Encrypting and decrypting (NIP-44) needs a shared secret between the account's key and another
person's key `Q`. Two pieces make it without the key being whole: each gives `λ_i · s_i · Q`,
and the two parts add up to `nsec · Q`. The device asks the box for its part with `ecdh`, adds
its own, and derives the NIP-44 v2 conversation key. A wrong part from the box cannot forge a
message; the NIP-44 check fails instead. The box does not see messages, only whose key they are
with.

## 8b. A new device learning where the box is

Three short texts, shown as QRs or pasted:

1. The new device shows an **invite**: `{ keykin: 2, invite: { key, name, chip } }`.
2. A device in the account adds it (section 7) and shows the **join text**:
   `{ keykin: 2, join: { addr, boxKey, npub } }`.
3. The new device reads that, collects its two halves from the box, and checks the npub.

## 8c. Signing in to sites (NIP-46)

A device can run a remote signer ("bunker"). It has its own key for talking to sites, separate
from the account. The link is `bunker://<bunker key>?relay=<relay>&secret=<secret>`.

- `connect` with the secret adds the site to the device's list. After that the site's requests
  are answered with no prompt (tier 2).
- Answered: `ping`, `get_public_key`, `sign_event`, `nip44_encrypt`, `nip44_decrypt`. Anything
  else gets `unsupported`.
- Every signature and every shared secret still goes through the box, so blocking the device
  stops every site it serves.
- The relay is whichever one the device is told to use. A site must be able to reach it.

## 8d. The command-line device

`cli/keykin.ts` makes a computer a device: `create`, `invite`, `add`, `join`, `status`, `sign`,
`block`, `unblock`, `bunker`, `nsec`. Its state is one file, `~/.keykin/device.json`, readable
only by its owner. The piece in it is not encrypted.

## 9. Not built yet

- **QRST login to the box's page.** `DIRECTION.md` says login is by QRST. Today it is an owner
  secret typed into the page. QRST runs over relays and needs the phone app to take part, so it
  is a later step; the page is built so that only the login form changes.
- **Resetting a lost owner secret.** Today: stop the box, delete the `owner` line from
  `state.json`, start it, and read the new secret from its output.
- **A real chip.** The box-side check is built and tested with a software P-256 key standing in.
  The Android Keystore and Secure Enclave side is not written, and nothing proves to the box
  that a chip key really lives in a chip.
- **Devices refusing to help a blocked device.** Devices can read the list from the box, but
  device-to-device transport is not written.
- **Cycling the keys** after a block, so the blocked piece is worthless.
- **Importing an existing nsec.** It would put a raw nsec on a device, which section 2 rules
  out. The splitting code exists and only tests use it.
- **NIP-04** (old-style messages) and the other NIP-46 methods.
- **Per-site limits and a way to sign a site out** of the remote signer.
- **Removing a device or a box from the list.** Blocking is the only way to stop one.
- **Apps:** Android (with NIP-55) and the browser extension (with NIP-07).
- **Tier 3.** Not planned for now.

## 10. Known weak spots

- A thief who can pass the fingerprint check on a stolen phone can form the nsec.
- The box's piece sits in its state file unencrypted.
- Requests travel as plain HTTP. The address is meant to be a tailnet one. Secrets inside
  requests are sealed (section 5), so an open network would expose the member list and the
  events being signed, not pieces.
