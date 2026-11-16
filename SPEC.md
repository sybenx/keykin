# Keykin v2

Draft 0.2, 2026-11-16. The direction and the reasons are in `DIRECTION.md`. This file says what
the code does. It replaces Keykin Core draft 14.26 (weights, seats, paper, helper), which stays
in the `cosign` repo's history.

## 1. Pieces

- The key is a secp256k1 Nostr key, split on a line `f(x) = a0 + a1·x`. `a0` is the nsec, in
  the form whose public key has even y (BIP-340).
- A **piece** is `f(i)` for an index `i ≥ 1`. Every device holds one piece. Every box holds one.
- **Any two pieces sign.** One piece alone can do nothing.
- The **commitment** is `[a0·G, a1·G]`. The npub is the x of `a0·G`.
- Indices only go up and are never reused. The first device is 1 and the box is 2.
- The account has an **epoch**, starting at 0. It goes up each time the keys are cycled (section 8f).

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
| `members` | Any unblocked member | No | Returns the list, the epoch and the next unused index |
| `cycle` | An unblocked device | **Yes** | Moves every piece to a new line and drops blocked members (section 8f) |
| `caught_up` | Any unblocked member | No | Says it has applied the changes left for it |
| `address` | Any unblocked member | No | Says where this device listens for other devices (section 8g) |
| `login` | An unblocked device | **Yes** | Logs a browser in to the box's page (section 6a) |
| `block` | Any unblocked member | No | Blocks a device. One press |
| `unblock` | An unblocked device | **Yes** | Unblocks a device |
| `add` | An unblocked device | **Yes** | Adds a device or a box, and makes the box's half of its piece |
| `welcome_put` | The device that did the `add` | No | Leaves the device's half for the newcomer |
| `welcome` | The newcomer | No | Collects both halves |
| `reveal` | An unblocked device | **Yes** | Hands the box's piece to that device, sealed |

A blocked member is refused everything. A box cannot be blocked through this endpoint and a box
may not ask for a signature.

`sign`, `ecdh`, `add`, `reveal` and `cycle` carry the device's `epoch`. If it is behind, the box
answers `stale` with the changes that device missed, and the device applies them and asks again.

**The box owner can block and unblock any device** from the box's page (section 6a). This is the way back when a thief with an unlocked phone blocks every other device
first: the owner blocks the phone and unblocks the rest. A stolen phone could always do that,
and the box is what recovers from it.

## 6a. The box's page

What the person who runs the box sees in a browser, at the box's address. Plain HTML from the
box itself, nothing loaded from elsewhere.

- **Log in by scanning.** Once there is an account, the login page shows a code:
  `{ keykin: 2, login: { addr, key, code } }`. A device in the account scans it and, after a
  fingerprint, sends `login` with the code. The page, which has been asking the box whether its
  code was approved, is then logged in. A code lasts three minutes, works once, and only for the
  browser that was shown it. A device accepts a login code only from its own box.
- **Or log in** with the owner secret. This is the only way before an account exists, and the
  way back if every device is lost or blocked. The box prints it once, on its first start, and keeps only
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

## 8e. The Android app

`android/` is the phone. Kotlin, with the same Rust FROST library as everything else and
libsecp256k1 for the member key.

- **Start:** scan the box's code (or paste it) to make an account, or show this phone's invite
  to join one.
- **Home:** the npub, the devices with Block and Unblock, Add a device, a test signature, and
  Form the whole key.
- **The chip key is real here.** A P-256 key in the Android Keystore that needs a strong
  fingerprint or face for every signature and is thrown away if new fingerprints are enrolled.
  Add a device, Unblock and Form the whole key each show the system fingerprint prompt, and the
  box checks the result.
- **A phone with no fingerprint set up has no chip key.** It signs, and cannot make account
  changes. (A debug build makes a key that asks for nothing instead, for emulators.)
- **Saved state** is one file in the app's no-backup folder, encrypted with a Keystore key.
- A debug build also accepts codes as text through an intent, since an emulator has no camera
  to point at a screen.

## 8f. Cycling the keys

After a block, the blocked device still holds a piece that fits with everyone else's. Cycling
ends that. It needs the fingerprint.

1. The asking device picks one random number `b1`. Every piece moves by `b1 · i`, which is a new
   line through the same key: the nsec and the npub do not change.
2. It sends `cycle` with `b1` sealed to the box and, for every other unblocked member, that
   member's `b1 · i` sealed to it.
3. The box moves its own piece, replaces the commitment's second point with `C1 + b1·G`, raises
   the epoch, and drops every blocked member from the list.
4. The others pick up their change the next time they ask for something (`stale`), check the
   new piece against the new commitment, and say `caught_up`.

A blocked member gets no change, so its old piece no longer fits with anyone's. A newcomer that
has not collected its piece yet holds up a cycle (`pending_welcome`), so it is never stranded.
Whoever picks `b1` learns nothing about the key from it.

## 8g. When the box is off

Any two pieces sign, so a device that can listen (a computer that stays on) can answer the
others. `keykin serve <port> <address>` does this: it tells the box its address with `address`,
keeps the list it last saw at the box, and answers `sign` and `ecdh` for unblocked devices at the
same epoch. Other devices keep those addresses and try them when the box cannot be reached. Only
signing and message keys work this way. Everything else needs the box.

A block made while the box is off does not reach a helper until the box is back.

## 8h. The browser extension

`ext/` makes a Chromium browser a device and gives pages `window.nostr` (NIP-07):
`getPublicKey`, `signEvent`, `nip44.encrypt`, `nip44.decrypt`.

- Set up by pasting the box's code, or by showing this browser's invite and pasting the join text.
- Each site is asked about once, in a small window. After Allow it is answered with no further
  questions until it is signed out in the extension's window.
- **A browser has no chip key.** So it cannot add devices, unblock, cycle or form the whole key.
  Those are done from a phone.
- Its piece is kept in the browser's extension storage, not encrypted.

## 8i. Other apps on the phone (NIP-55)

The Android app answers `nostrsigner:` requests: `get_public_key`, `sign_event`, `nip44_encrypt`,
`nip44_decrypt`. An app asks on a screen with Allow once, Always allow and Deny. An app that is
always allowed is answered silently through the content provider, and can be signed out on the
app's home screen.

## 9. Not built yet

- **The QRST protocol itself for the box's page.** Logging in by scanning with a device is
  built (section 6a), but it is Keykin's own exchange with the box, not the QRST protocol.
- **Resetting a lost owner secret.** Today: stop the box, delete the `owner` line from
  `state.json`, start it, and read the new secret from its output.
- **Proof that a chip key lives in a chip.** The Android app's key does, but the box takes the
  public key on trust. iOS (Secure Enclave) is not written.
- **The remote signer (NIP-46) in the Android app.** The command-line device has it. On the
  phone, other apps use NIP-55 and sites in a desktop browser use the extension.
- **A phone or a browser helping when the box is off.** Only the command-line device listens.
- **The camera scan on a real phone.** The scanner is wired in but was only exercised through
  pasted and intent-fed codes on an emulator.
- **Importing an existing nsec.** It would put a raw nsec on a device, which section 2 rules
  out. The splitting code exists and only tests use it.
- **NIP-04** (old-style messages) and the other NIP-46 methods.
- **Per-site limits.** A site that is allowed can ask for any signature.
- **Removing a box.** A device is removed by blocking it and cycling; a box cannot be blocked.
- **Firefox and Safari.** The extension is Chromium only.
- **Release builds.** The Android app is a debug build and the extension is unpacked.
- **Tier 3.** Not planned for now.

## 10. Known weak spots

- A thief who can pass the fingerprint check on a stolen phone can form the nsec.
- Logging in to the box's page by scanning trusts the person to scan only their own box's page.
  A device refuses a code from any other box, but a code shown by someone else's browser on the
  same box would log that browser in.
- A device that listens for others trusts the list it last saw. If the box is off, it cannot
  learn of a new block.
- The box's piece sits in its state file unencrypted.
- Requests travel as plain HTTP. The address is meant to be a tailnet one. Secrets inside
  requests are sealed (section 5), so an open network would expose the member list and the
  events being signed, not pieces.
