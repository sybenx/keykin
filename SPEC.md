# Keykin v2

Draft 0.11, 2026-11-17. The direction and the reasons are in `DIRECTION.md`. This file says what
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

### Bringing in a key the person already has

The other way to start an account, for someone who already has an nsec (Aaron, 2026-11-17).

1. The device takes the nsec, in its even-y form, as `a0`, picks a random `a1`, and so has the
   line. Its own piece is `f(1)` and the box's is `f(2)`.
2. It sends `{ op: "import", request, commitment: [a0·G, a1·G], share, name, chip }`, where
   `share` is `f(2)` sealed to the box with the purpose `import`, and `request` is a setup code
   or an approved request as for `create1`.
3. The box checks that the piece lies on that line, refuses a key it already holds
   (`already_here`), and stores the account. The npub is the one the nsec always had.
4. **The device keeps the whole nsec**, encrypted at rest, as the tier 1 backup. It is how the
   account comes back if the pieces are lost, and it can still be moved to another device by
   QRST. Signing uses the pieces from then on.
5. **Forgetting the nsec is the person's choice**, made on that device ("Forget the whole key on
   this phone", `keykin forget-key`). No code forgets it otherwise.

"The nsec is never raw on any device" (section 2) is about keys made together with the box. A
key that was brought in already exists, and its owner holds it.

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
- **A signature that is never done by accident** (level 2, section 11.6, The tap) carries `fp` the same
  way, checked the same way (Aaron, 2026-11-20). Without a valid one the box answers `needs_fingerprint`,
  now with `why`, the question in plain words; a device with no chip key gets `no_chip_key` with `why`.
  With a box, such a phone cannot sign a level 2 event, as it cannot make account changes. `tapped`
  alone never signs one.
- **Fallback (Aaron, 2026-11-16).** Where this checked fingerprint hits a blocker (a platform
  whose chip cannot do it, the browser extension, a device with no chip), that spot may use the
  easy kind instead: the app shows a fingerprint prompt and then proceeds, with nothing the box
  can verify. Spots using the easy kind:
  - **The command-line device** (`cli/`). Its chip key is a software key in its state file, and
    nothing prompts. The box still checks the signature, so the rule that a device with no chip
    key cannot make account changes holds; what is missing is the fingerprint itself. It never sends
    `fp` with `sign`, though it could: level 2 is the phone's (section 11.6).
  - **Marble on Android with no box in the signature** (the whole key on the phone, or another device
    helping while the box is off, section 8g). At level 2 it shows the phone's own fingerprint prompt
    and then signs, as it does before showing the whole key. A phone with no fingerprint set up has no
    prompt to show, so it asks Yes or No only: a box is an upgrade, never a burden.

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
| `sign` | An unblocked device | Level 2 only | Answers a signing round for an event of this account, or of one of its child keys (section 8k). A hard-to-undo event needs `tapped`, and one that is never done by accident the fingerprint (section 11.6, The tap) |
| `ecdh` | An unblocked device | No | The box's part of a shared secret with another person's key (section 8a), as the account or as a child key |
| `members` | Any unblocked member | No | Returns the list, the epoch, the next unused index, and `password` (true when the account has a username and password, section 11.3) |
| `cycle` | An unblocked device | **Yes** | Moves every piece to a new line and drops blocked members (section 8f) |
| `caught_up` | Any unblocked member | No | Says it has applied the changes left for it |
| `address` | Any unblocked member | No | Says where this device listens for other devices (section 8g) |
| `login` | An unblocked device | **Yes** | Logs a browser in to the box's page (section 6a) |
| `block` | Any unblocked member | No | Blocks a device, or another box in the account. One press |
| `unblock` | An unblocked device | **Yes** | Unblocks a device |
| `add` | An unblocked device | **Yes** | Adds a device or a box, and makes the box's half of its piece |
| `welcome_put` | The device that did the `add` | No | Leaves the device's half for the newcomer |
| `welcome` | The newcomer | No | Collects both halves |
| `reveal` | An unblocked device | **Yes** | Hands the box's piece to that device, sealed |
| `grants`, `revoke`, `limit` | Any unblocked member | No | What is signed in, and ending or limiting it (section 11.5) |

A blocked member is refused everything. A box may not ask for a signature.

**The list store.** To judge a change to a list, the box keeps the latest version it signed of
each kept list (section 11.6, The tap). It lives in `lists/` beside `state.json`, never inside it,
since the box rewrites the whole state file on every change. One file per account per list:
`lists/<account hex>/<kind>.json` for a replaceable list, `lists/<account hex>/<kind>-<first 32 hex
of SHA-256 of the d tag>.json` for a named set. Each is
`{ "key": "<kind>" or "<kind>:<d>", "at": <when the box kept it>, "event": { id, pubkey, created_at, kind, tags, content } }`,
written to a temporary file and renamed, and only when that list changes: when the box answers a
`sign` for a newer version (an equal `created_at` replaces, the same id does nothing). The box never
sees the finished signature, only the event it helped sign. Events dated ahead and child keys'
lists are not kept. Removing an account deletes its folder; at start the box deletes the folders of
accounts it no longer holds. A box from before the list store just has none yet, and compares from
the next version it signs.

**The soft cap.** Named sets (kinds 30000 to 39999, one per `d` tag) are kept up to a number per
account, 200 by default, set on the admin page or by `KEYKIN_KEPT_SETS` (which wins). The number is
a first proposal. Past it, the least recently changed set is dropped, and the box says so in the
account's activity ("Your bookmark set "reading" is no longer compared before signing: this box
keeps the 200 most recently changed sets") and lists it under `uncompared` in
`lists/<account hex>/sets.json`, which also holds when each kept set last changed. Over the cap never
refuses a signature: that set is simply not compared until it is signed again, when it is kept as
the newest. Replaceable lists are a fixed handful of kinds and have no cap.

**How much the box keeps** (2026-11-20). The box rewrites the whole state file on every change, so
nothing in it may grow without end. The people using a box are ones its admin knows, so the limits
guard against bugs and accidents, not strangers: they sit far above real use, the oldest goes first
where something can go, and none of them ever refuses a signature. The numbers are a first try.

| What | At most | Past it | Where |
|---|---|---|---|
| Devices and boxes in an account, blocked ones included | 50 (`MAX_MEMBERS`) | `add` is refused, `too_many_members`. Nothing is dropped | Section 7 |
| Accounts on an open box, from the account page | 500, set on the admin page or by `KEYKIN_OPEN_ACCOUNTS` | `protect` is refused, `box_full` | Section 11.6 |
| Setup codes made in advance and not used yet | 50 in all (`MAX_CODES`), one per account from `protect` | The oldest goes; a new `protect` code replaces that account's last | Section 11.4 |
| Waiting asks | 50 | `ask` is refused, `too_many` | Section 11.4 |
| Page sessions of one account | 100 | The least recently used is signed out, and the activity says so | Section 11.6 |
| Page sessions of accounts this box does not hold | 1000 in all (`MAX_UNHELD_SESSIONS`) | The least recently used goes | Section 11.6 |
| Passkeys of an account | 20 | `pk_add_start` is refused, `too_many` | Section 11.3 |
| Revoked grants, grants' last use, limits | 2000 each | The oldest goes; a grant's last kind goes with its last use | Section 11.5 |
| Browsers remembered for nostrconnect codes | 20, for 30 days | The oldest goes | Section 11.5 |
| Activity lines | 60 | The oldest goes | |
| Named sets the list store compares | 200, set on the admin page or by `KEYKIN_KEPT_SETS` | Not compared, never refused | The soft cap, above |

What a device that was removed left behind goes at the cycle that removed it (section 8f). The
changes waiting for a member that stays away (`catchups`) have no cap (section 8f). A state file from
before these limits loads as it is: what is pruned is brought under its limit the next time one is
added (a code, a session), a removed device's grants and stray last kinds go at load, and members and
accounts over their limit all stay, with nothing more taken in until there is room.

**Removing a box.** An account can hold a second box, as a backup. Any member can block it like a
device, and cycling the keys afterwards (section 8f) drops it for good. The box answering a request
cannot be blocked through it (`cannot_block_box`), whoever asks: the admin, the account page or a
device.

`sign`, `ecdh`, `add`, `reveal` and `cycle` carry the device's `epoch`. If it is behind, the box
answers `stale` with the changes that device missed, and the device applies them and asks again.

**The box owner can block and unblock any device** from the box's page (section 6a). This is the way back when a thief with an unlocked phone blocks every other device
first: the owner blocks the phone and unblocks the rest. A stolen phone could always do that,
and the box is what recovers from it.

## 6a. The admin page

What the person who runs the box sees, at the box's main port. Plain HTML from the box itself.
It is never on the public side.

- **Getting in:** the owner secret, which the box prints once on its first start and also
  leaves in `owner-secret.txt`. Or, **behind another login** (`KEYKIN_BEHIND_LOGIN=1`), nothing:
  the page trusts whoever got through, and the box makes no owner secret. Use that only when the
  page cannot be reached any other way, such as behind an Umbrel app's login.
- **An empty box** shows the first setup code straight away.
- **Waiting requests** (section 11.4), each with Approve and Refuse.
- **Every account:** its npub, its username if it has one, and its devices and boxes with Block
  and Unblock. Every row has a button except this box's own. Unblock here needs no device: it is
  the admin's own power, and the way back when a thief blocks every other device first.
- **Remove an account**, behind a tick box. It deletes the box's piece.
- **Make a setup code** for one new account: a request approved in advance, good for 24 hours.
- **Lists the box compares:** how many named sets the list store keeps per account (section 6,
  The soft cap). Shown, not editable, when `KEYKIN_KEPT_SETS` sets it.
- **Accounts from the account page**, on an open box only (`KEYKIN_OPEN=1`): how many accounts it may
  hold and still let one in by `protect` (section 11.6), 500 by default, and how many it holds now.
  Shown, not editable, when `KEYKIN_OPEN_ACCOUNTS` sets it.
- Every button carries a per-session token.

## 6b. Keykin Login and the side door

The box listens twice. The **main port** has the admin page plus `POST /keykin` and
`POST /page`. The **side port** (`KEYKIN_SIDE_PORT`) has only those two paths.

**Keykin Login** (`login/`) is a separate small server meant to face the internet. It serves the
account page and passes two things to the box's side port, and nothing else: `POST /keykin`
untouched, and `POST /api`, the account page's calls (section 11.6).

- It holds no piece, no device list and no account data. Stopping it shuts the outside door and
  leaves the box, the admin page and private devices working.
- It keeps the page session in a cookie the page's script cannot read, and never puts it in a
  reply. A session sent in a request body is ignored.
- `/api` needs a header only a page from the same origin can send, so another site cannot make
  the calls for someone.
- It allows a fixed list of calls (section 11.6). None hands over a key, a piece or a signature.
- It limits each address to 240 requests a minute.

The account page has six sections: Home, Devices, Signed in, Sign in to a site, Security and
Backup. Password sign-in needs the page to be served over `https`, because browsers only offer
the key-stretching it uses on secure pages. Device sign-in works either way.

## 7. Adding a member

The key is never whole here either. The asking device and the box each hold a piece. Using
FROST's share repair, each computes a half of the piece for the new index. The box's half
waits at the box, sealed to the newcomer. The device's half follows with `welcome_put`. The
newcomer opens both, adds them, and checks the result against the commitment and against the
npub it was told. The halves are dropped once the newcomer has signed.

**At most 50 members** (2026-11-20), devices and boxes, blocked ones and ones waiting for their approval
included. One more `add` is refused with `too_many_members` and the reason ("An account has at most 50
devices and boxes, blocked ones included. Removing blocked devices makes room."), before its index is
used. Nothing is dropped to make room: a blocked member's entry is what keeps it refused, at the box and
at a device that helps while the box is off (section 8g), until a cycle leaves its piece useless.
Cycling (section 8f) removes blocked members and makes room. A state file already over 50 keeps them all.

**A member added through the account page waits for its approval** (Aaron, 2026-11-19, after a red-team
finding: anyone could put their own invite in an `add=` link, and a person signed in to their page might
press Add). When the `add` names a page note (section 11.6), the box keeps a gate for the newcomer:
`{ note, at, challenge, code, short, until, tries }`. Its `welcome` then needs `code`, and also `verifier`
when the note carried a `challenge`:

- `code` is the long approval code (base64url of 18 random bytes) or the six digits. The box keeps only
  SHA-256 of each (of `"short:" + digits` for the six), compared in constant time.
- `verifier` must hash to the challenge: base64url(SHA-256(verifier)) = `challenge` (PKCE, S256).
- A wrong try counts. After 5 the newcomer is dropped from the list. It is dropped too 10 minutes after the
  codes were given (`until`), or 20 minutes after the add if the page never fetched them. Dropped means
  never added: its index is not used again, as always.
- Right: the gate goes (the codes work once), and the welcome is answered as before, now also with
  `boxKey`. A `welcome` with no `account` is taken for a gated member: the box finds the account by the
  member key, so an app that knows only the box (the six digits typed in, below) can still collect.
- Until then a gated member gets `not_approved` for every other op, so it cannot read or answer the
  account's notes, list the members, or sign.

A member added on a device by the fingerprint (a phone scanning a new device's code or invite, `keykin add`)
has no gate: nothing changes for it.

**Marble on Android signs in this way too** when no device of the account is at hand ("Use my name"): it
opens Marble Web with its invite, a PKCE challenge, a `state` and `return=https://marble.syb.lol/joined`,
and collects its piece with the code and its verifier as the Mac does.

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

**One code** (Aaron, 2026-11-19). The new device shows one code; a device in the account scans it and
decides what the newcomer gets, because only it knows how the account is set up. The code is the QRST
profile `keykin-device` (`qr-secret-transfer/profiles/keykin-device.md`), Flow A (`mode=offer`, the new
device is the Receiver), as an `https` link: Keykin's apps use `https://marble.syb.lol/add#…`, an App
Link to Marble. It carries one extra fragment parameter, `invite`, the new device's invite below,
base64url with no padding.

1. The new device shows the code and listens on its relays.
2. A device in the account reads it and asks **"Add *name*?"** (Add, Not now). On Add, with the
   fingerprint for an account change (section 4):
   - **The account has a box:** it adds the newcomer (section 7) and releases the **join text**. The
     newcomer collects its two halves from the box (`welcome`) and checks the npub.
   - **The account has no box** (the whole key lives on the adding device): it releases the **whole
     key**, and the newcomer keeps it as its own, the same as a QRST nsec transfer. The adding device
     keeps its own copy: nothing is forgotten.
   The rule is a box or not, never the person's choice and never the number of devices: a piece needs
   the box, which is one of the two helpers that make it.
3. The new device keeps what arrived with no second tap and is signed in, showing whose account it is.

The digits of QRST are compared only when the code was not read by the adding device's own camera (a
pasted link, the `qrst:` hand-off): then the adding device shows five digits and asks whether the new
device shows the same, and nothing is added until they match. A camera scan has no digits. Where this
departs from QRST section 9 (a short prompt, no second tap on the new device) is written in the profile.

**The texts**, unchanged and still accepted by the apps and the command line:

- An **invite**: `{ keykin: 2, invite: { key, name, chip } }`. `key` is the new device's member key.
- The **join text**: `{ keykin: 2, join: { addr, boxKey, npub, loginPage } }`. It holds no secret.
- The older way still works: the new device shows its invite, a device in the account adds it and shows
  the join text, and the new device reads that.

**Another app on the same phone** does not join. It signs through the app that is already in the
account, by NIP-55 (section 8i).

**Built (2026-11-19, branches `add-device`, not released):** the profile in qr-secret-transfer (spec, TypeScript,
Kotlin, vectors); here `src/adddevice.ts`, `keykin signin <relay>` and `keykin add '<code>'`, and the account
page's App Link return; Marble on Android (Welcome with Create your account and Sign in, the one code, Add with
the box or no-box rule, digits for a pasted code, Use my name) and Marble Web (`/add`, `/joined`, the App Link
return). Until qr-secret-transfer's main carries the profile, Keykin (`src/adddevice.ts`) and Marble
(`keykin/core/AddDevice.kt`) keep copies, tested against its vectors. Marble on the Mac and the browser extension
do not read the code yet.

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
- **A site that shows a code.** `nostrconnect://<site key>?relay=<relay>&secret=<secret>`, with
  optional `name` and `url`, and possibly several `relay`s. The signer lets the site's key in at once,
  as a grant named by the `url`'s origin (else `name`), listens on the code's relays as well as its
  own, and sends the answer the site waits for: a kind 24133 event to the site whose content is
  `{ id, result: <secret> }`, NIP-44 encrypted like any answer. At most five relays are used, `ws://`
  or `wss://`. A code with no relay, no secret or a site key that is not 64 hex is refused
  (`bad_code`).
- Each answer goes back on the relay its request came in on.
- Each site's requests name its grant (section 11.5). When the box answers `revoked`, the signer
  forgets the site and answers `not_connected` from then on.
- The signer cannot ask the person. An event the box asks about (section 11.6, The tap) gets the
  error `needs_tap: <why>`, and one it refuses `dated_ahead: <why>`, so the site can say why. One
  that is never done by accident (level 2) gets `needs_fingerprint: <why>. Do this from your phone.`
- **A site's name** (Aaron, 2026-11-19). A bunker `connect` says nothing of where the site runs, so
  the person may name the site when asking for the link ("Which site is it for?"). The link's secret
  is then a ticket (good once, for 15 minutes) that carries the name, and the site is listed by it.
  A site with no origin and no name takes one from the first `sign_event` it asks for that has a
  client tag (`["client", "<name>", ...]`, the second item). A name is cleaned (no control
  characters, trimmed, at most 60 characters; empty means none) and, once set, stays: the person's
  word wins over a client tag, and the first client tag over later ones. Devices name a site, here
  and in its grant, by its origin, else its name, else "A site". `keykin bunker <relay> --name <site>`
  prints such a link.

## 8d. The command-line device

`cli/keykin.ts` makes a computer a device: `create`, `import`, `forget-key`, `invite`, `signin`, `add`,
`join`, `status`, `sign`, `child`, `block`, `unblock`, `cycle`, `serve`, `agent`, `bunker`, `scan`, `sites`,
`signout`, `login`, `nsec`, `transfer`, `moved`. Its state is one file, `~/.keykin/device.json`,
readable only by its owner. The piece in it is not encrypted.

- `keykin sign` never sends `tapped` or the fingerprint. An event the box asks about fails with the
  box's words (`needs_tap: Remove 10 of your 30 follows`); sign it on a device that can ask. One that
  is never done by accident (level 2) fails with `Not signed: Empty your follow list. Do this from your
  phone.`
- `keykin agent <relay>` stays on and does what the account page asks (section 11.6): it adds a
  device, hands out a bunker link, becomes the signer for a pasted `nostrconnect://` code, and asks
  Yes or No at the keyboard before removing blocked devices (with nobody there, the answer is No).
- `keykin transfer '<setup code of the new box>'` moves the account to another box (section 11.4).
  The old box is the one the device uses now. It saves the new address and box key and prints a
  join text for the other devices.
- `keykin moved '<join text>'`, on each other device of the account, switches its saved address
  and box key to the new box. It checks that the join text is for this account and that the box at
  that address has that key. The piece is not touched: it catches up on the next request (`stale`).

**The sealed signer** (`device-rs/`, `keykin` in Rust, 2026-11-21): a command-line device with no piece in a
plain file, for signing from Terminal as the account. Above, the Node device keeps its piece unencrypted. As the
box signs with any one device, anything running as the person that reads `device.json` gets ordinary events
signed. So that one is for tests, servers and box admin, and this one is for a person at a Mac.

- **The device side** is Marble on Mac's (`keykin.rs`, with box-authority's reasons), lifted so that one copy
  serves every desktop device (the 2026-11-20 direction: one device core, library first, the command line on top).
- **The file**, `~/Library/Application Support/Keykin/device.json` (mode 600, folder 700), holds the account, the
  box, the device's name, its member key's public half and its index in plain text. The share and the member
  key's secret are sealed: XChaCha20-Poly1305 under HKDF-SHA256 (salt `keykin-signer-v1`) of an ECDH between a
  fresh P-256 key and a Secure Enclave key, with the member key as associated data. The chip key is CryptoKit's
  (`ThisDeviceOnly`, `.privateKeyUsage` and `.userPresence`). Its blob is usable only by this Mac's chip, and
  needs no keychain entitlement and no Apple developer signing.
- **Every use asks for the person**: Touch ID, or the login password without a sensor. The prompt names the event
  in words. Sealing needs only the chip's public key, so saving after a `stale` catch-up asks for nothing.
- **`keykin join`** signs in as Marble on Mac does (section 11.6, `add=` with PKCE, a loopback listener for ten
  minutes). The six digits with the page's address, or a phone's join code, can be typed where it waits.
- **`keykin sign`** never sends `tapped` or the fingerprint. `needs_tap` fails with the box's words and "sign it in
  Marble or on your phone". Level 2 fails with the box's words and "Do this from your phone." There is no helper
  path (section 8g): with the box off, nothing is signed.
- **Not covered:** a program running as the person that gets them to touch once gets the piece until the device is
  blocked or the keys are cycled. The prompt's words come from whoever asks, so a Touch ID prompt the person did
  not cause is the warning sign. The chip stops silent reads, copies, backups and a lost disk, not that.
- **Not built:** Linux (Secret Service) and Windows (DPAPI with Windows Hello). Until then `join` refuses rather
  than keeping a plain file. Also not built: Marble on Mac using this crate in place of its own copy, and child keys.

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
  box checks the result. So does a Yes to a level 2 signature (section 11.6, The tap).
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

A dropped member's grants (section 11.5) go with it at the cycle. Nothing is added to `revoked` for
them, so no older revoke is pushed out; their `limits` stay until they age out as before.

The changes left for a member (`catchups`) have no cap. One that stays away needs every change since,
each sealed to it so the box cannot add them up, and missing one would leave its piece useless for
good. Refusing the cycle instead would leave a blocked piece working. Each change is a cycle a person
asked for, so they grow only as fast as people cycle.

## 8g. When the box is off

Any two pieces sign, so a device that can listen (a computer that stays on) can answer the
others. `keykin serve <port> <address>` does this: it tells the box its address with `address`,
keeps the list it last saw at the box, and answers `sign` and `ecdh` for unblocked devices at the
same epoch. Other devices keep those addresses and try them when the box cannot be reached. Only
signing and message keys work this way. Everything else needs the box.

A block made while the box is off does not reach a helper until the box is back. A helper does not
check grants at all: a revoke or a limit (section 11.5) is kept only by the box. A helper does not
judge what is hard to undo either (section 11.6, The tap), nor check a fingerprint: asking is left to the
device that wants the signature, by its own rules.

## 8h. The browser extension

`ext/` makes a Chromium browser a device and gives pages `window.nostr` (NIP-07):
`getPublicKey`, `signEvent`, `nip44.encrypt`, `nip44.decrypt`.

- Set up by pasting the box's code, or by showing this browser's invite and pasting the join text.
- Each site is asked about once, in a small window. After Allow it is answered with no further
  questions until it is signed out in the extension's window, or revoked on the account page.
- **Each allowed site is a grant** (section 11.5), named by its origin. Allowing a site makes one and
  reports the whole list; signing out removes it and reports again. Every `signEvent` and message
  key for that site names its grant. When the box answers `revoked`, that request fails ("This site
  was signed out from your account page.") and the site is forgotten, so its next request asks
  again. The list is also reported each time the extension's window opens, which picks up revokes.
- A site limited to posting on the account page gets "This site may only post." for anything else.
- **A browser has no chip key.** So it cannot add devices, unblock, cycle or form the whole key.
  Those are done from a phone.
- Its piece is kept in the browser's extension storage, not encrypted.

## 8i. Other apps on the phone (NIP-55)

The Android app answers `nostrsigner:` requests: `get_public_key`, `sign_event`, `nip44_encrypt`,
`nip44_decrypt`. An app asks on a screen with Allow once, Always allow and Deny. An app that is
always allowed is answered silently through the content provider, and can be signed out on the
app's home screen.

## 8j. Signing in to a site by scanning its code (QRST `signer-ticket`)

This is the `signer-ticket` profile of QR Secret Transfer (`qr-secret-transfer/profiles/
signer-ticket.md`), followed as written. What moves is a single-use ticket, never a key.

1. The site shows a QRST code (Flow A, `mode=offer`). The site is the Receiver.
2. A Keykin device reads it and asks **"Let *origin* sign as you?"**, saying that the site gets
   access of its own and where it is removed.
3. On yes the device joins the QRST session. If its own camera read the code, the check level is
   `none`. If the code was pasted or handed over, it is `compare`: the device shows five digits
   and asks whether the site shows the same. Different digits end it and nothing is sent.
4. Only then is the ticket made: `{ v: 1, pubkey, signer, relays, t, expires }`, with `expires`
   15 minutes ahead. It is released to the site, sealed, through QRST.
5. The site asks **"Sign in as …, through your signer … on …?"**, and on yes sends NIP-46
   `connect` to `signer` on `relays` with `t` as the secret.
6. The signer accepts `t` once, records the site's own key against the origin the person
   approved, and from then on answers it (section 8c). Signing the site out refuses its key.

Who does what:

| Part | Where |
|---|---|
| The ticket format and both halves | `src/ticket.ts`, over the QRST library bundled as `vendor/qrst.js` |
| A site's widget, `KeykinSignIn.start(element, { relays })` | `site/signin.ts`, built to `site/dist/keykin-signin.js` |
| Command-line signer | `keykin bunker <relay>` running, then `keykin scan '<code>'` |
| Phone signer | The Android app: scan or paste a site's code. Sites are listed on the home screen with Sign out |

Limits today:

- **The phone's signer listens only while the app's process is alive.** There is no background
  service yet, so a site signed in through the phone stops getting answers once Android ends the app.
- **The phone listens on the relays the site's code names.** Nothing else is configured.
- **Relays must be `wss://`.** A relay on this machine or a private network over `ws://` is
  accepted only by the command-line signer, a debug build of the app, and a page given such a
  relay by its own operator.
- **The `nc` fallback, the bounce page and same-phone links** of the profile are not built. A
  code opened in a browser instead of a signer just loads the site.
- **`type` check level** (typing the digits) is not offered by Keykin's signers.

## 8k. Child keys

One account can sign as many npubs. Each extra one is a **child key**, named by a label such as
`home` or `work`. A child is an ordinary Nostr key to everyone else: any app and any relay takes
it, and nothing about it says which account it belongs to.

- **A child is the account's key plus a number**, the tweak `t`. Its nsec would be `a0 + t`, in
  the even-y form. Like the account's nsec, it is never whole anywhere.
- **Every piece of the account is also a piece of the child.** A holder adds `t` to its piece, and
  `t·G` to `C0`. If the child's key then has odd y, it negates its piece and the whole commitment.
  From there signing (section 3) and messages (section 8a) run unchanged, so any two pieces of the
  account sign as the child. No new pieces are made, stored or backed up.
- **Two pieces make the tweak together.** The label hashes to a point `Q`:
  `SHA-256("keykin2-child-point" ‖ n ‖ label)` for the first byte `n = 0, 1, …` that is the x of a
  point. The device asks for `ecdh` with `Q` as the peer, as the account, and gets the shared x of
  section 8a. Then `t = SHA-256("keykin2-child" ‖ shared x ‖ label) mod n`.
- **So a child can always be made again.** Any two pieces give the same `t` for the same label, on
  any device, before and after the keys are cycled (the nsec does not change). One piece alone
  cannot work `t` out. A device keeps the children it has made to save asking, and the box keeps
  nothing about them.
- **Asking as a child.** `sign` and `ecdh` take `child: <t, 32 bytes hex>`. The box moves its own
  piece by `t` and, for `sign`, refuses an event whose `pubkey` is not that child's
  (`wrong_account`). A `t` that is zero, out of range or not hex is `bad_child`. Everything else
  about the request is as before: the epoch, grants, limits and the tap for hard-to-undo events.
  A device helping when the box is off (section 8g) does the same.
- **A label** is 1 to 100 bytes of UTF-8. Children are made from the account only, never from
  another child.
- **Never form a child's nsec.** A child's nsec together with its `t` gives the account's nsec.
  There is no request that forms one, and there must not be. A child is used through pieces only.
- **The link is private until the person shows it.** Nothing published ties a child to the
  account. Tying them together on purpose (an attestation signed by both) is not built.

Built in the TypeScript core, the box and the command line: `keykin child <label>` makes one and
prints its npub, and `keykin sign '<event>' <label>` signs as it.

## 11. Shared formats (settled 2026-11-17)

These are fixed for both the Keykin work and the Marble app. `PLAN.md` says why they exist.
Each one says whether the box already does it. Anything marked **not built** is the target the
app should code against; the box will meet it.

### 11.1 The login-page pointer

A small replaceable event, signed by the account, that says where its login page is. Sites read
it to find where to send someone (Aaron, 2026-11-19: kind 10046, replacing kind 30078).

```json
{ "kind": 10046, "pubkey": "<account npub, hex>", "created_at": 1790000000,
  "tags": [["nostrconnect_url", "https://account.syb.lol/#connect=<nostrconnect>"],
           ["relays", "wss://relay1", "wss://relay2"]],
  "content": "" }
```

- **Why 10046.** NIP-78 changed in nips#2458 (2026-09-03): kind 30078 is not for public data, and
  relays should serve it only to its authenticated owner, so other sites may lose the right to read
  it. Kind 10046 is from the open draft nips#1578 (signer discovery from a public key). The draft is
  not merged, so its shape may still change. The `.well-known/nostr.json` file is not used: the
  person cannot always change it.
- **`nostrconnect_url`** is an `https://` template with exactly one `<nostrconnect>`, at its very
  end. A site replaces it with `encodeURIComponent` of its `nostrconnect://` code and opens the
  result. Keykin's template is always `<login page origin>/#connect=<nostrconnect>`, which keeps
  `connect=` last (section 11.6). A reader refuses a template that is not `https://` (except
  `http://localhost` or `127.0.0.1` when the reader itself runs there), has a user or password, or
  has no or more than one placeholder. It shows the template's origin to the person, and only then
  goes there.
- **`relays`** (optional) lists relays where the account's signers listen. Readers may ignore it.
- The draft's `pubkey` tag (a bunker's key) is left out: Keykin's bunker keys are per device
  (section 8c).
- **To find it:** `{ "kinds": [10046], "authors": ["<npub hex>"] }`, newest wins, signature
  checked. Ask the site's own relays and indexers, then the account's write relays (kind 10002) if
  those had none. A site's relay guards still apply.
- **To remove it:** publish 10046 with no `nostrconnect_url`. A newest 10046 with none means
  removed, and the reader does not fall back to the old kind.
- **The old kind, during the move.** Before this the pointer was kind 30078 with
  `["d", "keykin/login"]` and `["url", "<https origin>"]`. A reader that finds no 10046 at all
  reads that one (filter `{ "kinds": [30078], "authors": [..], "#d": ["keykin/login"] }`, `url`
  an https origin only) and treats it as the template `<url>/#connect=<nostrconnect>`. Devices
  keep both in place: a new pointer is signed as both kinds, a missing copy of either is sent
  again, and removing it removes both. The old kind goes once Marble Web, Discover and Tube in use
  all read 10046.
- **A caveat.** 10046 is one event per account. If another signer app starts publishing its own
  10046 for the same account under nips#1578, each would replace the other. Not a problem today:
  no other app is known to publish it.
- A device signs it like any other event (section 3).
- **Where a device learns the origin.** A box with Keykin Login in front knows its login page's
  address from its admin page, where the admin sets it ("Your login page address": https, origin
  only). `KEYKIN_LOGIN_URL`, when set, overrides that setting. The box's setup codes carry it:
  `"loginPage": "https://…"` (not `login`, which is the account page's own sign-in code). The admin
  page may suggest an address (the one it is visited at, if https, or the host Keykin Login says it
  serves), but nothing is used until the admin saves it.
  A device's join text carries it too, when the device knows it. A device given a code without it
  publishes nothing: it never guesses the page from the box's address, which a lookalike address
  passing the box through could fake.
- **Who publishes it, and keeps it there.** A device in the account checks right after it joins,
  and each time it signs a site in by a `nostrconnect://` code. A site that looked the person up by
  name and found no pointer marks its code `kk_login=missing` (next to `kk=account`); the check is
  the same either way, and the site looks again once the device has answered. It asks the account's write relays (kind 10002) and its own.
  - If the newest pointer names this origin, and some write relay that answered lacks it, the
    device sends that same signed event there again. No new signature, no box.
  - If no relay has any pointer, it signs a new one (device and box, as usual) and publishes it.
  - **The pointer follows the box the device signs with.** A device keeps, per account, the
    origins it got from codes of boxes it joined before (the current one is the last code's).
    If the newest pointer names one of those, and the current origin is a different one, the
    person has moved boxes: the device signs a new pointer naming the current origin, which
    replaces the old one by `created_at`. Joining a box makes its code's origin the current one
    and adds the one before to that history; a code without one leaves no current origin.
    Removing the device from the account keeps that history, so joining again at a new box
    still moves the pointer.
  - If the newest pointer has no `nostrconnect_url` (or `url` on the old kind: removed on purpose), or names an origin this device never
    got from a box code (another device's, or set by hand), it does nothing: the person chose that.
  - With no current origin, it does nothing, not even sending an existing pointer around.
  - Right after a join, a pointer naming an origin the device never got from a box code is asked
    about once on the device (switch to the current origin, or keep it and never ask about that
    pair again). At other checks it is left.
  - All of this runs on kind 10046, and on kind 30078 too during the move (above).
  - If no relay answers, it does nothing this time.
  The account page's "Publish it" button stays as the fallback, and publishes both kinds during the move.
- **Asked for from the account page (a `pointer` note).** A page signed in with a password or a passkey
  has no signer of its own, so it leaves a note (section 11.6): `note_put { kind: "pointer" }`. The box
  fills in the note's text with its own login page address (the admin setting, or `KEYKIN_LOGIN_URL`),
  never anything the page sent, and returns it as `url` next to `note`. With no address set it refuses
  with `no_login_page`. A device shows "Make <host> your sign-in page?" with Yes and No. On Yes it signs a
  new pointer naming that origin (both kinds during the move), publishes it, and answers `note_done`
  with `ok`; on No it answers `note_done` with `declined`. A No here is not `note_refuse`: it does not
  end the page's session. The page then asks the relays again and says what they show. `me` returns
  the same address as `loginPage` (null when none is set), and the page treats a pointer naming it as
  naming this page; only a box with no address set falls back to the page's own origin. Its own
  "Publish it" and the copies it sends again use that address too.

**Built (2026-11-19), kind 10046:** on the account page, with the rules in `login/static/pointer.js`
(tested on their own and in the browser). The page asks its relays for both kinds at once, reads 10046
first and 30078 only when no relay gave a 10046, treats a newest 10046 with no `nostrconnect_url` as
removed, and refuses a template as above (a refused one shows as a page that cannot be used, with
Publish offered). When the pointer names this page, it sends the newest copy of each kind as it is to
any of its relays that answered without it. "Publish it" signs both kinds (two signatures on the
phone, no `relays` tag), and when the pointer names this page a "Remove it" button signs both
removals. After a password or a passkey, the alert's **Publish it from my phone** leaves a `pointer`
note (built 2026-11-19 on the box and the page; `answerNotes` in `src/device.ts` answers it when given
a `pointer` function, which the tests do but `keykin agent` does not yet; Marble on Android is being
built against it in the Marble repo). Not built: the device's own check after joining and on `nostrconnect` sign-ins. The
command-line device has none; Marble's lives in the Marble repo. Marble Web, Discover and Tube read
the pointer in their own repos.

### 11.2 Accounts on a box, and how a request names its account

A box holds many accounts. **An account's id is its npub in hex** (the x-only key of section 1).

- Every device request names its account in the body: `"account": "<npub hex>"`. The box
  answers `unknown_account` if it holds no such account.
- The requests that come before an account exists (`ask`, `asked`, `create1`, `create2`,
  `transfer1`, `transfer2`) carry `"request": "<request id>"` instead (section 11.4).
- **Until every device is updated,** a box that holds exactly one account takes a body with no
  `account` as meaning that account. With two or more it answers `need_account`.
- One box has one member key, used in every account it holds. A device's member key may be in
  more than one account; the `account` field is what tells them apart.
- Codes that name the box gain nothing new: the setup code is still
  `{ keykin: 2, addr, key, code }`, and `code` is now a request id the admin approved in advance.
- The join text gains the account: `{ keykin: 2, join: { addr, boxKey, npub } }` is unchanged,
  and `npub` is the account id.

**Built:** the box, the TypeScript device code and the Kotlin core. The Keykin debug app on the phone still sends no `account`, which a one-account box accepts.

### 11.3 Username and password

They live on the box, per account. The box never sees the password.

- **Username:** 3 to 32 of `a-z 0-9 . _ -`, lower case, unique on the box.
- **Verifier:** `PBKDF2-HMAC-SHA256(password as UTF-8 after NFKC, salt, 600000 rounds, 32 bytes)`.
  The salt is 16 random bytes. Whoever types the password computes the verifier: the device
  when setting it, the login page's own script when logging in.
- **Stored on the box:** the username, the salt, and `SHA-256("keykin2-pw" ‖ verifier)`.
- **Setting or changing it** is an account change. A device sends
  `{ op: "password_set", account, username, salt, check }` with a fingerprint, where `check` is
  the stored hash above, hex. A password can be changed but never removed: the box refuses
  `{ op: "password_clear", account }` with `password_required`.
- **Always set at setup:** every way of making or bringing in an account (`keykin create`,
  `keykin import`, the app's create and import) asks for a username and the password, typed twice,
  before setup is done, and sends `password_set` as its last step. Passkeys do not stand in for it.
- **Logging in** is two calls from the page to the box (section 11.6):
  `pw_salt { username }` returns `{ salt }`, and `pw_login { username, verifier }` returns a page
  session. For a username that does not exist, `pw_salt` returns a salt made from the username
  and a secret of the box's, so it gives nothing away.
- **Limits on guessing:** five wrong tries for one username lock it for 15 minutes, doubling each
  time up to 24 hours; a right password clears the count. Across all usernames the box takes at
  most 30 tries a minute.
- **The page can change it too:** `pw_set { username, salt, check }` with a page session. The page's
  own script computes the verifier. `pw_clear` is refused with `password_required`.
- **Accounts made before this rule** may have no password. `members` says so (`password: false`),
  and the app and the account page show a plain prompt to set one until it is set.
- **What a password is worth:** the whole account (section 11.6). The limits on guessing are
  what stands between a guesser and that.

**Built:** the box (refusing removal, `password` in `members`), both device cores (`passwordSet`),
the account page's sign-in, change form and no-password prompt, `keykin create`/`import` (asked at
setup, or `--username`/`--password` and `KEYKIN_USERNAME`/`KEYKIN_PASSWORD` without a terminal) and
`keykin password`, and Marble Android's create and import with its no-password prompt.

**Passkeys (added 2026-11-18).** A passkey is another way into the page, worth the same as a
password or a scan. They live on the box, per account, as WebAuthn credentials:

- **Relying party:** the login page's own host (`rpId`): the box's login page address (section 11.1)
  when it is set, so the origin is that address too; otherwise taken by Keykin Login from the request it
  served. Never from the page. `https://` only, except `localhost` and `127.0.0.1` for testing. A
  resident (discoverable) key, user verification required, no attestation.
- **Stored on the box:** `{ id, key, counter, rpId, origin, added, last }` per passkey (the
  credential id, its COSE public key, base64url). A passkey signs in only on the host it was made on.
- **Adding** needs a page session: `pk_add_start` returns WebAuthn creation options, and
  `pk_add { response }` checks the answer and stores it. `pk_remove { id }` removes one.
- **Signing in:** `pk_login_start` returns request options with no list of credentials (the
  browser offers what it holds for this host), and `pk_login { response }` returns a page session.
  The box finds the account by the credential id, checks the signature, the challenge (one use,
  three minutes), the origin, the host and user verification, and keeps the signature counter.
- The page offers to save one right after a scan sign-in ("Save a passkey so next time it's one
  tap", with Skip). It is an offer: a password stays a first-class way in, and the Security section
  adds or removes passkeys at any time. On the sign-in screen "Sign in with a passkey" comes first,
  then the scan and the password.
- Verification uses `@simplewebauthn/server` 13.2.2 on the box. The page calls
  `navigator.credentials` itself.

**Built:** all of the above on the box, in Keykin Login and on the account page; tested with a
virtual authenticator in Chromium. **Not built:** passkeys in the apps (they have no use for them).

### 11.4 Asking to make or transfer an account

Anyone who can reach the box may ask. Nothing is made until the admin approves it on the box's
admin page.

**Asking.** A device sends `ask`, signed by its member key like any request:

```json
{ "op": "ask", "what": "make", "name": "Pixel 9a", "note": "Aaron's phone", "chip": "<chip key>" }
```

- `what` is `make` or `transfer`. A transfer also carries `"account": "<npub hex>"`.
- `name` is the device's name, up to 60 characters. `note` is free text for the admin, up to 200.
- The answer is `{ ok: true, request: "<id>", key: "<the box's member key>" }`. One member key may
  have one request waiting.
  The box keeps at most 50 waiting and drops those older than seven days.

**Waiting.** The device sends `{ op: "asked", request }` to hear `{ state, key }`. The state is
`waiting`, `approved`, `refused` or `gone`. `key` is the box's member key, which a device that
started from only an address needs for `create1` and `create2`. An approved request can be
used for 24 hours. `{ op: "ask_cancel", request }` from the device that asked takes it back.

A device that learned the key this way trusts the address it asked. Over `https` that is the
certificate; a setup code carries the key itself.

**What the admin sees:** the device's name, the note, `make` or `transfer` (with the npub for a
transfer), when it was asked, and the first 8 characters of the device's member key. Buttons:
Approve and Refuse. The admin can also make an approved request with no device asking; its id
is the `code` in the setup code the admin page shows.

**At most 50 unused codes** (2026-11-20): requests approved in advance, from the admin page and from the
account page's `protect` (section 11.6), in all. Making one more drops the oldest. A new `protect` code
replaces that account's earlier one, so an account has at most one. Asks the admin approved are not
counted. A move started with a code that is gone (`transfer1`, below) is forgotten with it.

**Making.** With an approved request the device runs section 2, sending `"request": "<id>"`
with `create1` and `create2` in place of the old `code`. The first device is index 1 and the box
is index 2, as before.

**Transferring** moves an account to this box from another Keykin box without the key ever
being whole. The account keeps its npub and its devices.

1. On the old box, a device adds the new box as a member of kind `box` (section 7), using the
   new box's member key from its setup code.
2. The device sends the new box `{ op: "transfer1", request }`. The answer is a signed
   `welcome` request, made by the new box for the old one.
3. The device hands that to the old box and gets back the two halves of the new box's piece.
4. The device sends the new box `{ op: "transfer2", request, welcome, oldBox, members, next }`,
   where `welcome` is the old box's answer from step 3, `oldBox` the old box's member key, and
   `members` and `next` the list as the old box gives it. The new box builds its piece, checks it
   against the commitment, and stores the account with the old box left out of the list and itself
   in its place. The device must be an unblocked device on that list. A list of more than 50 is
   refused with `too_many_members` (section 7), and the account stays on the old box.
5. The device cycles the keys on the new box (section 8f). The old box gets no change, so its
   piece stops fitting. Other devices are told the new address with a join text,
   `{ keykin: 2, join: { addr, boxKey, npub } }` naming the new box, and switch to it ("moved"):
   each checks the npub and that the box at `addr` reports `boxKey` in `members`, then uses it. Its
   piece catches up on its next request there (`stale`).

The fingerprint is asked twice: for adding the new box on the old one (step 1) and for the cycle
(step 5). `transfer1` and `transfer2` themselves carry none; the approved request is what lets them
in. A device that was behind on the old box (it missed a cycle there) cannot catch up on the new
one: it has to be removed and added again as a new device.

**Built:** asking, waiting, approving and making, on the box, the admin page and both device cores.
Transferring (`transfer1`, `transfer2`) on the box, `transferToBox` and "moved" in both device
cores, and `keykin transfer` / `keykin moved` on the command line. No app has a screen for asking
or moving yet.

### 11.5 What is signed in, and revoking it

So that the account page can show every site and app using the account, and end any of them,
each device tells the box what it has let in.

- A **grant** is `{ id, kind, name, since }`. `id` is 16 random bytes, hex, made by the device.
  `kind` is `site` (a site signed in through this device) or `app` (another app on the phone).
  `name` is the site's origin or the app's name. A site with no origin is named as in section 8c:
  the name the person typed, else its first client tag, else "A site". When a name comes later the
  device sends its list again with the new name. `since` is unix seconds.
- A device sends `{ op: "grants", account, grants: [...] }` with its whole list whenever it
  changes. The box keeps the list per device.
- **Telling grants apart** (Aaron, 2026-11-19). A grant may also carry, all optional:
  - `client`: the site's NIP-46 client key, hex.
  - `device`: the site's own label for where it runs, like "Chrome on Windows", at most 60
    characters. The site claims it, so it is a label only, never a check.
  - `via`: how it came in: `login` (a nostrconnect note left by the login page), `scan` (a scanned
    code), `paste` (a pasted code) or `bunker` (a bunker link).
  - `browser`: set by the box, never by a device. When the account page leaves a `nostrconnect`
    note, the box remembers the code's client key with that page session's browser label (from its
    `agent`, as in "Chrome on Windows"), for 30 days, at most 20 per account. A later reported grant
    whose `client` matches gets that label.

  A nostrconnect code may carry `device=<label>`; sites we control send it, and the device keeps it
  with the site and reports it. The box also keeps the last event kind signed for each grant (from a
  `sign` naming it), for as long as it keeps that grant's last use (at most 2000 grants). The page's `me` gives each grant `client`, `device`, `via`, `browser` and
  `lastKind`, with `deviceKey` and `deviceName` for the device that let it in. Sites and apps shows the
  name and then a line like "Chrome on Windows · signed in 19 Nov 06:14 through your login page ·
  approved by Pixel 9a · last used 2 h ago, last posted a reaction · key ab12…", leaving out what is
  missing. The key is the first 4 hex of `client`; Marble Web shows the same 4 in its account menu.
- When a device signs or makes a message key **for** a site or app, it names the grant:
  `"grant": "<id>"` in the `sign` or `ecdh` body. Requests for the person's own use carry none.
- **Revoking** is done on the box, from the account page or by any device:
  `{ op: "revoke", account, grant }`. From then on the box answers `revoked` to any request
  naming that grant, from any device. This is what makes a revoke stick even if the device that
  let the site in is offline.
- The answer to `grants` includes `revoked: [ids]`, so the device drops them from its own list.
- **A grant ends after 90 days unused** (2026-11-19). Use is any request naming it. The box keeps
  each grant's last use (its `since` until the first one), and once that is more than 90 days old it
  treats the grant as revoked: it answers `revoked` and lists it in `revoked`. The account page shows
  each grant's last use, and the activity list records "<site> signed out after 90 days unused".

**Limiting a grant to posting.** The person can let a site or app post and do nothing else.

- `{ op: "limit", account, grant, to: "posts" }` from any device sets it, and `to: null` lifts it.
  The account page's call is `limit { grant, to }`, for a grant on its list (`gone` otherwise).
  Neither needs a fingerprint: limiting takes power away, and a device can always sign for itself
  without naming a grant.
- The box keeps the limits per account. For a `sign` naming a limited grant it allows only kinds
  1, 6, 7, 16, 1111, 9734, 20, 21, 22 and 22242 (notes, reposts, reactions, comments, zap
  requests, media posts and relay logins) and answers `not_allowed` to anything else, so a profile,
  a follow list, a delete or a zap receipt (9735) is refused. It answers `not_allowed` to every
  `ecdh` naming it: a limited site cannot read or write messages.
- Revoking a grant removes its limit too.
- The page's `me` view gives each grant's `limit`: `"posts"` or `null`.

**Built:** the box, the account page (a "Posts only" switch on each row of Sites and apps), and
`reportGrants` / `revoke` / `limit` / the `grant` field in both device cores. The command-line
signer and the browser extension report each site they let in and name it on every request. The
Kotlin core's site signer (`SiteSigner`) gives each site a grant and names it. The Android app (Marble)
reports its grants every 30 seconds.

**Built (2026-11-19), 90 days unused:** on the box. It keeps each grant's last use in the account's
`used` map (by grant id, set by every `sign` or `ecdh` naming it), so a device's next `grants`
report does not wipe it. Expiry is checked on each `sign` or `ecdh` naming a grant, on each `grants`
report and on the page's `me`; an ended grant is revoked as the person would revoke it (so it is in
`revoked` from then on) and the activity line is written. A grant used but never reported ends the
same way, with no activity line, since the box has no name for it. `me` gives each grant's `last`
from that map, and Sites and apps shows it ("last used …"). Devices change nothing.

**Built (2026-11-19), telling grants apart:** on the box (`client`, `device`, `via` kept from reports,
`browser` from the nostrconnect note, `lastKind`), the account page's detail line (`login/static/rows.js`),
Marble (Android reports them, Marble Web sends `device=` and shows its key) and Tube (`device=` from the
start request's User-Agent).

**Turning on DMs and private lists from the account page.** (Aaron, 2026-11-19.) A device may keep two
switches of its own for a site: may it read the private lists (a message key with the account's own
key), and may it read and send DMs. Marble has them for each site it lets in, off at first, and checks
them on the phone. The account page can turn them on or off; the box only carries the choice.

1. In `grants`, a grant may carry `lists` and `dms`, booleans: the device's switches for that site
   as they are now. Absent means the device has no such switch for it (apps, the command-line
   signer). The box keeps them only when they are booleans.
2. The page's call is `scopes { grant, lists?, dms? }`, each a boolean, at least one. The box answers
   `gone` if the grant is not on the account's list, and `bad_request` if it is not a `site`, if its
   device did not report the switch asked about, or if the body is wrong. It keeps what the page
   wants in the account's `wants` map (by grant id, `{ lists?, dms? }`), merged with any want
   already there, and writes a line like "chat.nostr.com may read and send DMs, from the account
   page" or "chat.nostr.com may no longer read your private lists, from the account page". It
   follows the sign-in strength rows of 11.6 as `limit` does: turning a switch on is `limit:none`,
   turning one off is `limit:posts`.
3. The answer to `grants` carries `scopes: { "<grant id>": { lists?, dms? } }` for that device's
   grants with a want, and leaves the field out when there are none. The device sets its switches
   and reports again; once a report shows a switch as wanted, that part of the want is done. A want
   for a grant no device lists any more goes, and revoking a grant (from anywhere, or after 90 days
   unused) drops its want.
4. The page's `me` gives each grant `lists` and `dms` (as reported, or `null`) and `want` (or
   `null`). Sites and apps shows "Private lists" and "DMs" switches beside Posts only for a site
   that has them, showing the want while there is one, and adds "waiting for Pixel 9a" to the line
   while the want and the device differ. With Posts only on, both are greyed out: that limit already
   refuses every message key.

**Built (2026-11-19), the switches:** on the box (`wants`, `scopes` in the `grants` answer), the page
call and `me` (`box/pageapi.ts`, passed through by Keykin Login), the account page
(`login/static/account.js`, the waiting text in `login/static/rows.js`), and the TS device core
(`lists` and `dms` on `Grant`; `syncGrants` returns `{ revoked, scopes }`, and `reportGrants` still
returns `revoked` alone). Marble is built against this format separately.

### 11.6 The account page's calls, and what needs a device

Keykin Login is a public page with no piece and no list. It passes two kinds of thing to the
box and nothing else: device requests (`POST /keykin`, unchanged), and the page's own calls
(`POST /page`). The box is the one that knows who is logged in.

**Logging in to the page** gives a page session, a random token the box issues. How long it lasts
depends on how it was made (Aaron, 2026-11-19):

- **Passkey:** 90 days, and each call the session makes starts the 90 days again.
- **Password or scan:** 12 hours from sign-in, not extended by use.

There is no "keep me signed in" choice. The box keeps sessions in its state so they live through a
restart, storing `SHA-256(token)`, never the token itself. Each session records `how`, `made` and
`last` (unix seconds) and `agent`, the browser's `User-Agent` as Keykin Login saw it, cut to 200
characters. Keykin Login passes it in the `/page` body as `agent`. The page never sets it.

**Signed-in browsers.** `me` returns `browsers: [{ id, how, made, last, agent, until, this }]`
for the account's live page sessions. `id` is the first 16 hex of `SHA-256(token)`, and `this` marks
the session asking. `logout_browser { id }` ends one. The Security section lists them ("Chrome on
Windows · passkey · signed in 3 Nov · last used today") with Sign out on each, and the existing
"Sign out everywhere" (`logout_all`) stays.

- by password (section 11.3), or
- by passkey (section 11.3), or
- by a scanned code, the way any site signs in (section 8j). The page shows a QRST `signer-ticket`
  code and ends up with a remote signer for the account. It asks the box for a challenge
  (`signin_start`), has the signer sign a kind 22242 event with the tags `["relay", <page origin>]`
  and `["challenge", <challenge>]`, and sends that (`signin { event }`). The box checks the
  signature, the kind, that the challenge is one it gave and unused, and that `created_at` is
  within ten minutes. The session is for the event's `pubkey`.

On a phone the page shows a button, not a code, since a phone cannot scan its own screen. The
button is a `nostrconnect://` link (NIP-46) with a fresh page key and secret; the signer app
opens on it and answers on the relays, and the rest is the same challenge. The page listens
again from the start time each time it comes back to the front, because a phone drops a page's
connections while the app is in front.

**An account page marks its code and its link** with the parameter `kk=account` (QRST ignores
unknown parameters, and so does NIP-46). The page is about the account's own key, so a signer
that would otherwise offer a child key for a new site (section 8k) uses the account's key there,
on any origin and whoever runs it. The mark asks for nothing more than the person could choose
anyway, and the signer still asks before it connects.

The account page used to show a code of its own (`{ keykin: 2, login: … }`, answered by
`{ op: "login" }`). The page no longer shows it. The box still answers it, for apps built before
this.

**The box need not hold the account that signs in.** A phone with the whole key on it and no box
signs in the same way. For such a session `me` returns `{ held: false, npub, open }`, and the only
other calls are `logout` and `protect`. `protect` returns a setup code made for that one account
(a request approved in advance, with `only: <npub>`): the phone scans it and brings the account
in (`import`), keeping the whole key as its backup. The code is refused for any other account
and for making a new one. `protect` works only on an open box (`KEYKIN_OPEN=1`); otherwise it
answers `not_open` and the account needs a code from the admin page. An open box lets accounts in this
way while it holds fewer than 500 (set on the admin page, section 6a, or by `KEYKIN_OPEN_ACCOUNTS`,
which wins), counting every account. Past that, `protect` answers `box_full` with the reason as `why`
("This box holds 500 accounts, as many as its admin lets in from the account page. Ask the admin to
make room."), and so does `import` with a `protect` code made before the box filled; that code stays
good for its 24 hours, for when there is room. The admin's own codes still work. A new `protect`
replaces the account's earlier code (section 11.4).

**A site can send the person here to sign in.** A link to the page may carry a site's NIP-46
code in the fragment: `https://<login page>/#connect=<encodeURIComponent(nostrconnect://…)>`.
Marble's name-first sign-in reads the account's pointer (section 11.1) and sends the person there
this way. The page:

- reads `connect=` once. `connect=` must be the last fragment parameter. Everything after it is the
  code, taken as it is if it starts with `nostrconnect://` (a raw code, whose own `&` and `=` would
  otherwise split it), else URL-decoded once. It checks the code starts with `nostrconnect://`, has a
  64-hex client key, at least one `relay` and a `secret`, and takes the site's name and url from
  `name`/`url` (or the older `metadata` JSON);
- reads where the request really came from: the origin of `document.referrer` when the page loads
  with `connect=`, kept with the code. A site sending people here must not use `noreferrer`
  (`rel="noopener"` and the default referrer policy send the origin, which is all this needs);
- takes the parameter out of the address bar and history at once (`history.replaceState`), keeping
  any other fragment parameters, and keeps the code and the sender's origin in the tab's
  `sessionStorage` (`kk-connect`) so they live through the scan, the passkey or the password;
- **never leaves the note without a click** (2026-11-19). Before this, a browser already signed in
  here left the note at once, so any site that knew the login page could open it in a tab and be
  signed in with no click. Now it always shows a card first, after signing in or straight away if
  the browser is signed in already: **"Sign in to <host> as <name>?"** with the account's name and
  picture, the sender's origin, and the relay. The buttons are **Sign in** and **Not now**, and a
  small **Use a separate account for this site** that sends `as: "site"` (below). An already-signed-in
  browser needs no password, passkey or scan again: the click is the whole step;
- **checks the sender.** The host on the card is the sender's origin. If there is no referrer, or
  its host is not the code's `url` host, the card says so in plain words ("This request came from
  <sender>, but says it is <url host>" or "This page could not tell which site sent you here"), shows
  the code's name only as what it claims, and the button becomes **Sign in anyway** behind a second
  confirm. A match is the one-click case;
- on Sign in, leaves a `nostrconnect` note: `note_put { kind: "nostrconnect", text, from, as }`,
  where `from` is the sender's origin or null, and `as` is `"main"` or `"site"`. It shows "Waiting
  for one of your devices…", then "Done. Go back to <site>" linking to the sender's origin (or the
  code's `url` when they matched). After 60 seconds with no answer it says a device needs to be
  online with an up-to-date Marble, and keeps waiting while the note lives. The code leaves
  `sessionStorage` as soon as the note is left, so a reload does not send it twice;
- shows a code that is not a `nostrconnect://` code as wrong and leaves it alone.

**An app can send the person here to add it as a device** (Aaron, 2026-11-19: "the simpler answer is 'sign
in' opening a web page", then OAuth for native apps after the red team: RFC 8252 with PKCE). Marble on the
Mac holds no sign-in of its own and becomes a device, holding a piece. Its Sign in:

1. makes its invite (section 8b), a PKCE verifier (32 random bytes, base64url) and a `state`, and listens
   on `http://127.0.0.1:<random port>/` (RFC 8252 section 7.3: no "Open Marble?" prompt, unlike a custom
   scheme);
2. opens Marble Web in the default browser:
   `https://marble.syb.lol/#challenge=<base64url SHA-256(verifier)>&return=<encodeURIComponent(http://127.0.0.1:<port>/done)>&state=<state>&add=<encodeURIComponent(invite JSON)>`.

Marble Web finds the login page as its own sign-in does: the account this browser is signed in as, else
the name the person types (steps 1 and 2 of name-first sign-in, below). It shows the address, and a click
goes there with the same four parameters, `add=` last. With no login page, Marble Web shows the invite as
a code for the phone's Add a device instead. The login page:

- reads `add=` by the same rules as `connect=`: the last fragment parameter, everything after it
  URL-decoded once; `challenge`, `return` and `state` from the parameters before it, each URL-decoded once.
  All four leave the address bar and history at once (any other fragment parameters stay), and are kept in
  the tab's `sessionStorage` (`kk-add`) through the scan, the passkey or the password;
- checks the invite is a Keykin invite: JSON, `keykin: 2`, an `invite` with a 64-hex `key`. The `name` is
  shown (cut to 60 characters, "A new device" when there is none);
- **sends approvals to this device only.** `return` must be `http:` on `127.0.0.1` or `localhost`, with a
  port, and no user, password or fragment (RFC 8252 7.3), or exactly one of the phone apps' own App Link
  addresses (RFC 8252 7.2): today only `https://marble.syb.lol/joined`, which Marble on Android claims.
  `challenge` must be 43 base64url characters and `state` 8 to 128. Anything else ("not a Keykin invite",
  "send the approval to <host>, which is not this device", "not complete") is said plainly and left alone:
  nothing is kept;
- **never leaves the note without a click.** After signing in, or straight away if the browser is signed
  in already, it shows a card: **"Add <name> to your account?"** with the account's name and picture, the
  device's name, and **Add** and **Not now**. A tab an app opens has no referrer, so the card says to say
  yes only if you just pressed Sign in on this computer;
- on Add, leaves the usual note with the challenge: `note_put { kind: "invite", text, challenge }`. A
  device adds the newcomer as for any invite note (section 7: the box now holds its piece behind a gate).
  When the device has answered, `note_get` gives the page that left the note, once, `approval: { code,
  short, until }`;
- navigates to `return` with `code`, `state` and `join` (the join text, which is not secret) added to its
  query, or, for an App Link return, in its fragment, so that the web server behind it never sees them if
  the app does not open. The app checks `state`, then asks for its welcome with `code` and `verifier`, joins, and its
  listener answers the tab ("Done. Marble on Mac is signed in."). The listener takes one approval, and
  closes after it or after 10 minutes;
- **the fallback:** before leaving, the page keeps the six digits for this tab (`kk-add-done`, until they
  run out), so if the way back fails and the person comes Back, the page shows them: "type this only into
  <name> on this computer", with the page's address. The app has a small "Type a code instead": the six
  digits and the page's address. It sends `welcome` to that address with the digits and its verifier and
  no `account` (the box finds it, section 7).

**Why this holds.** A stranger can put their own invite and challenge in a link, and a person may press
Add. The device is added, but its piece stays at the box until someone shows the approval code with the
stranger's verifier. The long code goes only to a loopback address on the person's own computer, and the
six digits only to the person's own screen. Five wrong tries and ten minutes end it.

**Devices, Add a device (a pasted invite) goes through the same gate**, with no challenge: there is no
verifier behind a pasted invite. The page shows the join code and the six digits, "type this only into the
new device", and the code alone redeems: `keykin join '<join text>' <code>`. This is the weaker, typed
path: anyone who reads the digits off the screen within 10 minutes and holds the invite's key could use
them, so the page says to give them only to the new device.

**Which key a site gets** (Aaron, 2026-11-19). A site never chooses. `kk=account` on a site's own
code means nothing, and Marble Web no longer adds it: the mark is only for an account page's own code
(above). The person chooses once per site and the device remembers it in that site's record:

- through the login page, on the card above: the main account unless they pick a separate one;
- through a scan or a pasted code, on the device's own card (section 8k, Marble's `SiteChoice`);
- a site signed in before uses its remembered choice either way, with no question. The device
  matches it by origin, and for a note it uses `from` when the card showed a match, else the code's
  `url`.

The device answering a `nostrconnect` note names the grant by `from` when it is set and the card
matched, and by the code's `url` host otherwise.

**What a site does for name-first sign-in** (Discover, Tube and Marble Web follow this):

1. One field: a name (`name@domain`, or a bare `domain` meaning `_@domain`), an npub or nprofile,
   or 64 hex. A name is looked up by NIP-05 to get the account's key.
2. Look up where the account's login page is (section 11.1). Sites keep this in one small function,
   because where the address is published may still change.
3. Found: show the address ("Sign in at account.syb.lol"), and on a click open
   `<login page>/#connect=<encodeURIComponent(nostrconnect://…)>` in a new tab, with no
   `noreferrer`, then keep listening for the signer's answer as for any `nostrconnect://` code. The
   code carries `name` and `url` (the site's own origin), and no `kk=account`.
4. Not found: the site's usual scan code, marked `kk_login=missing` (section 11.1), and a way to
   paste a `bunker://` link. Those stay as fallbacks even when a login page is found.

**A page session has the person's authority, however it was made** (Aaron, 2026-11-17: "the
password *is* the auth"). The box records how it was made (`me` returns `how`: `password`,
`passkey` or `scan`), and today that changes nothing. The page still holds no piece of the key, so two kinds of thing
happen differently:

| The box does it at once | A device does it, with no prompt | A device asks Yes or No first |
|---|---|---|
| See devices, grants, activity | Add a device (`invite` note) | Remove blocked devices for good (`cycle` note) |
| Block and unblock a device | Become a site's signer (`nostrconnect` note) | Publish the sign-in-page pointer naming the box's login page (`pointer` note, section 11.1) |
| Revoke a grant, or limit it to posting (`limit`) | Hand out a `bunker://` link (`bunker` note) | |
| Set or change the password (`pw_set`; it is never removed, section 11.3) | | |
| End its own session, or all page sessions | | |

Forming the whole key is not offered on the page at all: it would put the key in a browser. It
stays in the app.

**The tap.** For the hard-to-undo things a device shows what is asked and the person presses
Yes or No. No fingerprint and no typing. No pushes the request away and ends the page session
that asked. The hard-to-undo things are removing blocked devices for good (cycling), forming the
whole key, and signing the events below.

**Two levels** (Aaron, 2026-11-20). Signing those events comes in two levels:

- **Level 1, Are you sure?** A big unfollow, a relay list trim, a profile losing fields, something
  dated in the future, five or more deletions at once. Yes or No on the device the person is using, as
  above.
- **Level 2, Never by accident.** Erasing the account (kind 62), wiping the profile, emptying the
  follow list, deleting a whole kept list, a list's private part emptied. The answer is No unless the
  person says Yes on the phone, behind the fingerprint. Every other device refuses and says to do it
  from the phone. This revises "no fingerprint and no typing" (2026-11-17) for level 2 only.

Not built: a Yes on the account page, and passing the question from one device to another device or
page.

**Which events, and who decides** (Aaron, 2026-11-20). The box decides. It is a relationship
(the admin, or the admin's friend or family), and that is why disputes between devices are settled
there. For a signature the box takes part in, a device needs no copy of its rules. The rules are in
`src/destructive.ts` (`judge`) and the cases in `vectors/hard-to-undo.json`:

- `sign` for a level 1 event, without `"tapped": true`, is answered
  `{ "error": "needs_tap", "why": "<the question, in plain words>" }`. A device shows `why` to the
  person with Yes and No and, on Yes, sends the same request again with `"tapped": true`. On No
  nothing is signed. A device that cannot ask anyone (a bunker, the command line) fails with the
  words: `needs_tap: <why>`.
- `sign` for a level 2 event, without a valid `fp` (section 4), is answered
  `{ "error": "needs_fingerprint", "why": "<the question>" }`, whatever `tapped` says, and a device
  with no chip key gets `{ "error": "no_chip_key", "why": "<the question>" }`. The answer carries the
  level, so a device needs no copy of the rules to know it, and an account change's refusal has no
  `why`, so the two are told apart. The phone shows `why` with No and Yes; on Yes it takes the
  fingerprint and sends the same request again with `fp`. Any other device shows `why` and that this
  is done from the phone, and sends nothing more. A device that knows only `needs_tap` gets an answer
  it does not ask about, so sending `tapped` can never sign a level 2 event.
- An event the box never signs, Yes or not, is answered `{ "error": "dated_ahead", "why": "<why>" }`.
- A device may ask more on top (Marble keeps its own rules, and a phone sometimes knows a newer
  version of a list than the box). When it has already asked and the person said Yes, it sends
  `tapped` with the first request, so nobody is asked twice for one event, and at level 2 `fp` too.
  When the person said Yes on the phone and the box then answers `needs_fingerprint`, the phone goes
  straight to the fingerprint, with the box's words, without asking Yes or No again.
- **When no box takes part, the device asks by its own rules, and must have them.** That is an
  account with no box (the whole key on the device, section 7) and two devices signing while the box
  is off (section 8g). A box is an upgrade here: it remembers a list's last version for every device
  and settles disputes, but being asked before something hard to undo does not depend on having one.
  At level 2 Marble shows the phone's own fingerprint prompt, with nothing to check it (section 4,
  fallback). A device with no rules of its own asks nothing on those paths (section 10).

What the box asks about, in its words (`<kind>` is the kind's name: profile, follow list, mute list,
relay list, bookmarks, bookmark set and so on, else `kind <n> event`):

| Event | The box | Level | `why` |
|---|---|---|---|
| A list (kind 0, 3, 10000 to 19999, 30000 to 39999) dated more than 600 s ahead | refuses | | `<Kind> dated <day>: a version dated ahead would block every later change` |
| A deletion with an `a` tag dated more than 600 s ahead | refuses | | `Deletion dated <day>: it would delete every version until then` |
| Anything else dated more than 600 s ahead | asks | 1, or 2 when the same event dated now would be 2 | `<Kind> dated in the future (<day>)` |
| A request to vanish (kind 62) | asks | 2 | `Ask relays to erase everything you have ever published` |
| A deletion naming a kept kind by `a` (`kind:pubkey:d`) or `k` | asks | 2 | `Delete your <kind of the first one>` |
| A deletion with five or more `e` and `a` tags | asks | 1 | `Delete <n> of your events` |
| A profile that empties two or more of name, display_name, picture, about, nip05, lud16, banner, website, or leaves none of name, display_name, about, picture, nip05, lud16 filled | asks | 2 when none of those six is left filled (the whole profile goes), else 1 | `Wipe your profile: <the fields emptied>` (`everything` when none were filled before, or there is no earlier version) |
| A kept list whose private part (content not blank and not starting with `{`) is now blank | asks | 2 | `Empty your private <kind>` |
| A kept list of 3 or more entries left with none | asks | 2 for the follow list, else 1 | `Empty your <kind> (it has <n> <items>)` |
| The relay list (10002) or the DM relays (10050), as the account: any change to the relays it names, an addition too, and any version when no earlier one is known (Aaron, 2026-11-21: relay changes are always looked at by hand). Not for a child key, whose relays are its app's | asks | 1 | `Set your <kind> to <relays>` (no earlier version), `Add <relays> to your <kind>`, `Remove <relays> from your <kind>`, `Remove every relay from your <kind>: <relays>`, else `Change your <kind> from <old> to <new>` |
| Another relay list (10006, 10007, 10051, 30002): 2 or more relays removed and at least half, or all of them | asks | 1 | `Change your <kind> from <old> to <new>`, or `Remove every relay from your <kind>: <old>` |
| Another kept list: 10 or more entries removed, and at least a fifth | asks | 1 | `Remove <r> of your <n> <items>s` (and ` (and add <a>)`) |
| A follow list with no `p` tag, whatever came before | asks | 2 | `Empty your follow list` |
| A kept list (not a named set, not the relay list or DM relays) signed for an app or a site (the request names a grant) with no earlier version known, neither the box's nor the device's (Aaron, 2026-11-21) | asks | 1 | `Replace your <kind>: there is no earlier version here to compare it with` |

Where a case sat between the levels, it took level 2: a profile left with only a banner or a website,
or with a name that is only white space; a first profile with nothing in it, or one that is not a JSON
object; a request to vanish, or a list's deletion by `k`, dated ahead. A follow list cut to one person
is a big unfollow, level 1. Emptying a list other than the follow list (mutes, bookmarks, a follow set,
relays) is level 1.

The rows that compare need the earlier version: the last version of that list the box signed, from
its list store (section 6), or the one the asking device sends as `prev` with `sign` when that one is newer.
A device sends the newest version it knows (one it read from relays, say). The box uses it only when it is a
signed event by the same key, of the same list (kind, and `d` for a named set), older than the change, with
an id and signature that hold; otherwise it is ignored. It is compared with, never kept. With none, they say nothing, as on a new phone, except the relay list
and DM relays row, which then asks. A child key's lists (section 8k) are not kept, so only the rows
that need no earlier version apply to a child, and the relay list and DM relays row does not. The
kept kinds are 0, 3, 10000 to 10004, 10006, 10007, 10015, 10030, 30000 to 30004, 30015 and 30030.
Entries are counted as Marble counts them: a follow list's `p` tags with a key, a relay list's `r` and
`relay` tags (a trailing `/` does not count), every other tag but `d`, `title` and `description`.

**One reading of a profile.** The content is exactly one JSON object as Keykin reads kind 0
(`parseJson` in `src/bytes.ts`, numbers by RFC 8259's grammar). A key named twice, a control
character in a string other than `\b \t \n \f \r`, a lone surrogate, a byte order mark, loose JSON
(an unquoted key, single quotes) or text after the object make it no profile at all, which counts as
empty. A field is filled when it is a string with at least one character that is not white space,
a control character or a format character. Anything else (a number, `null`) is empty.

Not asked about yet, and listed as uncaught in the vectors: deleting one article by address, fewer
than 10 entries removed (9 of 30 follows), a list of 1 or 2 emptied, kinds the box does not keep
(10050 DM relays, 10063 media servers, 30078 app data) emptied, and a private part swapped for a
shorter one.

**Notes: things the page starts and a device finishes.**

- The page leaves a note: `note_put { kind, text }`, and for `nostrconnect` also `from` and `as`
  (the sender's origin or null, and `"main"` or `"site"`, above). A device that does not know `as`
  uses the main account, as before. `kind` is `invite` (the text is a new
  device's invite), `nostrconnect` (the text is a `nostrconnect://` code), `bunker` (the text is
  an optional name for the site, section 8c, which the device cleans), `cycle` (no text) or `pointer`
  (no text: the box puts in its own login page address, section 11.1, and refuses with `no_login_page`
  when it has none). A `pointer` note needs no more than a `bunker` note does: any page session. A
  `bunker` or `nostrconnect` note may also carry `lists` and `dms`, the site's two switches ("Read
  your private lists", "Read and send DMs"). Only `true` turns one on; other kinds ignore them. For a
  `nostrconnect` note the account page's sign-in card shows both switches, and "Read your private
  lists" starts on when the code's `perms` name `nip44_decrypt` or `nip04_decrypt`, as a phone's
  scan does (Aaron, 2026-11-20). No device shows a card of its own for a code from the page, so
  without this a site that needs to decrypt, such as Marble Web's vault, was let in with both off.
- `{ op: "notes", account }` from a device returns the waiting ones, each
  `{ id, kind, text, at, tap }`, and for `bunker` and `nostrconnect` also `lists` and `dms` (true or
  false). `tap` is true for `cycle` and `pointer`. The device gives the site those switches when it
  connects.
- `{ op: "notes_wait", account, wait, seen }` is the same call, held open. `wait` is whole seconds;
  the box holds at most 25. `seen` (optional, up to 50 note ids) lists notes this device already has,
  such as a `cycle` note waiting for the person's Yes or No. If a waiting note is not in `seen`, the
  box answers at once, exactly as `notes` would. Otherwise it holds the reply until the account page
  leaves a note for the account or the wait runs out, then answers as `notes` would at that moment
  (`{ ok: true, notes: [] }` when nothing came). The request is checked once, when it arrives. A
  device blocked or removed while it waited gets `blocked` or `unknown_member` and no notes. At most
  4 are held for one account at a time: one more ends the oldest early, with the usual answer. A
  device that hangs up is let go. Keykin Login gives a device's request 35 seconds to come back from
  the box (the page's calls get 20), so keep any proxy in front of it above that (60 seconds is
  usual). An older box answers `unknown_op`; a device then checks with `notes` on a timer.
- The device does it and answers `{ op: "note_done", account, note, result }`. The result is
  the join text for `invite`, the link for `bunker`, `ok` or `declined` for `pointer`, and `ok` for the others.
- For `invite` and `cycle` the device sends the usual `add` or `cycle` with `"note": "<id>"`
  in place of the fingerprint. The box accepts that only while the note is waiting, and for
  `invite` only for the device the note names.
- After a No, the device sends `{ op: "note_refuse", account, note }`, which also ends the page session
  that asked. For `pointer` a No is `note_done` with `declined` instead, and the session stays.
- Notes last 10 minutes. If no device of the account is online, nothing happens: the public
  side has no piece and gets none.
- A sign-in made this way is a grant (section 11.5) on the device that answered, and works
  while that device can be reached.

**Recent activity.** The box keeps the last 60 things that happened to an account (sign-ins to
the page, blocks, revokes, password changes, notes, a No) and when each device and grant was
last used. The page shows them.

**Possible later: tiered sign-in strength (not adopted).** An idea from 2026-11-18, kept for
later. A passkey or a scan would be strong and a password alone weak:

| | Password alone | Passkey or phone scan | A device's Yes/No tap |
|---|---|---|---|
| See devices, grants, activity | yes | yes | |
| Block a device, revoke or limit a site | yes (stopping a thief is never gated) | yes | |
| Sign in to a site | posts and DMs (`limit: dms`) | full | |
| A site's DMs | yes | yes | |
| A site's private lists (the account's own key) | no | yes | |
| Add a device (`invite`), hand out a `bunker://` link | no | yes | |
| Change or clear the password, add or remove passkeys | no | yes | |
| Remove blocked devices for good (`cycle`), empty Trash, purge history | | | yes |

The box has the switch but it is off: `POLICY` in `box/pageapi.ts` maps calls to `strong` (empty
today) and `WEAK_SITE_LIMIT` is null. A weak session asking for a strong call would get
`need_strong`, and the page would then offer to confirm with a passkey or the phone (`pk_login` or
`signin` made while signed in swaps the session for a stronger one). A box owner can switch rows on
with `KEYKIN_POLICY`. The `dms` limit exists for this: it signs posts and DM kinds (4, 13, 14, 15,
1059) and computes message keys with other people's keys only. **Not built:** the page's
"Confirm with a passkey or your phone" prompt, since nothing asks for it today.

**Built (2026-11-19), sessions and the click before a site:** on the box, in Keykin Login and on the
account page. Sessions live in the state file under `sessions`, keyed by the SHA-256 of the token's hex
text; the token itself is only in the browser's cookie. A passkey session's `last` is saved at most
once a minute, so a crash can cost a sliding session up to a minute. An account keeps at most 100
sessions, the least recently used going first, and the activity says so ("A browser was signed out to
make room: an account keeps at most 100 signed in"). Sessions of accounts the box does not hold (made by
`signin`, which takes any key) are at most 1000 in all, the least recently used going first; there is
no activity to tell. A state file over either is brought under it at the next new session. Keykin Login sends `agent` only on the calls that make a
session (`pw_login`, `pk_login`, `signin`, `login_wait`), drops any `agent` the page sends, gives a
passkey session's cookie 90 days and renews it on each `me`, and clears the cookie when
`logout_browser` ends the browser asking (the box answers `{ ok, this }`). A session for an account the
box does not hold also gets `browsers` in `me` and may call `logout_browser`. The card shows the name
and picture from the account's kind 0 on the page's relays (falling back to the username or the npub),
so the page's CSP now allows `https:` images. `note_put` refuses a `from` that is not a bare
`http(s)://host[:port]` origin, or an `as` other than `main` or `site`. Devices acting on `as` and
`from`: Marble on Android does, on the Marble branch `note-site-choice`, not merged yet. Not built: the
command-line device still uses the main account and names the grant as before, and the sites' side of
name-first sign-in.

**Built (2026-11-19), `add=` and the gate:** on the box (`box/box.ts` gates, `approve`; `box/pageapi.ts`
`challenge` and `approval`), the command-line device (`keykin join <join> <code>`), the account page
(`login/static/account.js`; tested in `test/accounts.test.ts` and in a browser in `test/login.test.ts`), Marble
Web (`~/marble`, branch `mac-signin`) and Marble on the Mac (`~/marble-desktop`, branch `keykin`). Not
released or deployed. Marble on Android answers the notes unchanged; a device it adds by a page note now
needs the code to collect its piece, which only matters for apps that join that way.

**Built:** every call above on the box, Keykin Login in front of it (`login/`), and the account page, including the `connect` and `add` link parameters and passkeys. Notes travel end to end. The command-line device answers every kind of note with `keykin agent <relay>` and reports the sites it signs in as grants. The Kotlin core can answer a `nostrconnect` note (`SiteSigner.connect`). Marble on Android answers
`invite`, `bunker` and `nostrconnect` notes with no prompt and asks Yes or No for `cycle`, from its background
service (verified 2026-11-18, with the app closed). On its branch `notes-wait` it keeps one `notes_wait` open
at a time, so a note reaches it within about a second (a bunker note was answered in 0.1 to 0.8
seconds on an emulator, 2026-11-19, with the screen off and in forced Doze), and still checks every 30 seconds as before (that
check also keeps the device list and grants fresh, and is all it does with an older box).

### 11.7 The Shared home section (2026-11-22)

Where the owner and admins of a DMs home manage it, when the home has a box. The home is bothy (mailbox,
members, invite tree); the box keeps its files in Keykin Storage. Agreed with the DMs coordinating session,
2026-11-22. A home with no box keeps bothy's own admin page.

**Settings on Keykin Login.** `KEYKIN_HOME_URL` (the home, `https://<host>/`) and `KEYKIN_STORAGE_URL` (its file
server, optional). Each must be https (http only on this machine, for tests), with no user, query or fragment, or
Keykin Login will not start. With a home set, `me` returns `home: { url, storage }` for an account the box holds,
and the page's `connect-src` names exactly those two origins beside its relays, never all of `https:`. With no home
set there is no section and the headers are as before.

**Signing.** The page calls the home (NIP-86) and the file server (`POST <storage>/manage`, the same shape) itself.
Every call is a NIP-98 kind 27235 (`u`, `method` POST, `payload`), signed by the signer a scan left here (section
11.6, `kk=account`). Keykin Login and the box sign and pass on nothing. A password or passkey session cannot sign, so
the section asks for a scan, once each visit ("Changes here are signed by your phone, so this page asks for a scan
each visit."). No longer-lived signer is kept to avoid that.

**Who.** The home's NIP-11 `pubkey` is its owner; anyone else asks `myrole`, and only `owner` or `admin` sees the
section. An admin signs in with their own Keykin account. Where a person's Keykin key and messenger key differ, the
Keykin key is the one the owner makes an admin.

**What it shows** (plain words; keys, addresses and file hashes only in one Advanced card at the end):

- **People:** the invite tree from `listmembers`, the owner on top, each person under whoever let them in (under the
  owner when the inviter is unknown), names and photos from kind 0 on the home (with NIP-42 if the home asks). Each
  row: space used, "Admin", the switch "Sees where photos were taken" (`setclose`; the page only toggles, bothy
  sets the defaults) and Remove (`unallowpubkey`). Removing someone who invited people offers both choices with the
  count and names, "Keep the N people they invited" and "Remove them too", neither styled as the dangerous one.
  The page offers only what bothy takes: no Remove for the owner or yourself, and an admin gets none for an admin.
  "Recently removed" offers "Let back in" (`allowpubkey`).
- **Rows people can tell apart** (2026-11-22, after Aaron's first look): names from the home, then from the
  account's own relays for anyone still nameless. Each row says how they came in from `source` ("Added by",
  "Invited by", "Asked to join, let in by"), when they joined, what they store or "Nothing stored", and, once
  bothy sends them, `lastSeen` ("Last here 3 Sep", "Never signed in") and `waitingMail`. A row with no name shows
  the last six characters of its key. Rows with no inviter sit under "Added before invites"; members with no name,
  no photo, nothing stored and nobody under them sit under "No name yet", oldest first.
- **File servers are a list** (`KEYKIN_STORAGE_URL` may name several, comma-separated; `me.home.files`), so a
  second box is one more entry. Space leads with what the home stores ("Photos and files: 1.2 MB") and then the
  room left on each box, never the disk's other contents.
- **Space and Bin** (with a file server): storage `usage` and `bin`, the bin by person with Restore (`restore`)
  and, for the owner, Erase now (`erase`, after a confirm). A removed person's files say they come back if they are
  let back in before the date. Until bothy's `memberkeys` lists admins and storage reads it, storage answers only
  the owner, and an admin sees a line saying so.
- **File server** (owner only): `GET <storage>/manage/info` gives its key and the home it follows. Linking
  (`setstorage [url, key]`) first shows the key as an npub to check against the one Keykin Storage prints at start (its logs, or `home key`), and is refused on the page if
  the file server follows another home. Unlinking is under Advanced.

**Built:** `login/server.ts`, `login/static/home.js` (rules and calls, also loaded by the tests), the section in
`login/static/account.js`. Tested against stand-ins that follow the contracts (`test/home-fakes.ts`; bothy v0.28.0
calls, storage `/manage` as agreed) in `test/home.test.ts`, and in a browser with a stand-in phone in
`test/home-page.test.ts`. Not yet tried against a real bothy or Keykin Storage, neither of which has these calls
deployed.

## 9. Not built yet

- **A background service for the phone's site signer** (section 8j).
- **Resetting a lost owner secret.** Today: stop the box, delete the `owner` line from
  `state.json`, start it, and read the new secret from its output.
- **Proof that a chip key lives in a chip.** The Android app's key does, but the box takes the
  public key on trust. iOS (Secure Enclave) is not written.
- **A pasted bunker link on the phone.** The phone's remote signer takes sites in by a scanned
  code only.
- **A phone or a browser helping when the box is off.** Only the command-line device listens.
- **The camera scan on a real phone.** The scanner is wired in but was only exercised through
  pasted and intent-fed codes on an emulator.
- **NIP-04** (old-style messages) and the other NIP-46 methods.
- **Screens for moving an account to another box.** Built in the device cores and on the command
  line only.
- **Limits other than posting only, on the page.** The box also knows `dms` (posts and direct messages, section 11.6), but the page offers only posts only.
- **Paper backup and undo.** Not decided.
- **QRST sign-in to the account page.** It signs in by Keykin's own device login or a password.
- **Firefox and Safari.** The extension is Chromium only.
- **Release builds.** The Android app is a debug build and the extension is unpacked.
- **Child keys beyond the command line** (section 8k). The Android core, the app, the extension and
  the remote signer do not know them yet. So a site or an app cannot be signed in as a child.
- **Showing that a child belongs to the account.** No attestation, in either direction.
- **Tier 3.** Not planned for now.

## 10. Known weak spots

- A thief who can pass the fingerprint check on a stolen phone can form the nsec.
- **A password is now worth the whole account.** Whoever has it can add a device of their own, and from
  then on sign anything. What stands in the way is the guessing limit, and the admin's block and remove.
- The box cannot check that a device really asked before a level 1 signature. It takes the device's word.
- **At level 2 the box checks a fingerprint, not that it came from a phone.** It cannot tell a phone's
  chip key from the command line's software one (section 9, proof that a chip key lives in a chip).
  That only the phone says Yes rests on the other devices never sending `fp` with `sign`.
- **With the box off, only the asking device's own rules stand between a request and a hard-to-undo
  signature.** A helper (section 8g) signs without judging. Marble asks by its own rules, with its own
  fingerprint prompt at level 2 that nothing checks. The Mac app and the command-line device have none,
  so signing through a helper they ask nothing.
- The box compares a list only with the last version it signed. A version signed while the box was
  off (section 8g), or by another signer, is not known to it, so it may compare with an older one.
- Anyone who can reach the public door can ask for accounts (up to 50 waiting), start sign-in codes,
  sign in with keys of their own (up to 1000 sessions for keys the box does not hold, pushing out older
  ones), and keep a username locked by guessing wrong. None of that reaches a key, but it can be a nuisance.
- The side port and, behind another login, the admin page trust the network they are on. On an Umbrel,
  another app on the same machine could reach them.
- Logging in to the account page by scanning trusts the person to scan only their own page.
  A device refuses a code from any other box, but a code shown by someone else's browser on the
  same box would log that browser in.
- A device that listens for others trusts the list it last saw. If the box is off, it cannot
  learn of a new block.
- **A box that lies can hand out a wrong child key** (section 8k). A device cannot check the box's
  part of the tweak, so a wrong part gives a key that signs today and cannot be made again later
  with an honest helper. Making the child once more with a second device as the helper, and
  comparing, would catch it. Nothing does that yet.
- **A request for a child names the account and the child together**, so whoever can read the
  traffic to the box, and the box itself, can tie them.
- The box's piece sits in its state file unencrypted.
- Requests travel as plain HTTP. The address is meant to be a tailnet one. Secrets inside
  requests are sealed (section 5), so an open network would expose the member list and the
  events being signed, not pieces.
