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
| `sign` | An unblocked device | No | Answers a signing round for an event of this account, or of one of its child keys (section 8k) |
| `ecdh` | An unblocked device | No | The box's part of a shared secret with another person's key (section 8a), as the account or as a child key |
| `members` | Any unblocked member | No | Returns the list, the epoch and the next unused index |
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

## 8d. The command-line device

`cli/keykin.ts` makes a computer a device: `create`, `import`, `forget-key`, `invite`, `add`,
`join`, `status`, `sign`, `child`, `block`, `unblock`, `cycle`, `serve`, `agent`, `bunker`, `scan`, `sites`,
`signout`, `login`, `nsec`, `transfer`, `moved`. Its state is one file, `~/.keykin/device.json`,
readable only by its owner. The piece in it is not encrypted.

- `keykin agent <relay>` stays on and does what the account page asks (section 11.6): it adds a
  device, hands out a bunker link, becomes the signer for a pasted `nostrconnect://` code, and asks
  Yes or No at the keyboard before removing blocked devices (with nobody there, the answer is No).
- `keykin transfer '<setup code of the new box>'` moves the account to another box (section 11.4).
  The old box is the one the device uses now. It saves the new address and box key and prints a
  join text for the other devices.
- `keykin moved '<join text>'`, on each other device of the account, switches its saved address
  and box key to the new box. It checks that the join text is for this account and that the box at
  that address has that key. The piece is not touched: it catches up on the next request (`stale`).

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

A block made while the box is off does not reach a helper until the box is back. A helper does not
check grants at all: a revoke or a limit (section 11.5) is kept only by the box.

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

A small replaceable event, signed by the account, that names its login page. It is the only
thing `marble.syb.lol` reads to find where to send someone.

```json
{ "kind": 30078, "pubkey": "<account npub, hex>", "created_at": 1790000000,
  "tags": [["d", "keykin/login"], ["url", "https://account.syb.lol"]],
  "content": "" }
```

- Kind 30078 is NIP-78 application data, so no new kind is claimed. The `d` tag is exactly
  `keykin/login`.
- `url` is the page's origin, `https://` only, no path, query or fragment.
- To find it: `{ "kinds": [30078], "authors": ["<npub hex>"], "#d": ["keykin/login"] }`, newest
  wins. A reader checks the signature, shows the address to the person, and only then goes there.
- To remove it, publish the same event with no `url` tag.
- A device signs it like any other event (section 3). The account page offers to publish it.

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
  the stored hash above, hex. `{ op: "password_clear", account }` with a fingerprint removes it.
- **Logging in** is two calls from the page to the box (section 11.6):
  `pw_salt { username }` returns `{ salt }`, and `pw_login { username, verifier }` returns a page
  session. For a username that does not exist, `pw_salt` returns a salt made from the username
  and a secret of the box's, so it gives nothing away.
- **Limits on guessing:** five wrong tries for one username lock it for 15 minutes, doubling each
  time up to 24 hours; a right password clears the count. Across all usernames the box takes at
  most 30 tries a minute.
- **The page can set it too:** `pw_set { username, salt, check }` with a page session, and
  `pw_clear`. The page's own script computes the verifier.
- **What a password is worth:** the whole account (section 11.6). The limits on guessing are
  what stands between a guesser and that.

**Built:** the box, both device cores (`passwordSet`), and the account page's sign-in. No app has a screen for setting it yet.

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
   in its place. The device must be an unblocked device on that list.
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
  `name` is the site's origin or the app's name. `since` is unix seconds.
- A device sends `{ op: "grants", account, grants: [...] }` with its whole list whenever it
  changes. The box keeps the list per device.
- When a device signs or makes a message key **for** a site or app, it names the grant:
  `"grant": "<id>"` in the `sign` or `ecdh` body. Requests for the person's own use carry none.
- **Revoking** is done on the box, from the account page or by any device:
  `{ op: "revoke", account, grant }`. From then on the box answers `revoked` to any request
  naming that grant, from any device. This is what makes a revoke stick even if the device that
  let the site in is offline.
- The answer to `grants` includes `revoked: [ids]`, so the device drops them from its own list.

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
Kotlin core's site signer (`SiteSigner`) gives each site a grant and names it. **Not wired:** the
Android app does not report its grants to the box yet.

### 11.6 The account page's calls, and what needs a device

Keykin Login is a public page with no piece and no list. It passes two kinds of thing to the
box and nothing else: device requests (`POST /keykin`, unchanged), and the page's own calls
(`POST /page`). The box is the one that knows who is logged in.

**Logging in to the page** gives a page session, a random token the box issues for 12 hours:

- by password (section 11.3), or
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
answers `not_open` and the account needs a code from the admin page.

**A page session has the person's authority, however it was made** (Aaron, 2026-11-17: "the
password *is* the auth"). The page still holds no piece of the key, so two kinds of thing
happen differently:

| The box does it at once | A device does it, with no prompt | A device asks Yes or No first |
|---|---|---|
| See devices, grants, activity | Add a device (`invite` note) | Remove blocked devices for good (`cycle` note) |
| Block and unblock a device | Become a site's signer (`nostrconnect` note) | |
| Revoke a grant, or limit it to posting (`limit`) | Hand out a `bunker://` link (`bunker` note) | |
| Set, change or clear the password (`pw_set`, `pw_clear`) | | |
| End its own session, or all page sessions | | |

Forming the whole key is not offered on the page at all: it would put the key in a browser. It
stays in the app.

**The tap.** For the hard-to-undo things a device shows what is asked and the person presses
Yes or No. No fingerprint and no typing. No pushes the request away and ends the page session
that asked. The hard-to-undo things are:

- removing blocked devices for good (cycling), and forming the whole key;
- signing an event that asks relays to erase the account (kind 62);
- signing a delete of five or more posts at once (kind 5 with five or more `e` or `a` tags);
- signing an empty profile (kind 0 with no name, about or picture) or an empty follow list
  (kind 3 with no `p` tag).

For the three kinds of event, the device sends `"tapped": true` with `sign` once the person
said Yes. Without it the box answers `needs_tap`. `src/destructive.ts` and `Destructive` in the
Kotlin core are the test both sides use.

**Notes: things the page starts and a device finishes.**

- The page leaves a note: `note_put { kind, text }`. `kind` is `invite` (the text is a new
  device's invite), `nostrconnect` (the text is a `nostrconnect://` code), `bunker` (no text) or
  `cycle` (no text).
- `{ op: "notes", account }` from a device returns the waiting ones, each
  `{ id, kind, text, at, tap }`. `tap` is true only for `cycle`.
- The device does it and answers `{ op: "note_done", account, note, result }`. The result is
  the join text for `invite`, the link for `bunker`, and `ok` for the others.
- For `invite` and `cycle` the device sends the usual `add` or `cycle` with `"note": "<id>"`
  in place of the fingerprint. The box accepts that only while the note is waiting, and for
  `invite` only for the device the note names.
- After a No, the device sends `{ op: "note_refuse", account, note }`.
- Notes last 10 minutes. If no device of the account is online, nothing happens: the public
  side has no piece and gets none.
- A sign-in made this way is a grant (section 11.5) on the device that answered, and works
  while that device can be reached.

**Recent activity.** The box keeps the last 60 things that happened to an account (sign-ins to
the page, blocks, revokes, password changes, notes, a No) and when each device and grant was
last used. The page shows them.

**Built:** every call above on the box, Keykin Login in front of it (`login/`), and the account page. Notes travel end to end. The command-line device answers every kind of note with `keykin agent <relay>` and reports the sites it signs in as grants. The Kotlin core can answer a `nostrconnect` note (`SiteSigner.connect`). **Not wired:** the phone app does not look for notes or report grants yet.

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
- **The Android app answering the account page's notes, and reporting grants** (sections 11.5 and
  11.6). The Kotlin core has the calls; the app does not use them yet.
- **Screens for moving an account to another box.** Built in the device cores and on the command
  line only.
- **Limits other than posting only.** A grant is either limited to posts or not limited.
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
- The box cannot check that a device really asked before a hard-to-undo signature. It takes the device's word.
- Anyone who can reach the public door can ask for accounts (up to 50 waiting), start sign-in codes, and
  keep a username locked by guessing wrong. None of that reaches a key, but it can be a nuisance.
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
