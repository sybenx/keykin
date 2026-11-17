# Keykin v2

Draft 0.4, 2026-11-17. The direction and the reasons are in `DIRECTION.md`. This file says what
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

- **Sign in with your signer (QRST).** When the box is given relays (`KEYKIN_RELAYS`), its login
  page is a site like any other: it shows a sign-in code (section 8j), a device in the account
  answers it, and the page then has the account sign the box's challenge (a kind 22242 event
  naming this page's origin and a one-time challenge tied to this browser). The box logs the
  browser in if that signature is by this box's own account. Any other account is refused.
- **Log in by scanning, without relays.** With no relays set, the login page shows a code of
  Keykin's own instead:
  `{ keykin: 2, login: { addr, key, code } }`. A device in the account scans it and, after a
  fingerprint, sends `login` with the code. The page, which has been asking the box whether its
  code was approved, is then logged in. A code lasts three minutes, works once, and only for the
  browser that was shown it. A device accepts a login code only from its own box.
- **Behind another login** (`KEYKIN_BEHIND_LOGIN=1`), the page asks for nothing itself and the box
  makes no owner secret. This is for a box whose page can only be reached through something
  that already asks who you are, such as an Umbrel app's login.
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
| The box page as a site | `site/box-login.ts`, built to `box/static/signin.js` |
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

**Built:** not yet. Today's box holds one account and ignores `account`.

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
- **What a password is worth:** only what section 11.6 lists as needing no device.

**Built:** not yet.

### 11.4 Asking to make or transfer an account

Anyone who can reach the box may ask. Nothing is made until the admin approves it on the box's
admin page.

**Asking.** A device sends `ask`, signed by its member key like any request:

```json
{ "op": "ask", "what": "make", "name": "Pixel 9a", "note": "Aaron's phone", "chip": "<chip key>" }
```

- `what` is `make` or `transfer`. A transfer also carries `"account": "<npub hex>"`.
- `name` is the device's name, up to 60 characters. `note` is free text for the admin, up to 200.
- The answer is `{ ok: true, request: "<id>" }`. One member key may have one request waiting.
  The box keeps at most 50 waiting and drops those older than seven days.

**Waiting.** The device sends `{ op: "asked", request }` to hear the state: `waiting`,
`approved`, `refused` or `gone`. An approved request can be used for 24 hours.

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
4. The device sends the new box `{ op: "transfer2", request, welcome, account: { npub,
   commitment, epoch, next, members } }` with a fingerprint. The new box builds its piece, checks
   it against the commitment, and stores the account with the old box left out of the list.
5. The device cycles the keys on the new box (section 8f). The old box gets no change, so its
   piece stops fitting. Other devices are told the new address with a join text.

**Built:** not yet. Today the admin page shows one setup code and nobody asks.

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

**Built:** not yet. Today each device keeps its own list and the box knows nothing of it.

### 11.6 The account page's calls, and what needs a device

Keykin Login is a public page with no piece and no list. It passes two kinds of thing to the
box and nothing else: device requests (`POST /keykin`, unchanged), and the page's own calls
(`POST /page`). The box is the one that knows who is logged in.

**Logging in to the page** gives a page session, a random token the box issues for 12 hours:

- by password (section 11.3), or
- by a device: the page shows `{ keykin: 2, login: { addr, key, code } }`, a device sends
  `{ op: "login", account, code }` with a fingerprint, and the page's next `login_wait { code }`
  returns the session. (Section 6a, now per account.)

Both give the same session. **How someone logged in never widens what the page can do.**

| The page may, with a session alone | Needs a device's fingerprint |
|---|---|
| See devices, grants and the account's npub | Add a device |
| Block a device | Unblock a device |
| Revoke a grant | Sign anything, or make a message key |
| End its own session, or all page sessions | Cycle the keys |
| | Form the whole key |
| | Set, change or clear the password |

Everything in the left column only ever reduces access.

**Things the page starts and a device finishes.** The page can leave a note for the account's
devices, and a device that sees it asks the person and does it with a fingerprint:

- `{ op: "notes", account }` from a device returns the waiting notes.
- A note is `{ id, kind, text, at }`. `kind` is `nostrconnect` (a `nostrconnect://` code the
  person pasted into the page: the device becomes that site's signer), `invite` (a new device's
  invite text: the device adds it) or `bunker` (asking for a `bunker://` link: the device makes
  one and answers).
- A device answers with `{ op: "note_done", account, note, result }`. For `bunker` the result
  is the link, which the page then shows.
- Notes last 10 minutes. A `bunker://` or `nostrconnect://` sign-in made this way is a grant
  (section 11.5) on the device that answered, and works while that device can be reached.

**Built:** the device login of section 6a, for one account. The rest is not built.

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
