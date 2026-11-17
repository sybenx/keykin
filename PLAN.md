# Plan: Marble, Keykin Login, Keykin Box

Agreed with Aaron on 2026-11-17 in a side session. This is the target. `SPEC.md` still describes
what is built today.

## The four things

| Thing | Where | What it does |
|---|---|---|
| **Marble app** (Android) | His phone | Holds a piece, signs with the box, fingerprint for account changes, signs for other apps and sites |
| **Marble** | `marble.syb.lol` (Cloudflare) | Search and notes. Gains an account button |
| **Keykin Login** | `account.syb.lol`, Umbrel app 1, public behind a reverse proxy | The account page |
| **Keykin Box** | Umbrel app 2, tailnet or local only | The admin page, the pieces, the signing |

The browser extension waits until later. It may not be needed (see "Signing in from a desktop
browser").

## How they connect

- **Phone to Login to Box.** Devices send their signed requests to the public address. Keykin
  Login forwards only those to the box over Umbrel's internal network. It holds no piece and no
  device list.
- **Marble to Login.** Marble's account button reads a small event, signed by the account,
  that names the person's login page. It shows the address, then sends them there. Marble never
  handles the login. It is the accounts.google.com idea: the login page does not share an origin
  with Marble.
- **Stopping Keykin Login** shuts the outside door. The box, the admin page and tailnet devices
  keep working.

## Keykin Login: the account page

In the style of Google's account page: clear sections, plenty of options, nothing hidden.

- **Signing in to the page:** by QR (a device scans and approves with a fingerprint), or by
  username and password.
- **What it shows and does:** devices, what is signed in (sites and apps), revoke, block a
  device, backup options, undo, add a device, sign in to sites.
- **Rule for powers (changed later on 2026-11-17):** a page session has the person's
  authority, however it was made. "The password *is* the auth." Only really destructive,
  hard-to-undo changes need a tap on a device: a Yes or No on a notification, no fingerprint.
  Those are forming the whole key, removing blocked devices for good, a vanish request, a mass
  delete, and emptying the profile or follow list. No ends that browser's session.
- **The case this is for:** phone left at home but online, he signs in to the account page from
  a work PC with username and password, and uses Nostr there. The phone answers in the
  background with no prompt.
- **Still true:** the public side holds no piece, so a device must be online for each
  signature. Undo and veto stay with the box admin.

## Keykin Box: the admin page

- **Many accounts on one box.** Today's box holds exactly one. This is new work.
- **Approving accounts.** Anyone can ask to make an account on the box, or to transfer an
  existing one to it. Nothing happens until the admin approves it here.
- **Special powers that need no device:** setup, Unblock, removing an account, the owner login.
- Never served on the public side. The admin code is not in the Keykin Login container at all.

## Marble app

- **All the signing wiring, ready to use:** create or join an account, sign, encrypt, sign for
  other apps (NIP-55), sign in to sites by scanned code, fingerprint (chip key) for account
  changes.
- **Keep what made Marble convenient.** A lot of work went into backup, undo, seeing what is
  logged in, revoking, and the rest. Changing how the pieces work must not lose it. Move each
  feature over to the "any two pieces sign" design; do not delete it. Where a feature cannot
  carry over as it is, say so and propose the nearest equivalent before dropping anything.
- The device code to build on is the Kotlin core in `android/` here. The app to put it in is
  Marble, in the cosign repo.

## Signing in from a desktop browser

Aaron would like to skip the extension if a bunker from the account page can do the job.

- **What he means by bunker:** NIP-46 both ways. The account page hands out a `bunker://` link
  to paste into a site, and takes a `nostrconnect://` code that a site shows.
- **What works with no extension:** either of those from the account page, plus the scanned-code
  sign-in already built in `src/ticket.ts`, where the site gets its own remote-signer access.
- **The catch:** every signature still needs a device to take part, since the public side holds
  no piece. So a bunker from the account page works while a device of the account can answer.
- **Not on the table:** giving the public side a piece of its own so it can sign with the box
  with no device. That would be two servers signing alone.

## Shared formats to settle first

Both the Keykin work and the Marble work depend on these. The Keykin session decides them and
writes them into `SPEC.md` before either side builds against them.

1. **The login-page pointer.** A small replaceable event signed by the account, naming its
   login page URL. Not a field in the main profile.
2. **Account ids on a many-account box**, and how a device request names its account.
3. **Username and password:** where they live (the box), how they are stored, and the limits on
   guessing.
4. **The request to make or transfer an account,** and what the admin sees when approving.

## Open decisions for Aaron

- **Paper backup.** Under "any two pieces sign", one paper piece does nothing alone. Options: a
  paper piece that works with the box after a wait, or the whole key on paper formed by
  fingerprint. Not decided.
- **The reverse proxy.** Cloudflare tunnel or Pangolin. Either is fine with him.

## Who does what

- **Keykin session** (the one that built the box): the two Umbrel apps, the account page, the
  admin page, many accounts, the shared formats, the reverse proxy.
- **Marble session** (in the cosign repo, in its own worktree): the Marble Android app and the
  account button on `marble.syb.lol`.
- Either may test on Aaron's Pixel 9a over adb. The wireless debugging port changes each time.

## Where things stand today

- The box runs on ambrel inside the Umbrel app `marble-server`, as one app serving one account,
  with the admin page behind the Umbrel login and `/keykin` let through.
- Keykin's own debug app (`cc.aaro.keykin`) is installed on the Pixel. Marble is a separate app.
