# Keykin direction: no public servers

Direction note, 2026-11-16. Aaron's call, written up from a conversation. Nothing in the spec
or code has been changed yet. Spec facts are from Core draft 14.26 on
`claude/keykin-spec-0b883d`, read today.

## The direction

- **Keykin does not use public FROST servers.** You sign with devices you own, or with boxes
  run by people you personally trust. If you have neither, you do not get Keykin.
- **A friend's box is fine** (Aaron, 2026-11-16). It is not a public server.
- **Coordination stays off public relays.** Devices talk over a private path: a tailnet by
  default, or a relay you run yourself.

## Why

- **Nobody has a reason to run a public FROST server.** A relay holds posts and people its
  operator cares about. A FROST server holds one opaque key piece per stranger and nothing
  else. Running one is a public good with no reward.
- **Pomegranate shows where that leads.** Its operators are client teams who run one to get
  sign-ups. On 2026-11-16 the five default operators answered `/po/info` like this:

  | Operator | Answer |
  |---|---|
  | `po.njump.me`, `po.coracle.social` | Google only |
  | `po.yakihonne.com`, `po.f7z.io`, `po.jumble.social` | 404, most likely a build older than 2026-10-05 |

  Nobody had enabled secret mode six weeks after it shipped. The "old build" reading is an
  inference from the 404, not confirmed with the operators.
- **Public relays block coordination traffic.** Damus spam-blocked Keykin's messages earlier.
- **It fits the 2026-11-10 decision.** Keykin is for Aaron and Marble, not for reach.

## The setup (settled 2026-11-16)

Aaron's words: "my devices and my box", simple and easy. This replaces the weighted version
with home and away boxes, seats, the paper and the helper that this note held earlier.

The whole thing in three lines (Aaron, 2026-11-16):

- **I have devices, and they can sign together.**
- **It is more secure than a raw nsec because most devices do not hold the full nsec.** After
  the later change below, none does unless you ask for it with a fingerprint.
- **I also have a magical login page that lives on a friend's box.**

Build tiers 1 and 2 only. Tier 3 is not being built now.

### Pieces

- **Every device holds one piece of the key. Every box holds one piece.**
- **Any two pieces sign.**
- **There are no weights and no limits.** Add as many devices and boxes as you want. A box is
  just another piece.

| Who is asking | Result |
|---|---|
| Phone plus the box | Signs |
| Two devices, no box | Signs |
| Two boxes | Signs |
| One piece alone | Nothing |

### Creating the key (changed later on 2026-11-16)

- **You scan a QR on the box.** Your device and the box make the pieces together, right then.
- **The nsec is never raw on any device.** Nobody generates it and nobody holds it. It exists
  only as pieces.
- **Falling back to the nsec needs a fingerprint.** The box then hands its piece to that
  device, and the device forms the nsec. This is the only time a whole key exists.
- **Adding a device never forms the key either.** An existing device and the box each give
  half of the newcomer's piece.

This replaces the earlier idea of a primary device that generates the nsec and keeps it.

### Who acts as central

- **The box,** because it keeps the list of devices. Later, in tier 3, it would also
  coordinate the passkeys the other devices use.
- **No device is special.** With no primary device holding the nsec, any device with a
  fingerprint can add another.

### The box

- **One always-on machine, wherever it is.** For Aaron it is a friend's box. A second box is a later question and needs no
  new rules.
- **It never starts a signature.** It only helps a device that asks.
- **It serves the login page.** The page shows the list of devices with a Block button next
  to each.
- **Login to that page is by QRST.** Built so far: a device in the account scans a code on the
  page and approves with a fingerprint. The QRST protocol itself is not used yet.

### A lost phone

- **The phone's screen lock is the guard.** A locked phone is useless to a thief.
- **The box owner can block it:** log in to the box's page and press Block.
- **Aaron can block it** from any other device. That device tells the box, and the other
  devices stop helping the phone too.
- **Blocking is one press.** Unblocking or adding a device needs an approval from a device
  still in hand.
- **The box can always put it right.** A thief with an unlocked phone can block the other
  devices first. That was always true. The box owner logs in, blocks the phone and unblocks
  the rest.
- **Cycle the keys afterwards,** which makes the lost phone's piece worthless.

### What this simple version gives up

- **Box off:** a lone phone cannot sign until the box is back or a second device is awake.
- **Every device lost, first device included:** one box's piece cannot bring the account back.
  A second box can, since two boxes sign.

### Tiers

| Tier | What it is | Who it protects against | Build now? |
|---|---|---|---|
| 1. QRST | The nsec, copied between devices. Reached from tier 2 only by a fingerprint | Nobody | Yes (exists) |
| 2. Multi-device | Pieces on devices and boxes, no prompts | A stolen or hacked device, once blocked | Yes |
| 3. Fingerprint | Tier 2, plus the box wants a fingerprint before it helps | A stolen unlocked phone, and malware that cannot touch the sensor | No, later |

### Build order

1. Tier 1, QRST (exists).
2. Tier 2, devices plus the box and its login page, including the chip key so that adding or
   unblocking a device needs a fingerprint.

Stop there.

## Later: tier 3 (not being built now)

Kept for when it is wanted. Nothing in tiers 1 and 2 depends on it. Tier 3 would be a setting
on the boxes, with the same pieces as tier 2.

The chip key for account changes is **not** parked. Adding or unblocking a device needs a
fingerprint in tier 2 (Aaron, 2026-11-16), so the chip key is built with tier 2. Only the
fingerprint on everyday signing waits for tier 3.

### Where the fingerprint would be required

| Action | Tier 2 (default) | Tier 3 (opt-in) |
|---|---|---|
| Posts, likes, replies, reposts | No prompt | One fingerprint unlocks a session of about 12 hours |
| Profile, follow list, deletes, DMs | No prompt | Fingerprint each time |
| Add a device, unblock a device, change boxes, switch tiers | Fingerprint each time | Fingerprint each time |

- **Account changes need a fingerprint in every tier,** because they are how an account is
  taken for good, and they are rare.
- **The check is forced, not pretend.** The device holds a P-256 key inside its secure chip.
  The chip signs only after a fingerprint, and the box verifies that signature.
- **A FROST share cannot do this.** Phone chips do not support secp256k1 or Schnorr, so a
  share is always used in app memory.
- **Use a native chip key, not a web passkey:** fingerprint or face only, no PIN, bound to
  the phone, not synced.
- **Browser extensions** can only use a web passkey or a YubiKey, which the app labels as the
  weaker kind. The alternative is approving from the phone.
- **A device with no chip or fingerprint** signs in tier 2 but cannot approve account changes
  alone.
- **Skipped:** a fingerprint on every signature, and attestation that the key sits in a chip.


## Transport

- **The protocol says "an address", not "Tailscale".** A tailnet address is the default for
  Aaron's setup.
- **A private relay works just as well** against the spam-block problem, and Aaron already
  runs two.
- **Costs of a tailnet-only setup:**
  - every device must be on the tailnet with it switched on;
  - iOS allows one VPN at a time;
  - Tailscale's coordination service becomes a dependency (Headscale is the way out).
- **Websites are the catch.** A site using NIP-46 needs a relay its page can reach. A
  tailnet-only relay works only in browsers on Aaron's own devices. NIP-07 and NIP-55 need no
  relay, so the extension and the Android signer are unaffected.


## Open questions

1. **NIP-46 for websites off the tailnet.** Either a small relay exposed publicly, or accept
   that remote-signer sign-in only works on Aaron's own devices.
2. **A secure chip on the box.** Aaron wants a secure-module equivalent on boxes if there is
   one, and is not sure a TPM is it. A TPM cannot sign with the piece (no secp256k1). It can
   only seal the piece to that machine so a copied disk is useless elsewhere, and a VPS
   usually has none.

## Spec

Either cut the current spec down or call this Keykin v2. Aaron does not mind which, since git
history keeps the old one. The current spec (Core draft 14.26) is built on weights, seats,
paper and the helper, all dropped here.

## Dropped

- Weighted pieces, a threshold of 4, home and away boxes, server seats, the paper backup and
  the helper. They are in this file's history and in Core draft 14.26 if ever wanted.

## Not decided here

- Anything about Pomegranate. The login page and the upstream issue are separate questions.
