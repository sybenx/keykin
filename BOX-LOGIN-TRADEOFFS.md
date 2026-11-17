# Box login: what QRST sign-in gives up

Written 2026-11-17, after commit `6f53370` (sign in to sites by a scanned code).

The box page has two ways to log in. It shows one or the other.

| Setting | Login the page shows |
|---|---|
| `KEYKIN_RELAYS` not set | Keykin's own scan-to-log-in (the old one) |
| `KEYKIN_RELAYS` set | QRST sign-in, `signer-ticket` profile (the new one) |

Nothing was removed from the code. These are the things the box login loses when the new one
is switched on.

## 1. The fingerprint

- **Old:** the phone's chip key signs after a fingerprint, and the box checks that signature.
- **New:** no fingerprint. You scan, tap allow, and the account signs the box's challenge.
- **Why it matters:** the box owner's Block and Unblock buttons sit behind this login. The
  tiers table says unblocking a device needs a fingerprint each time. Unblocking from a device
  still asks for one. Unblocking from the box page, reached by the new login, does not.

## 2. Knowing which device logged in

- **Old:** one named, unblocked device approves the login. The box log names it.
- **New:** the box only learns that the account signed. The log says "login by the account,
  through its signer" and no device name.

## 3. Working with no relay

- **Old:** phone talks straight to the box over the tailnet. No relay involved.
- **New:** needs a `wss://` relay that both the browser and the phone can reach.
- **Why it matters:** DIRECTION.md says coordination stays off public relays. The new login
  fits that only if the relay is one of Aaron's own.

## 4. A one-shot approval

- **Old:** the phone approves one browser, once. The browser never gets signing access.
- **New:** the page gets general signing access to the account for a moment. It asks for one
  signature (the challenge), then closes its connection.
- **Left behind:** the box page stays in the device's list of sites until it is signed out
  there.

## 5. Blocking is weaker for login

- **Old:** the box refuses a blocked device directly, because the device itself asks the box.
- **New:** the box checks only the account's signature. A blocked device can still log in if a
  second device helps it sign without the box.

## The fix (not built)

- The device asks for a fingerprint before it answers a code from its own box.
- The box checks that chip signature alongside the account's signature.

This restores 1 and 2 and keeps QRST. It does not change 3 or 4. For 5, the box could then
refuse a chip signature from a blocked device.

## Until then

Leave `KEYKIN_RELAYS` unset on the box. Use the new sign-in for other sites only.
