# Keykin direction: Marble on the Mac

Direction note, 2026-11-19. Proposed, not agreed. Written up from a conversation with Aaron
about how a Mac should be a Keykin device. Nothing in the spec or code has changed.

The password manager idea from the same conversation is parked ("a cool idea for another
day") and written up elsewhere with the master and child work. It is not part of this note.

## The direction

**The Mac's device is Marble for the desktop (`~/marble-desktop`), made better.** Not a new
app, not the Terminal program, not the browser extension on its own. Marble is a search app
with notes, and the Mac app already is one.

Aaron: "a little search box and notes on my mac. we already have a mac app, it could just be
better."

## What the Mac app is today (0.1.0, last changed 2026-10-27)

- **A search box you summon** with ⌥ Space. Enter searches, and results open in Marble.
- **Later**, the list of things you saved, kept on the Mac and synced through one encrypted
  kind 30078 event (`d` = `marble/later`).
- **A marble icon in the menu bar** that opens a menu: Open, Later, Settings, Quit.
- **Sign-in on the old Cosign servers.** The Mac made its own three parts, kept in the login
  keychain, and signed with a Cosign server.

## What changed on the phone since then

- **0.13.0:** accounts moved from Cosign to Keykin. Cosign accounts do not carry over.
- **0.15.0:** notes moved into a vault: encrypted, kept on his own relays and Blossom servers,
  the same on every device, with versions for clashing edits, Trash, and a new key after a
  device is removed and the keys cycled. Marble Web opens the same vault.

So the Mac app can no longer sign in to Aaron's account, and its Later is not the phone's notes.

## What "better" means

1. **Clicking the marble in the menu bar opens the search box.** Aaron's picture of it. The
   menu (Later, Settings, Quit) moves to a right-click.
2. **Sign in with Keykin.** The Mac becomes a Keykin device of the account, like the phone: it
   shows an invite, the phone or the account page adds it, and it joins. Its piece stays in the
   login keychain, behind Marble's own Touch ID or password check as today.
3. **Notes from the vault.** The Mac reads and writes the same notes vault as the phone and
   Marble Web, with versions and Trash. "Later" becomes "Notes" to match the phone.
4. **Keep the box's design.** The small box, the Save button and the results window stay as
   they are, unless Aaron asks otherwise.

## Sign in, as built (2026-11-19)

Aaron, on the first sign-in screen (an invite to copy and a join code to paste): "where's the QR? where's
the magic 'click sign in' and it opens a website and comes back signed in?", then "the simpler answer is
'sign in' opening a web page and we use the same wiring built into marble.syb.lol. nothing has to live in
the actual app", and "it should be easier". Then the red team: with a plain `add=`, anyone could put their
own invite in a link, and a press of Add on the real account page would let their device in. So it is
OAuth for native apps (RFC 8252 with PKCE):

- **The Mac app holds no sign-in logic.** Settings, Sign in makes the invite, a PKCE verifier and a state,
  listens on `http://127.0.0.1:<random port>/` for ten minutes, and opens
  `https://marble.syb.lol/#challenge=…&return=http://127.0.0.1:<port>/done&state=…&add=<invite>`.
- **Marble Web does the finding**: the account its browser is signed in as (then straight on), else the
  name typed, then the login page the account names. It carries the four on. With no login page, it shows
  the invite as a QR for the phone's Add a device.
- **The account page asks once**: "Add Marble on Mac to your account?", Add or Not now. On Add it leaves
  the `invite` note with the challenge; a device adds the Mac; **the box holds the Mac's piece** until it
  sees the approval code with the verifier (hashed, one use, 10 minutes, 5 tries). The page gets the code
  and sends the browser back to the loopback address only (127.0.0.1 or localhost), and keeps six digits
  to type if that fails.
- **The Mac** checks the state, collects its piece with the code and the verifier, and says who it is
  signed in as. No Touch ID at join: the Add is the yes. The piece stays in the keychain item only Marble
  reads.
- "Type a code instead" on the Mac takes the six digits and the page's address, or a phone's join code.
- Devices, Add a device (a pasted invite) goes through the same gate with the six digits alone: the
  weaker, typed path, said so in the spec. Phone-scan adds are unchanged.

Spelled out in SPEC section 7 and 11.6 (Keykin branch `mac-add`). Marble Web's part is on the Marble
branch `mac-signin`, the app's on marble-desktop `keykin`. Not released or deployed yet.

## Later, not now

- **The Mac helping when the box is off,** and answering the account page in the background,
  as `keykin agent` and `keykin serve` do. The Mac app is always running, so it is a natural
  place for both.
- **The Mac as the box** ("Proposed: a computer as the box" in `DIRECTION.md`).
- **The browser extension asking the Mac app** instead of holding its own piece.
- **A real chip key.** The Secure Enclave can hold one behind Touch ID, but asking for it from
  the keychain needs Apple developer signing, which the app does not have.

## Open questions

1. **Which code the Mac uses for Keykin.** The TS core in `~/keykin/src` fits the app's
   TypeScript side; the Rust FROST crate already runs in its Rust side.
2. **Does a Mac signed in on Cosign need a way out?** Probably not: Aaron's account is on
   Keykin now.
