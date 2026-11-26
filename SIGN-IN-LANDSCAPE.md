# Sign-in: what it is and where it lives (2026-11-25)

Three looks, to settle the identity of the shared sign-in: a universal sign-in, a sign-in attached to
Keykin boxes, or the sign-in flow Nostr apps should use. Condensed from three agent reports. V = the agent
opened the page; U = snippet or memory only. Nothing here is decided.

## 1. Universal sign-in for any site: crowded. Ruled out.

- Passkey-first sign-in is already sold and given away: Hanko (free to 10,000 monthly users, V
  https://www.hanko.io/pricing), Clerk (V), Better Auth passkey plugin (U).
- "One account anywhere" died once: Mozilla Persona, shut 2016-11-30, "usage is low" (V
  https://wiki.mozilla.org/Identity/Persona_Shutdown_Guidelines_for_Reliers). Credible newcomer: AT Protocol
  OAuth (V https://atproto.com/blog/network-account-management).
- Only ground left: a component other sites embed. A different business.

## 2. Sign-in from a box someone in your circle runs: not crowded, unproven.

- The server half exists: Pocket ID (10.5k stars, passkeys only, invite links, groups, an admin code that
  lets someone back in; V https://pocket-id.org/docs/setup/user-management).
- No documented case of a household sign-in server working for non-technical members.
- How it fails: the box dies (21.3% of Mastodon servers gone for good within 15 months, Raman et al. 2019,
  V https://ar5iv.arxiv.org/html/1909.05801); "can let you back in" also means "can get in" (Facebook
  dropped Trusted Contacts 2022, V).
- What survives in shipped products: Apple Recovery Contacts only hand over a code and have no access
  (V https://support.apple.com/en-us/102641).
- Needs: accounts keep working when the box is gone; the owner's power to let you back in is limited and
  visible; near-zero upkeep and a clear payoff for the owner.

## 3. The sign-in flow for Nostr apps

- **Written flow: not crowded.** Only nostrdesign.org's sign-in page (2024, no passkeys, no remote
  signers; V https://nostrdesign.org/docs/how-to/sign-in-sign-up/).
- **A test apps run against themselves: empty.** No login or NIP-46 conformance suite found (U, searched
  twice).
- **Code: crowded and scattered.** nostr-login (94 stars, last push 2025-03, looks stalled; V
  https://github.com/nostrband/nostr-login), window.nostr.js, nostr-tools, NDK, applesauce, welshman,
  Nostrify, nstart (V https://github.com/dtonon/nstart), nonboard, keycast. About 15 small passkey
  libraries with no adopters.
- **Passkey accounts are being specified by others:** nips PR #2519 "Passkey-held Nostr keys and optional
  vaults", open since 2026-10-23, derived and stored modes (V
  https://github.com/nostr-protocol/nips/pull/2519). Earlier NIP-79 / Nosskey closed 2025-10 with
  objections: "no gains from interoperability", every app getting the whole key (V
  https://github.com/nostr-protocol/nips/pull/1919). nosskey-sdk, keytr.
- **Adoption:** what would be taken up is the test file and a one-page flow, with code that wraps
  existing signers. Most likely reason to be ignored: the objection to passkey storage, and big clients
  owning their own onboarding. Make passkeys one way in, not the spine.
- **Home:** no neutral home exists for this. Clients and signers will not run a rival product's test.
  Funders: OpenSats (remote signing topic, V https://opensats.org/topics/remote-signing), HRF (U).

## 4. How much the shared code leans on Keykin (code audit)

- Protocol: almost none. Only the login-page pointer (kind 10046, legacy 30078 d "keykin/login") and a
  `kk_login=missing` parameter. An app with no Keykin can use it today: name, phone code, signer link work.
- Naming and defaults: a lot. "Sign in with Marble", "Get Marble for Android", marble.syb.lol links
  (dialog.js:42,117,174,188,205,219-230; account-page.js:33-62); storage keys "marble.*" (me.js:9,
  dialog.js:135,250, pool.js:36); relays fixed to syb.lol (pool.js:8-12, connect.js:17); permissions for
  Marble and Kist kinds (connect.js:211); an always-shown "Your account page" link.
- The device-prompt account code is in DMs, not in signin/. Reusable: webauthn.ts, seal.ts, WebAuthnJson.kt,
  Seal.kt once labels are parameters. Its one real tie is the home that keeps the locked copy
  (vault.ts, VaultClient.kt).
- To extract: one configure() call for app name, wording, storage prefix, relays, permissions; the pointer
  and account page moved to one optional plug-in; a small "where the locked copy is kept" interface.
- Copies have drifted: Tube, Discover and one Marble worktree carry keykin bf1873d (me.js, pool.js differ
  from current). Marble main (~/marble/site/js) still uses its own code. An earlier standalone repo is
  archived at ~/archive/signin.

## Reading of the three

- It is the third: a flow and a test for Nostr apps. The test is the part nobody has.
- The box is a separate project that plugs into it. Its findings belong with Keykin.
- For other developers the rows must not require passkeys: an app declares which ways in it offers and
  runs those rows; the rows that apply to everyone are "never a second account", "never overwrite a
  profile", "no key shown to a new person".
- So it wants its own repo with a neutral name, holding: the one-page flow, the filter, the rows as a data
  file, and thin reference code. Keykin and each app depend on it.

## Open

- Read nips PR #2519 before designing the passkey account any further.
- Why ~/archive/signin was set aside.
- Whether a box can act as you, or only hand over a code (Apple's shape).
- Who this is for: building for other developers is a standing cost.

## Follow-up on the four open points (2026-11-25, evening)

Research only. No repo made, nothing published, nothing posted on the proposal.

### 1. The open proposal on fingerprint-held accounts

nostr-protocol/nips PR #2519, "Passkey-held Nostr keys and optional vaults". Read in full (both files,
all three comments). Open since 2026-10-23, last activity 2026-10-26, numbers and event kind provisional.
The only outside comment is fiatjaf's "What happens if I lose my phone?". It follows an earlier proposal
(#1919) that was closed unmerged, so it may not land.

What it defines:

- Two kinds of account, marked inside the saved passkey itself so any app can tell which it is:
  - **derived**: the key is worked out from the passkey. Nothing is kept anywhere. Lose the passkey, lose
    the account; a new passkey cannot recreate it.
  - **stored**: a random or existing key, locked with the passkey. The locked copy is kept in one or more
    of: the passkey's own storage where the device supports it, **ordinary relays as an event signed by
    the account itself**, or a file.
- A rule that matches ours: when the copy cannot be found, an app must not quietly make a new account. It
  offers to look again or "an explicit new-account action".
- Telling the device which passkeys an account already has, so a second one is not made over the first.
- A way to move a derived account to a stored one later.
- Test vectors for the formats (in the nostr-wot-sdk repo). They test the bytes, not the flow.
- It says apps "SHOULD offer to export the private key or seed" at creation. That fails our filter
  (questions 3 and 5). It is a should, not a must.

How it changes the plan:

- **It fills the "no invite, no home" gap better than what I proposed.** I suggested the derived kind.
  The stored kind with the locked copy on ordinary relays, signed by the account itself, needs no home and
  no admin either, and it keeps the account separate from any one passkey: a second device or a later box
  can be added without changing who you are. Derived stays as the fallback, and the proposal itself warns
  about it. DMs did keep a public copy like this once and moved to the home; the reason for that move
  should be read in dms/docs/fingerprint-restore-design.md before going back.
- **The standalone project should not define its own passkey format.** DMs' current one ("dms seal v2",
  copy on the home) is its own and matches nobody's. If this proposal settles, follow it; until then keep
  the format and "where the copy is kept" behind one small interface so it can be swapped.
- **Our part is confirmed as the missing part.** The proposal covers formats and recovery rules. It has no
  screens, no order of options and no test of behaviour. Its "never quietly make a new account" rule is
  the first row of our test.
- **Sharing one passkey across several apps** is described (a shared domain several apps are allowed to
  use) with a plain warning: every app on the list can get the key, and leaving the list can lose the
  account. That supports your choice of separate accounts per app until a box takes them in.
- Possible later, his call, not done: comment on the proposal with the flow rules and rows.

### 2. Why ~/archive/signin was set aside

It was not set aside for a flaw. On 2026-11-20 a sweep for duplicated code found website sign-in written
about six times. Marble Web's in-use code was made the one shared copy (keykin/signin), and ~/signin was
archived the same day as "a finished sign-in button nothing uses". ARCHIVED.txt in the folder says the
same. Eight commits, all 2026-10-27, no remote, three files with uncommitted changes.

What matters for today: the archived one is closer to a neutral standalone sign-in than the shared copy is.

- Its dialog "never says Nostr, key, signer or relay, and names no app". The shared copy says Marble.
- It asks a browser extension first. The shared copy has no extension sign-in (review C1).
- It handles a signer that asks for approval on a web page. The shared copy fails that (review C2).
- It has a settings call for which apps to suggest, and tests against a local relay with a stand-in phone
  app and a fake extension. Review D listed those stand-ins as "to build".
- It handles a phone dropping a background page's connections, found on a real Pixel.

What it lacks: typing your name to find your account's page, and any device-prompt account. So a
standalone repo would start from the archived button and bring the name lookup over from the shared copy
as the optional plug-in, not the other way round. Unverified: I read its README, log and file list, not
its code line by line, and did not run its tests.

### 3. The box: "acts as you" or "hands you a code"

**Acts as you.** The box holds enough to sign as the member by itself.
- Getting back in: the owner approves, the new phone is in. Member cost: nothing extra.
- The owner, or anyone who gets into the box, can be any member at any time, and nothing shows it.
- Changes Keykin's core rule (the box holds one piece and never signs alone).
- Also allows the box to do things for you while your phone is off. Nothing planned needs that.

**Hands you a code.** Day to day the box holds one piece, as built. Getting back in is a reset.
- The owner approves and passes the member a code or link. The member opens it on the new phone and uses
  that phone's prompt. Member cost: one tap and one prompt, only at the moment they are locked out.
- Every other device of that member, and the owner's own log, show that a reset happened.
- Honest limit: unlike Apple's version, the box is both the helper and the keeper, so an owner who wants
  to can still run a reset against their own member. What this shape gives is that it cannot be done
  quietly or by accident, and that the box cannot act as anyone in ordinary use.
- A stricter version (a second person in the circle must also approve) is possible later. Not now.

**Recommendation: hands you a code.**
- It passes the filter: the extra step is seen only by someone already locked out, and it prevents a real
  loss (someone else acting as you without anyone knowing).
- It follows your own rule that sealing exists to spare the person running the server: a box owner who
  cannot routinely act as their family is not put in the position of being able to.
- It is the shape that lasted elsewhere, and friend-based recovery that was looser was withdrawn.
- It leaves Keykin's design as it is, so less to rebuild.
This narrows answer 2 in SIGN-IN-GOAL.md ("a box holds enough to act for you without your phone") to
"a box can reset you, and it always shows". It needs his yes.

### 4. Other developers as an audience

One question: **Is this for your apps only, or do you want other Nostr developers to use it?**
- Yours only: it stays with Keykin, no neutral repo, no outside requests. The flow, filter and rows still
  do their job for DMs, Tube, Marble and Discover.
- Others too: the flow and the rows go in a neutral public repo that names none of your products, starting
  from the archived button. The likely outcome is being ignored; the cost of finding out is small if the
  repo is only the one-page flow, the rows and thin code.

## Decisions for Aaron

1. Yours only, or other developers too (point 4). This decides where it lives.
2. The box resets you with a code and it always shows, instead of acting as you (point 3). Narrows answer 2.
3. People with no invite: stored account with its locked copy on ordinary relays, derived as the fallback,
   and DMs still makes no account without an invite. Replaces the proposal under answer 3.
4. Start the standalone code from the archived button, with the name lookup as a plug-in (only if 1 is
   "others too", or if you want the cleanup either way).
5. Follow the open proposal's format once it settles, and keep ours swappable until then.

## Outcome (2026-11-25, evening)

Relayed as approved ("go with your picks"); full wording in SIGN-IN-GOAL.md, "Approved picks".
1. His apps only for now; stays with Keykin; no neutral repo.
2. The box resets you with a code and it always shows; it never acts as you.
3. No-invite accounts in the open apps: stored account, locked copy on ordinary relays, no derived
   fallback. Agreed by Aaron on 2026-11-26; that the copy can be counted is a real but smaller risk than
   losing the only copy.
4. The archived button's good parts move into keykin/signin on a branch with tests; no restart from it.
5. Passkey format and where the copy is kept sit behind one interface; follow PR 2519 if it settles.
