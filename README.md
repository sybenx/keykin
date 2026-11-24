# Keykin

Keykin splits a Nostr key (secp256k1, BIP-340) into FROST pieces held by a person's
devices and one box they or someone they trust runs. Any two pieces sign. One piece alone
signs nothing. There are no public servers.

This repository has the spec, the box, the device side in TypeScript, Kotlin and Rust, and
the pieces a web site needs for sign-in.

- `SPEC.md`: what the code does, what is not built (section 9) and known weak spots
  (section 10).
- `DIRECTION.md`: the design and the reasons for it.

## Status

Draft (spec 0.11), version 0.1.x. Not audited.

- The terminal signer runs on macOS only. Linux and Windows are not built, and
  `keykin join` refuses there because the piece would have to sit in a plain file.
- [Marble](https://github.com/sybenx/marble) carries a copy of the Kotlin core from
  `android/`.
- The box is packaged for Umbrel in
  [keykin-umbrel](https://github.com/sybenx/keykin-umbrel).

## Layout

| Path | What |
| --- | --- |
| `src/` | Pieces, the signing round, member requests, the device side. |
| `box/` | The box (`box.ts`), the account page's calls (`pageapi.ts`), the admin page (`page.ts`), the HTTP server (`server.ts`). |
| `login/` | Keykin Login: the public door and the account page. |
| `cli/` | A computer as a device (`keykin.ts`), including NIP-46 sign-in to sites. |
| `android/` | The phone app. |
| `ext/` | The browser extension. |
| `site/` | Sign-in by a scanned code for web pages (QRST `signer-ticket`). |
| `signin/` | Name-first sign-in for web sites (Marble Web, Discover, Tube). The one shared copy. See `signin/README.md`. |
| `device-rs/` | The device side in Rust, and `keykin`, the terminal signer. |
| `frost/` | The Rust FROST crate. Built to `frost-wasm/` and, for Android, to a JNI library. |
| `vendor/qrst.js` | The QRST library, bundled from the `qr-secret-transfer` repository. |
| `deploy/` | Dockerfiles and a compose file for the box and Keykin Login. |
| `vectors/`, `test/` | Test vectors and tests. |

## Running

Needs Node 24.

```bash
npm install
npm test
npm run box
```

The box listens on port 7460 and prints its owner secret once, on first start. The admin
page is at `http://127.0.0.1:7460`.

Keykin Login needs the box's side door:

```bash
KEYKIN_BOX=http://127.0.0.1:7461 npm run login
```

Builds:

```bash
node ext/build.mjs           # extension, to ext/dist (Chrome: Load unpacked)
node tools/build-site.mjs    # site/
node tools/build-qrst.mjs    # vendor/qrst.js
node tools/signin-copy.mjs <folder>   # copy signin/ into a site
```

## One computer, end to end

Start the box, log in to its page, and expand "No camera? Copy the code as text".

```bash
npm run keykin -- create '<the text>' 'MacBook'
npm run keykin -- bunker wss://your.relay
```

`create` makes the account with this computer as the first device. `bunker` prints a
NIP-46 link to paste into a site's remote-signer sign-in.

## Terminal signer (macOS)

`device-rs` builds `keykin`, which makes a Mac a device of an account. Its piece is sealed
by the Secure Enclave and every signature needs Touch ID. No nsec, bunker link or plain
file that can sign is kept on disk. Building needs Xcode's command line tools (`swiftc`).

```bash
cd device-rs && cargo build --release && mkdir -p ~/.local/bin && cp target/release/keykin ~/.local/bin/
```

| Command | What |
| --- | --- |
| `keykin join` | Opens Marble Web, which finds the account page. Pressing Add there joins this Mac as "<name> (Terminal)". If the browser cannot return, `join` accepts the six digits and address the account page shows. |
| `keykin sign '<event json>'` | Signs an event and prints it. `--for "<label>"` sets who the Touch ID prompt says asked. Without it the prompt names the calling script. |
| `keykin dm <npub> '<text>'` | Sends a NIP-17 message. `-` reads the text from stdin. `--relay wss://…` overrides where both copies go. |
| `keykin encrypt <npub> '<text>'`, `keykin decrypt <npub> '<text>'` | NIP-44 only. |
| `keykin status` | Shows which account this Mac signs as. |
| `keykin forget` | Deletes the sealed piece. The device should also be blocked from the phone. |

```bash
keykin sign '{"kind":1,"content":"hello"}' | nak event wss://relay.example
```

- The Touch ID prompt states what is being signed: the kind, the app, release or file
  where the event names one, and for a DM the recipient and the start of the text.
- The box still decides what is hard to undo. `keykin` does not answer those questions.
  They are answered in Marble or on the phone. Level 2 events (SPEC section 11.6) are
  refused with `needs_fingerprint` and have to be done from the phone.
- `keykin dm` looks up the recipient's DM relay list (falling back to their read relays),
  sends there, and sends a copy to the sender's own DM relays. It prints where each copy
  landed. Proof of work or NIP-42 auth demanded by a relay is done with the message's
  one-time key, so neither costs another Touch ID.

## Android app

Build the FROST library for Android once, and again when `frost/` changes, then the app.
Needs JDK 17, the Android NDK and `cargo-ndk`.

```bash
cd frost && cargo ndk -t arm64-v8a -t x86_64 -P 30 -o ../android/app/src/main/jniLibs build --release --features jni
cd android && ./gradlew :app:assembleDebug
```

- The app builds the QRST Kotlin library from `../qr-secret-transfer/kotlin`, so that
  repository must be checked out beside this one.
- The Kotlin tests run against a real box. Build the library for the host with
  `cargo build --release --features jni` in `frost/`, start a box, and pass its setup text
  in `KEYKIN_BOX_QR` to `./gradlew :app:testDebugUnitTest`. Without it the box test is
  skipped.

## History

Keykin v2 replaces the Cosign design (weighted shares on public servers). `frost/` was
carried over from the `cosign` repository, which has the earlier history.

## License

MIT.
