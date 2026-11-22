# Keykin

My devices and my box. Any two pieces sign.

- `DIRECTION.md`: why, and what the design is.
- `SPEC.md`: what the code does, and what is not built.
- `src/`: the pieces, the signing round, member requests, the device side.
- `box/`: the box (`box.ts`), the account page's calls (`pageapi.ts`), the admin page (`page.ts`) and its HTTP server (`server.ts`).
- `login/`: Keykin Login, the public door and the account page. `KEYKIN_BOX=http://127.0.0.1:7461 npm run login`.
- `cli/`: this computer as a device (`keykin.ts`), including sign-in to sites.
- `android/`: the phone app.
- `ext/`: the browser extension. `node ext/build.mjs`, then load `ext/dist` in Chrome with Load unpacked.
- `site/`: sign-in by a scanned code for web pages (QRST signer-ticket). `node tools/build-site.mjs`.
- `signin/`: name-first sign-in for web sites (Marble Web, Discover, Tube), the one shared copy. Plain browser modules; see `signin/README.md`. Sites take a copy with `node tools/signin-copy.mjs <folder>`.
- `vendor/qrst.js`: the QRST library, bundled from the `qr-secret-transfer` repo by `node tools/build-qrst.mjs`.
- `device-rs/`: the device side in Rust (lifted from Marble on Mac) and `keykin`, a signer for Terminal whose piece is sealed by the Secure Enclave. See "Signing from Terminal" below.
- `frost/`: the Rust FROST crate, built to `frost-wasm/`. Carried over from the `cosign` repo.

```bash
npm install
```

```bash
npm test
```

```bash
npm run box
```

The box prints its owner secret once, on first start. Open `http://127.0.0.1:7460` and log in with it.

## Try it on one computer

Start the box, log in to its page, and expand "No camera? Copy the code as text".

```bash
npm run box
```

Make the account from this computer, pasting that text:

```bash
npm run keykin -- create '<the text>' 'MacBook'
```

Sign in to a site: run this, then paste the link it prints into the site's remote signer sign-in.

```bash
npm run keykin -- bunker wss://your.relay
```

## Signing from Terminal

`device-rs` builds `keykin`, which makes this Mac a device of your account the way your phone is. Its piece is
sealed by the Mac's Secure Enclave, and every signature asks for Touch ID. There's no nsec, no bunker link and
nothing in a plain file that can sign. The Touch ID prompt says what is signed (which app, release or file, where
the event names one) and who asked: a script passes `keykin sign --for "Pinket release" …`, and without `--for` the
prompt names the calling script. It needs Xcode's command line tools (`swiftc`) to build.

```bash
cd device-rs && cargo build --release && mkdir -p ~/.local/bin && cp target/release/keykin ~/.local/bin/
```

```bash
keykin join
```

Marble on the web opens in your browser and finds your account page. Press **Add** there and this Mac joins as
"<this Mac's name> (Terminal)". If the browser can't come back, type the six digits your account page shows,
with its address, where `keykin join` waits.

```bash
keykin sign '{"kind":1,"content":"hello"}' | nak event wss://relay.example
```

The Touch ID prompt says what is signed ("sign a note (kind 1): “hello” as you"). Your box still decides what is
hard to undo. keykin never says Yes for you: what the box asks about is signed in Marble or on your phone, and
what is never done by accident only on your phone. `keykin status` shows who this Mac signs as, and
`keykin forget` deletes its sealed piece (block it on your phone too).

A private message needs no bunker and no other app. It's one Touch ID, and the prompt says who it's for and how
it starts ("send a private message to Alice (npub1…): “hi, are you…”"):

```bash
keykin dm npub1… 'hi, are you around this week?'
echo "a longer message from a script" | keykin dm --for "weekly report" npub1… -
```

It looks up where they read private messages (their DM relay list, else the relays they read from), leaves it
there, and leaves a copy for you on your own DM relays so it shows in your DM apps. It prints where each copy
landed. `--relay wss://…` sends both copies there instead. It's NIP-17: the message is sealed and signed as you,
then wrapped by a one-time key. `keykin encrypt <npub> '<text>'` and `keykin decrypt <npub> '<text>'` do NIP-44
alone, for scripts that build their own.

Linux and Windows aren't done yet: `keykin join` says so rather than keeping a piece in a plain file.

## The Android app

Build the FROST library for Android once (and again when `frost/` changes), then the app:

```bash
cd frost && ANDROID_NDK_HOME=/opt/homebrew/share/android-commandlinetools/ndk/29.0.14206865 cargo ndk -t arm64-v8a -t x86_64 -P 30 -o ../android/app/src/main/jniLibs build --release --features jni
```

```bash
cd android && JAVA_HOME=$(/usr/libexec/java_home -v 17) ./gradlew :app:assembleDebug
```

The Kotlin tests run against a real box. Build the library for this computer with `cargo build --release --features jni` in `frost/`, start a box, and pass its setup text in `KEYKIN_BOX_QR` to `./gradlew :app:testDebugUnitTest`. Without it the box test is skipped.

The Android app also builds the QRST Kotlin library from `../qr-secret-transfer/kotlin`, so that repo must be checked out beside this one.
