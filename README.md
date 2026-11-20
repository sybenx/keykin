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
