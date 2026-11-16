# Keykin

My devices and my box. Any two pieces sign.

- `DIRECTION.md`: why, and what the design is.
- `SPEC.md`: what the code does, and what is not built.
- `src/`: the pieces, the signing round, member requests, the device side.
- `box/`: the box (`box.ts`) and its HTTP server (`server.ts`).
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
