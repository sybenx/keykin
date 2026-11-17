// QRST (qr-secret-transfer) at commit a753ae0. Built by tools/build-qrst.mjs. Do not edit.
var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// ../qr-secret-transfer/node_modules/@noble/hashes/utils.js
function isBytes(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle = (title) => title ? `"${title}" ` : "";
function anumber(n, title = "") {
  if (typeof n !== "number")
    throw new TypeError(atitle(title) + "expected number, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
  return n;
}
function abytes(value, length, title = "") {
  if (isBytes(value) && (length === void 0 || value.length === length))
    return value;
  if (length !== void 0)
    anumber(length, "length");
  const bytes = isBytes(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message);
  throw new RangeError(message);
}
function ahash(h) {
  if (typeof h !== "function" || typeof h.create !== "function")
    throw new TypeError("expected hash wrapped by utils.createHasher");
  anumber(h.outputLen);
  anumber(h.blockLen);
  if (h.outputLen < 1 || h.blockLen < 1)
    throw new Error("hash blockLen / outputLen must be >= 1");
}
var aobject = (value, label) => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
};
var aopts = (value, label) => {
  aobject(value, label);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null)
    throw new TypeError(`"${label}" expected plain object`);
  if (Object.hasOwn(value, "__proto__"))
    throw new TypeError(`"${label}.__proto__" is not allowed`);
};
function aexists(instance, checkFinished = true) {
  if (instance.destroyed)
    throw new Error("hash was destroyed");
  if (checkFinished && instance.finished)
    throw new Error("digest() was already called");
}
function aoutput(out, instance) {
  abytes(out, void 0, "output");
  const min = instance.outputLen;
  if (!(out.length >= min)) {
    throw new RangeError('"output" expected length >= ' + min);
  }
}
function clean(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
function createView(arr) {
  return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
}
function rotr(word, shift) {
  return word << 32 - shift | word >>> shift;
}
var hasHexBuiltin = /* @__PURE__ */ (() => (
  // @ts-ignore
  typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
))();
var hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
function bytesToHex(bytes) {
  abytes(bytes);
  if (hasHexBuiltin)
    return bytes.toHex();
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += hexes[bytes[i]];
  }
  return hex;
}
function asciiToBase16(ch) {
  return ch >= 48 && ch <= 57 ? ch - 48 : ch >= 65 && ch <= 70 ? ch - (65 - 10) : ch >= 97 && ch <= 102 ? ch - (97 - 10) : void 0;
}
function hexToBytes(hex) {
  if (typeof hex !== "string")
    throw new TypeError("hex string expected, got " + typeof hex);
  if (hasHexBuiltin) {
    try {
      return Uint8Array.fromHex(hex);
    } catch (error) {
      if (error instanceof SyntaxError)
        throw new RangeError(error.message);
      throw error;
    }
  }
  const hl = hex.length;
  const al = hl / 2;
  if (hl % 2)
    throw new RangeError("hex string expected, got unpadded hex of length " + hl);
  const array = new Uint8Array(al);
  for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
    const n1 = asciiToBase16(hex.charCodeAt(hi));
    const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
    if (n1 === void 0 || n2 === void 0) {
      const char = hex[hi] + hex[hi + 1];
      throw new RangeError('hex string expected, got non-hex character "' + char + '" at index ' + hi);
    }
    array[ai] = n1 * 16 + n2;
  }
  return array;
}
function concatBytes(...arrays) {
  let sum = 0;
  for (let i = 0; i < arrays.length; i++) {
    const a = arrays[i];
    abytes(a);
    sum += a.length;
  }
  const res = new Uint8Array(sum);
  for (let i = 0, pad2 = 0; i < arrays.length; i++) {
    const a = arrays[i];
    res.set(a, pad2);
    pad2 += a.length;
  }
  return res;
}
function checkOpts(defaults, opts, title = "opts") {
  aopts(defaults, "defaults");
  if (opts !== void 0)
    aopts(opts, title);
  const merged = Object.assign(/* @__PURE__ */ Object.create(null), defaults, opts);
  return merged;
}
function createHasher(hashCons, info = {}) {
  if (typeof hashCons !== "function")
    throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
  info = checkOpts({}, info, "info");
  const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
  const tmp = hashCons(void 0);
  hashC.outputLen = tmp.outputLen;
  hashC.blockLen = tmp.blockLen;
  hashC.canXOF = tmp.canXOF;
  hashC.create = (opts) => hashCons(opts);
  Object.assign(hashC, info);
  return Object.freeze(hashC);
}
function randomBytes(bytesLength = 32) {
  anumber(bytesLength, "bytesLength");
  const cr = typeof globalThis === "object" ? globalThis.crypto : null;
  if (typeof cr?.getRandomValues !== "function")
    throw new Error("crypto.getRandomValues must be defined");
  if (bytesLength > 65536)
    throw new RangeError(`"bytesLength" expected <= 65536, got ${bytesLength}`);
  return cr.getRandomValues(new Uint8Array(bytesLength));
}
var oidNist = (suffix) => ({
  // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
  // Larger suffix values would need base-128 OID encoding and a different length byte.
  oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
});

// ../qr-secret-transfer/src/core/bytes.ts
var encoder = new TextEncoder();
var strictDecoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
function utf8Encode(text) {
  return encoder.encode(text);
}
function utf8Decode(bytes) {
  return strictDecoder.decode(bytes);
}
var HEX_64 = /^[0-9a-f]{64}$/;
function isHex32(value) {
  return typeof value === "string" && HEX_64.test(value);
}
function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
function equalAscii(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function wipe(...buffers) {
  for (const b of buffers) if (b) b.fill(0);
}

// ../qr-secret-transfer/src/core/constants.ts
var KINDS = {
  SEAL: 13,
  WRAP: 21059,
  AUTH: 22242,
  HELLO: 24401,
  REQUEST: 24402,
  NONCE: 24403,
  REVEAL: 24404,
  PAYLOAD: 24405,
  ACK: 24406,
  ABORT: 24407
};
var VERSION = 1;
var SESSION_SECONDS = 600;
var SLACK_SECONDS = 120;
var ACK_WAIT_SECONDS = 60;
var MAX_ATTEMPTS = 5;
var MAX_HELD = 3;
var MAX_PENDING = 5;
var DEFAULT_MAX_PAYLOAD = 2048;
var THROTTLE_SECONDS = 3600;
var FAILED_SESSIONS_BEFORE_WARNING = 3;
var MAX_RELAYS = 4;
var PROFILE_ID = /^[a-z0-9-]{1,24}$/;
var CODE_CHECKS = ["none", "compare", "type"];
function isCodeCheck(value) {
  return typeof value === "string" && CODE_CHECKS.includes(value);
}
function stricter(a, b) {
  return CODE_CHECKS.indexOf(a) >= CODE_CHECKS.indexOf(b) ? a : b;
}
var TOKEN_BYTES = 16;

// ../qr-secret-transfer/node_modules/@noble/hashes/_u64.js
var fromNumH = (n) => n / 2 ** 32 | 0;
var fromNumL = (n) => n >>> 0;
function setU64FromNum(view, byteOffset, n, isLE2) {
  const h = fromNumH(n);
  const l = fromNumL(n);
  view.setUint32(byteOffset, isLE2 ? l : h, isLE2);
  view.setUint32(byteOffset + 4, isLE2 ? h : l, isLE2);
}

// ../qr-secret-transfer/node_modules/@noble/hashes/_md.js
function Chi(a, b, c) {
  return a & b ^ ~a & c;
}
function Maj(a, b, c) {
  return a & b ^ a & c ^ b & c;
}
var HashMD = class {
  blockLen;
  outputLen;
  canXOF = false;
  padOffset;
  isLE;
  // For partial updates less than block size
  buffer;
  view;
  finished = false;
  length = 0;
  pos = 0;
  destroyed = false;
  constructor(blockLen, outputLen, padOffset, isLE2) {
    this.blockLen = blockLen;
    this.outputLen = outputLen;
    this.padOffset = padOffset;
    this.isLE = isLE2;
    this.buffer = new Uint8Array(blockLen);
    this.view = createView(this.buffer);
  }
  update(data) {
    aexists(this);
    abytes(data);
    const { view, buffer, blockLen } = this;
    const len = data.length;
    let processed = false;
    for (let pos = 0; pos < len; ) {
      const take = Math.min(blockLen - this.pos, len - pos);
      if (take === blockLen) {
        const dataView = createView(data);
        for (; blockLen <= len - pos; pos += blockLen)
          this.process(dataView, pos);
        processed = true;
        continue;
      }
      buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
      this.pos += take;
      pos += take;
      if (this.pos === blockLen) {
        this.process(view, 0);
        this.pos = 0;
        processed = true;
      }
    }
    this.length += data.length;
    if (processed)
      this.roundClean();
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const { buffer, view, blockLen, isLE: isLE2 } = this;
    let { pos } = this;
    buffer[pos++] = 128;
    buffer.fill(0, pos);
    if (this.padOffset > blockLen - pos) {
      this.process(view, 0);
      buffer.fill(0);
    }
    setU64FromNum(view, blockLen - 8, this.length * 8, isLE2);
    this.process(view, 0);
    this.roundClean();
    const oview = out === buffer ? view : createView(out);
    const len = this.outputLen;
    const outLen = len / 4;
    const state = this.get();
    if (len % 4 || outLen > state.length)
      throw new Error("invalid outputLen");
    for (let i = 0; i < outLen; i++)
      oview.setUint32(4 * i, state[i], isLE2);
  }
  digest() {
    const { buffer, outputLen } = this;
    this.digestInto(buffer);
    const res = buffer.slice(0, outputLen);
    this.destroy();
    return res;
  }
  _cloneIntoMeta(to) {
    const { buffer, length, finished, destroyed, pos } = this;
    to.destroyed = destroyed;
    to.finished = finished;
    to.length = length;
    to.pos = pos;
    if (pos)
      to.buffer.set(buffer);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
};
var SHA256_IV = /* @__PURE__ */ Uint32Array.from([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]);

// ../qr-secret-transfer/node_modules/@noble/hashes/sha2.js
var SHA256_K = /* @__PURE__ */ Uint32Array.from([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var SHA256_W = /* @__PURE__ */ new Uint32Array(64);
var SHA2_32B = class extends HashMD {
  // We cannot use array here since array allows indexing by variable
  // which means optimizer/compiler cannot use registers.
  // Numeric initializers matter: starting the fields as `undefined` changes
  // V8's field representation and makes sha256 3x slower (measured).
  A = 0;
  B = 0;
  C = 0;
  D = 0;
  E = 0;
  F = 0;
  G = 0;
  H = 0;
  constructor(outputLen, IV) {
    super(64, outputLen, 8, false);
    this.A = IV[0] | 0;
    this.B = IV[1] | 0;
    this.C = IV[2] | 0;
    this.D = IV[3] | 0;
    this.E = IV[4] | 0;
    this.F = IV[5] | 0;
    this.G = IV[6] | 0;
    this.H = IV[7] | 0;
  }
  get() {
    const { A, B, C, D, E, F, G, H } = this;
    return [A, B, C, D, E, F, G, H];
  }
  // prettier-ignore
  set(A, B, C, D, E, F, G, H) {
    this.A = A | 0;
    this.B = B | 0;
    this.C = C | 0;
    this.D = D | 0;
    this.E = E | 0;
    this.F = F | 0;
    this.G = G | 0;
    this.H = H | 0;
  }
  _cloneInto(to) {
    (to ||= new this.constructor()).set(...this.get());
    return this._cloneIntoMeta(to);
  }
  process(view, offset) {
    for (let i = 0; i < 16; i++, offset += 4)
      SHA256_W[i] = view.getUint32(offset, false);
    for (let i = 16; i < 64; i++) {
      const W15 = SHA256_W[i - 15];
      const W2 = SHA256_W[i - 2];
      const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
      const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
      SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
    }
    let { A, B, C, D, E, F, G, H } = this;
    for (let i = 0; i < 64; i++) {
      const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
      const T1 = H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i] | 0;
      const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
      const T2 = sigma0 + Maj(A, B, C) | 0;
      H = G;
      G = F;
      F = E;
      E = D + T1 | 0;
      D = C;
      C = B;
      B = A;
      A = T1 + T2 | 0;
    }
    A = A + this.A | 0;
    B = B + this.B | 0;
    C = C + this.C | 0;
    D = D + this.D | 0;
    E = E + this.E | 0;
    F = F + this.F | 0;
    G = G + this.G | 0;
    H = H + this.H | 0;
    this.set(A, B, C, D, E, F, G, H);
  }
  roundClean() {
    clean(SHA256_W);
  }
  destroy() {
    this.destroyed = true;
    this.set(0, 0, 0, 0, 0, 0, 0, 0);
    clean(this.buffer);
  }
};
var _SHA256 = class extends SHA2_32B {
  constructor() {
    super(32, SHA256_IV);
  }
};
var sha256 = /* @__PURE__ */ createHasher(
  () => new _SHA256(),
  /* @__PURE__ */ oidNist(1)
);

// ../qr-secret-transfer/node_modules/@noble/curves/utils.js
function aarray(item, title, inner = () => {
}) {
  if (!Array.isArray(item))
    throw new TypeError(`"${title}" expected array, got type=${typeof item}`);
  for (let i = 0; i < item.length; i++)
    inner(item[i], `${title}[${i}]`);
  return item;
}
var abytes2 = (value, length, title) => abytes(value, length, title);
var anumber2 = anumber;
function astring(value, title = "") {
  if (typeof value !== "string") {
    const prefix = title && `"${title}" `;
    throw new TypeError(prefix + "expected string, got type=" + typeof value);
  }
  return value;
}
function aobject2(value, title = "object") {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError(title === "object" ? "expected valid options object" : `"${title}" expected object, got type=${typeof value}`);
  return value;
}
function afunction(value, title) {
  if (typeof value !== "function")
    throw new TypeError(`"${title}" is invalid: expected function, got ${typeof value}`);
  return value;
}
var bytesToHex2 = bytesToHex;
var concatBytes2 = (...arrays) => concatBytes(...arrays);
var hexToBytes2 = (hex) => hexToBytes(hex);
var isBytes2 = isBytes;
var randomBytes2 = (bytesLength) => randomBytes(bytesLength);
var _0n = /* @__PURE__ */ BigInt(0);
var _1n = /* @__PURE__ */ BigInt(1);
var atitle2 = (title) => title ? `"${title}" ` : "";
function abool(value, title = "") {
  if (typeof value !== "boolean")
    throw new TypeError(atitle2(title) + "expected boolean, got type=" + typeof value);
  return value;
}
function abignumber(n) {
  if (typeof n === "bigint") {
    if (!isPosBig(n))
      throw new RangeError("positive bigint expected, got " + n);
  } else
    anumber2(n);
  return n;
}
function asafenumber(value, title = "") {
  if (typeof value !== "number") {
    const prefix = title && `"${title}" `;
    throw new TypeError(prefix + "expected number, got type=" + typeof value);
  }
  if (!Number.isSafeInteger(value)) {
    const prefix = title && `"${title}" `;
    throw new RangeError(prefix + "expected safe integer, got " + value);
  }
}
function numberToHexUnpadded(num2) {
  const hex = abignumber(num2).toString(16);
  return hex.length & 1 ? "0" + hex : hex;
}
function hexToNumber(hex) {
  if (typeof hex !== "string")
    throw new TypeError("hex string expected, got " + typeof hex);
  return hex === "" ? _0n : BigInt("0x" + hex);
}
function bytesToNumberBE(bytes) {
  return hexToNumber(bytesToHex(bytes));
}
function bytesToNumberLE(bytes) {
  return hexToNumber(bytesToHex(copyBytes(abytes(bytes)).reverse()));
}
function numberToBytesBE(n, len) {
  anumber(len);
  if (len === 0)
    throw new Error("zero output length is invalid");
  n = abignumber(n);
  const expectedLen = len * 2;
  const hex = n.toString(16);
  if (hex.length > expectedLen)
    throw new RangeError("number is too large");
  return hexToBytes(hex.padStart(expectedLen, "0"));
}
function numberToBytesLE(n, len) {
  return numberToBytesBE(n, len).reverse();
}
function copyBytes(bytes) {
  return Uint8Array.from(abytes2(bytes));
}
function asciiToBytes(ascii) {
  if (typeof ascii !== "string")
    throw new TypeError("ascii string expected, got " + typeof ascii);
  return Uint8Array.from(ascii, (c, i) => {
    const charCode = c.charCodeAt(0);
    if (c.length !== 1 || charCode > 127) {
      throw new RangeError(`string contains non-ASCII character "${ascii[i]}" with code ${charCode} at position ${i}`);
    }
    return charCode;
  });
}
function isPosBig(n) {
  return typeof n === "bigint" && _0n <= n;
}
function inRange(n, min, max) {
  return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
}
function aInRange(title, n, min, max) {
  if (!inRange(n, min, max))
    throw new RangeError("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
}
function bitLen(n) {
  if (n < _0n)
    throw new Error("expected non-negative bigint, got " + n);
  return n === _0n ? 0 : n.toString(2).length;
}
var bitMask = (n) => {
  asafenumber(n, "n");
  return (_1n << BigInt(n)) - _1n;
};
function createHmacDrbg(hashLen, qByteLen, hmacFn) {
  anumber(hashLen, "hashLen");
  anumber(qByteLen, "qByteLen");
  if (typeof hmacFn !== "function")
    throw new TypeError("hmacFn must be a function");
  const u8n = (len) => new Uint8Array(len);
  const NULL = Uint8Array.of();
  const byte0 = Uint8Array.of(0);
  const byte1 = Uint8Array.of(1);
  const _maxDrbgIters = 1e3;
  let v = u8n(hashLen);
  let k = u8n(hashLen);
  let i = 0;
  const reset = () => {
    v.fill(1);
    k.fill(0);
    i = 0;
  };
  const h = (...msgs) => hmacFn(k, concatBytes2(v, ...msgs));
  const reseed = (seed = NULL) => {
    k = h(byte0, seed);
    v = h();
    if (seed.length === 0)
      return;
    k = h(byte1, seed);
    v = h();
  };
  const gen = () => {
    if (i++ >= _maxDrbgIters)
      throw new Error("drbg: tried max amount of iterations");
    let len = 0;
    const out = [];
    while (len < qByteLen) {
      v = h();
      const sl = v.slice();
      out.push(sl);
      len += v.length;
    }
    return concatBytes2(...out);
  };
  const genUntil = (seed, pred) => {
    reset();
    reseed(seed);
    let res = void 0;
    while ((res = pred(gen())) === void 0)
      reseed();
    reset();
    return res;
  };
  return genUntil;
}
function validateObject(object, fields = {}, optFields = {}, title = "object") {
  aobject2(object, title);
  aobject2(fields, "fields");
  aobject2(optFields, "optFields");
  function checkField(fieldName, expectedType, isOpt) {
    const label = title === "object" ? `param "${String(fieldName)}"` : `"${title}.${String(fieldName)}"`;
    const val = object[fieldName];
    if (!Object.hasOwn(object, fieldName) && (isOpt ? val !== void 0 : expectedType !== "function")) {
      throw new TypeError(`${label} is invalid: expected own property`);
    }
    if (isOpt && val === void 0)
      return;
    const current = typeof val;
    if (current !== expectedType || val === null)
      throw new TypeError(`${label} is invalid: expected ${expectedType}, got ${current}`);
  }
  const iter = (f, isOpt) => Object.entries(f).forEach(([k, v]) => checkField(k, v, isOpt));
  iter(fields, false);
  iter(optFields, true);
}

// ../qr-secret-transfer/node_modules/@noble/curves/abstract/modular.js
var _0n2 = /* @__PURE__ */ BigInt(0);
var _1n2 = /* @__PURE__ */ BigInt(1);
var _2n = /* @__PURE__ */ BigInt(2);
var _3n = /* @__PURE__ */ BigInt(3);
var _4n = /* @__PURE__ */ BigInt(4);
var _5n = /* @__PURE__ */ BigInt(5);
var _7n = /* @__PURE__ */ BigInt(7);
var _8n = /* @__PURE__ */ BigInt(8);
var _9n = /* @__PURE__ */ BigInt(9);
var _15n = /* @__PURE__ */ BigInt(15);
var _16n = /* @__PURE__ */ BigInt(16);
var POW_WINDOWED_MIN = /* @__PURE__ */ BigInt("0x10000000000000000");
function mod(a, b) {
  if (b <= _0n2)
    throw new Error("mod: expected positive modulus, got " + b);
  const result = a % b;
  return result >= _0n2 ? result : b + result;
}
function pow(num2, power, modulo) {
  if (modulo <= _1n2)
    throw new Error("pow: expected modulus > 1, got " + modulo);
  if (typeof power !== "bigint")
    throw new TypeError("invalid exponent: expected bigint, got " + typeof power);
  if (power < _0n2)
    throw new Error("invalid exponent, negatives unsupported");
  if (power === _0n2)
    return _1n2;
  if (power === _1n2)
    return num2;
  let d = num2 % modulo;
  if (d < _0n2)
    d += modulo;
  if (power < POW_WINDOWED_MIN) {
    let p2 = _1n2;
    while (power > _0n2) {
      if (power & _1n2)
        p2 = p2 * d % modulo;
      d = d * d % modulo;
      power >>= _1n2;
    }
    return p2;
  }
  const digits = [];
  while (power > _0n2) {
    digits.push(Number(power & _15n));
    power >>= _4n;
  }
  const table = new Array(16);
  table[0] = _1n2;
  table[1] = d;
  for (let i = 2; i < 16; i++)
    table[i] = table[i - 1] * d % modulo;
  let p = table[digits[digits.length - 1]];
  for (let w = digits.length - 2; w >= 0; w--) {
    p = p * p % modulo;
    p = p * p % modulo;
    p = p * p % modulo;
    p = p * p % modulo;
    const digit = digits[w];
    if (digit !== 0)
      p = p * table[digit] % modulo;
  }
  return p;
}
function pow2(x, power, modulo) {
  if (modulo <= _1n2)
    throw new Error("pow2: expected modulus > 1, got " + modulo);
  if (power < _0n2)
    throw new Error("pow2: expected non-negative exponent, got " + power);
  let res = x;
  while (power-- > _0n2) {
    res *= res;
    res %= modulo;
  }
  return res;
}
function invert(number, modulo) {
  if (number === _0n2)
    throw new Error("invert: expected non-zero number");
  if (modulo <= _1n2)
    throw new Error("invert: expected modulus > 1, got " + modulo);
  let a = mod(number, modulo);
  let b = modulo;
  let x = _0n2, u = _1n2;
  while (a !== _0n2) {
    const q = b / a;
    const r = b - a * q;
    const m = x - u * q;
    b = a, a = r, x = u, u = m;
  }
  const gcd = b;
  if (gcd !== _1n2)
    throw new Error("invert: does not exist");
  return mod(x, modulo);
}
function invertCt(a, prime) {
  if (prime <= _1n2)
    throw new Error("invertCt: expected prime modulus > 1, got " + prime);
  const an = mod(a, prime);
  if (an === _0n2)
    throw new Error("invertCt: expected non-zero number");
  const inverse = pow(an, prime - _2n, prime);
  if (mod(an * inverse, prime) !== _1n2)
    throw new Error("invertCt: does not exist");
  return inverse;
}
function assertIsSquare(Fp, root, n) {
  const F = Fp;
  if (!F.eql(F.sqr(root), n))
    throw new Error("Cannot find square root");
}
function aoddModulus(order, fnName) {
  if ((order & _1n2) === _0n2)
    throw new Error(fnName + ": expected odd modulus, got " + order);
}
function sqrt3mod4(Fp, n) {
  const F = Fp;
  const p1div4 = (F.ORDER + _1n2) / _4n;
  const root = F.pow(n, p1div4);
  assertIsSquare(F, root, n);
  return root;
}
function sqrt5mod8(Fp, n) {
  const F = Fp;
  const p5div8 = (F.ORDER - _5n) / _8n;
  const n2 = F.mul(n, _2n);
  const v = F.pow(n2, p5div8);
  const nv = F.mul(n, v);
  const i = F.mul(F.mul(nv, _2n), v);
  const root = F.mul(nv, F.sub(i, F.ONE));
  assertIsSquare(F, root, n);
  return root;
}
function sqrt9mod16(P) {
  const Fp_ = Field(P);
  const tn = tonelliShanks(P);
  const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));
  const c2 = tn(Fp_, c1);
  const c3 = tn(Fp_, Fp_.neg(c1));
  const c4 = (P + _7n) / _16n;
  return ((Fp, n) => {
    const F = Fp;
    let tv1 = F.pow(n, c4);
    let tv2 = F.mul(tv1, c1);
    const tv3 = F.mul(tv1, c2);
    const tv4 = F.mul(tv1, c3);
    const e1 = F.eql(F.sqr(tv2), n);
    const e2 = F.eql(F.sqr(tv3), n);
    tv1 = F.cmov(tv1, tv2, e1);
    tv2 = F.cmov(tv4, tv3, e2);
    const e3 = F.eql(F.sqr(tv2), n);
    const root = F.cmov(tv1, tv2, e3);
    assertIsSquare(F, root, n);
    return root;
  });
}
function tonelliShanks(P) {
  if (P < _3n)
    throw new Error("sqrt is not defined for small field");
  aoddModulus(P, "tonelliShanks");
  let Q = P - _1n2;
  let S = 0;
  while (Q % _2n === _0n2) {
    Q /= _2n;
    S++;
  }
  let Z = _2n;
  const _Fp = Field(P);
  while (FpLegendre(_Fp, Z) === 1) {
    if (Z++ > 1e3)
      throw new Error("Cannot find square root: probably non-prime P");
  }
  if (S === 1)
    return sqrt3mod4;
  let cc = _Fp.pow(Z, Q);
  const Q1div2 = (Q + _1n2) / _2n;
  return function tonelliSlow(Fp, n) {
    const F = Fp;
    if (F.is0(n))
      return n;
    if (FpLegendre(F, n) !== 1)
      throw new Error("Cannot find square root");
    let M = S;
    let c = F.mul(F.ONE, cc);
    let t = F.pow(n, Q);
    let R = F.pow(n, Q1div2);
    while (!F.eql(t, F.ONE)) {
      if (F.is0(t))
        throw new Error("Cannot find square root: probably non-prime P");
      let i = 1;
      let t_tmp = F.sqr(t);
      while (!F.eql(t_tmp, F.ONE)) {
        i++;
        t_tmp = F.sqr(t_tmp);
        if (i === M)
          throw new Error("Cannot find square root");
      }
      const exponent = _1n2 << BigInt(M - i - 1);
      const b = F.pow(c, exponent);
      M = i;
      c = F.sqr(b);
      t = F.mul(t, c);
      R = F.mul(R, b);
    }
    return R;
  };
}
function FpSqrt(P) {
  aoddModulus(P, "Fp.sqrt");
  if (P % _4n === _3n)
    return sqrt3mod4;
  if (P % _8n === _5n)
    return sqrt5mod8;
  if (P % _16n === _9n)
    return sqrt9mod16(P);
  return tonelliShanks(P);
}
var FIELD_FIELDS = [
  "create",
  "isValid",
  "is0",
  "neg",
  "inv",
  "sqrt",
  "sqr",
  "eql",
  "add",
  "sub",
  "mul",
  "pow",
  "div",
  "addN",
  "subN",
  "mulN",
  "sqrN"
];
function validateField(field) {
  aobject2(field, "field");
  if (typeof field.ORDER !== "bigint")
    throw new TypeError('param "ORDER" is invalid: expected bigint, got ' + typeof field.ORDER);
  asafenumber(field.BYTES, "BYTES");
  asafenumber(field.BITS, "BITS");
  for (const name of FIELD_FIELDS)
    afunction(field[name], "field." + name);
  if (field.BYTES < 1 || field.BITS < 1)
    throw new Error("invalid field: expected BYTES/BITS > 0");
  if (field.ORDER <= _1n2)
    throw new Error("invalid field: expected ORDER > 1, got " + field.ORDER);
  return field;
}
function FpInvertBatch(Fp, nums, passZero = false) {
  validateField(Fp);
  aarray(nums, "nums");
  abool(passZero, "passZero");
  const F = Fp;
  const inverted = new Array(nums.length).fill(passZero ? F.ZERO : void 0);
  const multipliedAcc = nums.reduce((acc, num2, i) => {
    if (F.is0(num2))
      return acc;
    inverted[i] = acc;
    return F.mul(acc, num2);
  }, F.ONE);
  const invertedAcc = F.inv(multipliedAcc);
  nums.reduceRight((acc, num2, i) => {
    if (F.is0(num2))
      return acc;
    inverted[i] = F.mul(acc, inverted[i]);
    return F.mul(acc, num2);
  }, invertedAcc);
  return inverted;
}
function FpLegendre(Fp, n) {
  validateField(Fp);
  const F = Fp;
  aoddModulus(F.ORDER, "FpLegendre");
  const p1mod2 = (F.ORDER - _1n2) / _2n;
  const powered = F.pow(n, p1mod2);
  const yes = F.eql(powered, F.ONE);
  const zero = F.eql(powered, F.ZERO);
  const no = F.eql(powered, F.neg(F.ONE));
  if (!yes && !zero && !no)
    throw new Error("invalid Legendre symbol result");
  return yes ? 1 : zero ? 0 : -1;
}
function nLength(n, nBitLength) {
  if (nBitLength !== void 0)
    anumber2(nBitLength);
  if (n <= _0n2)
    throw new Error("invalid n length: expected positive n, got " + n);
  if (nBitLength !== void 0 && nBitLength < 1)
    throw new Error("invalid n length: expected positive bit length, got " + nBitLength);
  const bits = bitLen(n);
  if (nBitLength !== void 0 && nBitLength < bits)
    throw new Error(`invalid n length: expected nBitLength (${nBitLength}) >= bitLen(n) (${bits})`);
  const _nBitLength = nBitLength !== void 0 ? nBitLength : bits;
  const nByteLength = Math.ceil(_nBitLength / 8);
  return { nBitLength: _nBitLength, nByteLength };
}
var FIELD_SQRT = /* @__PURE__ */ new WeakMap();
var _Field = class {
  ORDER;
  BITS;
  BYTES;
  isLE;
  ZERO = _0n2;
  ONE = _1n2;
  _lengths;
  _mod;
  constructor(ORDER, opts = {}) {
    if (ORDER <= _1n2)
      throw new Error("invalid field: expected ORDER > 1, got " + ORDER);
    let _nbitLength = void 0;
    this.isLE = false;
    if (opts != null && typeof opts === "object") {
      if (typeof opts.BITS === "number")
        _nbitLength = opts.BITS;
      if (typeof opts.sqrt === "function")
        Object.defineProperty(this, "sqrt", { value: opts.sqrt, enumerable: true });
      if (typeof opts.isLE === "boolean")
        this.isLE = opts.isLE;
      if (opts.allowedLengths)
        this._lengths = Object.freeze(opts.allowedLengths.slice());
      if (typeof opts.modFromBytes === "boolean")
        this._mod = opts.modFromBytes;
    }
    const { nBitLength, nByteLength } = nLength(ORDER, _nbitLength);
    if (nByteLength > 2048)
      throw new Error("invalid field: expected ORDER of <= 2048 bytes");
    this.ORDER = ORDER;
    this.BITS = nBitLength;
    this.BYTES = nByteLength;
    Object.freeze(this);
  }
  create(num2) {
    return mod(num2, this.ORDER);
  }
  isValid(num2) {
    if (typeof num2 !== "bigint")
      throw new TypeError("invalid field element: expected bigint, got " + typeof num2);
    return _0n2 <= num2 && num2 < this.ORDER;
  }
  is0(num2) {
    return num2 === _0n2;
  }
  // is valid and invertible
  isValidNot0(num2) {
    return !this.is0(num2) && this.isValid(num2);
  }
  isOdd(num2) {
    return (num2 & _1n2) === _1n2;
  }
  neg(num2) {
    return mod(-num2, this.ORDER);
  }
  eql(lhs, rhs) {
    return lhs === rhs;
  }
  sqr(num2) {
    return mod(num2 * num2, this.ORDER);
  }
  add(lhs, rhs) {
    return mod(lhs + rhs, this.ORDER);
  }
  sub(lhs, rhs) {
    return mod(lhs - rhs, this.ORDER);
  }
  mul(lhs, rhs) {
    return mod(lhs * rhs, this.ORDER);
  }
  pow(num2, power) {
    return pow(num2, power, this.ORDER);
  }
  div(lhs, rhs) {
    return mod(lhs * invert(rhs, this.ORDER), this.ORDER);
  }
  // Same as above, but doesn't normalize
  sqrN(num2) {
    return num2 * num2;
  }
  addN(lhs, rhs) {
    return lhs + rhs;
  }
  subN(lhs, rhs) {
    return lhs - rhs;
  }
  mulN(lhs, rhs) {
    return lhs * rhs;
  }
  inv(num2) {
    return invert(num2, this.ORDER);
  }
  sqrt(num2) {
    let sqrt = FIELD_SQRT.get(this);
    if (!sqrt)
      FIELD_SQRT.set(this, sqrt = FpSqrt(this.ORDER));
    return sqrt(this, num2);
  }
  toBytes(num2) {
    return this.isLE ? numberToBytesLE(num2, this.BYTES) : numberToBytesBE(num2, this.BYTES);
  }
  fromBytes(bytes, skipValidation = false) {
    abytes2(bytes);
    const { _lengths: allowedLengths, BYTES, isLE: isLE2, ORDER, _mod: modFromBytes } = this;
    if (allowedLengths) {
      if (bytes.length < 1 || !allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
        throw new Error("Field.fromBytes: expected " + allowedLengths + " bytes, got " + bytes.length);
      }
      const padded = new Uint8Array(BYTES);
      padded.set(bytes, isLE2 ? 0 : padded.length - bytes.length);
      bytes = padded;
    }
    if (bytes.length !== BYTES)
      throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
    let scalar = isLE2 ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
    if (modFromBytes)
      scalar = mod(scalar, ORDER);
    if (!skipValidation) {
      if (!this.isValid(scalar))
        throw new Error("invalid field element: outside of range 0..ORDER");
    }
    return scalar;
  }
  // TODO: we don't need it here, move out to separate fn
  invertBatch(lst) {
    return FpInvertBatch(this, lst, true);
  }
  // We can't move this out because Fp6, Fp12 implement it
  // and it's unclear what to return in there.
  cmov(a, b, condition) {
    abool(condition, "condition");
    return condition ? b : a;
  }
};
function Field(ORDER, opts = {}) {
  Object.freeze(_Field.prototype);
  return new _Field(ORDER, opts);
}
function getFieldBytesLength(fieldOrder) {
  if (typeof fieldOrder !== "bigint")
    throw new Error("field order must be bigint");
  if (fieldOrder <= _1n2)
    throw new Error("field order must be greater than 1");
  const bitLength = bitLen(fieldOrder - _1n2);
  return Math.ceil(bitLength / 8);
}
function getMinHashLength(fieldOrder) {
  const length = getFieldBytesLength(fieldOrder);
  return length + Math.ceil(length / 2);
}
function mapHashToField(key, fieldOrder, isLE2 = false) {
  abytes2(key);
  const len = key.length;
  const fieldLen = getFieldBytesLength(fieldOrder);
  const minLen = Math.max(getMinHashLength(fieldOrder), 16);
  if (len < minLen || len > 1024)
    throw new Error("expected " + minLen + "-1024 bytes of input, got " + len);
  const num2 = isLE2 ? bytesToNumberLE(key) : bytesToNumberBE(key);
  const reduced = mod(num2, fieldOrder - _1n2) + _1n2;
  return isLE2 ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
}

// ../qr-secret-transfer/node_modules/@noble/curves/abstract/curve.js
var _0n3 = /* @__PURE__ */ BigInt(0);
var _1n3 = /* @__PURE__ */ BigInt(1);
var _4n2 = /* @__PURE__ */ BigInt(4);
var BLIND_BYTES = 16;
var BLIND_BITS = 128;
var FW_WINDOW = 5;
var TABLE_BYTES_MAX = /* @__PURE__ */ (() => 2 ** 31)();
function validatePointCons(Point) {
  const pc = Point;
  if (typeof pc !== "function")
    throw new TypeError('"Point" expected constructor, got type=' + typeof Point);
  afunction(pc.fromAffine, "Point.fromAffine");
  afunction(pc.fromBytes, "Point.fromBytes");
  afunction(pc.fromHex, "Point.fromHex");
  aobject2(pc.BASE, "Point.BASE");
  aobject2(pc.ZERO, "Point.ZERO");
  validateField(pc.Fp);
  validateField(pc.Fn);
}
function normalizeZ(c, points) {
  validatePointCons(c);
  validateMSMPoints(points, c);
  const invertedZs = FpInvertBatch(c.Fp, points.map((p) => p.Z));
  return points.map((p, i) => c.fromAffine(p.toAffine(invertedZs[i])));
}
function validateW(W, bits, min = 1) {
  if (!Number.isSafeInteger(W) || W < min || W > bits)
    throw new Error("invalid window size, expected [" + min + ".." + bits + "], got W=" + W);
}
function validateTableBytes(numPoints, fpBytes) {
  const bytes = numPoints * (4 * fpBytes + 128);
  if (bytes > TABLE_BYTES_MAX)
    throw new Error("invalid window size: table would need ~" + Math.ceil(bytes / 2 ** 20) + " MiB, max " + TABLE_BYTES_MAX / 2 ** 20 + " MiB");
}
function probeRandomBytes(randomBytes4, length) {
  if (randomBytes4 === void 0)
    return void 0;
  afunction(randomBytes4, "randomBytes");
  try {
    const probe = randomBytes4(length);
    if (!isBytes2(probe) || probe.length !== length)
      return void 0;
  } catch {
    return void 0;
  }
  return randomBytes4;
}
function validateMSMPoints(points, c) {
  aarray(points, "points");
  points.forEach((p, i) => {
    if (!(p instanceof c))
      throw new Error("invalid point at index " + i);
  });
}
function validateMSMScalars(scalars, field, maxScalar) {
  if (!Array.isArray(scalars))
    throw new Error("array of scalars expected");
  scalars.forEach((s, i) => {
    const ok = maxScalar === void 0 ? field.isValid(s) : isPosBig(s) && s < maxScalar;
    if (!ok)
      throw new Error("invalid scalar at index " + i);
  });
}
var pointWindowSizes = /* @__PURE__ */ new WeakMap();
function getWindowSize(P) {
  return pointWindowSizes.get(P) || 1;
}
function oddMultiples(p, size) {
  const dbl = p.double();
  const t = [p];
  for (let j = 1; j < size; j++)
    t.push(t[j - 1].add(dbl));
  return t;
}
function wnafDigits(n, W) {
  const size = 2 ** W;
  const half = size / 2;
  const mask = BigInt(size - 1);
  const d = [];
  while (n > _0n3) {
    let w = 0;
    if (n & _1n3) {
      w = Number(n & mask);
      if (w >= half)
        w -= size;
      n -= BigInt(w);
    }
    d.push(w);
    n >>= _1n3;
  }
  return d;
}
function signedWindowDigits(n, W, windows) {
  const size = 2 ** W;
  const half = size / 2;
  const mask = BigInt(size - 1);
  const shiftBy = BigInt(W);
  const d = [];
  for (let w = 0; w < windows; w++) {
    let v = Number(n & mask);
    n >>= shiftBy;
    if (v > half) {
      v -= size;
      n += _1n3;
    }
    d.push(v);
  }
  if (n !== _0n3)
    throw new Error("invalid wnaf");
  return d;
}
function wnafWalk(zero, tables, digits) {
  let max = 0;
  for (const d of digits)
    max = Math.max(max, d.length);
  let acc = zero;
  for (let bit = max - 1; bit >= 0; bit--) {
    if (bit !== max - 1)
      acc = acc.double();
    for (let i = 0; i < digits.length; i++) {
      const w = digits[i][bit];
      if (w) {
        const item = tables[i][Math.abs(w) - 1 >> 1];
        acc = acc.add(w < 0 ? item.negate() : item);
      }
    }
  }
  return acc;
}
var ScalarMultiplier = class {
  Point;
  BASE;
  ZERO;
  randomBytes;
  wnafPrecomputes = /* @__PURE__ */ new WeakMap();
  baseCanBeBlinded;
  bits;
  // Parametrized with a given Point class (not individual point)
  constructor(Point, randomBytes4) {
    validatePointCons(Point);
    this.randomBytes = probeRandomBytes(randomBytes4, BLIND_BYTES);
    this.Point = Point;
    this.BASE = Point.BASE;
    this.ZERO = Point.ZERO;
    this.bits = Point.Fn.BITS;
  }
  /**
   * Creates a signed fixed-window wNAF precomputation table: for every window w, the
   * multiples `[1..2^(W−1)]⋅2^(w⋅W)⋅P`, flattened. All doublings are baked into the table,
   * so cached multiplication is additions-only. `windows = ceil(bits/W) + 1`: the extra
   * window absorbs the final carry of signed-digit recoding.
   * For a 256-bit curve and W=6, the table is 44⋅32 = 1408 points.
   * @param point - Point instance
   * @param W - window size
   * @param bits - scalar bitlength the table must cover
   */
  buildWnafTable(point, W, bits) {
    const windows = Math.ceil(bits / W) + 1;
    const half = 2 ** (W - 1);
    const comp = [];
    let base = point;
    for (let w = 0; w < windows; w++) {
      let acc = base;
      for (let i = 0; i < half; i++) {
        comp.push(acc);
        acc = acc.add(base);
      }
      base = comp[comp.length - 1].double();
    }
    return { W, bits, windows, comp };
  }
  /**
   * Implements ec multiplication using precomputed signed fixed-window wNAF tables.
   * Constant-time: fixed window count with one table addition per window — zero digits feed
   * the fake accumulator — and no doublings; the lookup scans the whole window slice.
   * Scalar bounds are validated by the public entry points ({@link ScalarMultiplier.mulCT},
   * {@link ScalarMultiplier.mulCTBlinded}, {@link ScalarMultiplier.mulUnsafe});
   * signedWindowDigits throws if `n` exceeds the table.
   * @returns real and fake (for const-time) points
   */
  wnafCachedCT(precomputes, n) {
    const { W, windows, comp } = precomputes;
    const half = 2 ** (W - 1);
    const digits = signedWindowDigits(n, W, windows);
    let p = this.ZERO;
    let f = this.BASE;
    for (let w = 0; w < windows; w++) {
      const digit = digits[w];
      const start = w * half;
      const idx = Math.abs(digit) - 1;
      let sel = comp[start];
      for (let i = 1; i < half; i++)
        sel = i === idx ? comp[start + i] : sel;
      const neg = sel.negate();
      if (digit === 0)
        f = f.add(comp[start]);
      else
        p = p.add(digit < 0 ? neg : sel);
    }
    return { p, f };
  }
  // Cache key is point identity plus (W, bits); at most two entries exist per point (public-width
  // `Fn.BITS` and blinded `Fn.BITS + BLIND_BITS`). Callers must not reuse the same point with
  // incompatible `transform(...)` layouts and expect a separate cache entry.
  getWnafPrecomputes(W, point, bits, transform) {
    let entries = this.wnafPrecomputes.get(point);
    let comp = entries?.find((entry) => entry.W === W && entry.bits === bits);
    if (!comp) {
      comp = this.buildWnafTable(point, W, bits);
      if (typeof transform === "function")
        comp = { ...comp, comp: transform(comp.comp) };
      if (!entries) {
        entries = [];
        this.wnafPrecomputes.set(point, entries);
      }
      entries.push(comp);
    }
    return comp;
  }
  assertPoint(point) {
    if (!(point instanceof this.Point))
      throw new TypeError('"point" expected Point instance, got type=' + typeof point);
  }
  // Shared prologue of the constant-time entry points. Rejects scalar 0: in key/signature-style
  // callers a zero scalar means broken upstream plumbing, and concrete Points already reject it.
  // Uses inRange instead of Fn.isValidNot0: validateField() only certifies the arithmetic subset.
  validateMulInput(point, scalar) {
    this.assertPoint(point);
    if (!inRange(scalar, _1n3, this.Point.Fn.ORDER))
      throw new Error("invalid scalar");
  }
  // Constant-time dispatch shared by mulCT / mulCTBlinded. Un-precomputed points (W===1, e.g.
  // ECDH peer keys) skip building a throwaway cached table in favor of a small fixed-window
  // multiply. `n` must be < 2^bits.
  runCT(point, n, bits, transform) {
    const W = getWindowSize(point);
    if (W === 1)
      return this.fixedWindowCT(point, n, bits);
    return this.wnafCachedCT(this.getWnafPrecomputes(W, point, bits, transform), n);
  }
  mulCT(point, scalar, transform) {
    this.validateMulInput(point, scalar);
    return this.runCT(point, scalar, this.bits, transform);
  }
  mulCTBlinded(point, scalar, transform) {
    this.validateMulInput(point, scalar);
    if (this.randomBytes === void 0)
      throw new Error("randomBytes is required for scalar blinding");
    const bits = this.Point.Fn.BITS + BLIND_BITS;
    const blind = this.randomBytes(BLIND_BYTES);
    if (!isBytes2(blind) || blind.length !== BLIND_BYTES)
      throw new Error("randomBytes returned invalid byte array");
    blind[0] = blind[0] & 63 | 128;
    const n = scalar + bytesToNumberBE(blind) * this.Point.Fn.ORDER;
    return this.runCT(point, n, bits, transform);
  }
  /**
   * Constant-time multiplication `n*point` for an un-precomputed point, via a small fixed window.
   * A cached wNAF table only pays off when reused; a flat 2^FW_WINDOW table (`size-1` adds) is
   * far cheaper to build for a single use. The point-operation sequence is independent of `n`:
   * build the table, then per window exactly FW_WINDOW doublings, a data-oblivious scan over
   * every table entry, and one addition (adds the identity when the window digit is 0 — never
   * skipped).
   *
   * `n` must be `< 2^bits`. Assumes complete addition (adding the identity costs the same as any
   * add), which holds for the Weierstrass/Edwards point types used here. The table is left in
   * projective form (no normalizeZ): normalizing this small a table costs more than the
   * mixed-add savings it would buy for a single multiply.
   * @returns real point `p`; `f` duplicates it only to match {@link wnafCachedCT}'s return shape
   * (this path needs no fake accumulator — its op-count is already scalar-independent).
   */
  fixedWindowCT(point, n, bits) {
    const W = FW_WINDOW;
    const size = 1 << W;
    const mask = bitMask(W);
    const table = new Array(size);
    table[0] = this.ZERO;
    for (let i = 1; i < size; i++)
      table[i] = table[i - 1].add(point);
    const windows = Math.ceil(bits / W);
    let acc = this.ZERO;
    for (let window = windows - 1; window >= 0; window--) {
      if (window !== windows - 1)
        for (let d = 0; d < W; d++)
          acc = acc.double();
      const digit = Number(n >> BigInt(window * W) & mask);
      let sel = table[0];
      for (let i = 1; i < size; i++)
        sel = i === digit ? table[i] : sel;
      acc = acc.add(sel);
    }
    return { p: acc, f: acc };
  }
  shouldBlind(point, cofactor) {
    if (this.randomBytes === void 0)
      return false;
    if (cofactor === _1n3)
      return true;
    if (point !== this.BASE)
      return false;
    if (this.baseCanBeBlinded === void 0)
      this.baseCanBeBlinded = this.mulUnsafe(this.BASE, this.Point.Fn.ORDER).is0();
    return this.baseCanBeBlinded;
  }
  mulSecret(point, scalar, cofactor, transform) {
    return this.shouldBlind(point, cofactor) ? this.mulCTBlinded(point, scalar, transform) : this.mulCT(point, scalar, transform);
  }
  mulUnsafe(point, scalar, transform) {
    this.assertPoint(point);
    if (!isPosBig(scalar))
      throw new Error("invalid scalar");
    const W = getWindowSize(point);
    if (W === 1 || scalar >= this.Point.Fn.ORDER)
      return mulAddUnsafe(this.Point, [point], [scalar], true);
    const precomputes = this.getWnafPrecomputes(W, point, this.bits, transform);
    return this.wnafCachedCT(precomputes, scalar).p;
  }
  // Remembers the window size used for precomputed wNAF multiplication of the given point
  // and drops any previously built tables. Usually only the base point is precomputed.
  // W=1 resets the point to the un-precomputed (table-less) paths.
  // W is additionally capped so tables stay under ~2 GiB ({@link TABLE_BYTES_MAX}).
  setWindowSize(point, W) {
    this.assertPoint(point);
    validateW(W, this.bits);
    const windows = Math.ceil((this.bits + BLIND_BITS) / W) + 1;
    validateTableBytes(windows * 2 ** (W - 1), this.Point.Fp.BYTES);
    pointWindowSizes.set(point, W);
    this.wnafPrecomputes.delete(point);
  }
  // True when a window size is set: tables themselves are built lazily on first multiply.
  hasWindowSize(point) {
    return getWindowSize(point) !== 1;
  }
};
function mulAddUnsafe(c, points, scalars, allowOversized = false) {
  validatePointCons(c);
  validateMSMPoints(points, c);
  abool(allowOversized, "allowOversized");
  validateMSMScalars(scalars, c.Fn, allowOversized ? c.Fn.ORDER ** _4n2 : void 0);
  if (points.length !== scalars.length)
    throw new Error("arrays of points and scalars must have equal length");
  const tables = points.map((p) => oddMultiples(p, 4));
  const digits = scalars.map((n) => wnafDigits(n, 4));
  return wnafWalk(c.ZERO, tables, digits);
}
function createField(order, field, isLE2) {
  if (field) {
    if (field.ORDER !== order)
      throw new Error("Field.ORDER must match order: Fp == p, Fn == n");
    validateField(field);
    return field;
  } else {
    return Field(order, { isLE: isLE2 });
  }
}
function createCurveFields(type, CURVE, curveOpts = {}, FpFnLE) {
  if (type !== "weierstrass" && type !== "edwards")
    throw new Error('expected curve type "weierstrass" or "edwards"');
  if (FpFnLE === void 0)
    FpFnLE = type === "edwards";
  if (!CURVE || typeof CURVE !== "object")
    throw new Error(`expected valid ${type} CURVE object`);
  validateObject(curveOpts);
  for (const p of ["p", "n", "h"]) {
    const val = CURVE[p];
    if (!(isPosBig(val) && val !== _0n3))
      throw new Error(`CURVE.${p} must be positive bigint`);
  }
  const Fp = createField(CURVE.p, curveOpts.Fp, FpFnLE);
  const Fn = createField(CURVE.n, curveOpts.Fn, FpFnLE);
  const _b = type === "weierstrass" ? "b" : "d";
  const params = ["Gx", "Gy", "a", _b];
  for (const p of params) {
    if (!Fp.isValid(CURVE[p]))
      throw new Error(`CURVE.${p} must be valid field element of CURVE.Fp`);
  }
  CURVE = Object.freeze(Object.assign({}, CURVE));
  return { CURVE, Fp, Fn };
}
function createKeygen(randomSecretKey, getPublicKey) {
  return function keygen(seed) {
    const secretKey = randomSecretKey(seed);
    return { secretKey, publicKey: getPublicKey(secretKey) };
  };
}

// ../qr-secret-transfer/node_modules/@noble/hashes/hmac.js
var _HMAC = class {
  oHash;
  iHash;
  blockLen;
  outputLen;
  canXOF = false;
  finished = false;
  destroyed = false;
  constructor(hash, key) {
    ahash(hash);
    abytes(key, void 0, "key");
    this.iHash = hash.create();
    if (typeof this.iHash.update !== "function")
      throw new Error("expected Hash instance");
    this.blockLen = this.iHash.blockLen;
    this.outputLen = this.iHash.outputLen;
    const blockLen = this.blockLen;
    const pad2 = new Uint8Array(blockLen);
    pad2.set(key.length > blockLen ? hash.create().update(key).digest() : key);
    for (let i = 0; i < pad2.length; i++)
      pad2[i] ^= 54;
    this.iHash.update(pad2);
    this.oHash = hash.create();
    for (let i = 0; i < pad2.length; i++)
      pad2[i] ^= 54 ^ 92;
    this.oHash.update(pad2);
    clean(pad2);
  }
  update(buf) {
    aexists(this);
    this.iHash.update(buf);
    return this;
  }
  digestInto(out) {
    aexists(this);
    aoutput(out, this);
    this.finished = true;
    const buf = out.subarray(0, this.outputLen);
    this.iHash.digestInto(buf);
    this.oHash.update(buf);
    this.oHash.digestInto(buf);
    this.destroy();
  }
  digest() {
    const out = new Uint8Array(this.oHash.outputLen);
    this.digestInto(out);
    return out;
  }
  _cloneInto(to) {
    to ||= Object.create(Object.getPrototypeOf(this), {});
    const { oHash, iHash, finished, destroyed, blockLen, outputLen, canXOF } = this;
    to = to;
    to.finished = finished;
    to.destroyed = destroyed;
    to.blockLen = blockLen;
    to.outputLen = outputLen;
    to.canXOF = canXOF;
    to.oHash = oHash._cloneInto(to.oHash);
    to.iHash = iHash._cloneInto(to.iHash);
    return to;
  }
  clone() {
    return this._cloneInto();
  }
  destroy() {
    this.destroyed = true;
    this.oHash.destroy();
    this.iHash.destroy();
  }
};
var hmac = /* @__PURE__ */ (() => {
  const hmac_ = ((hash, key, message) => new _HMAC(hash, key).update(message).digest());
  hmac_.create = (hash, key) => new _HMAC(hash, key);
  return hmac_;
})();

// ../qr-secret-transfer/node_modules/@noble/curves/abstract/der.js
var _0n4 = /* @__PURE__ */ BigInt(0);
var DERErr = class extends Error {
  constructor(m = "") {
    super(m);
  }
};
var _DER = {
  // asn.1 DER encoding utils
  Err: DERErr,
  // Basic building block is TLV (Tag-Length-Value)
  _tlv: {
    encode: (tag, data) => {
      const { Err: E } = _DER;
      asafenumber(tag, "tag");
      if (tag < 0 || tag > 255)
        throw new E("tlv.encode: wrong tag");
      astring(data, "data");
      if (data.length & 1)
        throw new E("tlv.encode: unpadded data");
      const dataLen = data.length / 2;
      const len = numberToHexUnpadded(dataLen);
      if (len.length / 2 & 128)
        throw new E("tlv.encode: long form length too big");
      const lenLen = dataLen > 127 ? numberToHexUnpadded(len.length / 2 | 128) : "";
      const t = numberToHexUnpadded(tag);
      return t + lenLen + len + data;
    },
    // v - value, l - left bytes (unparsed)
    decode(tag, data) {
      const { Err: E } = _DER;
      data = abytes2(data, void 0, "DER data");
      let pos = 0;
      if (tag < 0 || tag > 255)
        throw new E("tlv.decode: wrong tag");
      if (data.length < 2 || data[pos++] !== tag)
        throw new E("tlv.decode: wrong tlv");
      const first = data[pos++];
      const isLong = !!(first & 128);
      let length = 0;
      if (!isLong)
        length = first;
      else {
        const lenLen = first & 127;
        if (!lenLen)
          throw new E("tlv.decode(long): indefinite length not supported");
        if (lenLen > 4)
          throw new E("tlv.decode(long): byte length is too big");
        const lengthBytes = data.subarray(pos, pos + lenLen);
        if (lengthBytes.length !== lenLen)
          throw new E("tlv.decode: length bytes not complete");
        if (lengthBytes[0] === 0)
          throw new E("tlv.decode(long): zero leftmost byte");
        for (const b of lengthBytes)
          length = length << 8 | b;
        pos += lenLen;
        if (length < 128)
          throw new E("tlv.decode(long): not minimal encoding");
      }
      const v = data.subarray(pos, pos + length);
      if (v.length !== length)
        throw new E("tlv.decode: wrong value length");
      return { v, l: data.subarray(pos + length) };
    }
  },
  // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
  // since we always use positive integers here. It must always be empty:
  // - add zero byte if exists
  // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
  _int: {
    encode(num2) {
      const { Err: E } = _DER;
      abignumber(num2);
      if (num2 < _0n4)
        throw new E("integer: negative integers are not allowed");
      let hex = numberToHexUnpadded(num2);
      if (Number.parseInt(hex[0], 16) & 8)
        hex = "00" + hex;
      if (hex.length & 1)
        throw new E("unexpected DER parsing assertion: unpadded hex");
      return hex;
    },
    decode(data) {
      const { Err: E } = _DER;
      if (data.length < 1)
        throw new E("invalid signature integer: empty");
      if (data[0] & 128)
        throw new E("invalid signature integer: negative");
      if (data.length > 1 && data[0] === 0 && !(data[1] & 128))
        throw new E("invalid signature integer: unnecessary leading zero");
      return bytesToNumberBE(data);
    }
  },
  toSig(bytes, maxScalarBytes) {
    const { Err: E, _int: int, _tlv: tlv } = _DER;
    if (maxScalarBytes !== void 0) {
      asafenumber(maxScalarBytes, "maxScalarBytes");
      if (maxScalarBytes < 1)
        throw new E("invalid signature: maxScalarBytes must be positive");
    }
    const data = abytes2(bytes, void 0, "signature");
    const { v: seqBytes, l: seqLeftBytes } = tlv.decode(48, data);
    if (seqLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    const { v: rBytes, l: rLeftBytes } = tlv.decode(2, seqBytes);
    const { v: sBytes, l: sLeftBytes } = tlv.decode(2, rLeftBytes);
    if (sLeftBytes.length)
      throw new E("invalid signature: left bytes after parsing");
    if (maxScalarBytes !== void 0 && (rBytes.length > maxScalarBytes || sBytes.length > maxScalarBytes))
      throw new E("invalid signature: integer too large");
    return { r: int.decode(rBytes), s: int.decode(sBytes) };
  },
  hexFromSig(sig) {
    const { _tlv: tlv, _int: int } = _DER;
    validateObject(sig, { r: "bigint", s: "bigint" }, {}, "sig");
    const rs = tlv.encode(2, int.encode(sig.r));
    const ss = tlv.encode(2, int.encode(sig.s));
    const seq = rs + ss;
    return tlv.encode(48, seq);
  }
};
var DER = /* @__PURE__ */ (() => {
  Object.freeze(_DER._tlv);
  Object.freeze(_DER._int);
  return Object.freeze(_DER);
})();

// ../qr-secret-transfer/node_modules/@noble/curves/abstract/weierstrass.js
var divNearest = (num2, den) => (num2 + (num2 >= 0 ? den : -den) / _2n2) / den;
function _splitEndoScalar(k, basis, n) {
  aInRange("scalar", k, _0n5, n);
  const [[a1, b1], [a2, b2]] = basis;
  const c1 = divNearest(b2 * k, n);
  const c2 = divNearest(-b1 * k, n);
  let k1 = k - c1 * a1 - c2 * a2;
  let k2 = -c1 * b1 - c2 * b2;
  const k1neg = k1 < _0n5;
  const k2neg = k2 < _0n5;
  if (k1neg)
    k1 = -k1;
  if (k2neg)
    k2 = -k2;
  const MAX_NUM = bitMask(Math.ceil(bitLen(n) / 2)) + _1n4;
  if (k1 < _0n5 || k1 >= MAX_NUM || k2 < _0n5 || k2 >= MAX_NUM) {
    throw new Error("splitScalar (endomorphism): failed for k");
  }
  return { k1neg, k1, k2neg, k2 };
}
function validateSigFormat(format) {
  if (!["compact", "recovered", "der"].includes(format))
    throw new Error('Signature format must be "compact", "recovered", or "der"');
  return format;
}
function validateSigOpts(opts, def) {
  validateObject(opts);
  const optsn = {};
  for (let optName of Object.keys(def)) {
    optsn[optName] = opts[optName] === void 0 ? def[optName] : opts[optName];
  }
  abool(optsn.lowS, "lowS");
  abool(optsn.prehash, "prehash");
  if (optsn.format !== void 0)
    validateSigFormat(optsn.format);
  return optsn;
}
var _0n5 = /* @__PURE__ */ BigInt(0);
var _1n4 = /* @__PURE__ */ BigInt(1);
var _2n2 = /* @__PURE__ */ BigInt(2);
var _3n2 = /* @__PURE__ */ BigInt(3);
var _4n3 = /* @__PURE__ */ BigInt(4);
function weierstrass(params, extraOpts = {}) {
  const validated = createCurveFields("weierstrass", params, extraOpts);
  const Fp = validated.Fp;
  const Fn = validated.Fn;
  let CURVE = validated.CURVE;
  const { h: cofactor, n: CURVE_ORDER } = CURVE;
  validateObject(extraOpts, {}, {
    allowInfinityPoint: "boolean",
    clearCofactor: "function",
    isTorsionFree: "function",
    fromBytes: "function",
    toBytes: "function",
    endo: "object",
    randomBytes: "function"
  });
  const { endo: endoOpts, allowInfinityPoint, clearCofactor, isTorsionFree, fromBytes, toBytes } = extraOpts;
  const randomBytes4 = extraOpts.randomBytes === void 0 ? randomBytes2 : extraOpts.randomBytes;
  if (endoOpts) {
    if (!Fp.is0(CURVE.a) || typeof endoOpts.beta !== "bigint" || !Array.isArray(endoOpts.basises)) {
      throw new Error('invalid endo: expected "beta": bigint and "basises": array');
    }
  }
  const endo = endoOpts ? {
    beta: endoOpts.beta,
    basises: endoOpts.basises.map((basis) => [...basis])
  } : void 0;
  const lengths = getWLengths(Fp, Fn);
  function assertCompressionIsSupported() {
    if (!Fp.isOdd)
      throw new Error("compression is not supported: Field does not have .isOdd()");
  }
  function pointToBytes2(_c, point, isCompressed) {
    if (point.is0()) {
      if (!allowInfinityPoint)
        throw new Error("bad point: ZERO");
      return Uint8Array.of(0);
    }
    const { x, y } = point.toAffine();
    const bx = Fp.toBytes(x);
    abool(isCompressed, "isCompressed");
    if (isCompressed) {
      assertCompressionIsSupported();
      const hasEvenY = !Fp.isOdd(y);
      return concatBytes2(pprefix(hasEvenY), bx);
    } else {
      return concatBytes2(Uint8Array.of(4), bx, Fp.toBytes(y));
    }
  }
  function pointFromBytes(bytes) {
    abytes2(bytes, void 0, "Point");
    const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths;
    const length = bytes.length;
    const head = bytes[0];
    const tail = bytes.subarray(1);
    if (allowInfinityPoint && length === 1 && head === 0)
      return { x: Fp.ZERO, y: Fp.ZERO };
    if (length === comp && (head === 2 || head === 3)) {
      const x = Fp.fromBytes(tail);
      if (!Fp.isValid(x))
        throw new Error("bad point: is not on curve, wrong x");
      const y2 = weierstrassEquation(x);
      let y;
      try {
        y = Fp.sqrt(y2);
      } catch (sqrtError) {
        const err = sqrtError instanceof Error ? ": " + sqrtError.message : "";
        throw new Error("bad point: is not on curve, sqrt error" + err);
      }
      assertCompressionIsSupported();
      const evenY = Fp.isOdd(y);
      const evenH = (head & 1) === 1;
      if (evenH !== evenY)
        y = Fp.neg(y);
      return { x, y };
    } else if (length === uncomp && head === 4) {
      const L = Fp.BYTES;
      const x = Fp.fromBytes(tail.subarray(0, L));
      const y = Fp.fromBytes(tail.subarray(L, L * 2));
      if (!isValidXY(x, y))
        throw new Error("bad point: is not on curve");
      return { x, y };
    } else {
      throw new Error(`bad point: got length ${length}, expected compressed=${comp} or uncompressed=${uncomp}`);
    }
  }
  const encodePoint = toBytes === void 0 ? pointToBytes2 : toBytes;
  const decodePoint = fromBytes === void 0 ? pointFromBytes : fromBytes;
  const b3 = Fp.mul(CURVE.b, _3n2);
  const mulA = Fp.is0(CURVE.a) ? (_) => Fp.ZERO : (x) => Fp.mul(CURVE.a, x);
  function weierstrassEquation(x) {
    const x2 = Fp.sqr(x);
    const x3 = Fp.mul(x2, x);
    return Fp.add(Fp.add(x3, Fp.mul(x, CURVE.a)), CURVE.b);
  }
  function isValidXY(x, y) {
    const left = Fp.sqr(y);
    const right = weierstrassEquation(x);
    return Fp.eql(left, right);
  }
  if (!isValidXY(CURVE.Gx, CURVE.Gy))
    throw new Error("bad curve params: generator point");
  const _4a3 = Fp.mul(Fp.pow(CURVE.a, _3n2), _4n3);
  const _27b2 = Fp.mul(Fp.sqr(CURVE.b), BigInt(27));
  if (Fp.is0(Fp.add(_4a3, _27b2)))
    throw new Error("bad curve params: a or b");
  function acoord(title, n, banZero = false) {
    if (!Fp.isValid(n) || banZero && Fp.is0(n))
      throw new Error(`bad point coordinate ${title}`);
    return typeof n === "object" && n !== null ? Fp.create(n) : n;
  }
  function aprjpoint(other) {
    if (!(other instanceof Point))
      throw new Error("Weierstrass Point expected");
  }
  function splitEndoScalarN(k) {
    if (!endo || !endo.basises)
      throw new Error("no endo");
    return _splitEndoScalar(k, endo.basises, Fn.ORDER);
  }
  function pushWnafPair(points, scalars, p, k) {
    if (!Fn.isValid(k))
      throw new RangeError("invalid scalar: out of range");
    if (endo) {
      const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(k);
      const psi = new Point(Fp.mul(p.X, endo.beta), p.Y, p.Z);
      points.push(k1neg ? p.negate() : p, k2neg ? psi.negate() : psi);
      scalars.push(k1, k2);
    } else {
      points.push(p);
      scalars.push(k);
    }
  }
  const validityCache = /* @__PURE__ */ new WeakSet();
  class Point {
    static BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
    static ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);
    static Fp = Fp;
    static Fn = Fn;
    X;
    Y;
    Z;
    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    constructor(X, Y, Z) {
      this.X = acoord("x", X);
      this.Y = acoord("y", Y, true);
      this.Z = acoord("z", Z);
      Object.freeze(this);
    }
    static CURVE() {
      return CURVE;
    }
    /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
    static fromAffine(p) {
      const { x, y } = p || {};
      if (!p || !Fp.isValid(x) || !Fp.isValid(y))
        throw new Error("invalid affine point");
      if (p instanceof Point)
        throw new Error("projective point not allowed");
      if (Fp.is0(x) && Fp.is0(y))
        return Point.ZERO;
      return new Point(x, y, Fp.ONE);
    }
    static fromBytes(bytes) {
      const P = Point.fromAffine(decodePoint(abytes2(bytes, void 0, "point")));
      P.assertValidity();
      return P;
    }
    static fromHex(hex) {
      return Point.fromBytes(hexToBytes2(hex));
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    /**
     * @param isLazy - true will defer table computation until the first multiplication
     */
    precompute(windowSize = 6, isLazy = true) {
      wnaf.setWindowSize(this, windowSize);
      if (!isLazy)
        this.multiply(_3n2);
      return this;
    }
    // TODO: return `this`
    /** A point on curve is valid if it conforms to equation. */
    assertValidity() {
      const p = this;
      if (p.is0()) {
        if (allowInfinityPoint && Fp.is0(p.X) && Fp.eql(p.Y, Fp.ONE) && Fp.is0(p.Z))
          return;
        throw new Error("bad point: ZERO");
      }
      if (validityCache.has(p))
        return;
      const { x, y } = p.toAffine();
      if (!Fp.isValid(x) || !Fp.isValid(y))
        throw new Error("bad point: x or y not field elements");
      if (!isValidXY(x, y))
        throw new Error("bad point: equation left != right");
      if (!p.isTorsionFree())
        throw new Error("bad point: not in prime-order subgroup");
      validityCache.add(p);
    }
    hasEvenY() {
      const { y } = this.toAffine();
      if (!Fp.isOdd)
        throw new Error("Field doesn't support isOdd");
      return !Fp.isOdd(y);
    }
    /** Compare one point to another. */
    equals(other) {
      aprjpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
      const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
      return U1 && U2;
    }
    /** Flips point to one corresponding to (x, -y) in Affine coordinates. */
    negate() {
      return new Point(this.X, Fp.neg(this.Y), this.Z);
    }
    // Renes-Costello-Batina exception-free doubling formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 3
    // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
    double() {
      const { X: X1, Y: Y1, Z: Z1 } = this;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
      let t0 = Fp.mul(X1, X1);
      let t1 = Fp.mul(Y1, Y1);
      let t2 = Fp.mul(Z1, Z1);
      let t3 = Fp.mul(X1, Y1);
      t3 = Fp.add(t3, t3);
      Z3 = Fp.mul(X1, Z1);
      Z3 = Fp.add(Z3, Z3);
      X3 = mulA(Z3);
      Y3 = Fp.mul(b3, t2);
      Y3 = Fp.add(X3, Y3);
      X3 = Fp.sub(t1, Y3);
      Y3 = Fp.add(t1, Y3);
      Y3 = Fp.mul(X3, Y3);
      X3 = Fp.mul(t3, X3);
      Z3 = Fp.mul(b3, Z3);
      t2 = mulA(t2);
      t3 = Fp.sub(t0, t2);
      t3 = mulA(t3);
      t3 = Fp.add(t3, Z3);
      Z3 = Fp.add(t0, t0);
      t0 = Fp.add(Z3, t0);
      t0 = Fp.add(t0, t2);
      t0 = Fp.mul(t0, t3);
      Y3 = Fp.add(Y3, t0);
      t2 = Fp.mul(Y1, Z1);
      t2 = Fp.add(t2, t2);
      t0 = Fp.mul(t2, t3);
      X3 = Fp.sub(X3, t0);
      Z3 = Fp.mul(t2, t1);
      Z3 = Fp.add(Z3, Z3);
      Z3 = Fp.add(Z3, Z3);
      return new Point(X3, Y3, Z3);
    }
    // Renes-Costello-Batina exception-free addition formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 1
    // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
    add(other) {
      aprjpoint(other);
      const { X: X1, Y: Y1, Z: Z1 } = this;
      const { X: X2, Y: Y2, Z: Z2 } = other;
      let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
      let t0 = Fp.mul(X1, X2);
      let t1 = Fp.mul(Y1, Y2);
      let t2 = Fp.mul(Z1, Z2);
      let t3 = Fp.add(X1, Y1);
      let t4 = Fp.add(X2, Y2);
      t3 = Fp.mul(t3, t4);
      t4 = Fp.add(t0, t1);
      t3 = Fp.sub(t3, t4);
      t4 = Fp.add(X1, Z1);
      let t5 = Fp.add(X2, Z2);
      t4 = Fp.mul(t4, t5);
      t5 = Fp.add(t0, t2);
      t4 = Fp.sub(t4, t5);
      t5 = Fp.add(Y1, Z1);
      X3 = Fp.add(Y2, Z2);
      t5 = Fp.mul(t5, X3);
      X3 = Fp.add(t1, t2);
      t5 = Fp.sub(t5, X3);
      Z3 = mulA(t4);
      X3 = Fp.mul(b3, t2);
      Z3 = Fp.add(X3, Z3);
      X3 = Fp.sub(t1, Z3);
      Z3 = Fp.add(t1, Z3);
      Y3 = Fp.mul(X3, Z3);
      t1 = Fp.add(t0, t0);
      t1 = Fp.add(t1, t0);
      t2 = mulA(t2);
      t4 = Fp.mul(b3, t4);
      t1 = Fp.add(t1, t2);
      t2 = Fp.sub(t0, t2);
      t2 = mulA(t2);
      t4 = Fp.add(t4, t2);
      t0 = Fp.mul(t1, t4);
      Y3 = Fp.add(Y3, t0);
      t0 = Fp.mul(t5, t4);
      X3 = Fp.mul(t3, X3);
      X3 = Fp.sub(X3, t0);
      t0 = Fp.mul(t3, t1);
      Z3 = Fp.mul(t5, Z3);
      Z3 = Fp.add(Z3, t0);
      return new Point(X3, Y3, Z3);
    }
    subtract(other) {
      aprjpoint(other);
      return this.add(other.negate());
    }
    is0() {
      return this.equals(Point.ZERO);
    }
    /**
     * Constant time multiplication.
     * Uses precomputed tables (signed fixed-window wNAF) when available.
     * Uses scalar blinding and avoids endomorphism splitting in the secret-scalar path.
     * @param scalar - by which the point would be multiplied
     * @returns New point
     */
    multiply(scalar) {
      if (!Fn.isValidNot0(scalar))
        throw new RangeError("invalid scalar: out of range");
      const { p, f } = wnaf.mulSecret(this, scalar, cofactor, normalize);
      return normalize([p, f])[0];
    }
    /**
     * Non-constant-time multiplication. Uses width-4 wNAF with GLV endomorphism splitting
     * when available (two half-width scalars sharing one halved doubling chain).
     * It's faster, but should only be used when you don't care about
     * an exposed secret key e.g. sig verification, which works over *public* keys.
     */
    multiplyUnsafe(scalar) {
      const p = this;
      const sc = scalar;
      if (!Fn.isValid(sc))
        throw new RangeError("invalid scalar: out of range");
      if (sc === _0n5 || p.is0())
        return Point.ZERO;
      if (sc === _1n4)
        return p;
      if (wnaf.hasWindowSize(this))
        return wnaf.mulUnsafe(p, sc, normalize);
      const points = [];
      const scalars = [];
      pushWnafPair(points, scalars, p, sc);
      return mulAddUnsafe(Point, points, scalars);
    }
    /**
     * Non-constant-time double-scalar multiplication `a⋅this + b⋅other` (Strauss–Shamir).
     * Both walks share one doubling chain via {@link mulAddUnsafe}, and GLV endomorphism
     * (when available) halves the chain again by splitting each scalar into two half-width
     * parts. Used by ECDSA verification and public-key recovery for `R = u1⋅G + u2⋅P`.
     * Only for public scalars.
     */
    mulAddUnsafe(a, other, b) {
      aprjpoint(other);
      const points = [];
      const scalars = [];
      pushWnafPair(points, scalars, this, a);
      pushWnafPair(points, scalars, other, b);
      return mulAddUnsafe(Point, points, scalars);
    }
    /**
     * Converts Projective point to affine (x, y) coordinates.
     * (X, Y, Z) ∋ (x=X/Z, y=Y/Z).
     * @param invertedZ - Z^-1 (inverted zero) - optional, precomputation is useful for invertBatch
     */
    toAffine(invertedZ) {
      const p = this;
      let iz = invertedZ;
      if (iz != null && !Fp.isValid(iz))
        throw new RangeError('"invertedZ" expected valid field element');
      const { X, Y, Z } = p;
      if (Fp.eql(Z, Fp.ONE))
        return { x: X, y: Y };
      const is0 = p.is0();
      if (iz == null)
        iz = is0 ? Fp.ONE : Fp.inv(Z);
      const x = Fp.mul(X, iz);
      const y = Fp.mul(Y, iz);
      const zz = Fp.mul(Z, iz);
      if (is0)
        return { x: Fp.ZERO, y: Fp.ZERO };
      if (!Fp.eql(zz, Fp.ONE))
        throw new Error("invZ was invalid");
      return { x, y };
    }
    /**
     * Checks whether Point is free of torsion elements (is in prime subgroup).
     * Always torsion-free for cofactor=1 curves.
     */
    isTorsionFree() {
      if (cofactor === _1n4)
        return true;
      if (isTorsionFree)
        return isTorsionFree(Point, this);
      return wnaf.mulUnsafe(this, CURVE_ORDER).is0();
    }
    clearCofactor() {
      if (cofactor === _1n4)
        return this;
      if (clearCofactor)
        return clearCofactor(Point, this);
      return this.multiplyUnsafe(cofactor);
    }
    isSmallOrder() {
      if (cofactor === _1n4)
        return this.is0();
      return this.clearCofactor().is0();
    }
    toBytes(isCompressed = true) {
      abool(isCompressed, "isCompressed");
      this.assertValidity();
      return encodePoint(Point, this, isCompressed);
    }
    toHex(isCompressed = true) {
      return bytesToHex2(this.toBytes(isCompressed));
    }
    toString() {
      return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
    }
  }
  const normalize = (points) => normalizeZ(Point, points);
  const wnaf = new ScalarMultiplier(Point, randomBytes4);
  if (wnaf.bits >= 6)
    Point.BASE.precompute(6);
  Object.freeze(Point.prototype);
  Object.freeze(Point);
  return Point;
}
function pprefix(hasEvenY) {
  return Uint8Array.of(hasEvenY ? 2 : 3);
}
function getWLengths(Fp, Fn) {
  return {
    secretKey: Fn.BYTES,
    publicKey: 1 + Fp.BYTES,
    publicKeyUncompressed: 1 + 2 * Fp.BYTES,
    publicKeyHasPrefix: true,
    // Raw compact `(r || s)` signature width; DER and recovered signatures use
    // different lengths outside this helper.
    signature: 2 * Fn.BYTES
  };
}
function ecdh(Point, ecdhOpts = {}) {
  validatePointCons(Point);
  const { Fn } = Point;
  const randomBytes_ = ecdhOpts.randomBytes === void 0 ? randomBytes2 : ecdhOpts.randomBytes;
  const lengths = Object.assign(getWLengths(Point.Fp, Fn), {
    seed: Math.max(getMinHashLength(Fn.ORDER), 16)
  });
  function isValidSecretKey(secretKey) {
    try {
      const num2 = Fn.fromBytes(secretKey);
      return Fn.isValidNot0(num2);
    } catch (error) {
      return false;
    }
  }
  function isValidPublicKey2(publicKey2, isCompressed) {
    const { publicKey: comp, publicKeyUncompressed } = lengths;
    try {
      const l = publicKey2.length;
      if (isCompressed === true && l !== comp)
        return false;
      if (isCompressed === false && l !== publicKeyUncompressed)
        return false;
      return !Point.fromBytes(publicKey2).is0();
    } catch (error) {
      return false;
    }
  }
  function randomSecretKey(seed) {
    seed = seed === void 0 ? randomBytes_(lengths.seed) : seed;
    return mapHashToField(abytes2(seed, lengths.seed, "seed"), Fn.ORDER);
  }
  function getPublicKey(secretKey, isCompressed = true) {
    return Point.BASE.multiply(Fn.fromBytes(secretKey)).toBytes(isCompressed);
  }
  function isProbPub(item) {
    const { secretKey, publicKey: publicKey2, publicKeyUncompressed } = lengths;
    const allowedLengths = Fn._lengths;
    if (!isBytes2(item))
      return void 0;
    const l = abytes2(item, void 0, "key").length;
    const isPub = l === publicKey2 || l === publicKeyUncompressed;
    const isSec = l === secretKey || !!allowedLengths?.includes(l);
    if (isPub && isSec)
      return void 0;
    return isPub;
  }
  function getSharedSecret(secretKeyA, publicKeyB, isCompressed = true) {
    if (isProbPub(secretKeyA) === true)
      throw new Error("first arg must be private key");
    if (isProbPub(publicKeyB) === false)
      throw new Error("second arg must be public key");
    const s = Fn.fromBytes(secretKeyA);
    const b = Point.fromBytes(publicKeyB);
    if (b.is0())
      throw new Error("invalid public key: point at infinity");
    return b.multiply(s).toBytes(isCompressed);
  }
  const utils = {
    isValidSecretKey,
    isValidPublicKey: isValidPublicKey2,
    randomSecretKey
  };
  const keygen = createKeygen(randomSecretKey, getPublicKey);
  Object.freeze(utils);
  Object.freeze(lengths);
  return Object.freeze({ getPublicKey, getSharedSecret, keygen, Point, utils, lengths });
}
function ecdsa(Point, hash, ecdsaOpts = {}) {
  validatePointCons(Point);
  const hash_ = hash;
  ahash(hash_);
  validateObject(ecdsaOpts, {}, {
    hmac: "function",
    lowS: "boolean",
    randomBytes: "function",
    bits2int: "function",
    bits2int_modN: "function"
  });
  const opts = Object.assign({}, ecdsaOpts);
  const randomBytes4 = opts.randomBytes === void 0 ? randomBytes2 : opts.randomBytes;
  const hmac2 = opts.hmac === void 0 ? (key, msg) => hmac(hash_, key, msg) : opts.hmac;
  const { Fp, Fn } = Point;
  const { ORDER: CURVE_ORDER, BITS: fnBits } = Fn;
  const blindLength = getMinHashLength(CURVE_ORDER);
  const csprng = probeRandomBytes(randomBytes4, blindLength);
  const { keygen, getPublicKey, getSharedSecret, utils, lengths } = ecdh(Point, opts);
  const defaultSigOpts = {
    prehash: true,
    lowS: typeof opts.lowS === "boolean" ? opts.lowS : true,
    format: "compact",
    extraEntropy: false
  };
  const hasLargeRecoveryLifts = CURVE_ORDER * _2n2 + _1n4 < Fp.ORDER;
  function isBiggerThanHalfOrder(number) {
    const HALF = CURVE_ORDER >> _1n4;
    return number > HALF;
  }
  function validateRS(title, num2) {
    if (!Fn.isValidNot0(num2))
      throw new Error(`invalid signature ${title}: out of range 1..Point.Fn.ORDER`);
    return num2;
  }
  function assertFieldSignIsSupported() {
    if (!Fp.isOdd)
      throw new Error("Field doesn't support isOdd");
  }
  function getRecoveryBit(x, y, r) {
    assertFieldSignIsSupported();
    return (x === r ? 0 : 2) | Number(Fp.isOdd(y));
  }
  function assertRecoverableCurve() {
    if (hasLargeRecoveryLifts)
      throw new Error('"recovered" sig type is not supported for cofactor >2 curves');
  }
  function validateSigLength(bytes, format) {
    validateSigFormat(format);
    const size = lengths.signature;
    const sizer = format === "compact" ? size : format === "recovered" ? size + 1 : void 0;
    return abytes2(bytes, sizer);
  }
  class Signature {
    r;
    s;
    recovery;
    constructor(r, s, recovery) {
      this.r = validateRS("r", r);
      this.s = validateRS("s", s);
      if (recovery != null) {
        assertRecoverableCurve();
        if (![0, 1, 2, 3].includes(recovery))
          throw new Error("invalid recovery id");
        this.recovery = recovery;
      }
      Object.freeze(this);
    }
    static fromBytes(bytes, format = defaultSigOpts.format) {
      validateSigLength(bytes, format);
      let recid;
      if (format === "der") {
        if (bytes.length > 2 * Fn.BYTES + 16)
          throw new DER.Err("invalid signature: DER signature too long");
        const { r: r2, s: s2 } = DER.toSig(abytes2(bytes), Fn.BYTES + 1);
        return new Signature(r2, s2);
      }
      if (format === "recovered") {
        recid = bytes[0];
        format = "compact";
        bytes = bytes.subarray(1);
      }
      const L = lengths.signature / 2;
      const r = bytes.subarray(0, L);
      const s = bytes.subarray(L, L * 2);
      return new Signature(Fn.fromBytes(r), Fn.fromBytes(s), recid);
    }
    static fromHex(hex, format) {
      return this.fromBytes(hexToBytes2(hex), format);
    }
    assertRecovery() {
      const { recovery } = this;
      if (recovery == null)
        throw new Error("invalid recovery id: must be present");
      return recovery;
    }
    addRecoveryBit(recovery) {
      return new Signature(this.r, this.s, recovery);
    }
    // Unlike the top-level helper below, this method expects a digest that has
    // already been hashed to the curve's message representative.
    recoverPublicKey(messageHash) {
      const { r, s } = this;
      const recovery = this.assertRecovery();
      const radj = recovery === 2 || recovery === 3 ? r + CURVE_ORDER : r;
      if (!Fp.isValid(radj))
        throw new Error("invalid recovery id: sig.r+curve.n != R.x");
      const x = Fp.toBytes(radj);
      const R = Point.fromBytes(concatBytes2(pprefix((recovery & 1) === 0), x));
      const ir = Fn.inv(radj);
      const h = bits2int_modN(abytes2(messageHash, void 0, "msgHash"));
      const u1 = Fn.create(-h * ir);
      const u2 = Fn.create(s * ir);
      const Q = Point.BASE.mulAddUnsafe(u1, R, u2);
      if (Q.is0())
        throw new Error("invalid recovery: point at infinify");
      Q.assertValidity();
      return Q;
    }
    // Signatures should be low-s, to prevent malleability.
    hasHighS() {
      return isBiggerThanHalfOrder(this.s);
    }
    toBytes(format = defaultSigOpts.format) {
      validateSigFormat(format);
      if (format === "der")
        return hexToBytes2(DER.hexFromSig(this));
      const { r, s } = this;
      const rb = Fn.toBytes(r);
      const sb = Fn.toBytes(s);
      if (format === "recovered") {
        assertRecoverableCurve();
        return concatBytes2(Uint8Array.of(this.assertRecovery()), rb, sb);
      }
      return concatBytes2(rb, sb);
    }
    toHex(format) {
      return bytesToHex2(this.toBytes(format));
    }
  }
  Object.freeze(Signature.prototype);
  Object.freeze(Signature);
  const bits2int = opts.bits2int === void 0 ? function bits2int_def(bytes) {
    if (bytes.length > 8192)
      throw new Error("input is too large");
    const num2 = bytesToNumberBE(bytes);
    const delta = bytes.length * 8 - fnBits;
    return delta > 0 ? num2 >> BigInt(delta) : num2;
  } : opts.bits2int;
  const bits2int_modN = opts.bits2int_modN === void 0 ? function bits2int_modN_def(bytes) {
    return Fn.create(bits2int(bytes));
  } : opts.bits2int_modN;
  const ORDER_MASK = bitMask(fnBits);
  function int2octets(num2) {
    aInRange("num < 2^" + fnBits, num2, _0n5, ORDER_MASK);
    return Fn.toBytes(num2);
  }
  function validateMsgAndHash(message, prehash) {
    abytes2(message, void 0, "message");
    return prehash ? abytes2(hash_(message), void 0, "prehashed message") : message;
  }
  function prepSig(message, secretKey, opts2) {
    const { lowS, prehash, extraEntropy } = validateSigOpts(opts2, defaultSigOpts);
    message = validateMsgAndHash(message, prehash);
    const h1int = bits2int_modN(message);
    const d = Fn.fromBytes(secretKey);
    if (!Fn.isValidNot0(d))
      throw new Error("invalid private key");
    const seedArgs = [int2octets(d), int2octets(h1int)];
    if (extraEntropy != null && extraEntropy !== false) {
      const e = extraEntropy === true ? randomBytes4(lengths.secretKey) : extraEntropy;
      seedArgs.push(abytes2(e, void 0, "extraEntropy"));
    }
    const seed = concatBytes2(...seedArgs);
    const m = h1int;
    function k2sig(kBytes) {
      const k = bits2int(kBytes);
      if (!Fn.isValidNot0(k))
        return;
      const q = Point.BASE.multiply(k).toAffine();
      const r = Fn.create(q.x);
      if (r === _0n5)
        return;
      let s;
      if (csprng !== void 0) {
        const b = bytesToNumberBE(mapHashToField(csprng(blindLength), CURVE_ORDER));
        const ibk = Fn.inv(Fn.mul(b, k));
        const bm = Fn.mul(b, m);
        const bd = Fn.mul(b, d);
        s = Fn.create(ibk * Fn.create(bm + bd * r));
      } else {
        const ik = invertCt(k, CURVE_ORDER);
        s = Fn.create(ik * Fn.create(m + r * d));
      }
      if (s === _0n5)
        return;
      let recovery = getRecoveryBit(q.x, q.y, r);
      let normS = s;
      if (lowS && isBiggerThanHalfOrder(s)) {
        normS = Fn.neg(s);
        recovery ^= 1;
      }
      return new Signature(r, normS, hasLargeRecoveryLifts ? void 0 : recovery);
    }
    return { seed, k2sig };
  }
  function sign2(message, secretKey, opts2 = {}) {
    const { seed, k2sig } = prepSig(message, secretKey, opts2);
    const drbg = createHmacDrbg(hash_.outputLen, Fn.BYTES, hmac2);
    const sig = drbg(seed, k2sig);
    return sig.toBytes(opts2.format);
  }
  function verify2(signature, message, publicKey2, opts2 = {}) {
    const { lowS, prehash, format } = validateSigOpts(opts2, defaultSigOpts);
    publicKey2 = abytes2(publicKey2, void 0, "publicKey");
    message = validateMsgAndHash(message, prehash);
    if (!isBytes2(signature)) {
      const end = signature instanceof Signature ? ", use sig.toBytes()" : "";
      throw new Error("verify expects Uint8Array signature" + end);
    }
    validateSigLength(signature, format);
    try {
      const sig = Signature.fromBytes(signature, format);
      const P = Point.fromBytes(publicKey2);
      if (P.is0())
        return false;
      if (lowS && sig.hasHighS())
        return false;
      const { r, s } = sig;
      const h = bits2int_modN(message);
      const is = Fn.inv(s);
      const u1 = Fn.create(h * is);
      const u2 = Fn.create(r * is);
      const R = Point.BASE.mulAddUnsafe(u1, P, u2);
      if (R.is0())
        return false;
      const q = R.toAffine();
      const v = Fn.create(q.x);
      if (v !== r)
        return false;
      if (format === "recovered" && sig.recovery !== getRecoveryBit(q.x, q.y, r))
        return false;
      return true;
    } catch (e) {
      return false;
    }
  }
  function recoverPublicKey(signature, message, opts2 = {}) {
    const { prehash } = validateSigOpts(opts2, defaultSigOpts);
    message = validateMsgAndHash(message, prehash);
    return Signature.fromBytes(signature, "recovered").recoverPublicKey(message).toBytes();
  }
  return Object.freeze({
    keygen,
    getPublicKey,
    getSharedSecret,
    utils,
    lengths,
    Point,
    sign: sign2,
    verify: verify2,
    recoverPublicKey,
    Signature,
    hash: hash_
  });
}

// ../qr-secret-transfer/node_modules/@noble/curves/secp256k1.js
var secp256k1_CURVE = {
  p: BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
  n: BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
  h: BigInt(1),
  a: BigInt(0),
  b: BigInt(7),
  Gx: BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
  Gy: BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
};
var secp256k1_ENDO = {
  beta: BigInt("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"),
  basises: [
    [BigInt("0x3086d221a7d46bcde86c90e49284eb15"), -BigInt("0xe4437ed6010e88286f547fa90abfe4c3")],
    [BigInt("0x114ca50f7a8e2f3f657c1108d9d44cfd8"), BigInt("0x3086d221a7d46bcde86c90e49284eb15")]
  ]
};
var _0n6 = /* @__PURE__ */ BigInt(0);
var _2n3 = /* @__PURE__ */ BigInt(2);
function sqrtMod(y) {
  const P = secp256k1_CURVE.p;
  const _3n3 = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
  const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
  const b2 = y * y * y % P;
  const b3 = b2 * b2 * y % P;
  const b6 = pow2(b3, _3n3, P) * b3 % P;
  const b9 = pow2(b6, _3n3, P) * b3 % P;
  const b11 = pow2(b9, _2n3, P) * b2 % P;
  const b22 = pow2(b11, _11n, P) * b11 % P;
  const b44 = pow2(b22, _22n, P) * b22 % P;
  const b88 = pow2(b44, _44n, P) * b44 % P;
  const b176 = pow2(b88, _88n, P) * b88 % P;
  const b220 = pow2(b176, _44n, P) * b44 % P;
  const b223 = pow2(b220, _3n3, P) * b3 % P;
  const t1 = pow2(b223, _23n, P) * b22 % P;
  const t2 = pow2(t1, _6n, P) * b2 % P;
  const root = pow2(t2, _2n3, P);
  if (!Fpk1.eql(Fpk1.sqr(root), y))
    throw new Error("Cannot find square root");
  return root;
}
var Fpk1 = /* @__PURE__ */ Field(secp256k1_CURVE.p, { sqrt: sqrtMod });
var Pointk1 = /* @__PURE__ */ weierstrass(secp256k1_CURVE, {
  Fp: Fpk1,
  endo: secp256k1_ENDO
});
var secp256k1 = /* @__PURE__ */ ecdsa(Pointk1, sha256);
var TAGGED_HASH_PREFIXES = /* @__PURE__ */ Object.create(null);
function taggedHash(tag, ...messages) {
  let tagP = TAGGED_HASH_PREFIXES[tag];
  if (tagP === void 0) {
    const tagH = sha256(asciiToBytes(tag));
    tagP = concatBytes2(tagH, tagH);
    TAGGED_HASH_PREFIXES[tag] = tagP;
  }
  return sha256(concatBytes2(tagP, ...messages));
}
var pointToBytes = (point) => point.toBytes(true).slice(1);
var affineXToBytes = ({ x }) => Fpk1.toBytes(x);
var hasEven = (y) => !Fpk1.isOdd(y);
function schnorrGetExtPubKey(priv) {
  const { Fn, BASE } = Pointk1;
  const d_ = Fn.fromBytes(abytes2(priv, 32, "secretKey"));
  const p = BASE.multiply(d_);
  const affine = p.toAffine();
  const scalar = hasEven(affine.y) ? d_ : Fn.neg(d_);
  return { scalar, bytes: affineXToBytes(affine) };
}
function lift_x(x) {
  const Fp = Fpk1;
  if (!Fp.isValidNot0(x))
    throw new Error("invalid x: Fail if x \u2265 p");
  const xx = Fp.sqr(x);
  const c = Fp.add(Fp.mulN(xx, x), BigInt(7));
  let y = Fp.sqrt(c);
  if (!hasEven(y))
    y = Fp.neg(y);
  const p = Pointk1.fromAffine({ x, y });
  p.assertValidity();
  return p;
}
var num = bytesToNumberBE;
function challenge(...args) {
  return Pointk1.Fn.create(num(taggedHash("BIP0340/challenge", ...args)));
}
function schnorrGetPublicKey(secretKey) {
  return schnorrGetExtPubKey(secretKey).bytes;
}
function schnorrSign(message, secretKey, auxRand = randomBytes(32)) {
  const { Fn, BASE } = Pointk1;
  const m = copyBytes(abytes2(message, void 0, "message"));
  const { bytes: px, scalar: d } = schnorrGetExtPubKey(secretKey);
  const a = abytes2(auxRand, 32, "auxRand");
  const t = Fn.toBytes(d ^ num(taggedHash("BIP0340/aux", a)));
  const rand = taggedHash("BIP0340/nonce", t, px, m);
  const k_ = Fn.create(num(rand));
  if (k_ === _0n6)
    throw new Error("sign failed: k is zero");
  const p = BASE.multiply(k_);
  const affine = p.toAffine();
  const k = hasEven(affine.y) ? k_ : Fn.neg(k_);
  const rx = affineXToBytes(affine);
  const e = challenge(rx, px, m);
  const sig = new Uint8Array(64);
  sig.set(rx, 0);
  sig.set(Fn.toBytes(Fn.create(k + e * d)), 32);
  if (!schnorrVerify(sig, m, px))
    throw new Error("sign: Invalid signature produced");
  return sig;
}
function schnorrVerify(signature, message, publicKey2) {
  const { Fp, Fn, BASE } = Pointk1;
  const sig = abytes2(signature, 64, "signature");
  const m = abytes2(message, void 0, "message");
  const pub = abytes2(publicKey2, 32, "publicKey");
  try {
    const P = lift_x(num(pub));
    const rBytes = sig.subarray(0, 32);
    const r = num(rBytes);
    if (!Fp.isValidNot0(r))
      return false;
    const s = num(sig.subarray(32, 64));
    if (!Fn.isValidNot0(s))
      return false;
    const e = challenge(rBytes, pointToBytes(P), m);
    const R = BASE.mulAddUnsafe(s, P, Fn.neg(e));
    const { x, y } = R.toAffine();
    if (R.is0() || !hasEven(y) || !Fp.eql(x, r))
      return false;
    return true;
  } catch (error) {
    return false;
  }
}
var schnorr = /* @__PURE__ */ (() => {
  const size = 32;
  const seedLength = 48;
  const randomSecretKey = (seed) => {
    seed = seed === void 0 ? randomBytes(seedLength) : seed;
    return mapHashToField(abytes2(seed, seedLength, "seed"), secp256k1_CURVE.n);
  };
  return Object.freeze({
    keygen: createKeygen(randomSecretKey, schnorrGetPublicKey),
    getPublicKey: schnorrGetPublicKey,
    sign: schnorrSign,
    verify: schnorrVerify,
    Point: Pointk1,
    utils: Object.freeze({
      randomSecretKey,
      taggedHash,
      lift_x,
      pointToBytes
    }),
    lengths: Object.freeze({
      secretKey: size,
      publicKey: size,
      publicKeyHasPrefix: false,
      signature: size * 2,
      seed: seedLength
    })
  });
})();

// ../qr-secret-transfer/node_modules/@scure/base/index.js
var freeze = (fn) => Object.freeze(fn());
function isBytes3(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
function abytes3(b) {
  if (!isBytes3(b))
    throw new TypeError("Uint8Array expected");
}
function isArrayOf(isString, arr) {
  if (!Array.isArray(arr))
    return false;
  if (arr.length === 0)
    return true;
  if (isString) {
    return arr.every((item) => typeof item === "string");
  } else {
    return arr.every((item) => Number.isSafeInteger(item));
  }
}
function afn(input) {
  if (typeof input !== "function")
    throw new TypeError("function expected");
  return true;
}
function astr(label, input) {
  if (typeof input !== "string")
    throw new TypeError(`${label}: string expected`);
  return true;
}
function anumber3(n, title = "number") {
  if (typeof n !== "number")
    throw new TypeError(`${title}: expected number, got ${typeof n}`);
  if (!Number.isSafeInteger(n))
    throw new RangeError(`${title}: expected safe integer, got ${n}`);
}
function anumArr(label, input) {
  if (!isArrayOf(false, input))
    throw new TypeError(`${label}: array of numbers expected`);
}
function chain(...args) {
  const id = (a) => a;
  const wrap2 = (a, b) => (c) => a(b(c));
  const encode = args.map((x) => x.encode).reduceRight(wrap2, id);
  const decode = args.map((x) => x.decode).reduce(wrap2, id);
  return { encode, decode };
}
var powers = /* @__PURE__ */ (() => {
  let res = [];
  for (let i = 0; i < 40; i++)
    res.push(2 ** i);
  return res;
})();
function u8ToNumArr(u8, len = u8.length) {
  const res = new Array(len);
  for (let i = 0; i < len; i++)
    res[i] = u8[i];
  return res;
}
var asciiDecoder = /* @__PURE__ */ (() => {
  try {
    const decoder = new TextDecoder();
    return decoder.decode(Uint8Array.of(65, 48, 43, 127)) === "A0+\x7F" ? decoder : void 0;
  } catch (e) {
    return void 0;
  }
})();
var B2S_CHUNK = 8192;
function charcodesToString(codes) {
  const len = codes.length;
  if (asciiDecoder !== void 0 && len >= 12)
    return asciiDecoder.decode(codes);
  if (len <= B2S_CHUNK)
    return String.fromCharCode.apply(null, codes);
  let res = "";
  for (let i = 0; i < len; i += B2S_CHUNK)
    res += String.fromCharCode.apply(null, codes.subarray(i, i + B2S_CHUNK));
  return res;
}
function radix2(bits) {
  anumber3(bits);
  if (bits <= 0 || bits > 8)
    throw new RangeError("radix2: bits should be in (0..8]");
  const mask = powers[bits] - 1;
  return {
    encode: (bytes) => {
      abytes3(bytes);
      const len = bytes.length;
      const res = new Uint8Array(Math.ceil(len * 8 / bits));
      let carry = 0;
      let pos = 0;
      let j = 0;
      for (let i = 0; i < len; ) {
        if (i + 2 < len) {
          carry = carry << 24 | bytes[i] << 16 | bytes[i + 1] << 8 | bytes[i + 2];
          pos += 24;
          i += 3;
        } else {
          carry = (carry << 8 | bytes[i]) & 65535;
          pos += 8;
          i++;
        }
        for (; ; ) {
          pos -= bits;
          res[j++] = carry >> pos & mask;
          if (pos < bits)
            break;
        }
      }
      if (pos > 0)
        res[j] = carry << bits - pos & mask;
      return res;
    },
    decode: (digits) => {
      const len = digits.length;
      const res = new Uint8Array(Math.floor(len * bits / 8));
      let carry = 0;
      let pos = 0;
      let j = 0;
      for (let i = 0; i < len; i++) {
        carry = (carry << bits | digits[i]) & 65535;
        pos += bits;
        for (; pos >= 8; pos -= 8)
          res[j++] = carry >> pos - 8 & 255;
      }
      carry = carry << 8 - pos & 255;
      if (pos >= bits)
        throw new Error("Excess padding");
      if (carry > 0)
        throw new Error(`Non-zero padding: ${carry}`);
      return res;
    }
  };
}
function alphabet(letters, aliases) {
  const len = letters.length;
  if (len > 128)
    throw new Error("alphabet: max 128 letters");
  const encTable = new Uint8Array(len);
  const decTable = new Int8Array(128).fill(-1);
  for (let i = 0; i < len; i++) {
    const code = letters.charCodeAt(i);
    if (letters.codePointAt(i) !== code || code > 127)
      throw new Error("alphabet: single-char ASCII letters only");
    encTable[i] = code;
    decTable[code] = i;
  }
  if (aliases !== void 0) {
    for (const alias of Object.keys(aliases)) {
      const code = alias.charCodeAt(0);
      const target = decTable[aliases[alias].charCodeAt(0)];
      if (alias.length !== 1 || code > 127 || target === void 0 || target === -1)
        throw new Error(`alphabet: invalid alias ${alias}`);
      decTable[code] = target;
    }
  }
  return {
    encode: (digits) => {
      const codes = new Uint8Array(digits.length);
      for (let i = 0; i < digits.length; i++) {
        const d = digits[i];
        const code = encTable[d];
        if (code === void 0)
          throw new Error(`alphabet.encode: invalid digit ${d}`);
        codes[i] = code;
      }
      return charcodesToString(codes);
    },
    decode: (input) => {
      astr("decode", input);
      const slen = input.length;
      const digits = new Uint8Array(slen);
      for (let i = 0; i < slen; i++) {
        const code = input.charCodeAt(i);
        const digit = code < 128 ? decTable[code] : -1;
        if (digit === -1)
          throw new Error(`Unknown letter "${input[i]}". Allowed: ${letters}`);
        digits[i] = digit;
      }
      return digits;
    }
  };
}
function padding(bits, chr = "=") {
  anumber3(bits);
  astr("padding", chr);
  return {
    encode(data) {
      while (data.length * bits % 8)
        data += chr;
      return data;
    },
    decode(input) {
      astr("decode", input);
      let end = input.length;
      if (end * bits % 8)
        throw new Error("padding: invalid length");
      for (; end > 0 && input[end - 1] === chr; end--) {
        const byte = (end - 1) * bits;
        if (byte % 8 === 0)
          throw new Error("padding: excess padding");
      }
      return input.slice(0, end);
    }
  };
}
function unsafeWrapper(fn) {
  afn(fn);
  return function(...args) {
    try {
      return fn.apply(null, args);
    } catch (e) {
    }
  };
}
var hasBase64Builtin = /* @__PURE__ */ (() => typeof Uint8Array.from([]).toBase64 === "function" && typeof Uint8Array.fromBase64 === "function")();
var ASCII_WHITESPACE = /[\t\n\f\r ]/;
var decodeBase64Builtin = (s, isUrl) => {
  astr("base64", s);
  const alphabet2 = isUrl ? "base64url" : "base64";
  if (s.length > 0 && ASCII_WHITESPACE.test(s))
    throw new Error("invalid base64");
  return Uint8Array.fromBase64(s, { alphabet: alphabet2, lastChunkHandling: "strict" });
};
var base64Fallback = /* @__PURE__ */ freeze(() => chain(radix2(6), alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), padding(6)));
var base64 = /* @__PURE__ */ freeze(() => hasBase64Builtin ? {
  encode(b) {
    abytes3(b);
    return b.toBase64();
  },
  decode(s) {
    return decodeBase64Builtin(s, false);
  }
} : base64Fallback);
var BECH_ALPHABET = /* @__PURE__ */ alphabet("qpzry9x8gf2tvdw0s3jn54khce6mua7l");
var BECH_UPPERCASE_PRINTABLE = /^[\x21-\x60\x7b-\x7e]+$/;
function assertBech32Printable(label, value) {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c < 33 || c > 126)
      throw new Error(`${label}: printable ASCII expected`);
  }
}
function wordsToU8(words) {
  const len = words.length;
  const res = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    const w = words[i];
    if (w < 0 || w >= 32)
      throw new Error(`alphabet.encode: invalid digit ${w}`);
    res[i] = w;
  }
  return res;
}
var POLYMOD_GENERATORS = [996825010, 642813549, 513874426, 1027748829, 705979059];
function bech32Polymod(pre) {
  const b = pre >> 25;
  let chk = (pre & 33554431) << 5;
  for (let i = 0; i < POLYMOD_GENERATORS.length; i++) {
    if ((b >> i & 1) === 1)
      chk ^= POLYMOD_GENERATORS[i];
  }
  return chk;
}
function bechChecksum(prefix, words, encodingConst = 1) {
  const len = prefix.length;
  let chk = 1;
  for (let i = 0; i < len; i++) {
    const c = prefix.charCodeAt(i);
    if (c < 33 || c > 126)
      throw new Error(`Invalid prefix (${prefix})`);
    chk = bech32Polymod(chk) ^ c >> 5;
  }
  chk = bech32Polymod(chk);
  for (let i = 0; i < len; i++)
    chk = bech32Polymod(chk) ^ prefix.charCodeAt(i) & 31;
  for (let v of words)
    chk = bech32Polymod(chk) ^ v;
  for (let i = 0; i < 6; i++)
    chk = bech32Polymod(chk);
  chk ^= encodingConst;
  const sum = new Uint8Array(6);
  for (let i = 0; i < 6; i++)
    sum[i] = chk >>> 5 * (5 - i) & 31;
  return BECH_ALPHABET.encode(sum);
}
function genBech32(encoding) {
  const ENCODING_CONST = encoding === "bech32" ? 1 : 734539939;
  const _words = radix2(5);
  const toWords = (from) => {
    abytes3(from);
    const len = from.length;
    const res = new Array(Math.ceil(len * 8 / 5));
    let carry = 0;
    let pos = 0;
    let j = 0;
    for (let i = 0; i < len; i++) {
      carry = carry << 8 | from[i];
      pos += 8;
      for (; pos >= 5; pos -= 5)
        res[j++] = carry >> pos - 5 & 31;
    }
    if (pos > 0)
      res[j] = carry << 5 - pos & 31;
    return res;
  };
  const fromWords = (to) => {
    anumArr("radix2.decode", to);
    const len = to.length;
    const digits = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      const w = to[i];
      if (w < 0 || w >= 32)
        throw new Error(`convertRadix2: invalid word=${w}`);
      digits[i] = w;
    }
    return _words.decode(digits);
  };
  const fromWordsUnsafe = unsafeWrapper(fromWords);
  function encode(prefix, words, limit = 90) {
    astr("bech32.encode prefix", prefix);
    if (limit !== false)
      anumber3(limit, "limit");
    if (isBytes3(words))
      words = u8ToNumArr(words);
    anumArr("bech32.encode", words);
    const plen = prefix.length;
    if (plen === 0)
      throw new TypeError(`Invalid prefix length ${plen}`);
    const actualLength = plen + 7 + words.length;
    if (limit !== false && actualLength > limit)
      throw new TypeError(`Length ${actualLength} exceeds limit ${limit}`);
    assertBech32Printable("bech32.encode prefix", prefix);
    const lowered = prefix.toLowerCase();
    const sum = bechChecksum(lowered, words, ENCODING_CONST);
    return `${lowered}1${BECH_ALPHABET.encode(wordsToU8(words))}${sum}`;
  }
  function decode(str, limit = 90) {
    astr("bech32.decode input", str);
    if (limit !== false)
      anumber3(limit, "limit");
    const slen = str.length;
    if (slen < 8 || limit !== false && slen > limit)
      throw new TypeError(`invalid string length ${slen}, expected (8..${limit})`);
    const lowered = str.toLowerCase();
    if (str !== lowered) {
      if (!BECH_UPPERCASE_PRINTABLE.test(str)) {
        assertBech32Printable("bech32.decode input", str);
        throw new Error(`mixed-case string not allowed`);
      }
    }
    const sepIndex = lowered.lastIndexOf("1");
    if (sepIndex === 0 || sepIndex === -1)
      throw new Error(`invalid separator "1"`);
    const prefix = lowered.slice(0, sepIndex);
    const data = lowered.slice(sepIndex + 1);
    if (data.length < 6)
      throw new Error("invalid data length");
    const digits = BECH_ALPHABET.decode(data);
    const words = u8ToNumArr(digits, digits.length - 6);
    const sum = bechChecksum(prefix, words, ENCODING_CONST);
    if (!data.endsWith(sum))
      throw new Error(`Invalid checksum in ${str}`);
    return { prefix, words };
  }
  const decodeUnsafe = unsafeWrapper(decode);
  function decodeToBytes(str, limit = 90) {
    const { prefix, words } = decode(str, limit);
    return {
      prefix,
      words,
      bytes: fromWords(words)
    };
  }
  function encodeFromBytes(prefix, bytes) {
    return encode(prefix, toWords(bytes));
  }
  return {
    encode,
    decode,
    encodeFromBytes,
    decodeToBytes,
    decodeUnsafe,
    fromWords,
    fromWordsUnsafe,
    toWords
  };
}
var bech32 = /* @__PURE__ */ freeze(() => genBech32("bech32"));

// ../qr-secret-transfer/src/core/event.ts
function generateSecretKey(random) {
  for (; ; ) {
    const candidate = random(32);
    try {
      schnorr.getPublicKey(candidate);
      return candidate;
    } catch {
    }
  }
}
function publicKey(secretKey) {
  return bytesToHex(schnorr.getPublicKey(secretKey));
}
function serialize(e) {
  return JSON.stringify([0, e.pubkey, e.created_at, e.kind, e.tags, e.content]);
}
function eventId(e) {
  return bytesToHex(sha256(utf8Encode(serialize(e))));
}
function rumor(template) {
  return { ...template, id: eventId(template) };
}
function sign(template, secretKey, random) {
  const id = eventId(template);
  const sig = bytesToHex(schnorr.sign(hexToBytes(id), secretKey, random(32)));
  return { ...template, id, sig };
}
var HEX_128 = /^[0-9a-f]{128}$/;
function isEventShape(value) {
  if (typeof value !== "object" || value === null) return false;
  const e = value;
  if (!isHex32(e.pubkey)) return false;
  if (typeof e.created_at !== "number" || !Number.isSafeInteger(e.created_at) || e.created_at < 0) return false;
  if (typeof e.kind !== "number" || !Number.isInteger(e.kind) || e.kind < 0 || e.kind > 65535) return false;
  if (typeof e.content !== "string") return false;
  if (!Array.isArray(e.tags)) return false;
  for (const tag of e.tags) {
    if (!Array.isArray(tag)) return false;
    for (const item of tag) if (typeof item !== "string") return false;
  }
  return true;
}
function verify(value) {
  if (!isEventShape(value)) return false;
  const e = value;
  if (!isHex32(e.id) || typeof e.sig !== "string" || !HEX_128.test(e.sig)) return false;
  if (eventId(e) !== e.id) return false;
  try {
    return schnorr.verify(hexToBytes(e.sig), hexToBytes(e.id), hexToBytes(e.pubkey));
  } catch {
    return false;
  }
}
function firstTag(e, name) {
  for (const tag of e.tags) if (tag[0] === name) return tag[1];
  return void 0;
}
function npubEncode(publicKeyHex) {
  if (!isHex32(publicKeyHex)) throw new Error("npub: bad public key");
  return bech32.encode("npub", bech32.toWords(hexToBytes(publicKeyHex)), 90);
}
function npubDecode(npub) {
  const decoded = bech32.decode(npub, 90);
  if (decoded.prefix !== "npub") throw new Error("npub: wrong prefix");
  const bytes = bech32.fromWords(decoded.words);
  if (bytes.length !== 32) throw new Error("npub: wrong length");
  const hex = bytesToHex(bytes);
  if (!isValidPublicKey(hex)) throw new Error("npub: not a valid key");
  return hex;
}
function isValidPublicKey(publicKeyHex) {
  if (!isHex32(publicKeyHex)) return false;
  try {
    schnorr.Point.fromBytes(hexToBytes("02" + publicKeyHex));
    return true;
  } catch {
    return false;
  }
}

// ../qr-secret-transfer/src/core/nip44.ts
var nip44_exports = {};
__export(nip44_exports, {
  conversationKey: () => conversationKey,
  decrypt: () => decrypt,
  encrypt: () => encrypt,
  paddedLength: () => paddedLength
});

// ../qr-secret-transfer/node_modules/@noble/ciphers/utils.js
function isBytes4(a) {
  return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
}
var atitle3 = (title) => title ? `"${title}" ` : "";
function abool2(value, title = "") {
  if (typeof value !== "boolean")
    throw new TypeError(atitle3(title) + "expected boolean, got type=" + typeof value);
  return value;
}
function anumber4(n, title = "") {
  if (typeof n !== "number")
    throw new TypeError(atitle3(title) + "expected number, got " + typeof n);
  if (!Number.isSafeInteger(n) || n < 0)
    throw new RangeError(atitle3(title) + "expected integer >= 0, got " + n);
  return n;
}
function abytes4(value, length, title = "") {
  if (isBytes4(value) && (length === void 0 || value.length === length))
    return value;
  if (length !== void 0)
    anumber4(length, "length");
  const bytes = isBytes4(value);
  const ofLen = length !== void 0 ? ` of length ${length}` : "";
  const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
  const message = atitle3(title) + "expected Uint8Array" + ofLen + ", got " + got;
  if (!bytes)
    throw new TypeError(message);
  throw new RangeError(message);
}
var aobject3 = (value, label) => {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new TypeError(label === "object" ? "expected valid options object" : `"${label}" expected object, got type=${typeof value}`);
};
function u32(arr) {
  return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
}
function clean2(...arrays) {
  for (let i = 0; i < arrays.length; i++) {
    arrays[i].fill(0);
  }
}
var isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
function byteSwap(word) {
  return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
}
function byteSwap32(arr) {
  for (let i = 0; i < arr.length; i++) {
    arr[i] = byteSwap(arr[i]);
  }
  return arr;
}
var swap32IfBE = isLE ? (u) => u : byteSwap32;
function overlapBytes(a, b) {
  if (!a.byteLength || !b.byteLength)
    return false;
  return a.buffer === b.buffer && // best we can do, may fail with an obscure Proxy
  a.byteOffset < b.byteOffset + b.byteLength && // a starts before b end
  b.byteOffset < a.byteOffset + a.byteLength;
}
function complexOverlapBytes(input, output) {
  if (overlapBytes(input, output) && input.byteOffset < output.byteOffset)
    throw new Error("complex overlap of input and output is not supported");
}
function checkOpts2(defaults, opts) {
  aobject3(defaults, "defaults");
  aobject3(opts, "opts");
  const merged = Object.assign(defaults, opts);
  return merged;
}
function getOutput(expectedLength, out, onlyAligned = true) {
  if (out === void 0)
    return new Uint8Array(expectedLength);
  abytes4(out, expectedLength, "output");
  if (onlyAligned && !isAligned32(out))
    throw new Error("invalid output, must be aligned");
  return out;
}
function isAligned32(bytes) {
  return bytes.byteOffset % 4 === 0;
}
function copyBytes2(bytes) {
  return Uint8Array.from(abytes4(bytes));
}

// ../qr-secret-transfer/node_modules/@noble/ciphers/_arx.js
var encodeStr = (str) => Uint8Array.from(str.split(""), (c) => c.charCodeAt(0));
var sigma16_32 = /* @__PURE__ */ (() => swap32IfBE(u32(encodeStr("expand 16-byte k"))))();
var sigma32_32 = /* @__PURE__ */ (() => swap32IfBE(u32(encodeStr("expand 32-byte k"))))();
function rotl(a, b) {
  return a << b | a >>> 32 - b;
}
var BLOCK_LEN = 64;
var BLOCK_LEN32 = 16;
var MAX_COUNTER = /* @__PURE__ */ (() => 2 ** 32 - 1)();
var U32_EMPTY = /* @__PURE__ */ Uint32Array.of();
function runCipher(core, sigma, key, nonce, data, output, counter, rounds) {
  const len = data.length;
  const block = new Uint8Array(BLOCK_LEN);
  const b32 = u32(block);
  const isAligned = isLE && isAligned32(data) && isAligned32(output);
  const d32 = isAligned ? u32(data) : U32_EMPTY;
  const o32 = isAligned ? u32(output) : U32_EMPTY;
  if (!isLE) {
    for (let pos = 0; pos < len; counter++) {
      core(sigma, key, nonce, b32, counter, rounds);
      swap32IfBE(b32);
      if (counter >= MAX_COUNTER)
        throw new Error("arx: counter overflow");
      const take = Math.min(BLOCK_LEN, len - pos);
      for (let j = 0, posj; j < take; j++) {
        posj = pos + j;
        output[posj] = data[posj] ^ block[j];
      }
      pos += take;
    }
    return;
  }
  for (let pos = 0; pos < len; counter++) {
    core(sigma, key, nonce, b32, counter, rounds);
    if (counter >= MAX_COUNTER)
      throw new Error("arx: counter overflow");
    const take = Math.min(BLOCK_LEN, len - pos);
    if (isAligned && take === BLOCK_LEN) {
      const pos32 = pos / 4;
      if (pos % 4 !== 0)
        throw new Error("arx: invalid block position");
      for (let j = 0, posj; j < BLOCK_LEN32; j++) {
        posj = pos32 + j;
        o32[posj] = d32[posj] ^ b32[j];
      }
      pos += BLOCK_LEN;
      continue;
    }
    for (let j = 0, posj; j < take; j++) {
      posj = pos + j;
      output[posj] = data[posj] ^ block[j];
    }
    pos += take;
  }
}
function createCipher(core, opts) {
  const { allowShortKeys, extendNonceFn, counterLength, counterRight, rounds } = checkOpts2({ allowShortKeys: false, counterLength: 8, counterRight: false, rounds: 20 }, opts);
  if (typeof core !== "function")
    throw new Error("core must be a function");
  anumber4(counterLength);
  anumber4(rounds);
  abool2(counterRight);
  abool2(allowShortKeys);
  return (key, nonce, data, output, counter = 0) => {
    abytes4(key, void 0, "key");
    abytes4(nonce, void 0, "nonce");
    abytes4(data, void 0, "data");
    const len = data.length;
    const hasOutput = output !== void 0;
    output = getOutput(len, output, false);
    if (hasOutput)
      complexOverlapBytes(data, output);
    anumber4(counter);
    if (counter < 0 || counter >= MAX_COUNTER)
      throw new Error("arx: counter overflow");
    const toClean = [];
    let l = key.length;
    let k;
    let sigma;
    if (l === 32) {
      toClean.push(k = copyBytes2(key));
      sigma = sigma32_32;
    } else if (l === 16 && allowShortKeys) {
      k = new Uint8Array(32);
      k.set(key);
      k.set(key, 16);
      sigma = sigma16_32;
      toClean.push(k);
    } else {
      abytes4(key, 32, "arx key");
      throw new Error("invalid key size");
    }
    if (!isLE || !isAligned32(nonce))
      toClean.push(nonce = copyBytes2(nonce));
    let k32 = u32(k);
    if (extendNonceFn) {
      if (nonce.length !== 24)
        throw new Error("arx: extended nonce must be 24 bytes");
      const n16 = nonce.subarray(0, 16);
      if (isLE)
        extendNonceFn(sigma, k32, u32(n16), k32);
      else {
        const sigmaRaw = swap32IfBE(Uint32Array.from(sigma));
        extendNonceFn(sigmaRaw, k32, u32(n16), k32);
        clean2(sigmaRaw);
        swap32IfBE(k32);
      }
      nonce = nonce.subarray(16);
    } else if (!isLE)
      swap32IfBE(k32);
    const nonceNcLen = 16 - counterLength;
    if (nonceNcLen !== nonce.length)
      throw new Error(`arx: nonce must be ${nonceNcLen} or 16 bytes`);
    if (nonceNcLen !== 12) {
      const nc = new Uint8Array(12);
      nc.set(nonce, counterRight ? 0 : 12 - nonce.length);
      nonce = nc;
      toClean.push(nonce);
    }
    const n32 = swap32IfBE(u32(nonce));
    try {
      runCipher(core, sigma, k32, n32, data, output, counter, rounds);
      return output;
    } finally {
      clean2(...toClean);
    }
  };
}

// ../qr-secret-transfer/node_modules/@noble/ciphers/chacha.js
function chachaCore(s, k, n, out, cnt, rounds = 20) {
  let y00 = s[0], y01 = s[1], y02 = s[2], y03 = s[3], y04 = k[0], y05 = k[1], y06 = k[2], y07 = k[3], y08 = k[4], y09 = k[5], y10 = k[6], y11 = k[7], y12 = cnt, y13 = n[0], y14 = n[1], y15 = n[2];
  let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
  for (let r = 0; r < rounds; r += 2) {
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 16);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 12);
    x00 = x00 + x04 | 0;
    x12 = rotl(x12 ^ x00, 8);
    x08 = x08 + x12 | 0;
    x04 = rotl(x04 ^ x08, 7);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 16);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 12);
    x01 = x01 + x05 | 0;
    x13 = rotl(x13 ^ x01, 8);
    x09 = x09 + x13 | 0;
    x05 = rotl(x05 ^ x09, 7);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 16);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 12);
    x02 = x02 + x06 | 0;
    x14 = rotl(x14 ^ x02, 8);
    x10 = x10 + x14 | 0;
    x06 = rotl(x06 ^ x10, 7);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 16);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 12);
    x03 = x03 + x07 | 0;
    x15 = rotl(x15 ^ x03, 8);
    x11 = x11 + x15 | 0;
    x07 = rotl(x07 ^ x11, 7);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 16);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 12);
    x00 = x00 + x05 | 0;
    x15 = rotl(x15 ^ x00, 8);
    x10 = x10 + x15 | 0;
    x05 = rotl(x05 ^ x10, 7);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 16);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 12);
    x01 = x01 + x06 | 0;
    x12 = rotl(x12 ^ x01, 8);
    x11 = x11 + x12 | 0;
    x06 = rotl(x06 ^ x11, 7);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 16);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 12);
    x02 = x02 + x07 | 0;
    x13 = rotl(x13 ^ x02, 8);
    x08 = x08 + x13 | 0;
    x07 = rotl(x07 ^ x08, 7);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 16);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 12);
    x03 = x03 + x04 | 0;
    x14 = rotl(x14 ^ x03, 8);
    x09 = x09 + x14 | 0;
    x04 = rotl(x04 ^ x09, 7);
  }
  let oi = 0;
  out[oi++] = y00 + x00 | 0;
  out[oi++] = y01 + x01 | 0;
  out[oi++] = y02 + x02 | 0;
  out[oi++] = y03 + x03 | 0;
  out[oi++] = y04 + x04 | 0;
  out[oi++] = y05 + x05 | 0;
  out[oi++] = y06 + x06 | 0;
  out[oi++] = y07 + x07 | 0;
  out[oi++] = y08 + x08 | 0;
  out[oi++] = y09 + x09 | 0;
  out[oi++] = y10 + x10 | 0;
  out[oi++] = y11 + x11 | 0;
  out[oi++] = y12 + x12 | 0;
  out[oi++] = y13 + x13 | 0;
  out[oi++] = y14 + x14 | 0;
  out[oi++] = y15 + x15 | 0;
}
var chacha20 = /* @__PURE__ */ createCipher(chachaCore, {
  counterRight: false,
  counterLength: 4,
  allowShortKeys: false
});

// ../qr-secret-transfer/node_modules/@noble/hashes/hkdf.js
function extract(hash, ikm, salt) {
  ahash(hash);
  if (salt === void 0)
    salt = new Uint8Array(hash.outputLen);
  return hmac(hash, salt, ikm);
}
var HKDF_COUNTER = /* @__PURE__ */ Uint8Array.of(0);
var EMPTY_BUFFER = /* @__PURE__ */ Uint8Array.of();
function expand(hash, prk, info, length = 32, _recycled) {
  ahash(hash);
  anumber(length, "length");
  abytes(prk, void 0, "prk");
  const olen = hash.outputLen;
  if (prk.length < olen)
    throw new Error('"prk" must be at least HashLen octets');
  if (length > 255 * olen)
    throw new Error("Length must be <= 255*HashLen");
  const blocks = Math.ceil(length / olen);
  if (info === void 0)
    info = EMPTY_BUFFER;
  else
    abytes(info, void 0, "info");
  if (!blocks) {
    if (_recycled)
      clean(prk);
    return new Uint8Array();
  }
  const okm = _recycled && blocks === 1 ? prk : new Uint8Array(blocks * olen);
  const { iHash, oHash } = hmac.create(hash, prk);
  const T = _recycled ? prk : new Uint8Array(olen);
  const worker = blocks > 1 ? _recycled?.iHash || hash.create() : void 0;
  for (let counter = 0; counter < blocks - 1; counter++) {
    HKDF_COUNTER[0] = counter + 1;
    const iWork = iHash._cloneInto(worker);
    if (counter)
      iWork.update(T);
    iWork.update(info).update(HKDF_COUNTER).digestInto(T);
    oHash._cloneInto(worker).update(T).digestInto(T);
    okm.set(T, olen * counter);
  }
  HKDF_COUNTER[0] = blocks;
  if (blocks > 1)
    iHash.update(T);
  iHash.update(info).update(HKDF_COUNTER).digestInto(T);
  oHash.update(T).digestInto(T);
  okm.set(T, olen * (blocks - 1));
  iHash.destroy();
  oHash.destroy();
  worker?.destroy();
  if (T !== okm)
    clean(T);
  clean(HKDF_COUNTER);
  if (length === okm.length)
    return okm;
  const res = okm.slice(0, length);
  clean(okm);
  return res;
}

// ../qr-secret-transfer/src/core/nip44.ts
var SALT = utf8Encode("nip44-v2");
var MIN_PLAINTEXT = 1;
var MAX_PLAINTEXT = 65535;
function conversationKey(secretKey, publicKeyHex) {
  if (!isHex32(publicKeyHex)) throw new Error("nip44: bad public key");
  const shared = secp256k1.getSharedSecret(secretKey, hexToBytes("02" + publicKeyHex));
  const x = shared.subarray(1, 33);
  const key = extract(sha256, x, SALT);
  wipe(shared);
  return key;
}
function messageKeys(conversation, nonce) {
  if (conversation.length !== 32) throw new Error("nip44: bad conversation key");
  if (nonce.length !== 32) throw new Error("nip44: bad nonce");
  const keys = expand(sha256, conversation, nonce, 76);
  return {
    chachaKey: keys.subarray(0, 32),
    chachaNonce: keys.subarray(32, 44),
    hmacKey: keys.subarray(44, 76),
    all: keys
  };
}
function paddedLength(length) {
  if (!Number.isSafeInteger(length) || length < 1) throw new Error("nip44: bad length");
  if (length <= 32) return 32;
  const nextPower = 2 ** (Math.floor(Math.log2(length - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((length - 1) / chunk) + 1);
}
function pad(plaintext) {
  const bytes = utf8Encode(plaintext);
  const n = bytes.length;
  if (n < MIN_PLAINTEXT || n > MAX_PLAINTEXT) throw new Error("nip44: plaintext length out of range");
  const out = new Uint8Array(2 + paddedLength(n));
  out[0] = n >>> 8;
  out[1] = n & 255;
  out.set(bytes, 2);
  return out;
}
function unpad(padded) {
  const n = padded[0] << 8 | padded[1];
  const body = padded.subarray(2, 2 + n);
  if (n < MIN_PLAINTEXT || n > MAX_PLAINTEXT || body.length !== n || padded.length !== 2 + paddedLength(n)) {
    throw new Error("nip44: bad padding");
  }
  return utf8Decode(body);
}
function encrypt(plaintext, conversation, nonce) {
  const k = messageKeys(conversation, nonce);
  const padded = pad(plaintext);
  const ciphertext = chacha20(k.chachaKey, k.chachaNonce, padded);
  const mac = hmac(sha256, k.hmacKey, concatBytes(nonce, ciphertext));
  wipe(k.all, padded);
  return base64.encode(concatBytes(new Uint8Array([2]), nonce, ciphertext, mac));
}
function decrypt(payload, conversation) {
  const length = payload.length;
  if (length === 0 || payload[0] === "#") throw new Error("nip44: unknown version");
  if (length < 132 || length > 87472) throw new Error("nip44: bad payload size");
  let data;
  try {
    data = base64.decode(payload);
  } catch {
    throw new Error("nip44: bad base64");
  }
  if (data.length < 99 || data.length > 65603) throw new Error("nip44: bad data size");
  if (data[0] !== 2) throw new Error("nip44: unknown version");
  const nonce = data.subarray(1, 33);
  const ciphertext = data.subarray(33, data.length - 32);
  const mac = data.subarray(data.length - 32);
  const k = messageKeys(conversation, nonce);
  const expected = hmac(sha256, k.hmacKey, concatBytes(nonce, ciphertext));
  if (!equalBytes(expected, mac)) {
    wipe(k.all);
    throw new Error("nip44: bad mac");
  }
  const padded = chacha20(k.chachaKey, k.chachaNonce, ciphertext);
  wipe(k.all);
  try {
    return unpad(padded);
  } finally {
    wipe(padded);
  }
}

// ../qr-secret-transfer/src/core/profile.ts
function assertProfile(p) {
  if (!PROFILE_ID.test(p.id)) throw new Error("profile: identifier must match [a-z0-9-]{1,24}");
  if (!Number.isInteger(p.maxPayloadBytes) || p.maxPayloadBytes < 1) throw new Error("profile: bad maximum size");
}
function previewLength(characters) {
  return Math.min(3, Math.floor(characters / 4));
}
var demoText = {
  id: "qrst-demo-text",
  maxPayloadBytes: DEFAULT_MAX_PAYLOAD,
  revocable: false,
  // The spec advises against `none` for what cannot be revoked. This profile carries
  // made-up demo text and exists to show every level, so it permits all three.
  minCheck: "none",
  encode(value) {
    const bytes = utf8Encode(value);
    if (bytes.length < 1) throw new Error("There is nothing to send.");
    if (bytes.length > this.maxPayloadBytes) {
      throw new Error(`That is ${bytes.length} bytes; the most this profile carries is ${this.maxPayloadBytes}.`);
    }
    return base64.encode(bytes);
  },
  check(content) {
    let bytes;
    try {
      bytes = base64.decode(content);
    } catch {
      return { ok: false, reason: "not base64" };
    }
    if (bytes.length < 1 || bytes.length > this.maxPayloadBytes) return { ok: false, reason: "size out of range" };
    try {
      return { ok: true, value: utf8Decode(bytes) };
    } catch {
      return { ok: false, reason: "not text" };
    }
  },
  render(value) {
    const characters = Array.from(value);
    const count = `${characters.length} character${characters.length === 1 ? "" : "s"}`;
    const shown = previewLength(characters.length);
    if (shown === 0) return count;
    const start = characters.slice(0, shown).join("").replace(/\s/g, "\u2423");
    return `${count}, starting with \u201C${start}\u201D`;
  },
  direction: {
    offer: "Scanning this QR code sends a text from your other device to this one.",
    request: "This device is sending a text. Scan this QR code to receive it."
  },
  release: {
    heading: "This is not a login. You are about to give your text to another device.",
    body: "The text itself leaves this device and is delivered to the device described below. Once it is sent it cannot be taken back.",
    confirm: (origin) => origin ? `Send my text to the device at ${origin}` : "Send my text to that device",
    decline: "Don\u2019t send"
  },
  accept: {
    heading: "Your other device sent a text",
    confirm: "Keep it",
    decline: "Discard it"
  }
};

// ../qr-secret-transfer/src/core/sas.ts
var COMMIT_LABEL = utf8Encode("qrst-commit");
var SAS_LABEL = utf8Encode("qrst-sas");
function key32(hex, what) {
  if (!isHex32(hex)) throw new Error(`sas: ${what} must be 32 bytes of lowercase hex`);
  return hexToBytes(hex);
}
function versionByte(v) {
  if (!Number.isInteger(v) || v < 0 || v > 255) throw new Error("sas: bad version");
  return new Uint8Array([v]);
}
function commit(v, contactingPub, contactingNonce) {
  return sha256(
    concatBytes(COMMIT_LABEL, versionByte(v), key32(contactingPub, "public key"), key32(contactingNonce, "nonce"))
  );
}
function sasCode(t) {
  if (!PROFILE_ID.test(t.profile)) throw new Error("sas: bad profile identifier");
  const p = utf8Encode(t.profile);
  return sha256(
    concatBytes(
      SAS_LABEL,
      versionByte(t.v),
      new Uint8Array([p.length]),
      p,
      key32(t.senderPub, "sender public key"),
      key32(t.receiverPub, "receiver public key"),
      key32(t.senderNonce, "sender nonce"),
      key32(t.receiverNonce, "receiver nonce")
    )
  );
}
function sasDigits(code) {
  if (code.length < 5) throw new Error("sas: code too short");
  let n = 0;
  for (let i = 0; i < 5; i++) n = n * 256 + code[i];
  return String(n % 1e5).padStart(5, "0");
}
function sas(t) {
  return sasDigits(sasCode(t));
}

// ../qr-secret-transfer/src/core/uri.ts
var UriError = class extends Error {
  constructor(code) {
    super(`pairing link: ${code}`);
    this.code = code;
    this.name = "UriError";
  }
  code;
};
var TOKEN = new RegExp(`^[0-9a-f]{${TOKEN_BYTES * 2}}$`);
function isToken(value) {
  return typeof value === "string" && TOKEN.test(value);
}
var LOOPBACK = /* @__PURE__ */ new Set(["localhost", "127.0.0.1", "[::1]"]);
var relayPolicy = { loopback: false };
function isPrivateHost(hostname) {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  if (LOOPBACK.has(h) || /\.(localhost|local|internal|home\.arpa|ts\.net)$/.test(h)) return true;
  if (h.startsWith("[")) {
    const mapped = /^\[::ffff:([0-9a-f]{1,4}):[0-9a-f]{1,4}\]$/.exec(h);
    if (mapped) {
      const high = parseInt(mapped[1], 16);
      return isPrivateIpv4(high >> 8, high & 255);
    }
    return /^\[(::1|f[cd][0-9a-f]{2}:|fe[89ab][0-9a-f]:)/.test(h);
  }
  const m = /^(\d+)\.(\d+)\.\d+\.\d+$/.exec(h);
  return m !== null && isPrivateIpv4(Number(m[1]), Number(m[2]));
}
function isPrivateIpv4(a, b) {
  return a === 10 || a === 127 || a === 0 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 169 && b === 254 || a === 100 && b >= 64 && b <= 127;
}
function normalizeRelayUrl(input) {
  let u;
  try {
    u = new URL(input.trim());
  } catch {
    return void 0;
  }
  const local = LOOPBACK.has(u.hostname);
  if (local && !relayPolicy.loopback) return void 0;
  if (u.protocol !== "wss:" && !(u.protocol === "ws:" && local)) return void 0;
  if (u.username || u.password) return void 0;
  const path = u.pathname === "/" ? "" : u.pathname;
  return `${u.protocol}//${u.host}${path}${u.search}`;
}
function normalizeOrigin(input) {
  let u;
  try {
    u = new URL(input.trim());
  } catch {
    return void 0;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return void 0;
  if (u.hostname.length > 253 || u.hostname.split(".").some((label) => label.length > 63)) return void 0;
  return u.origin === "null" ? void 0 : u.origin;
}
function enc(value) {
  return encodeURIComponent(value).replace(/%3A/gi, ":").replace(/%2F/gi, "/");
}
function buildUri(base, p) {
  if (!PROFILE_ID.test(p.profile)) throw new Error("pairing link: bad profile identifier");
  if (p.relays.length < 1 || p.relays.length > MAX_RELAYS) throw new Error("pairing link: needs 1 to 4 relays");
  if (!isCodeCheck(p.check)) throw new Error("pairing link: bad check");
  if (!isToken(p.token)) throw new Error("pairing link: bad token");
  const parts = [`v=${p.v}`, `mode=${p.mode}`, `p=${p.profile}`, `npub=${npubEncode(p.pub)}`, `check=${p.check}`, `token=${p.token}`];
  for (const relay of p.relays) {
    const normal = normalizeRelayUrl(relay);
    if (!normal) throw new Error("pairing link: bad relay");
    parts.push(`relay=${enc(normal)}`);
  }
  if (p.origin !== void 0) {
    const origin = normalizeOrigin(p.origin);
    if (!origin) throw new Error("pairing link: bad origin");
    parts.push(`origin=${enc(origin)}`);
  }
  const hashAt = base.indexOf("#");
  return `${hashAt < 0 ? base : base.slice(0, hashAt)}#${parts.join("&")}`;
}
var HANDOFF_SCHEME = "qrst";
var SCHEME_FORM = /^([a-z][a-z0-9+.-]*):\/\/(npub1[02-9ac-hj-np-z]+)\/?\?([^#]*)$/i;
function buildHandoffUri(p) {
  const fragment = buildUri("", p).slice(1);
  const npub = npubEncode(p.pub);
  const rest = fragment.split("&").filter((part) => part !== `npub=${npub}`);
  return `${HANDOFF_SCHEME}://${npub}?${rest.join("&")}`;
}
function isHandoff(text) {
  const m = SCHEME_FORM.exec(text.trim());
  return m !== null && m[1].toLowerCase() === HANDOFF_SCHEME;
}
function parameters(text) {
  const m = SCHEME_FORM.exec(text);
  if (m) {
    const scheme = m[1].toLowerCase();
    return scheme === HANDOFF_SCHEME ? `npub=${m[2].toLowerCase()}&${m[3]}` : void 0;
  }
  return text.includes("#") ? text.slice(text.indexOf("#") + 1) : text;
}
function looksLikePairing(text) {
  const fragment = parameters(text.trim());
  return fragment !== void 0 && /(^|&)npub=npub1/.test(fragment) && /(^|&)v=/.test(fragment);
}
function parseUri(input) {
  const text = input.trim();
  if (!looksLikePairing(text)) throw new UriError("not-a-pairing-link");
  const q = new URLSearchParams(parameters(text));
  if (q.get("v") !== String(VERSION)) throw new UriError("unknown-version");
  const mode = q.get("mode");
  if (mode !== "offer" && mode !== "request") throw new UriError("missing-mode");
  const profile = q.get("p");
  if (profile === null || !PROFILE_ID.test(profile)) throw new UriError("missing-profile");
  let pub;
  try {
    pub = npubDecode(q.get("npub") ?? "");
  } catch {
    throw new UriError("bad-key");
  }
  const token = q.get("token");
  if (!isToken(token)) throw new UriError("bad-token");
  const rawCheck = q.get("check");
  const check = isCodeCheck(rawCheck) ? rawCheck : "type";
  const relays = [];
  for (const raw of q.getAll("relay")) {
    const relay = normalizeRelayUrl(raw);
    if (!relay) throw new UriError("bad-relay");
    if (!relays.includes(relay)) relays.push(relay);
  }
  if (relays.length === 0) throw new UriError("no-relays");
  relays.length = Math.min(relays.length, MAX_RELAYS);
  const params = { v: VERSION, mode, profile, pub, check, token, relays };
  const rawOrigin = q.get("origin");
  if (rawOrigin !== null) {
    const origin = normalizeOrigin(rawOrigin);
    if (!origin) throw new UriError("bad-origin");
    params.origin = origin;
  }
  return params;
}
function scannerRole(mode) {
  return mode === "offer" ? "sender" : "receiver";
}
function showingMode(role) {
  return role === "receiver" ? "offer" : "request";
}

// ../qr-secret-transfer/src/core/wrap.ts
function buildRumor(input, senderPub, now) {
  return rumor({
    pubkey: senderPub,
    created_at: now,
    kind: input.kind,
    tags: input.tags ?? [],
    content: input.content ?? ""
  });
}
function wrap(r, senderSecret, recipientPub, env) {
  return giftWrap(seal(r, senderSecret, recipientPub, env), recipientPub, env);
}
function seal(r, senderSecret, recipientPub, env) {
  if (!isHex32(recipientPub)) throw new Error("wrap: bad recipient");
  const now = env.now();
  const sealKey = conversationKey(senderSecret, recipientPub);
  const sealed = sign(
    {
      pubkey: publicKey(senderSecret),
      created_at: now,
      kind: KINDS.SEAL,
      tags: [],
      content: encrypt(JSON.stringify(r), sealKey, env.random(32))
    },
    senderSecret,
    env.random
  );
  wipe(sealKey);
  return sealed;
}
function giftWrap(sealed, recipientPub, env) {
  if (!isHex32(recipientPub)) throw new Error("wrap: bad recipient");
  const now = env.now();
  const oneTime = generateSecretKey(env.random);
  const wrapKey = conversationKey(oneTime, recipientPub);
  const wrapped = sign(
    {
      pubkey: publicKey(oneTime),
      created_at: now,
      kind: KINDS.WRAP,
      tags: [
        ["p", recipientPub],
        ["expiration", String(now + SESSION_SECONDS)]
      ],
      content: encrypt(JSON.stringify(sealed), wrapKey, env.random(32))
    },
    oneTime,
    env.random
  );
  wipe(oneTime, wrapKey);
  return wrapped;
}
function open(secret, peerPub, content) {
  let key;
  try {
    key = conversationKey(secret, peerPub);
    return decrypt(content, key);
  } catch {
    return void 0;
  } finally {
    wipe(key);
  }
}
function parse(json) {
  try {
    return JSON.parse(json);
  } catch {
    return void 0;
  }
}
function unwrap(event, recipientSecret) {
  if (!isEventShape(event) || event.kind !== KINDS.WRAP) return { ok: false, reason: "not-a-wrap" };
  const own = publicKey(recipientSecret);
  if (!event.tags.some((t) => t[0] === "p" && t[1] === own)) return { ok: false, reason: "not-for-us" };
  if (!verify(event)) return { ok: false, reason: "bad-wrap-signature" };
  const sealJson = open(recipientSecret, event.pubkey, event.content);
  if (sealJson === void 0) return { ok: false, reason: "undecryptable" };
  const seal2 = parse(sealJson);
  if (!isEventShape(seal2) || seal2.kind !== KINDS.SEAL || !verify(seal2)) return { ok: false, reason: "bad-seal" };
  const rumorJson = open(recipientSecret, seal2.pubkey, seal2.content);
  if (rumorJson === void 0) return { ok: false, reason: "undecryptable" };
  const inner = parse(rumorJson);
  if (!isEventShape(inner)) return { ok: false, reason: "bad-rumor" };
  const template = {
    pubkey: inner.pubkey,
    created_at: inner.created_at,
    kind: inner.kind,
    tags: inner.tags,
    content: inner.content
  };
  if (template.pubkey !== seal2.pubkey) return { ok: false, reason: "attribution" };
  const id = eventId(template);
  if (inner.id !== void 0 && inner.id !== id) return { ok: false, reason: "bad-rumor" };
  return { ok: true, rumor: { ...template, id } };
}

// ../qr-secret-transfer/src/core/session.ts
var short = (pub) => `${pub.slice(0, 8)}\u2026`;
var MAX_SEEN = 512;
var STEPS = [[KINDS.HELLO, KINDS.REQUEST], [KINDS.NONCE], [KINDS.REVEAL], [KINDS.PAYLOAD], [KINDS.ACK]];
var ALL_KINDS = STEPS.flat().concat(KINDS.ABORT);
function answeredBy(kind) {
  if (kind === KINDS.ABORT) return ALL_KINDS;
  const step = STEPS.findIndex((kinds) => kinds.includes(kind));
  return step > 0 ? STEPS.slice(0, step).flat() : [];
}
var Session = class {
  role;
  showing;
  profile;
  pub;
  startedAt;
  env;
  secretKey;
  peerPub;
  isBlocked;
  /** This device's own setting. */
  own;
  /**
   * Showing device: the token in its QR. Contacting device: the token it read. A
   * contact that does not echo it never saw the code and is not a responder.
   */
  token;
  /** Contacting device: the check agreed with the QR. Showing device: its own, raised by every responder. */
  peak;
  /** Sender that showed the code: candidates the user said did not match. */
  rejected = /* @__PURE__ */ new Set();
  /** Showing device: a responder was agreed at `none`, so no second one can be told apart from it. */
  noneAgreed = false;
  payloadContent;
  phase = "waiting";
  outcome;
  peers = /* @__PURE__ */ new Map();
  seen = /* @__PURE__ */ new Set();
  /**
   * Every burner that has contacted this session, whether or not it is still held.
   * A burner gets one nonce exchange, and a slot is never handed out twice: a party
   * that learns our nonce before revealing its own must not be able to walk away and
   * ask again until it likes the code (§6, §13).
   */
  contacted = /* @__PURE__ */ new Set();
  /** Sender: burners a code entry failed against, kept even if the peer is later dropped (§9.3). */
  failedPeers = /* @__PURE__ */ new Set();
  order = 0;
  attempts = 0;
  multipleResponders = false;
  dropped = 0;
  /** Receiver: the peer whose code is on screen. */
  active;
  /** Sender: the peer the payload went to. */
  releasedTo;
  releasedSas;
  ackDeadline;
  released = false;
  started = false;
  constructor(options) {
    assertProfile(options.profile);
    this.role = options.role;
    this.showing = options.showing;
    this.profile = options.profile;
    this.env = options.env;
    this.secretKey = options.secretKey;
    this.pub = publicKey(options.secretKey);
    this.startedAt = options.env.now();
    this.isBlocked = options.isBlocked ?? (() => false);
    if (options.check !== void 0 && !isCodeCheck(options.check)) throw new Error("session: unknown check");
    this.own = stricter(options.check ?? "type", this.profile.minCheck ?? "compare");
    if (this.showing) {
      if (options.peerPub !== void 0) throw new Error("session: the showing device has no peer yet");
      this.token = bytesToHex(this.env.random(TOKEN_BYTES));
      this.peak = this.own;
    } else {
      if (!isToken(options.token)) throw new Error("session: the contacting device needs the token from the QR");
      this.token = options.token;
      this.peak = stricter(this.own, isCodeCheck(options.peerCheck) ? options.peerCheck : "type");
      if (!isHex32(options.peerPub)) throw new Error("session: the contacting device needs the key from the QR");
      if (options.peerPub === this.pub) throw new Error("session: a device cannot pair with itself");
      if (!isValidPublicKey(options.peerPub)) throw new Error("session: the key from the QR is not a valid key");
    }
    this.peerPub = options.peerPub;
    if (this.role === "sender") {
      if (options.payload === void 0) throw new Error("session: the Sender needs something to send");
      this.payloadContent = this.profile.encode(options.payload);
    } else if (options.payload !== void 0) {
      throw new Error("session: a Receiver sends no payload");
    }
  }
  /** The filter a relay subscription for this session uses (§11.5). */
  filter() {
    return { kinds: [KINDS.WRAP], "#p": [this.pub], since: this.startedAt - SLACK_SECONDS };
  }
  view() {
    const ready = [...this.peers.values()].filter((p) => p.sas !== void 0);
    const activePeer = this.active ? this.peers.get(this.active) : void 0;
    const check = this.role === "receiver" && this.showing ? activePeer?.check ?? this.own : this.peak;
    const view = {
      role: this.role,
      showing: this.showing,
      phase: this.phase,
      check,
      attemptsLeft: MAX_ATTEMPTS - this.attempts,
      ready: ready.length,
      multipleResponders: this.multipleResponders,
      dropped: this.dropped,
      canAdvance: this.role === "receiver" && this.showing && ready.some((p) => p.pub !== this.active),
      expiresAt: this.startedAt + SESSION_SECONDS,
      released: this.released
    };
    if (this.outcome) view.outcome = this.outcome;
    if (this.role === "receiver" && activePeer?.sas && check !== "none" && (this.phase === "code" || this.phase === "accept")) {
      view.code = activePeer.sas;
    }
    const comparing = this.phase === "release" && check === "compare" ? this.comparing() : void 0;
    if (comparing) view.compare = comparing.sas;
    if (this.phase === "accept" && activePeer?.held !== void 0) view.rendering = this.profile.render(activePeer.held);
    if (this.ackDeadline !== void 0 && this.phase === "sent") view.ackDeadline = this.ackDeadline;
    return view;
  }
  // ---- messages out -------------------------------------------------------------------
  send(to, input, label) {
    const r = buildRumor(input, this.pub, this.env.now());
    const sealed = seal(r, this.secretKey, to, this.env);
    return {
      t: "publish",
      event: giftWrap(sealed, to, this.env),
      seal: sealed,
      to,
      kind: input.kind,
      unanswered: input.kind === KINDS.ACK || input.kind === KINDS.ABORT,
      label: `${label} \u2192 ${short(to)}`
    };
  }
  abort(to, reason) {
    return this.send(to, { kind: KINDS.ABORT, ...reason ? { tags: [["reason", reason]] } : {} }, "ABORT");
  }
  /**
   * A wrap addressed to this session's own burner, carrying a PAYLOAD-shaped rumor of
   * the profile's maximum size: the loopback test a relay must pass before it is
   * listed. The host recognises it by event id and never hands it back.
   */
  probe() {
    this.assertLive();
    const content = base64.encode(this.env.random(this.profile.maxPayloadBytes));
    const r = buildRumor({ kind: KINDS.PAYLOAD, content }, this.pub, this.env.now());
    return wrap(r, this.secretKey, this.pub, this.env);
  }
  /** NIP-42 authentication with the burner, the only identity a session ever shows a relay (§11.5). */
  signAuth(relayUrl, challenge2) {
    this.assertLive();
    return sign(
      {
        pubkey: this.pub,
        created_at: this.env.now(),
        kind: KINDS.AUTH,
        tags: [
          ["relay", relayUrl],
          ["challenge", challenge2]
        ],
        content: ""
      },
      this.secretKey,
      this.env.random
    );
  }
  // ---- inputs -------------------------------------------------------------------------
  /** Contacting party: speak first. The showing device has nothing to start. */
  start() {
    if (this.phase === "ended" || this.started) return [];
    this.started = true;
    if (this.showing || !this.peerPub) return [];
    if (this.role === "sender" && this.isBlocked(this.peerPub)) return this.finish("blocked-peer", []);
    const ownNonce = bytesToHex(this.env.random(32));
    this.peers.set(this.peerPub, { pub: this.peerPub, order: this.order++, ownNonce, displayed: false, failed: false, check: this.peak });
    const commitment = bytesToHex(commit(VERSION, this.pub, ownNonce));
    const kind = this.role === "sender" ? KINDS.HELLO : KINDS.REQUEST;
    const label = this.role === "sender" ? "HELLO" : "REQUEST";
    const tags = [
      ["commit", commitment],
      ["token", this.token],
      ["check", this.peak]
    ];
    return [this.send(this.peerPub, { kind, tags }, label)];
  }
  /** A gift wrap arrived from a relay. Anything that is not a valid message of this session is ignored. */
  receive(event) {
    if (this.phase === "ended") return [];
    const opened = unwrap(event, this.secretKey);
    if (!opened.ok) return [{ t: "trace", text: `ignored a wrap: ${opened.reason}` }];
    return this.receiveRumor(opened.rumor);
  }
  /** True once the ten minutes are up. Checked on every input, not only by the timer. */
  expired() {
    return this.phase !== "sent" && this.phase !== "ended" && this.env.now() >= this.startedAt + SESSION_SECONDS;
  }
  /** Exposed for tests that drive the machine without the encryption layer. */
  receiveRumor(r) {
    if (this.phase === "ended") return [];
    if (this.expired()) return this.tick();
    if (r.pubkey === this.pub) return [];
    if (r.created_at < this.startedAt - SLACK_SECONDS || r.created_at > this.startedAt + SESSION_SECONDS + SLACK_SECONDS) {
      return [{ t: "trace", text: "ignored a message outside the session window" }];
    }
    if (this.seen.has(r.id)) return [];
    if (this.seen.size < MAX_SEEN) this.seen.add(r.id);
    const effects = this.dispatch(r);
    const answered = effects.length > 0 ? answeredBy(r.kind) : [];
    return answered.length > 0 ? [{ t: "settled", peer: r.pubkey, kinds: answered }, ...effects] : effects;
  }
  dispatch(r) {
    switch (r.kind) {
      case KINDS.HELLO:
        return this.showing && this.role === "receiver" ? this.onContact(r) : [];
      case KINDS.REQUEST:
        return this.showing && this.role === "sender" ? this.onContact(r) : [];
      case KINDS.NONCE:
        return !this.showing ? this.onNonce(r) : [];
      case KINDS.REVEAL:
        return this.showing ? this.onReveal(r) : [];
      case KINDS.PAYLOAD:
        return this.role === "receiver" ? this.onPayload(r) : [];
      case KINDS.ACK:
        return this.role === "sender" ? this.onAck(r) : [];
      case KINDS.ABORT:
        return this.onAbort(r);
      default:
        return [];
    }
  }
  /** Showing device: a HELLO (Flow A) or REQUEST (Flow B) from a burner we have not met. */
  onContact(r) {
    const commitment = firstTag(r, "commit");
    if (!isHex32(commitment)) return [];
    const token = firstTag(r, "token");
    if (token === void 0 || !equalAscii(token, this.token)) {
      return [{ t: "trace", text: `ignored ${short(r.pubkey)}: it did not echo this code's token` }];
    }
    if (this.contacted.has(r.pubkey)) return [];
    if (this.role === "sender" && this.isBlocked(r.pubkey)) {
      return [{ t: "trace", text: `ignored ${short(r.pubkey)}: a code already failed against it` }];
    }
    const announced = firstTag(r, "check");
    const check = stricter(this.own, isCodeCheck(announced) ? announced : "type");
    if (this.contacted.size >= 1 && (check === "none" || this.noneAgreed)) return this.secondResponder(r.pubkey);
    if (this.phase !== "waiting" && this.phase !== "release" && this.phase !== "code") {
      this.multipleResponders = true;
      return [{ t: "trace", text: `another device, ${short(r.pubkey)}, answered after this one was chosen` }];
    }
    if (this.contacted.size >= 1) this.multipleResponders = true;
    const cap = this.role === "receiver" ? MAX_HELD : MAX_PENDING;
    if (this.contacted.size >= cap) {
      this.dropped++;
      return [{ t: "trace", text: `turned away ${short(r.pubkey)}: this code has already been answered ${cap} times` }];
    }
    this.contacted.add(r.pubkey);
    if (check === "none") this.noneAgreed = true;
    this.peak = stricter(this.peak, check);
    const ownNonce = bytesToHex(this.env.random(32));
    this.peers.set(r.pubkey, {
      pub: r.pubkey,
      order: this.order++,
      commit: commitment,
      ownNonce,
      displayed: false,
      failed: false,
      check
    });
    return [
      { t: "trace", text: `${r.kind === KINDS.HELLO ? "HELLO" : "REQUEST"} \u2190 ${short(r.pubkey)}` },
      this.send(r.pubkey, { kind: KINDS.NONCE, tags: [["nonce", ownNonce]] }, "NONCE")
    ];
  }
  /**
   * Showing device, where a responder was agreed at `none`: a second device answered. Without a
   * code nothing can tell the two apart, so nothing moves and both are told why. If
   * the text has already gone, it is too late to stop; the user is still told.
   */
  secondResponder(pub) {
    this.multipleResponders = true;
    if (this.phase === "sent") return [{ t: "trace", text: `another device, ${short(pub)}, answered after the text was sent` }];
    if (this.phase === "ended") return [];
    const effects = [{ t: "trace", text: `a second device, ${short(pub)}, answered; with no code there is no telling which is yours` }];
    for (const p of this.peers.values()) effects.push(this.abort(p.pub, "second-responder"));
    effects.push(this.abort(pub, "second-responder"));
    return this.finish("second-responder", effects);
  }
  /** Contacting party: the showing device answered with its nonce. Reveal ours and derive the code. */
  onNonce(r) {
    if (r.pubkey !== this.peerPub) return [];
    const peer = this.peers.get(r.pubkey);
    const nonce = firstTag(r, "nonce");
    if (!peer || peer.peerNonce !== void 0 || !isHex32(nonce)) return [];
    peer.peerNonce = nonce;
    peer.sas = this.codeFor(peer);
    const effects = [
      { t: "trace", text: `NONCE \u2190 ${short(r.pubkey)}` },
      this.send(peer.pub, { kind: KINDS.REVEAL, tags: [["nonce", peer.ownNonce]] }, "REVEAL")
    ];
    if (this.role === "sender") {
      this.phase = "release";
    } else {
      this.active = peer.pub;
      peer.displayed = true;
      this.phase = "code";
    }
    return effects;
  }
  /** Showing device: a peer opened its commitment. */
  onReveal(r) {
    const peer = this.peers.get(r.pubkey);
    const nonce = firstTag(r, "nonce");
    if (!peer || peer.commit === void 0 || peer.peerNonce !== void 0 || !isHex32(nonce)) return [];
    if (!equalAscii(bytesToHex(commit(VERSION, peer.pub, nonce)), peer.commit)) {
      this.peers.delete(peer.pub);
      return [{ t: "trace", text: `dropped ${short(peer.pub)}: reveal does not match its commitment` }];
    }
    peer.peerNonce = nonce;
    peer.sas = this.codeFor(peer);
    const effects = [{ t: "trace", text: `REVEAL \u2190 ${short(peer.pub)}, commitment verified` }];
    if (this.role === "sender") {
      if (this.phase === "waiting") this.phase = "release";
    } else if (this.active === void 0) {
      this.activateNext();
    }
    return effects;
  }
  /** The code for a peer, with the two burners in ROLE order whoever made contact (§6). */
  codeFor(peer) {
    const iAmSender = this.role === "sender";
    return sas({
      v: VERSION,
      profile: this.profile.id,
      senderPub: iAmSender ? this.pub : peer.pub,
      receiverPub: iAmSender ? peer.pub : this.pub,
      senderNonce: iAmSender ? peer.ownNonce : peer.peerNonce,
      receiverNonce: iAmSender ? peer.peerNonce : peer.ownNonce
    });
  }
  /** Receiver: put the earliest ready candidate's code on screen. Returns false if there is none. */
  activateNext() {
    const next = [...this.peers.values()].filter((p) => p.sas !== void 0).sort((a, b) => a.order - b.order)[0];
    if (!next) {
      this.active = void 0;
      this.phase = "waiting";
      return false;
    }
    this.active = next.pub;
    next.displayed = true;
    this.phase = "code";
    return true;
  }
  /** Receiver: a payload arrived. It is held, never kept, until the user confirms (§9.4). */
  onPayload(r) {
    const peer = this.peers.get(r.pubkey);
    if (!peer || peer.held !== void 0) return [];
    if (peer.sas === void 0) {
      this.seen.delete(r.id);
      return [{ t: "trace", text: `PAYLOAD \u2190 ${short(peer.pub)} arrived before its REVEAL; waiting for it again` }];
    }
    if (this.phase !== "code") return [];
    if (peer.pub !== this.active || !peer.displayed) {
      this.peers.delete(peer.pub);
      return [{ t: "trace", text: `dropped ${short(peer.pub)}: payload arrived before its code was shown` }];
    }
    const checked = this.profile.check(r.content);
    if (!checked.ok) {
      this.peers.delete(peer.pub);
      const effects = [
        { t: "trace", text: `dropped ${short(peer.pub)}: payload is not a ${this.profile.id} (${checked.reason})` },
        this.abort(peer.pub)
      ];
      if (this.activateNext()) return effects;
      return this.finish("bad-payload", effects);
    }
    peer.held = checked.value;
    this.phase = "accept";
    return [{ t: "trace", text: `PAYLOAD \u2190 ${short(peer.pub)}, held for confirmation` }];
  }
  onAck(r) {
    if (this.phase !== "sent" || r.pubkey !== this.releasedTo) return [];
    return this.finish("delivered", [{ t: "trace", text: `ACK \u2190 ${short(r.pubkey)}` }]);
  }
  onAbort(r) {
    const peer = this.peers.get(r.pubkey);
    if (!peer) return [];
    const effects = [{ t: "trace", text: `ABORT \u2190 ${short(r.pubkey)}` }];
    if (!this.showing || r.pubkey === this.releasedTo) {
      return this.finish(firstTag(r, "reason") === "second-responder" ? "second-responder" : "peer-aborted", effects);
    }
    this.peers.delete(peer.pub);
    if (this.role === "sender") {
      if (this.phase === "release" && !this.hasCandidate()) this.phase = "waiting";
      return effects;
    }
    if (peer.pub !== this.active) return effects;
    this.activateNext();
    return effects;
  }
  /**
   * Sender: the user typed the five digits shown on the Receiver.
   *
   * The comparison happens here and only here (§9.2). The typed value is checked
   * against the code this device computed for each ready peer; it is never sent, and a
   * result asserted by a peer is never accepted. A value that matches exactly one peer
   * releases to that peer. Anything else spends one attempt.
   */
  enterCode(digits) {
    if (!this.canRelease("type")) return [];
    if (this.expired()) return this.tick();
    if (!/^[0-9]{5}$/.test(digits)) throw new Error("session: a pairing code is exactly five digits");
    const ready = [...this.peers.values()].filter((p) => p.sas !== void 0);
    const matches = ready.filter((p) => equalAscii(p.sas, digits));
    if (matches.length === 1) return this.releaseTo(matches[0]);
    return this.miss(ready);
  }
  /**
   * Sender, check `compare`: the user says the code this device shows, `view().compare`,
   * is the one on the other device. Release to the device it belongs to.
   */
  confirmMatch() {
    if (!this.canRelease("compare")) return [];
    if (this.expired()) return this.tick();
    const target = this.comparing();
    return target ? this.releaseTo(target) : [];
  }
  /**
   * Sender, check `compare`: the user says the codes differ. That spends an attempt,
   * as a wrong code typed would. A Sender that showed the code moves on to the next
   * device that answered; one that scanned has only the one, and waits for the
   * other device to show a different candidate's code.
   */
  rejectMatch() {
    if (!this.canRelease("compare")) return [];
    if (this.expired()) return this.tick();
    const target = this.comparing();
    if (!target) return [];
    if (this.showing) this.rejected.add(target.pub);
    const effects = this.miss([target]);
    if (this.phase === "release" && !this.hasCandidate()) this.phase = "waiting";
    return effects;
  }
  /** Sender, check `none`: the user confirmed the release prompt. Only ever to a lone responder. */
  release() {
    if (!this.canRelease("none")) return [];
    if (this.expired()) return this.tick();
    const ready = [...this.peers.values()].filter((p) => p.sas !== void 0);
    if (ready.length !== 1 || this.showing && this.contacted.size !== 1) return [];
    return this.releaseTo(ready[0]);
  }
  canRelease(check) {
    return this.phase === "release" && this.role === "sender" && this.peak === check;
  }
  /** Sender, check `compare`: the device whose code is on screen. The earliest that has not been rejected. */
  comparing() {
    return [...this.peers.values()].filter((p) => p.sas !== void 0 && !this.rejected.has(p.pub)).sort((a, b) => a.order - b.order)[0];
  }
  hasCandidate() {
    return [...this.peers.values()].some((p) => p.sas !== void 0 && !this.rejected.has(p.pub));
  }
  releaseTo(target) {
    const effects = [this.send(target.pub, { kind: KINDS.PAYLOAD, content: this.payloadContent }, "PAYLOAD")];
    for (const other of this.peers.values()) if (other.pub !== target.pub) effects.push(this.abort(other.pub));
    this.releasedTo = target.pub;
    this.releasedSas = target.sas;
    this.released = true;
    this.payloadContent = void 0;
    this.ackDeadline = this.env.now() + ACK_WAIT_SECONDS;
    this.phase = "sent";
    effects.push(this.record("sent-unconfirmed", target.pub, target.sas));
    return effects;
  }
  /** A code did not match these peers. Spends one attempt, and the session after the last. */
  miss(peers) {
    this.attempts++;
    for (const p of peers) {
      p.failed = true;
      this.failedPeers.add(p.pub);
    }
    const effects = [{ t: "trace", text: `code did not match (attempt ${this.attempts} of ${MAX_ATTEMPTS})` }];
    if (this.attempts < MAX_ATTEMPTS) return effects;
    for (const p of this.peers.values()) effects.push(this.abort(p.pub));
    return this.finish("attempts-exhausted", effects);
  }
  /** Receiver: the user confirmed the rendering. Keep the payload and acknowledge. */
  accept() {
    const peer = this.active ? this.peers.get(this.active) : void 0;
    if (this.phase !== "accept" || !peer || peer.held === void 0) return [];
    if (this.expired()) return this.tick();
    const value = peer.held;
    return this.finish(
      "received",
      [{ t: "commit", value }, this.send(peer.pub, { kind: KINDS.ACK }, "ACK")],
      { peer: peer.pub, sas: peer.sas }
    );
  }
  /** The user refused: a Sender declining to release, or a Receiver discarding what arrived. */
  decline() {
    if (this.role === "receiver" && this.showing && this.phase === "accept" && this.active) {
      const gone = this.active;
      this.peers.delete(gone);
      this.activateNext();
      return [{ t: "trace", text: `discarded what ${short(gone)} sent; ${this.active ? "showing the next code" : "waiting"}` }, this.abort(gone)];
    }
    return this.leave("declined");
  }
  /** The user left the flow. */
  cancel() {
    return this.leave("cancelled");
  }
  leave(outcome) {
    if (this.phase === "ended") return [];
    if (this.phase === "sent") return this.finish("sent-unconfirmed", []);
    const effects = [];
    for (const p of this.peers.values()) effects.push(this.abort(p.pub));
    return this.finish(outcome, effects);
  }
  /**
   * Receiver that showed the QR: the device being paired says this code is wrong, so
   * the code on screen belongs to someone else. Discard that candidate and show the
   * next one (§13). With nobody behind it, go back to waiting.
   */
  advance() {
    if (this.role !== "receiver" || !this.showing || this.phase !== "code" || !this.active) return [];
    const gone = this.active;
    this.peers.delete(gone);
    this.activateNext();
    return [{ t: "trace", text: `set ${short(gone)} aside; ${this.active ? "showing the next code" : "waiting"}` }];
  }
  /** Call about once a second. Enforces the ten-minute lifetime and the acknowledgement wait. */
  tick() {
    if (this.phase === "ended") return [];
    const now = this.env.now();
    if (this.phase === "sent") {
      return this.ackDeadline !== void 0 && now >= this.ackDeadline ? this.finish("sent-unconfirmed", []) : [];
    }
    if (now < this.startedAt + SESSION_SECONDS) return [];
    const effects = [];
    for (const p of this.peers.values()) effects.push(this.abort(p.pub));
    return this.finish("expired", effects);
  }
  // ---- ending -------------------------------------------------------------------------
  finish(outcome, effects, done) {
    const completed = done ?? (this.releasedTo && this.releasedSas ? { peer: this.releasedTo, sas: this.releasedSas } : void 0);
    if (completed) {
      effects.push(this.record(outcome, completed.peer, completed.sas));
    } else if (this.role === "sender" && this.failedPeers.size > 0) {
      effects.push({ t: "failed-peers", pubs: [...this.failedPeers] });
    }
    this.phase = "ended";
    this.outcome = outcome;
    this.active = void 0;
    this.payloadContent = void 0;
    this.peers.clear();
    this.seen.clear();
    this.contacted.clear();
    this.failedPeers.clear();
    this.rejected.clear();
    wipe(this.secretKey);
    effects.push({ t: "ended", outcome });
    return effects;
  }
  /** §14. A later record for the same peer replaces an earlier one. */
  record(outcome, peer, sas2) {
    return {
      t: "record",
      record: {
        ts: this.env.now(),
        profile: this.profile.id,
        role: this.role,
        outcome,
        sas: sas2,
        peer,
        multi: this.multipleResponders,
        check: this.recordedCheck(peer)
      }
    };
  }
  /** The level that was actually applied: a Sender that showed the code applies the strictest it agreed. */
  recordedCheck(pub) {
    return this.role === "receiver" && this.showing ? this.peers.get(pub)?.check ?? this.peak : this.peak;
  }
  assertLive() {
    if (this.phase === "ended") throw new Error("session: ended");
  }
};

// ../qr-secret-transfer/src/web/pool.ts
var RESEND_MS = 3e3;
var FINAL_RESEND_MS = 2e4;
var BACKOFF_MS = [500, 1e3, 2e3, 4e3, 8e3];
function tidy(text, fallback) {
  if (typeof text !== "string" || text === "") return fallback;
  return text.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 120);
}
var RelayLink = class {
  constructor(url, pool, options, reconnect) {
    this.url = url;
    this.pool = pool;
    this.options = options;
    this.reconnect = reconnect;
    this.connect();
  }
  url;
  pool;
  options;
  reconnect;
  state = "connecting";
  /** The relay's most recent refusal or notice, for the person looking at the relay list. */
  lastReason;
  acks = /* @__PURE__ */ new Map();
  ws;
  subId = `q${Math.random().toString(36).slice(2, 10)}`;
  challenge;
  authId;
  authed = false;
  attempt = 0;
  /** A relay that answered "rate-limited" gets no timed re-sends until then (ms since the epoch). */
  restUntil = 0;
  rests = 0;
  timer;
  closedByUs = false;
  /** Events for this relay alone: the loopback probe, until it has passed. */
  local = [];
  connect() {
    if (this.closedByUs) return;
    this.state = "connecting";
    this.authed = false;
    this.authId = void 0;
    this.challenge = void 0;
    const Impl = this.options.WebSocketImpl ?? WebSocket;
    let ws;
    try {
      ws = new Impl(this.url);
    } catch (e) {
      this.lastReason = e instanceof Error ? e.message : "could not connect";
      this.onClose();
      return;
    }
    this.ws = ws;
    ws.onopen = () => {
      if (this.ws !== ws) return;
      this.state = "open";
      this.attempt = 0;
      this.subscribe();
      this.republish();
      this.pool.changed();
    };
    ws.onmessage = (m) => {
      if (this.ws === ws) this.onMessage(m.data);
    };
    ws.onerror = () => {
    };
    ws.onclose = () => {
      if (this.ws === ws) this.onClose();
    };
  }
  onClose() {
    this.ws = void 0;
    this.state = "closed";
    this.pool.changed();
    if (this.closedByUs || !this.reconnect) return;
    const wait = BACKOFF_MS[Math.min(this.attempt++, BACKOFF_MS.length - 1)];
    this.timer = setTimeout(() => this.connect(), wait);
  }
  raw(message) {
    if (this.ws && this.state === "open") {
      try {
        this.ws.send(JSON.stringify(message));
      } catch {
      }
    }
  }
  subscribe() {
    this.raw(["REQ", this.subId, this.options.filter]);
  }
  republish() {
    this.pool.resend(this);
    for (const event of this.local) this.raw(["EVENT", event]);
  }
  /** The page came back into view: a socket that is down tries again now, not after its backoff. */
  wake() {
    if (this.closedByUs || this.state !== "closed" || !this.reconnect) return;
    if (this.timer) clearTimeout(this.timer);
    this.attempt = 0;
    this.connect();
  }
  authenticate() {
    if (!this.challenge || this.authId) return;
    let event;
    try {
      event = this.options.signAuth(this.url, this.challenge);
    } catch {
      return;
    }
    this.authId = event.id;
    this.raw(["AUTH", event]);
  }
  onMessage(data) {
    if (typeof data !== "string") return;
    let message;
    try {
      message = JSON.parse(data);
    } catch {
      return;
    }
    if (!Array.isArray(message)) return;
    const [type, a, b, c] = message;
    switch (type) {
      case "EVENT":
        if (a === this.subId) this.pool.incoming(this, b);
        return;
      case "OK": {
        if (typeof a !== "string") return;
        const ok = b === true;
        const text = tidy(c, "");
        if (a === this.authId) {
          if (ok) {
            this.authed = true;
            this.subscribe();
            this.republish();
          } else {
            this.lastReason = text || "authentication refused";
            this.authId = void 0;
          }
          this.pool.changed();
          return;
        }
        this.acks.set(a, { ok, message: text });
        if (ok) this.rests = 0;
        else if (text.startsWith("rate-limited")) {
          this.restUntil = Date.now() + Math.min(6e4, 1e4 * 2 ** this.rests++);
        }
        if (!ok) {
          this.lastReason = text || "refused";
          const wantsAuth = text.startsWith("auth-required") && !this.authed;
          if (wantsAuth) this.authenticate();
          else this.pool.refused(this, a);
        }
        this.pool.changed();
        return;
      }
      case "CLOSED":
        if (a !== this.subId) return;
        this.lastReason = tidy(b, "subscription closed");
        if (this.lastReason.startsWith("auth-required") && !this.authed) this.authenticate();
        this.pool.changed();
        return;
      case "AUTH":
        if (typeof a !== "string") return;
        this.challenge = a;
        this.authId = void 0;
        this.authenticate();
        return;
      case "NOTICE":
        this.lastReason = tidy(a, "notice");
        return;
      default:
        return;
    }
  }
  /** Publishes one of the session's messages. The pool's outbox owns it. */
  publish(event) {
    this.raw(["EVENT", event]);
  }
  /** Publishes to this relay only, and again after a reconnect or an authentication. */
  publishLocal(event) {
    this.local.push(event);
    this.raw(["EVENT", event]);
  }
  clearLocal() {
    this.local = [];
  }
  close() {
    this.closedByUs = true;
    if (this.timer) clearTimeout(this.timer);
    const ws = this.ws;
    this.ws = void 0;
    this.state = "closed";
    if (ws) {
      ws.onopen = ws.onmessage = ws.onerror = ws.onclose = null;
      try {
        ws.close();
      } catch {
      }
    }
  }
};
var Pool = class {
  constructor(options) {
    this.options = options;
    globalThis.document?.addEventListener("visibilitychange", this.onVisible);
    globalThis.addEventListener?.("online", this.onVisible);
  }
  options;
  outbox = [];
  links = /* @__PURE__ */ new Map();
  seen = /* @__PURE__ */ new Set();
  ignored = /* @__PURE__ */ new Set();
  waiters = /* @__PURE__ */ new Map();
  closed = false;
  /** The session has ended; only its last messages are still going out. */
  ending = false;
  resendTimer;
  onVisible = () => {
    if (globalThis.document?.visibilityState !== "hidden") this.wake();
  };
  /** True once the pool is closed, or winding down after its session ended. */
  get isClosed() {
    return this.closed || this.ending;
  }
  changed() {
    if (!this.closed) this.options.onChange?.();
  }
  add(url, reconnect) {
    const existing = this.links.get(url);
    if (existing) {
      existing.reconnect ||= reconnect;
      return existing;
    }
    const link = new RelayLink(url, this, this.options, reconnect);
    this.links.set(url, link);
    return link;
  }
  remove(url) {
    this.links.get(url)?.close();
    this.links.delete(url);
    this.changed();
  }
  get(url) {
    return this.links.get(url);
  }
  all() {
    return [...this.links.values()];
  }
  /** Publishes to every relay in parallel and keeps the message to send again (§11.5). */
  publish(message) {
    if (this.closed) return;
    this.outbox.push({ ...message, until: message.unanswered ? Date.now() + (this.options.finalMs ?? FINAL_RESEND_MS) : void 0 });
    for (const link of this.links.values()) link.publish(message.event);
    this.resendTimer ??= setInterval(() => this.tick(), this.options.resendMs ?? RESEND_MS);
  }
  /** The peer `to` has evidently received the messages of these kinds sent to it: stop sending them. */
  settle(to, kinds) {
    for (let i = this.outbox.length - 1; i >= 0; i--) {
      const e = this.outbox[i];
      if (e.to === to && e.kind !== void 0 && kinds.includes(e.kind)) this.outbox.splice(i, 1);
    }
  }
  /**
   * Sends every message in the outbox again, in a fresh wrap, to one relay (a socket
   * opened, or authenticated) or to all of them.
   */
  resend(only) {
    if (this.closed) return;
    const now = Date.now();
    for (const e of this.outbox) if (e.until === void 0 || now < e.until) this.again(e, only);
  }
  again(e, only, timed = false) {
    if (e.again) {
      try {
        e.event = e.again();
      } catch {
        return;
      }
    }
    if (only) only.publish(e.event);
    else for (const link of this.links.values()) if (!timed || Date.now() >= link.restUntil) link.publish(e.event);
  }
  /** The timed re-send: everything outstanding, and what nothing will answer while its time lasts. */
  tick() {
    if (this.closed) return;
    const now = Date.now();
    for (const e of this.outbox) if (e.until === void 0 || now < e.until) this.again(e, void 0, true);
  }
  /** Reconnects what is down and sends everything outstanding again, now. */
  wake() {
    if (this.closed) return;
    for (const link of this.links.values()) link.wake();
    this.resend();
  }
  /** An event id this pool must never hand to the session: a loopback probe. */
  ignore(id) {
    this.ignored.add(id);
  }
  incoming(link, event) {
    if (this.closed || typeof event !== "object" || event === null) return;
    const id = event.id;
    if (typeof id !== "string") return;
    const waiter = this.waiters.get(`${link.url} ${id}`);
    if (waiter && verify(event)) waiter(true);
    if (this.ignored.has(id)) return;
    if (this.seen.has(id)) return;
    if (!verify(event)) return;
    this.seen.add(id);
    this.options.onEvent(event, link.url);
  }
  /** A relay answered a publish with a final refusal. */
  refused(link, id) {
    this.waiters.get(`${link.url} ${id}`)?.(false);
  }
  /**
   * The loopback test of §11.3a. Opens a link, publishes `probe` (a wrap addressed to
   * the session's own burner) to that relay alone, and passes only if the same event
   * comes back on the subscription. A relay that passes stays in the pool as a
   * session relay; one that fails is removed.
   */
  async loopback(url, probe, echoMs = 3e3, connectMs = 5e3) {
    if (this.isClosed) return { ok: false, reason: "cancelled" };
    const link = this.add(url, false);
    const fail = (reason) => {
      this.remove(url);
      return { ok: false, reason };
    };
    const opened = await this.until(() => link.state === "open" || link.state === "closed" && !link.reconnect, connectMs);
    if (this.isClosed) return { ok: false, reason: "cancelled" };
    if (!opened || link.state !== "open") return fail("could not connect");
    const key = `${url} ${probe.id}`;
    const echoed = new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.waiters.delete(key);
        resolve(false);
      }, echoMs);
      this.waiters.set(key, (echo) => {
        clearTimeout(timer);
        this.waiters.delete(key);
        resolve(echo);
      });
    });
    link.publishLocal(probe);
    const ok = await echoed;
    if (this.isClosed) return { ok: false, reason: "cancelled" };
    if (!ok) {
      const ack = link.acks.get(probe.id);
      if (ack && !ack.ok) return fail(`refused: ${ack.message || "no reason given"}`);
      if (ack?.ok) return fail("accepted the event but did not deliver it");
      return fail(link.lastReason ? `no answer (${link.lastReason})` : "no answer");
    }
    link.clearLocal();
    link.reconnect = true;
    this.changed();
    return { ok: true };
  }
  until(condition, ms) {
    return new Promise((resolve) => {
      const started = Date.now();
      const check = () => {
        if (condition()) return resolve(true);
        if (this.closed || Date.now() - started >= ms) return resolve(false);
        setTimeout(check, 25);
      };
      check();
    });
  }
  /** Resolves once every message in the outbox was accepted by some relay, or after `ms`. */
  drain(ms) {
    return this.until(
      () => this.outbox.every((e) => this.all().some((l) => l.acks.get(e.event.id)?.ok === true)),
      ms
    );
  }
  /**
   * The session has ended. What was still waiting for an answer will not get one and is
   * dropped; the last messages (an ACK, an ABORT) go out their remaining times, and
   * then the pool closes.
   */
  async windDown() {
    if (this.closed || this.ending) return;
    this.ending = true;
    for (let i = this.outbox.length - 1; i >= 0; i--) if (this.outbox[i].until === void 0) this.outbox.splice(i, 1);
    const last = Math.max(Date.now(), ...this.outbox.map((e) => e.until));
    await this.until(() => Date.now() >= last, last - Date.now() + 1e3);
    await this.drain(2500);
    this.close();
  }
  close() {
    this.closed = true;
    if (this.resendTimer) clearInterval(this.resendTimer);
    globalThis.document?.removeEventListener("visibilitychange", this.onVisible);
    globalThis.removeEventListener?.("online", this.onVisible);
    for (const link of this.links.values()) link.close();
    this.links.clear();
    this.waiters.clear();
  }
};

// ../qr-secret-transfer/src/web/select.ts
var DEFAULT_TIMING = {
  echoMs: 3e3,
  connectMs: 5e3,
  graceMs: 1200,
  nip11Ms: 2500,
  queryMs: 4e3,
  retryMs: 4e3,
  resendMs: RESEND_MS,
  finalMs: FINAL_RESEND_MS
};
var TARGET_RELAYS = 3;
var STAGE_SIZE = 8;
var DISCOVERY_SOURCES = 8;
var DISCOVERY_TESTS = 6;
var DISCOVERY_MAX_AGE = 30 * 24 * 3600;
var KIND_RELAY_DISCOVERY = 30166;
async function relayInfo(url, ms, net = {}) {
  const doFetch = net.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  try {
    const response = await doFetch(url.replace(/^ws/, "http"), {
      headers: { Accept: "application/nostr+json" },
      signal: controller.signal,
      credentials: "omit",
      referrerPolicy: "no-referrer"
    });
    if (!response.ok) return void 0;
    const doc = await response.json();
    const limits = doc?.limitation;
    if (typeof limits !== "object" || limits === null) return {};
    const number = (v) => typeof v === "number" && v > 0 ? v : void 0;
    const info = {};
    const message = number(limits.max_message_length);
    const content = number(limits.max_content_length);
    if (message !== void 0) info.maxMessageLength = message;
    if (content !== void 0) info.maxContentLength = content;
    if (limits.payment_required === true) info.paymentRequired = true;
    return info;
  } catch {
    return void 0;
  } finally {
    clearTimeout(timer);
  }
}
function ruledOutBy(info, probe) {
  if (!info) return void 0;
  if (info.paymentRequired) return "requires payment";
  if (info.maxContentLength !== void 0 && probe.content.length > info.maxContentLength) {
    return `advertises a content limit of ${info.maxContentLength}, below what this profile needs`;
  }
  const bytes = new TextEncoder().encode(JSON.stringify(["EVENT", probe])).length;
  if (info.maxMessageLength !== void 0 && bytes > info.maxMessageLength) {
    return `advertises a message limit of ${info.maxMessageLength}, below what this profile needs`;
  }
  return void 0;
}
function queryRelay(url, filter, ms, net = {}) {
  return new Promise((resolve) => {
    const Impl = net.WebSocketImpl ?? WebSocket;
    const events = [];
    let ws;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try {
        ws?.close();
      } catch {
      }
      resolve(events);
    };
    const timer = setTimeout(finish, ms);
    try {
      ws = new Impl(url);
    } catch {
      return finish();
    }
    ws.onopen = () => ws.send(JSON.stringify(["REQ", "d", filter]));
    ws.onmessage = (m) => {
      try {
        const message = JSON.parse(String(m.data));
        if (message[0] === "EVENT" && message[1] === "d") events.push(message[2]);
        else if (message[0] === "EOSE" || message[0] === "CLOSED") finish();
      } catch {
      }
    };
    ws.onerror = finish;
    ws.onclose = finish;
  });
}
var tagValues = (e, name) => e.tags.filter((t) => t[0] === name).map((t) => t[1] ?? "");
function rankDiscovered(events, now, random = Math.random, allowLoopback = false) {
  const seen = /* @__PURE__ */ new Map();
  for (const e of events) {
    if (!isEventShape(e) || e.kind !== KIND_RELAY_DISCOVERY) continue;
    if (now - e.created_at > DISCOVERY_MAX_AGE) continue;
    const url = normalizeRelayUrl(firstTag(e, "d") ?? "");
    if (!url || !url.startsWith("wss://") && !allowLoopback) continue;
    const host = new URL(url).hostname;
    if (/\.(onion|i2p|loki)$/.test(host)) continue;
    if (isPrivateHost(host) && !allowLoopback) continue;
    const networks = tagValues(e, "n");
    if (networks.length > 0 && !networks.includes("clearnet")) continue;
    const requirements = tagValues(e, "R");
    if (requirements.includes("payment")) continue;
    const kinds = tagValues(e, "k");
    if (kinds.includes(`!${KINDS.WRAP}`)) continue;
    let score = 0;
    if (requirements.includes("!payment")) score += 1;
    if (requirements.includes("!auth")) score += 1;
    if (kinds.includes(String(KINDS.WRAP))) score += 1;
    const rtt = Number(firstTag(e, "rtt-open"));
    if (Number.isFinite(rtt) && rtt > 0) score += rtt < 300 ? 1 : rtt < 1e3 ? 0.5 : 0;
    const entry = seen.get(url) ?? { score: 0, monitors: /* @__PURE__ */ new Set() };
    entry.score = Math.max(entry.score, score);
    entry.monitors.add(e.pubkey);
    seen.set(url, entry);
  }
  return [...seen.entries()].map(([url, v]) => ({ url, score: v.score + (v.monitors.size > 1 ? 1 : 0), jitter: random() })).sort((a, b) => b.score - a.score || a.jitter - b.jitter).map((x) => x.url);
}
async function discover(from, now, ms, net = {}) {
  const sources = from.slice(0, DISCOVERY_SOURCES);
  const batches = await Promise.all(
    sources.map((url) => queryRelay(url, { kinds: [KIND_RELAY_DISCOVERY], limit: 300 }, ms, net))
  );
  return rankDiscovered(batches.flat(), now, Math.random, net.allowLoopbackDiscovery === true).filter(
    (url) => !from.includes(url)
  );
}
var originOf = (c, memos) => c.source === "remembered" ? memos.find((m) => m.url === c.url)?.origin ?? "seed" : c.source;
async function selectRelays(options) {
  const { pool, store } = options;
  const timing = { ...DEFAULT_TIMING, ...options.timing };
  const net = options.net ?? {};
  const progress = /* @__PURE__ */ new Map();
  const listed = [];
  let frozen = false;
  let cancelled = false;
  let firstPassAt;
  let wake = () => {
  };
  const failures = /* @__PURE__ */ new Map();
  let anyPassed = false;
  const noteFail = (url, origin, why) => {
    if (anyPassed) store.noteFail(url, origin, why);
    else failures.set(url, { origin, why });
  };
  const notePass = (url, origin) => {
    store.notePass(url, origin);
    failures.delete(url);
    if (anyPassed) return;
    anyPassed = true;
    for (const [failed, f] of failures) store.noteFail(failed, f.origin, f.why);
    failures.clear();
  };
  const report = () => options.onProgress([...progress.values()]);
  const test = async (c) => {
    progress.set(c.url, { url: c.url, source: c.source, state: "testing" });
    report();
    const origin = originOf(c, store.memos());
    let probe;
    try {
      probe = options.probe();
    } catch {
      cancelled = true;
      wake();
      return;
    }
    const [loop, info] = await Promise.all([
      pool.loopback(c.url, probe, timing.echoMs, timing.connectMs),
      relayInfo(c.url, timing.nip11Ms, net)
    ]);
    let result = loop;
    if (loop.reason === "cancelled") {
      cancelled = true;
      wake();
      return;
    }
    const ruledOut = loop.ok ? ruledOutBy(info, probe) : void 0;
    if (ruledOut) {
      pool.remove(c.url);
      result = { ok: false, reason: ruledOut };
    }
    if (!result.ok) {
      noteFail(c.url, origin, result.reason ?? "failed");
      progress.set(c.url, { url: c.url, source: c.source, state: "failed", why: result.reason ?? "failed" });
    } else {
      notePass(c.url, origin);
      if (!frozen && listed.length < Math.min(TARGET_RELAYS, MAX_RELAYS)) {
        listed.push(c.url);
        firstPassAt ??= Date.now();
        progress.set(c.url, { url: c.url, source: c.source, state: "listed" });
      } else {
        pool.remove(c.url);
        progress.set(c.url, { url: c.url, source: c.source, state: "spare" });
      }
    }
    report();
  };
  const stage = async (batch) => {
    const fresh = batch.filter((c) => progress.get(c.url)?.state !== "testing" && !listed.includes(c.url));
    if (fresh.length === 0) return;
    let pending = fresh.length;
    for (const c of fresh) {
      void test(c).finally(() => {
        pending--;
        wake();
      });
    }
    for (; ; ) {
      if (cancelled || pending === 0 || listed.length >= TARGET_RELAYS) return;
      if (firstPassAt !== void 0 && Date.now() - firstPassAt >= timing.graceMs) return;
      await new Promise((resolve) => {
        const wait = firstPassAt === void 0 ? 250 : Math.max(10, timing.graceMs - (Date.now() - firstPassAt));
        const timer = setTimeout(resolve, wait);
        wake = () => {
          clearTimeout(timer);
          resolve();
        };
      });
    }
  };
  const bySource = (...sources) => store.candidates().filter((c) => sources.includes(c.source));
  for (; ; ) {
    if (pool.isClosed) return [];
    const known = bySource("configured", "remembered", "learned", "discovered");
    for (let i = 0; i < known.length && listed.length === 0 && !cancelled && !pool.isClosed; i += STAGE_SIZE) {
      await stage(known.slice(i, i + STAGE_SIZE));
    }
    if (!cancelled && listed.length === 0) {
      const seeds = bySource("seed").slice(0, STAGE_SIZE);
      const askable = [.../* @__PURE__ */ new Set([...options.discoveryHints ?? [], ...store.candidates().map((c) => c.url)])];
      const discovering = discover(askable, options.now(), timing.queryMs, net).then((urls) => {
        if (urls.length > 0) store.noteDiscovered(urls.slice(0, DISCOVERY_TESTS * 2));
        return urls.slice(0, DISCOVERY_TESTS).map((url) => ({ url, source: "discovered" }));
      });
      await stage(seeds);
      if (!cancelled && listed.length === 0) await stage(await discovering);
    }
    if (cancelled) return [];
    if (listed.length > 0) break;
    await new Promise((resolve) => setTimeout(resolve, timing.retryMs));
    if (pool.isClosed) return [];
    for (const [url, p] of progress) if (p.state === "failed") progress.delete(url);
  }
  frozen = true;
  report();
  return [...listed];
}
async function loopbackOnce(url, profile, env, options = {}) {
  const timing = { ...DEFAULT_TIMING, ...options.timing };
  const session = new Session({
    role: "receiver",
    showing: true,
    profile,
    secretKey: generateSecretKey(env.random),
    env
  });
  const pool = new Pool({
    filter: session.filter(),
    signAuth: (relay, challenge2) => session.signAuth(relay, challenge2),
    onEvent: () => {
    },
    ...options.net?.WebSocketImpl ? { WebSocketImpl: options.net.WebSocketImpl } : {}
  });
  try {
    const probe = session.probe();
    pool.ignore(probe.id);
    const [loop, info] = await Promise.all([
      pool.loopback(url, probe, timing.echoMs, timing.connectMs),
      relayInfo(url, timing.nip11Ms, options.net)
    ]);
    const ruledOut = loop.ok ? ruledOutBy(info, probe) : void 0;
    return ruledOut ? { ok: false, reason: ruledOut } : loop;
  } finally {
    pool.close();
    session.cancel();
  }
}
async function replenish(store, profile, env, options = {}) {
  const timing = { ...DEFAULT_TIMING, ...options.timing };
  const known = store.candidates().map((c) => c.url);
  const found = await discover([.../* @__PURE__ */ new Set([...options.hints ?? [], ...known])], env.now(), timing.queryMs, options.net);
  const untried = found.filter((url) => !known.includes(url)).slice(0, options.limit ?? 3);
  let passed = 0;
  for (const url of untried) {
    const result = await loopbackOnce(url, profile, env, options);
    if (result.ok) {
      store.notePass(url, "discovered");
      passed++;
    }
  }
  store.noteDiscovered([]);
  return passed;
}

// ../qr-secret-transfer/src/web/store.ts
var KEY = "qrst.v1";
var MAX_MEMOS = 40;
var MAX_LOG = 50;
var FORGET_AFTER_FAILS = 6;
function empty() {
  return { relays: [], configured: [], seeds: null, blocked: {}, failedSessions: [], log: [], discoveredAt: 0 };
}
function memoryStorage() {
  const map = /* @__PURE__ */ new Map();
  return {
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => void map.set(k, v),
    removeItem: (k) => void map.delete(k)
  };
}
var Store = class {
  constructor(storage, now, shippedSeeds = [], adopterRelays = []) {
    this.now = now;
    this.shippedSeeds = shippedSeeds;
    this.adopterRelays = adopterRelays;
    this.storage = storage ?? memoryStorage();
    this.data = this.load();
  }
  now;
  shippedSeeds;
  adopterRelays;
  /** Goes up every time something stored changes, so a view can tell when to redraw. */
  version = 0;
  data;
  storage;
  load() {
    try {
      const raw = this.storage.getItem(KEY);
      if (!raw) return empty();
      const parsed = JSON.parse(raw);
      return { ...empty(), ...parsed };
    } catch {
      return empty();
    }
  }
  save() {
    this.version++;
    try {
      this.storage.setItem(KEY, JSON.stringify(this.data));
    } catch {
      try {
        for (const m of this.data.relays) delete m.why;
        this.storage.setItem(KEY, JSON.stringify(this.data));
      } catch {
      }
    }
  }
  // ---- the check ----------------------------------------------------------------------
  /** How this device checks the code, if the user has chosen. */
  check() {
    return isCodeCheck(this.data.check) ? this.data.check : void 0;
  }
  setCheck(check) {
    this.data.check = check;
    this.save();
  }
  // ---- relays -------------------------------------------------------------------------
  /** Relays the user added here, after the ones the adopting page supplies. */
  configured() {
    return [.../* @__PURE__ */ new Set([...this.adopterRelays, ...this.data.configured])];
  }
  userConfigured() {
    return [...this.data.configured];
  }
  addConfigured(input) {
    const url = normalizeRelayUrl(input);
    if (!url) return void 0;
    if (!this.data.configured.includes(url)) this.data.configured.push(url);
    this.save();
    return url;
  }
  removeConfigured(url) {
    this.data.configured = this.data.configured.filter((u) => u !== url);
    this.save();
  }
  seeds() {
    return [...this.data.seeds ?? this.shippedSeeds];
  }
  removeSeed(url) {
    if (!this.seeds().includes(url)) return;
    this.data.seeds = this.seeds().filter((u) => u !== url);
    this.save();
  }
  restoreSeeds() {
    this.data.seeds = null;
    this.save();
  }
  memos() {
    return this.data.relays.map((m) => ({ ...m }));
  }
  memo(url, origin) {
    let m = this.data.relays.find((r) => r.url === url);
    if (!m) {
      m = { url, origin, fails: 0 };
      this.data.relays.push(m);
    }
    return m;
  }
  notePass(url, origin) {
    const m = this.memo(url, origin);
    m.lastPass = this.now();
    m.fails = 0;
    delete m.why;
    this.trim();
    this.save();
  }
  noteFail(url, origin, why) {
    const m = this.memo(url, origin);
    m.lastFail = this.now();
    m.fails++;
    m.why = why.slice(0, 160);
    if (m.fails >= FORGET_AFTER_FAILS && m.origin !== "configured") {
      this.data.relays = this.data.relays.filter((r) => r !== m);
    }
    this.save();
  }
  /** §11.3a "Learned": relays named in a QR this device scanned, where that session completed. */
  noteLearned(urls) {
    for (const url of urls) this.memo(url, "learned");
    this.trim();
    this.save();
  }
  noteDiscovered(urls) {
    for (const url of urls) this.memo(url, "discovered");
    this.data.discoveredAt = this.now();
    this.trim();
    this.save();
  }
  discoveryAge() {
    return this.now() - this.data.discoveredAt;
  }
  forgetRelay(url) {
    this.data.relays = this.data.relays.filter((r) => r.url !== url);
    this.save();
  }
  trim() {
    if (this.data.relays.length <= MAX_MEMOS) return;
    const score = (m) => m.lastPass ?? 0;
    this.data.relays.sort((a, b) => score(b) - score(a));
    this.data.relays.length = MAX_MEMOS;
  }
  /**
   * Every relay this device could try, in the order §11.3a prefers: configured, then
   * those that passed here before (most recent first), then learned, discovered, seeds.
   */
  candidates() {
    const out = [];
    const add = (url, source) => {
      if (!out.some((c) => c.url === url)) out.push({ url, source });
    };
    for (const url of this.configured()) add(url, "configured");
    const passed = this.data.relays.filter((m) => m.lastPass !== void 0).sort((a, b) => b.lastPass - a.lastPass);
    for (const m of passed) add(m.url, "remembered");
    for (const origin of ["learned", "discovered"]) {
      for (const m of this.data.relays) if (m.lastPass === void 0 && m.origin === origin) add(m.url, origin);
    }
    for (const url of this.seeds()) add(url, "seed");
    return out;
  }
  // ---- §9.3 restart throttle ----------------------------------------------------------
  prune() {
    const cutoff = this.now() - THROTTLE_SECONDS;
    for (const [pub, at] of Object.entries(this.data.blocked)) if (at < cutoff) delete this.data.blocked[pub];
    this.data.failedSessions = this.data.failedSessions.filter((at) => at >= cutoff);
  }
  /** A session ended with a failed code entry against these burners. */
  noteFailedSession(pubs) {
    this.prune();
    for (const pub of pubs) this.data.blocked[pub] = this.now();
    this.data.failedSessions.push(this.now());
    this.save();
  }
  isBlocked(pub) {
    const at = this.data.blocked[pub];
    return at !== void 0 && at >= this.now() - THROTTLE_SECONDS;
  }
  /** True once repeated failures should be explained as possible interference (§9.3). */
  shouldWarnOfInterference() {
    this.prune();
    return this.data.failedSessions.length >= FAILED_SESSIONS_BEFORE_WARNING;
  }
  // ---- §14 transfer log ---------------------------------------------------------------
  /** §14. A record for the same peer burner and role replaces the earlier one: a session writes at release, then at its end. */
  addRecord(record) {
    this.data.log = this.data.log.filter((r) => !(r.peer === record.peer && r.role === record.role));
    this.data.log.unshift(record);
    this.data.log.length = Math.min(this.data.log.length, MAX_LOG);
    this.save();
  }
  records() {
    return this.data.log.map((r) => ({ ...r }));
  }
  /** Forgets everything this page has stored on this device. */
  clear() {
    this.version++;
    this.data = empty();
    try {
      this.storage.removeItem(KEY);
    } catch {
    }
  }
};

// ../qr-secret-transfer/src/web/transfer.ts
var ALL_BUT_ABORT = Object.values(KINDS).filter((k) => k !== KINDS.ABORT);
var REPLENISH_EVERY = 24 * 3600;
function browserEnv() {
  return {
    random: (n) => crypto.getRandomValues(new Uint8Array(n)),
    now: () => Math.floor(Date.now() / 1e3)
  };
}
var Transfer = class _Transfer {
  constructor(deps, session, params, viaCamera) {
    this.deps = deps;
    this.session = session;
    this.params = params;
    this.viaCamera = viaCamera;
    this.pool = new Pool({
      filter: session.filter(),
      signAuth: (url, challenge2) => session.signAuth(url, challenge2),
      onEvent: (event) => {
        const effects = session.receive(event);
        const content = event.content;
        if (typeof content === "string" && effects.some((e) => e.t !== "trace")) this.onCross(content, "in");
        this.apply(effects);
      },
      onChange: () => this.emit(),
      ...deps.net?.WebSocketImpl ? { WebSocketImpl: deps.net.WebSocketImpl } : {},
      ...deps.timing?.resendMs ? { resendMs: deps.timing.resendMs } : {},
      ...deps.timing?.finalMs ? { finalMs: deps.timing.finalMs } : {}
    });
    this.timer = setInterval(() => this.apply(this.session.tick()), 1e3);
  }
  deps;
  session;
  params;
  viaCamera;
  onChange = () => {
  };
  /**
   * A sealed message crossed a relay, out of this device or into it. `ciphertext` is
   * the wrap's content as a relay sees it. For display only.
   */
  onCross = () => {
  };
  pool;
  timer;
  log = [];
  startedMs = Date.now();
  progress = [];
  relays = [];
  uri;
  value;
  disposed = false;
  /**
   * Why this device must not act on a scanned code, checked before a burner is
   * generated: it does not implement the profile (§11.2), the code would give it the
   * role it already has (§11.2, role collision), or it recently failed a code against
   * that burner (§9.3).
   */
  static refusal(deps, params, committedRole) {
    if (params.profile !== deps.profile.id) return "unknown-profile";
    const role = scannerRole(params.mode);
    if (committedRole && committedRole !== role) return "role-collision";
    if (role === "sender" && deps.store.isBlocked(params.pub)) return "blocked-peer";
    return void 0;
  }
  /** This device shows the code. A Receiver shows `mode=offer` (Flow A), a Sender `mode=request` (Flow B). */
  static show(deps, role, payload) {
    const session = new Session({
      role,
      showing: true,
      profile: deps.profile,
      secretKey: generateSecretKey(deps.env.random),
      env: deps.env,
      isBlocked: (pub) => deps.store.isBlocked(pub),
      check: deps.check ?? "type",
      ...payload !== void 0 ? { payload } : {}
    });
    const transfer = new _Transfer(deps, session, void 0, true);
    transfer.findRelays().catch((error) => transfer.fail(error));
    return transfer;
  }
  /** This device scanned, opened or pasted a code. Its role is the complement of the code's mode. */
  static join(deps, params, how, payload) {
    const role = scannerRole(params.mode);
    const session = new Session({
      role,
      showing: false,
      profile: deps.profile,
      secretKey: generateSecretKey(deps.env.random),
      peerPub: params.pub,
      token: params.token,
      peerCheck: params.check,
      env: deps.env,
      isBlocked: (pub) => deps.store.isBlocked(pub),
      check: deps.check ?? "type",
      ...payload !== void 0 ? { payload } : {}
    });
    const transfer = new _Transfer(deps, session, params, how.viaCamera);
    transfer.relays = [...params.relays];
    for (const url of params.relays) transfer.pool.add(url, true);
    queueMicrotask(() => transfer.apply(session.start()));
    return transfer;
  }
  async findRelays() {
    const listed = await selectRelays({
      pool: this.pool,
      store: this.deps.store,
      probe: () => {
        const probe = this.session.probe();
        this.pool.ignore(probe.id);
        return probe;
      },
      now: this.deps.env.now,
      onProgress: (progress) => {
        this.progress = progress;
        this.emit();
      },
      ...this.deps.discoveryHints ? { discoveryHints: this.deps.discoveryHints } : {},
      ...this.deps.timing ? { timing: this.deps.timing } : {},
      ...this.deps.net ? { net: this.deps.net } : {}
    });
    if (this.disposed || listed.length === 0 || this.session.view().phase === "ended") return;
    this.relays = listed;
    this.uri = buildUri(this.deps.baseUrl, {
      v: VERSION,
      mode: showingMode(this.session.role),
      profile: this.deps.profile.id,
      pub: this.session.pub,
      check: this.session.view().check,
      token: this.session.token,
      relays: listed,
      origin: this.deps.origin
    });
    this.trace(`listening on ${listed.length} relay${listed.length === 1 ? "" : "s"} that passed the loopback test`);
    this.emit();
    if (this.deps.replenish !== false && this.deps.store.discoveryAge() > REPLENISH_EVERY) {
      setTimeout(() => {
        if (this.disposed) return;
        void replenish(this.deps.store, this.deps.profile, this.deps.env, {
          ...this.deps.discoveryHints ? { hints: this.deps.discoveryHints } : {},
          ...this.deps.timing ? { timing: this.deps.timing } : {},
          ...this.deps.net ? { net: this.deps.net } : {}
        }).catch(() => {
        });
      }, 3e3);
    }
  }
  view() {
    const session = this.session.view();
    const links = this.pool.all();
    const relays = [];
    const inUse = this.relays.length > 0 ? this.relays : this.progress.filter((p) => p.state === "listed").map((p) => p.url);
    for (const url of inUse) {
      const link = links.find((l) => l.url === url);
      const source = this.progress.find((p) => p.url === url)?.source;
      relays.push({
        url,
        state: link?.state ?? "closed",
        inUse: true,
        ...source ? { source } : {},
        ...link?.lastReason ? { why: link.lastReason } : {}
      });
    }
    for (const p of this.progress) {
      if (inUse.includes(p.url)) continue;
      const state = p.state === "listed" ? "spare" : p.state;
      relays.push({ url: p.url, state, inUse: false, source: p.source, ...p.why ? { why: p.why } : {} });
    }
    const view = {
      role: this.session.role,
      showing: this.session.showing,
      mode: this.params?.mode ?? showingMode(this.session.role),
      stage: session.phase === "ended" ? "ended" : this.session.showing && !this.uri ? "relays" : "session",
      session,
      relays,
      connected: inUse.some((url) => links.find((l) => l.url === url)?.state === "open"),
      viaCamera: this.viaCamera,
      log: [...this.log]
    };
    if (this.uri && session.phase !== "ended") view.uri = this.uri;
    if (this.params?.origin) view.peerOrigin = this.params.origin;
    if (this.value !== void 0) view.value = this.value;
    return view;
  }
  /** Sender: the five digits read from the other device. Throws on anything that is not five digits. */
  enterCode(digits) {
    this.apply(this.session.enterCode(digits));
  }
  /** Sender, check `compare`: the code on screen is the one on the other device. */
  confirmMatch() {
    this.apply(this.session.confirmMatch());
  }
  /** Sender, check `compare`: the codes differ. */
  rejectMatch() {
    this.apply(this.session.rejectMatch());
  }
  /** Sender, check `none`: send on consent alone. */
  release() {
    this.apply(this.session.release());
  }
  /** Sender: do not send. Receiver: discard what arrived. */
  decline() {
    this.apply(this.session.decline());
  }
  /** Receiver: keep what arrived. */
  accept() {
    this.apply(this.session.accept());
  }
  /** Receiver that showed the code: the other device rejected the code on screen; show the next. */
  advance() {
    this.apply(this.session.advance());
  }
  cancel() {
    this.apply(this.session.cancel());
  }
  /**
   * Re-sends what is outstanding and reconnects what is down, now. The pool does this
   * by itself when the page comes back into view; a host with its own notion of
   * "resumed" can call it too.
   */
  wake() {
    this.pool.wake();
  }
  /** Stops everything. Safe to call more than once. Does not wait for the network. */
  dispose() {
    if (this.disposed) return;
    this.cancel();
    this.disposed = true;
    clearInterval(this.timer);
    this.value = void 0;
  }
  /** Something outside the protocol went wrong. Say so and stop, instead of waiting for ever. */
  fail(error) {
    this.trace(`stopped: ${error instanceof Error ? error.message : String(error)}`);
    this.cancel();
  }
  trace(text) {
    const seconds = Math.floor((Date.now() - this.startedMs) / 1e3);
    const stamp = `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
    this.log.push(`${stamp}  ${text}`);
    if (this.log.length > 200) this.log.shift();
  }
  apply(effects) {
    if (effects.length === 0) return;
    for (const e of effects) {
      switch (e.t) {
        case "publish": {
          const { seal: seal2, to } = e;
          if (e.kind === KINDS.ABORT) this.pool.settle(to, ALL_BUT_ABORT);
          this.pool.publish({
            event: e.event,
            again: () => giftWrap(seal2, to, this.deps.env),
            to,
            kind: e.kind,
            unanswered: e.unanswered
          });
          this.trace(e.label);
          this.onCross(e.event.content, "out");
          break;
        }
        case "settled":
          this.pool.settle(e.peer, e.kinds);
          break;
        case "commit":
          this.value = e.value;
          break;
        case "record":
          this.deps.store.addRecord({ ...e.record, transport: "relay", relays: [...this.relays] });
          break;
        case "failed-peers":
          this.deps.store.noteFailedSession(e.pubs);
          break;
        case "trace":
          this.trace(e.text);
          break;
        case "ended":
          this.ended(e.outcome);
          break;
      }
    }
    this.emit();
  }
  ended(outcome) {
    clearInterval(this.timer);
    this.trace(`session ended: ${outcome}`);
    if (!this.session.showing && this.params && (outcome === "delivered" || outcome === "sent-unconfirmed" || outcome === "received")) {
      this.deps.store.noteLearned(this.params.relays.filter((url) => relayPolicy.loopback || !isPrivateHost(new URL(url).hostname)));
    }
    void this.pool.windDown();
  }
  emit() {
    if (!this.disposed) this.onChange();
  }
};
export {
  ACK_WAIT_SECONDS,
  CODE_CHECKS,
  DEFAULT_MAX_PAYLOAD,
  DEFAULT_TIMING,
  FAILED_SESSIONS_BEFORE_WARNING,
  FINAL_RESEND_MS,
  HANDOFF_SCHEME,
  KINDS,
  MAX_ATTEMPTS,
  MAX_HELD,
  MAX_PENDING,
  MAX_RELAYS,
  PROFILE_ID,
  Pool,
  RESEND_MS,
  RelayLink,
  SESSION_SECONDS,
  SLACK_SECONDS,
  Session,
  Store,
  TARGET_RELAYS,
  THROTTLE_SECONDS,
  TOKEN_BYTES,
  Transfer,
  UriError,
  VERSION,
  assertProfile,
  browserEnv,
  buildHandoffUri,
  buildRumor,
  buildUri,
  bytesToHex,
  commit,
  concatBytes,
  demoText,
  discover,
  equalAscii,
  equalBytes,
  eventId,
  firstTag,
  generateSecretKey,
  giftWrap,
  hexToBytes,
  isCodeCheck,
  isEventShape,
  isHandoff,
  isHex32,
  isPrivateHost,
  isToken,
  isValidPublicKey,
  looksLikePairing,
  loopbackOnce,
  nip44_exports as nip44,
  normalizeOrigin,
  normalizeRelayUrl,
  npubDecode,
  npubEncode,
  parseUri,
  publicKey,
  queryRelay,
  rankDiscovered,
  relayInfo,
  relayPolicy,
  replenish,
  ruledOutBy,
  rumor,
  sas,
  sasCode,
  sasDigits,
  scannerRole,
  seal,
  selectRelays,
  serialize,
  showingMode,
  sign,
  stricter,
  unwrap,
  utf8Decode,
  utf8Encode,
  verify,
  wipe,
  wrap
};
/*! Bundled license information:

@noble/curves/utils.js:
@noble/curves/abstract/modular.js:
@noble/curves/abstract/curve.js:
@noble/curves/abstract/der.js:
@noble/curves/abstract/weierstrass.js:
@noble/curves/secp256k1.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@scure/base/index.js:
  (*! scure-base - MIT License (c) 2022 Paul Miller (paulmillr.com) *)

@noble/ciphers/utils.js:
  (*! noble-ciphers - MIT License (c) 2023 Paul Miller (paulmillr.com) *)
*/
