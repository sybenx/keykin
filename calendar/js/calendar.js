// The shared calendar module: the event format's rules and the merge by field (KIST calendar profile §2,
// ~/kist proposals/calendar-profile.md). Plain ES module, no imports but sha256.js, works in Node and browsers.
// It knows nothing about where versions are kept or sent: an app passes versions in and gets versions out.
//
// A version is {meta, data, deleted}: `meta` an object with `kind` and the fields, `data` the notes or null,
// `deleted` true for a deletion (then `meta` is {kind} only). Every field of `meta` except `kind` and `edited`,
// and `data`, carries a stamp in `meta.edited`: {"t": <ms>, "d": "<8 hex>"}. A field with no stamp has stamp 0.
// The Kotlin copy (../kotlin/Calendar.kt) gives the same bytes for the same input; ../vectors/ holds the cases.
import { sha256 } from "./sha256.js";

/** The member of a version whose stamp is `edited.data`. */
export const DATA = "data";
/** Fields that are never stamped or merged as values. */
const UNSTAMPED = new Set(["kind", "edited"]);

// ── canonical JSON (RFC 8785, integers only) ──

/** RFC 8785 canonical JSON for integer-only JSON: keys sorted by UTF-16 code units, integers within ±2^53. */
export function canon(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") { if (!Number.isSafeInteger(v)) throw new Error("not an integer"); return String(v); }
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (typeof v === "object") return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
  throw new Error("not JSON");
}
/** Parses JSON, refusing floats and integers past ±2^53. */
export function parse(text) {
  const v = JSON.parse(text);
  canon(v);
  return v;
}

// ── stamps ──

const isObj = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const DEVICE = /^[0-9a-f]{8}$/;
/** A stamp as written, or null when missing or malformed (a malformed stamp counts as no stamp). */
function readStamp(s) {
  if (!isObj(s) || !Number.isSafeInteger(s.t) || s.t < 0 || typeof s.d !== "string" || !DEVICE.test(s.d)) return null;
  return { t: s.t, d: s.d };
}
/** Orders stamps: `t`, then `d`; no stamp is below every stamp. */
export function compareStamps(a, b) {
  a = readStamp(a); b = readStamp(b);
  if (!a || !b) return (a ? 1 : 0) - (b ? 1 : 0);
  if (a.t !== b.t) return a.t < b.t ? -1 : 1;
  return a.d < b.d ? -1 : a.d > b.d ? 1 : 0;
}
const stampOf = (v, f) => readStamp(isObj(v.meta.edited) ? v.meta.edited[f] : undefined);
const has = (v, f) => (f === DATA ? Object.hasOwn(v, DATA) : Object.hasOwn(v.meta, f));
const valueOf = (v, f) => (f === DATA ? v.data : v.meta[f]);
/** Every stamped field a version has a value or a stamp for. */
function fieldsOf(v) {
  const out = new Set();
  for (const k of Object.keys(v.meta)) if (!UNSTAMPED.has(k)) out.add(k);
  if (Object.hasOwn(v, DATA)) out.add(DATA);
  if (isObj(v.meta.edited)) for (const k of Object.keys(v.meta.edited)) if (!UNSTAMPED.has(k)) out.add(k);
  return out;
}
function checkVersion(v) {
  if (!isObj(v) || !isObj(v.meta) || typeof v.meta.kind !== "string") throw new Error("a version needs meta.kind");
  canon(v.meta); if (Object.hasOwn(v, DATA)) canon(v.data);
}

/**
 * A new version stamped against the one it replaces (§2.4). `prev` is the version the edit was made on (null for a
 * new entry; a deletion counts as none), `next` is {meta, data} as the person left it (its `edited` is ignored).
 * Only fields whose value changed get a new stamp, `t` = max(clock, that field's t in `prev` + 1); a new entry
 * stamps every field it has. Other fields keep `prev`'s stamps.
 */
export function stamp(prev, next, { clock, device }) {
  if (!Number.isSafeInteger(clock) || clock < 0) throw new Error("clock must be whole milliseconds");
  if (typeof device !== "string" || !DEVICE.test(device)) throw new Error("device must be 8 lowercase hex");
  checkVersion(next);
  if (prev && prev.deleted === true) prev = null;
  if (prev) checkVersion(prev);
  // `data` is always there in a whole version: missing is null
  next = { meta: next.meta, data: next.data ?? null };
  if (prev) prev = { meta: prev.meta, data: prev.data ?? null };
  const edited = {};
  const fields = new Set(fieldsOf(next));
  if (prev) for (const f of fieldsOf(prev)) fields.add(f);
  for (const f of fields) {
    const before = prev ? stampOf(prev, f) : null;
    if (prev) {
      // unchanged, including a field neither has (one someone removed earlier): keeps its stamp
      const same = has(prev, f) === has(next, f) && (!has(next, f) || canon(valueOf(prev, f)) === canon(valueOf(next, f)));
      if (same) { if (before) edited[f] = before; continue; }
    } else if (!has(next, f)) continue;
    edited[f] = { t: Math.max(clock, before ? before.t + 1 : 0), d: device };
  }
  const meta = {};
  for (const [k, v] of Object.entries(next.meta)) if (k !== "edited") meta[k] = v;
  meta.edited = edited;
  return { meta, data: next.data, deleted: false };
}

/**
 * The merge of an entry's current versions (§2.4): each field takes the value with the highest stamp (`t`, then
 * `d`); at equal stamps a value beats no value, then the higher canonical JSON wins. `edited` is the per-field
 * maximum. An edit beats a delete: deletions count only when every version is one. The result is the same for the
 * same versions in any order, so every device writes the same bytes (canon of the result).
 */
export function merge(versions) {
  if (!Array.isArray(versions) || !versions.length) throw new Error("nothing to merge");
  for (const v of versions) checkVersion(v);
  const live = versions.filter((v) => v.deleted !== true);
  if (!live.length) {
    const kinds = new Set(versions.map((v) => v.meta.kind));
    if (kinds.size !== 1) throw new Error("versions of different kinds");
    return { meta: { kind: versions[0].meta.kind }, data: null, deleted: true };
  }
  const kinds = new Set(live.map((v) => v.meta.kind));
  if (kinds.size !== 1) throw new Error("versions of different kinds");
  const fields = new Set();
  for (const v of live) for (const f of fieldsOf(v)) fields.add(f);
  const meta = { kind: live[0].meta.kind }, edited = {};
  let data = null;
  for (const f of [...fields].sort()) {
    let best = null;
    for (const v of live) {
      const c = { stamp: stampOf(v, f), present: has(v, f), value: valueOf(v, f) };
      c.text = c.present ? canon(c.value) : "";
      if (!best || better(c, best)) best = c;
    }
    if (best.stamp) edited[f] = best.stamp;
    if (!best.present) continue;
    if (f === DATA) data = best.value; else meta[f] = best.value;
  }
  meta.edited = edited;
  return { meta, data, deleted: false };
}
function better(a, b) {
  const s = compareStamps(a.stamp, b.stamp);
  if (s) return s > 0;
  if (a.present !== b.present) return a.present;
  return a.text > b.text;
}

/**
 * What a changed instance shows (§2.2): the series' fields, then every field the instance gives that is not null,
 * with `rrule` null and `exdates`/`rdates` empty. `edited` is left out: this is for showing, not for merging.
 */
export function instanceView(series, instance) {
  const out = {};
  for (const [k, v] of Object.entries(series)) if (k !== "edited") out[k] = v;
  for (const [k, v] of Object.entries(instance)) if (k !== "edited" && v !== null) out[k] = v;
  out.kind = "instance"; out.rrule = null; out.exdates = []; out.rdates = [];
  return out;
}

// ── entry ids ──

const te = new TextEncoder();
function unhex(h, bytes, what) {
  if (typeof h !== "string" || h.length !== bytes * 2 || /[^0-9a-f]/.test(h)) throw new Error(`${what} must be ${bytes} bytes of lowercase hex`);
  return Uint8Array.from({ length: bytes }, (_, i) => parseInt(h.slice(i * 2, i * 2 + 2), 16));
}
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
/** TH(tag, m) = SHA-256(utf8(tag) ‖ 0x00 ‖ m), as KIST §2. */
export function taggedHash(tag, ...parts) {
  const bs = [te.encode(tag), Uint8Array.of(0), ...parts];
  const all = new Uint8Array(bs.reduce((n, b) => n + b.length, 0));
  let o = 0;
  for (const b of bs) { all.set(b, o); o += b.length; }
  return sha256(all);
}
const id32 = (tag, ...parts) => hex(taggedHash(tag, ...parts)).slice(0, 32);

/** A changed instance's entry id: TH("nostr-vault/instance/1", series entry ‖ utf8(canon(original))). */
export const instanceId = (seriesEntry, original) => id32("nostr-vault/instance/1", unhex(seriesEntry, 16, "series entry"), te.encode(canon(original)));
/** An imported event's entry id: TH("nostr-vault/cal-import/1", vault id ‖ utf8(uid)). */
export const importId = (vaultId, uid) => id32("nostr-vault/cal-import/1", unhex(vaultId, 32, "vault id"), te.encode(uid));
/** A calendar vault's settings entry id: TH("nostr-vault/cal-settings/1", vault id). */
export const settingsId = (vaultId) => id32("nostr-vault/cal-settings/1", unhex(vaultId, 32, "vault id"));
