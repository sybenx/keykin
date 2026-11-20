// A short message at the bottom of the page, and "Approve it on your phone…" while something waits on you. Moved from
// Marble Web's act.js. The page styles #toast (signin.css has Marble Web's rules).
import { current } from "./me.js";

const $ = (s, el = document) => el.querySelector(s);

let toastTimer = null;
export function toast(text, { stay = false } = {}) {
  let el = $("#toast");
  if (!el) { el = document.createElement("div"); el.id = "toast"; el.setAttribute("role", "status"); document.body.append(el); }
  el.textContent = text;
  el.hidden = !text;
  clearTimeout(toastTimer);
  if (text && !stay) toastTimer = setTimeout(() => (el.hidden = true), 3500);
}

/** While something waits on you approving it elsewhere, say where, after a moment. */
export async function approving(promise) {
  let asked = false;
  const t = setTimeout(() => { asked = true; toast("Approve it on your phone…", { stay: true }); }, 700);
  // (only its own message goes: one said meanwhile, like "Signed out", stays)
  try { return await promise; } finally { clearTimeout(t); if (asked && current()) toast(""); }
}
