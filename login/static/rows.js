// The detail line of a row in Sites and apps (SPEC 11.5). A plain script for the page, and importable by tests.
'use strict';
(() => {
  const KINDS = { 0: 'profile', 1: 'note', 3: 'follow list', 4: 'DM', 5: 'delete', 6: 'repost', 7: 'reaction', 14: 'DM', 16: 'repost', 1059: 'DM', 1111: 'comment', 9734: 'zap request',
    10002: 'relay list', 10003: 'bookmark list', 20: 'picture', 21: 'video', 22: 'video', 22242: 'relay login', 24133: 'remote signer message', 27235: 'web login', 30023: 'article' };
  const kindWord = (k) => (Number.isInteger(k) ? KINDS[k] ?? `kind ${k} event` : null);
  const VIA = { login: 'through your login page', scan: 'by a scanned code', paste: 'by a pasted code', bunker: 'through a bunker link' };
  const when = (t) => new Date(t * 1000).toLocaleString('en-GB', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false }).replace(',', '');
  const ago = (t, now) => {
    const s = Math.max(0, now - t);
    if (s < 90) return 'a minute ago';
    if (s < 3600) return `${Math.round(s / 60)} min ago`;
    if (s < 86400) return `${Math.round(s / 3600)} h ago`;
    if (s < 2 * 86400) return 'yesterday';
    return `${Math.round(s / 86400)} days ago`;
  };
  /** g is a grant from `me`; now is unix seconds. Missing parts are left out. */
  function siteDetail(g, now = Date.now() / 1000) {
    const who = g.device || g.browser || null;
    const kind = kindWord(g.lastKind);
    const parts = g.kind === 'app'
      ? [`App on ${g.deviceName}`, `added ${when(g.since)}`]
      : [who, ['signed in', when(g.since), VIA[g.via]].filter(Boolean).join(' '), g.deviceName ? `approved by ${g.deviceName}` : null];
    parts.push(g.last ? `last used ${ago(g.last, now)}${kind ? `, last posted ${/^[aeiou]/.test(kind) ? 'an' : 'a'} ${kind}` : ''}` : 'not used yet');
    if (typeof g.client === 'string' && /^[0-9a-f]{4}/.test(g.client)) parts.push(`key ${g.client.slice(0, 4)}…`);
    parts.push(scopeWaiting(g));
    return parts.filter(Boolean).join(' · ');
  }
  // A site's two switches (SPEC 11.5), `lists` and `dms`: what the device reported, or what the page asked
  // for while the device has not picked it up yet.
  const SCOPES = ['lists', 'dms'];
  /** The value a switch shows: the page's want if there is one, else the device's own. */
  const scopeShown = (g, k) => (typeof g.want?.[k] === 'boolean' ? g.want[k] : g[k] === true);
  /** "waiting for Pixel 9a" while a want differs from what the device reported, else null. */
  const scopeWaiting = (g) => (SCOPES.some((k) => typeof g.want?.[k] === 'boolean' && typeof g[k] === 'boolean' && g.want[k] !== g[k]) ? `waiting for ${g.deviceName}` : null);
  /**
   * One row of Recent signing (SPEC 11.6): r is a row of `me.signed`, boxKey `me.boxKey`, grants `me.grants`.
   * Returns who signed ("Pixel 9a + your box") and the detail line.
   */
  function signedRow(r, boxKey, grants = [], now = Date.now() / 1000) {
    const asker = r.askerName ?? 'A removed device';
    const helper = r.helper === boxKey ? 'your box' : r.helperName ?? 'a removed device';
    const kind = kindWord(r.kind);
    const what = r.op === 'ecdh' ? 'made a message key' : kind ? `signed ${/^[aeiou]/.test(kind) ? 'an' : 'a'} ${kind}` : 'signed an event';
    const g = r.grant ? grants.find((x) => x.id === r.grant) : null;
    const site = g ? ` for ${g.name.replace(/^https?:\/\//, '')}` : r.grant ? ' for a site that was signed out' : '';
    const id = typeof r.eventId === 'string' && /^[0-9a-f]{8}/.test(r.eventId) ? `event ${r.eventId.slice(0, 8)}…` : null;
    return { who: `${asker} + ${helper}`, detail: [`${cap(what)}${site}`, ago(r.signedAt, now), id].filter(Boolean).join(' · ') };
  }
  const cap = (x) => x.charAt(0).toUpperCase() + x.slice(1);
  globalThis.KeykinRows = { siteDetail, kindWord, when, scopeShown, scopeWaiting, signedRow };
})();
