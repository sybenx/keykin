// The bridge between the page and the extension. It adds nothing of its own.
window.addEventListener('message', async (e) => {
  if (e.source !== window || e.data?.keykin !== 'ask') return;
  const { id, method, params } = e.data;
  let answer: any;
  try { answer = await chrome.runtime.sendMessage({ kind: 'nostr', method, params }); }
  catch (err) { answer = { error: 'Keykin is not available. Reload the page.' }; }
  window.postMessage({ keykin: 'answer', id, result: answer?.result, error: answer?.error }, window.location.origin);
});
