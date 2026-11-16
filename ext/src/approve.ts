// Asks once whether a site may use the account.
const origin = new URLSearchParams(location.search).get('origin') ?? '';
document.getElementById('what')!.textContent = `Let ${origin} sign in with your account?`;
let decided = false;
const decide = async (allow: boolean) => { decided = true; await chrome.runtime.sendMessage({ kind: 'ui', cmd: 'decide', origin, allow }); window.close(); };
document.getElementById('allow')!.onclick = () => decide(true);
document.getElementById('deny')!.onclick = () => decide(false);
window.addEventListener('pagehide', () => { if (!decided) chrome.runtime.sendMessage({ kind: 'ui', cmd: 'decide', origin, allow: false }); });
