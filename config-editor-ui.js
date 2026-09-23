/**
 * BBSFirewall - Config editor HTML views
 *
 * Two server-rendered pages: a login screen and the editor application shell.
 * All CSS and client JavaScript is inlined so there is no build step and no
 * static asset routes to secure. The app shell pulls its data from
 * /api/config after load and posts changes back to /api/save; the Performance
 * tab polls /api/stats; the Tools tab pulls /api/health and /api/update/check
 * (both fetched separately, without blocking the rest of the page — see
 * loadHealth()/loadUpdateInfo()) and drives /api/geoip, /api/sshkey,
 * /api/cert, and /api/update/apply|rollback.
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

function htmlEscape(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Server-rendered counterpart to the client-side ICONS map (see the inline
// <script>) for the Tools tab's three static cards, which aren't built from
// ENV_SCHEMA so there's no `sec.icon` to key off. Same path data, duplicated
// on purpose — one lives in Node's module scope, the other only exists once
// emitted into the browser script, so they can't share a single definition.
function toolsIcon(name) {
  const paths = {
    globe: '<circle cx="10" cy="10" r="7"/><path d="M3 10h14M10 3c2.5 2 2.5 12 0 14M10 3c-2.5 2-2.5 12 0 14"/>',
    key: '<circle cx="6" cy="14" r="3"/><path d="M8.2 11.8L16 4M13 7l2 2M15.5 4.5l2 2"/>',
    lock: '<rect x="4.5" y="9" width="11" height="8" rx="1.5"/><path d="M6.5 9V6.5a3.5 3.5 0 017 0V9"/>',
    refresh: '<path d="M4 10a6 6 0 0110-4.2M16 10a6 6 0 01-10 4.2"/><path d="M14 3v3h-3M6 17v-3h3"/>',
  };
  return '<svg class="icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (paths[name] || '') + '</svg>';
}

const BASE_CSS = `
  * { box-sizing: border-box; }
  body { margin: 0; background: #0f1720; color: #d7e0ea;
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  a { color: #6fb3ff; }
  h1, h2, h3 { color: #f2f6fb; font-weight: 600; }
  .wrap { max-width: 960px; margin: 0 auto; padding: 24px 20px 96px; }
  .card { background: #16212e; border: 1px solid #26374a; border-radius: 10px; padding: 20px; margin-bottom: 16px; }
  .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 18px; }
  .brand .logo { height: 30px; width: auto; display: block; }
  .brand .tag { font-size: 12px; color: #7f93a8; }
  .brand-home { display: inline-flex; align-items: center; gap: 10px; cursor: pointer; border-radius: 6px; }
  .brand-home:hover .logo { opacity: 0.85; }
  .brand-home:focus-visible { outline: 2px solid #3b82f6; outline-offset: 3px; }
  .footer-credit { text-align: center; color: #7f93a8; font-size: 12px; line-height: 1.7; margin: 32px 0 0; }
  .footer-credit .heart { color: #e0546b; }
  .user-menu { position: relative; }
  .user-menu-trigger { background: none; border: 1px solid transparent; color: #eef3f9; font: inherit;
    font-weight: 600; cursor: pointer; display: inline-flex; align-items: center; gap: 5px;
    padding: 6px 10px; border-radius: 7px; }
  .user-menu-trigger:hover, .user-menu-trigger[aria-expanded="true"] { background: #1c2b3c; border-color: #26374a; }
  .user-menu-trigger .caret { font-size: 11px; color: #7f93a8; }
  .user-menu-panel { position: absolute; right: 0; top: calc(100% + 6px); min-width: 190px;
    background: #16212e; border: 1px solid #26374a; border-radius: 9px; padding: 6px;
    box-shadow: 0 12px 28px rgba(0,0,0,.45); z-index: 40; }
  .user-menu-panel button { display: block; width: 100%; text-align: left; background: none;
    border: none; color: #d7e0ea; font-weight: 400; padding: 9px 10px; border-radius: 6px;
    cursor: pointer; }
  .user-menu-panel button:hover { background: #22344a; }
  .icon { width: 16px; height: 16px; vertical-align: -3px; margin-right: 7px; color: #6fb3ff; flex: none; }
  .qr-wrap { display: flex; justify-content: center; padding: 10px; background: #fff; border-radius: 8px;
    max-width: 220px; margin: 10px auto; }
  .backup-codes { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px;
    background: #0f1a25; border: 1px solid #263a4e; border-radius: 7px; padding: 12px 14px;
    display: grid; grid-template-columns: 1fr 1fr; gap: 6px 16px; }
  label { display: block; font-weight: 600; margin-bottom: 4px; color: #eef3f9; }
  input[type=text], input[type=password], input[type=number], textarea, select {
    width: 100%; padding: 8px 10px; background: #0f1a25; color: #e6edf5;
    border: 1px solid #2c3f54; border-radius: 6px; font: inherit; }
  input:disabled, textarea:disabled, select:disabled { opacity: 0.45; }
  textarea { min-height: 220px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; resize: vertical; }
  button { font: inherit; font-weight: 600; padding: 9px 16px; border-radius: 7px;
    border: 1px solid #2c3f54; background: #22344a; color: #eaf1f8; cursor: pointer; }
  button.primary { background: #2f6df0; border-color: #2f6df0; color: #fff; }
  button.danger  { background: #7a2233; border-color: #92304a; color: #ffe9ee; }
  button.small { padding: 5px 10px; font-size: 12px; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .muted { color: #7f93a8; }
  .field { margin-bottom: 14px; }
  .field .help { font-weight: 400; color: #93a7bc; font-size: 12px; margin-top: 3px; }
  .field.optional-off input, .field.optional-off select { opacity: 0.45; }
  .toggle-row { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
  .toggle-row input[type=checkbox] { width: auto; }
  details.more { margin-top: 4px; }
  details.more > summary { cursor: pointer; color: #6fb3ff; font-size: 12px; list-style: none; }
  details.more > summary::-webkit-details-marker { display: none; }
  details.more > summary::before { content: "\\25b8 "; }
  details.more[open] > summary::before { content: "\\25be "; }
  details.more .body { white-space: pre-wrap; font-size: 12.5px; color: #b9c9da;
    background: #0f1a25; border: 1px solid #263a4e; border-radius: 6px; padding: 10px 12px; margin-top: 6px; }
  .sec-help { color: #93a7bc; font-size: 12.5px; margin: 0 0 12px; }
  details.sec { border: 1px solid #26374a; border-radius: 9px; margin: 0 0 12px; padding: 0 18px; }
  details.sec > summary { cursor: pointer; list-style: none; padding: 13px 0; font-weight: 700;
    color: #f2f6fb; font-size: 15px; }
  details.sec > summary::-webkit-details-marker { display: none; }
  details.sec > summary::before { content: "\\25b8 "; color: #6fb3ff; font-size: 12px; }
  details.sec[open] > summary::before { content: "\\25be "; }
  details.sec > summary .sec-count { font-weight: 400; color: #7f93a8; font-size: 12px; margin-left: 8px; }
  details.sec .sec-body { padding: 2px 0 16px; }
  details.sec-sub { border: 1px solid #203044; border-radius: 8px; margin: 8px 0 0; padding: 0 14px; background: #101b26; }
  details.sec-sub > summary { cursor: pointer; list-style: none; padding: 10px 0; font-weight: 600;
    color: #cfe0f2; font-size: 13px; display: flex; align-items: center; }
  details.sec-sub > summary::-webkit-details-marker { display: none; }
  details.sec-sub > summary::before { content: "\\25b8 "; color: #6fb3ff; font-size: 11px; }
  details.sec-sub[open] > summary::before { content: "\\25be "; }
  details.sec-sub > summary .sec-count { font-weight: 400; color: #7f93a8; font-size: 12px; margin-left: 8px; }
  details.sec-sub .sec-body { padding: 0 0 12px; }
  .log-older-label { font-size: 11px; text-transform: uppercase; letter-spacing: .05em;
    color: #7f93a8; margin: 16px 0 8px; padding-top: 12px; border-top: 1px dashed #26374a; }
  .tabs { display: flex; gap: 6px; margin-bottom: 16px; flex-wrap: wrap; }
  .tabs button { background: #16212e; }
  .tabs button.active { background: #2f6df0; border-color: #2f6df0; color: #fff; }
  .bar { position: fixed; left: 0; right: 0; bottom: 0; background: #0d1620ee;
    border-top: 1px solid #26374a; padding: 12px 20px; backdrop-filter: blur(4px); }
  .bar .inner { max-width: 960px; margin: 0 auto; display: flex; gap: 10px; align-items: center; }
  .bar .spacer, .spacer { flex: 1; }
  .notice { padding: 10px 12px; border-radius: 7px; margin-bottom: 14px; font-size: 13px; white-space: pre-wrap; }
  .notice.err { background: #3a1620; border: 1px solid #7a2233; color: #ffd7de; }
  .notice.ok  { background: #14301f; border: 1px solid #2e6b45; color: #d6f5e2; }
  .notice.warn { background: #322612; border: 1px solid #7a5a1f; color: #ffe9c2; }
  .row { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
  .pw-wrap { position: relative; }
  .pw-wrap button { position: absolute; right: 4px; top: 4px; padding: 4px 8px; font-size: 12px; }
  .hidden { display: none !important; }
  .statline { font-size: 12px; color: #7f93a8; margin-top: 10px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 12px; }
  .stat { background: #0f1a25; border: 1px solid #26374a; border-radius: 9px; padding: 14px; }
  .stat .k { font-size: 12px; color: #7f93a8; text-transform: uppercase; letter-spacing: .04em; }
  .stat .v { font-size: 22px; font-weight: 700; color: #f2f6fb; margin-top: 4px; }
  .stat .sub { font-size: 12px; color: #93a7bc; margin-top: 2px; }
  .meter { height: 6px; background: #21303f; border-radius: 4px; margin-top: 8px; overflow: hidden; }
  .meter > i { display: block; height: 100%; background: #2f6df0; }
  .meter.warn > i { background: #d99a2b; }
  .meter.crit > i { background: #d9534f; }
  .console { background: #0a1017; border: 1px solid #26374a; border-radius: 7px; padding: 10px 12px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px;
    color: #cdd9e5; white-space: pre-wrap; max-height: 320px; overflow: auto; margin-top: 10px; }
  .kv { font-size: 13px; }
  .kv div { display: flex; gap: 8px; padding: 2px 0; }
  .kv div b { color: #93a7bc; font-weight: 600; min-width: 130px; }
  .pill { display: inline-block; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 999px; }
  .pill.good { background: #14301f; color: #7fe0a4; border: 1px solid #2e6b45; }
  .pill.bad  { background: #3a1620; color: #ffb3c0; border: 1px solid #7a2233; }
  .pill.warn { background: #322612; color: #ffdf9e; border: 1px solid #7a5a1f; }
  .modal-bg { position: fixed; inset: 0; background: #05080ccc; display: flex; align-items: center;
    justify-content: center; z-index: 50; }
  .modal { background: #16212e; border: 1px solid #2c3f54; border-radius: 12px; padding: 22px;
    max-width: 440px; width: calc(100% - 40px); }
  .logtable-wrap { overflow-x: auto; }
  .logtable { width: 100%; border-collapse: collapse; font-size: 13px; }
  .logtable th, .logtable td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #26374a; white-space: nowrap; }
  .logtable th { color: #93a7bc; font-weight: 600; font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
`;

function loginPage(opts = {}) {
  const err = opts.error ? `<div class="notice err">${htmlEscape(opts.error)}</div>` : '';
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BBSFirewall - Config Editor</title>
<link rel="icon" href="/favicon.ico">
<style>${BASE_CSS}</style>
</head>
<body>
<div class="wrap" style="max-width:420px;margin-top:9vh">
  <div class="brand"><img class="logo" src="/assets/logo.svg" alt="BBSFirewall"><span class="tag">config editor</span></div>
  <div class="card">
    ${err}
    <form method="POST" action="login" autocomplete="off">
      <div class="field">
        <label for="u">Username</label>
        <input id="u" name="username" type="text" autocomplete="username" autofocus required>
      </div>
      <div class="field">
        <label for="p">Password</label>
        <input id="p" name="password" type="password" autocomplete="current-password" required>
      </div>
      <button class="primary" type="submit" style="width:100%">Sign in</button>
    </form>
  </div>
  <p class="statline">This session is restricted to trusted hosts.</p>
  <p class="footer-credit">Created with love <span class="heart">&#10084;&#65039;</span> by Mark Laudenbach in Iowa, USA.<br>
    <a href="https://github.com/SysopNetwork/BBSFirewall" target="_blank" rel="noopener noreferrer">github.com/SysopNetwork/BBSFirewall</a></p>
</div>
</body>
</html>`;
}

// Shown after a correct password when the account has MFA enabled but this
// session hasn't verified it yet — the router only lets a session in this
// state reach POST /api/security/mfa/verify-login and POST /logout, so this
// page (and its own small inline script) is the only thing such a session
// can otherwise be served.
function mfaPage(opts = {}) {
  const csrf = htmlEscape(opts.csrf || '');
  const nonce = htmlEscape(opts.nonce || '');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BBSFirewall - Config Editor</title>
<link rel="icon" href="/favicon.ico">
<style>${BASE_CSS}</style>
</head>
<body>
<div class="wrap" style="max-width:420px;margin-top:9vh">
  <div class="brand"><img class="logo" src="/assets/logo.svg" alt="BBSFirewall"><span class="tag">config editor</span></div>
  <div class="card">
    <div id="notice"></div>
    <p class="muted" style="margin-top:0">Enter the 6-digit code from your authenticator app, or one of your backup codes.</p>
    <div class="field">
      <label for="mfa-code">Code</label>
      <input id="mfa-code" type="text" inputmode="numeric" autocomplete="one-time-code" autofocus>
    </div>
    <button class="primary" id="mfa-submit" type="button" style="width:100%">Verify</button>
  </div>
  <p class="statline">This session is restricted to trusted hosts.</p>
  <p class="footer-credit">Created with love <span class="heart">&#10084;&#65039;</span> by Mark Laudenbach in Iowa, USA.<br>
    <a href="https://github.com/SysopNetwork/BBSFirewall" target="_blank" rel="noopener noreferrer">github.com/SysopNetwork/BBSFirewall</a></p>
</div>
<script nonce="${nonce}">
const CSRF = "${csrf}";
const codeInput = document.getElementById("mfa-code");
const noticeEl = document.getElementById("notice");
function esc(s) { return String(s).replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function showError(msg) { noticeEl.innerHTML = '<div class="notice err">' + esc(msg) + '</div>'; }
let busy = false;
async function submit() {
  if (busy) return;
  const raw = codeInput.value.trim();
  if (!raw) return;
  busy = true;
  const body = raw.includes("-") ? { backupCode: raw } : { code: raw };
  try {
    const res = await fetch("api/security/mfa/verify-login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
      body: JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (res.ok && data.ok) {
      location.href = "/";
      return;
    }
    if (res.status === 401) { location.href = "login"; return; }
    showError(data.error || "Verification failed.");
    codeInput.value = "";
    codeInput.focus();
  } catch (e) {
    showError("Request failed: " + e.message);
  } finally {
    busy = false;
  }
}
document.getElementById("mfa-submit").addEventListener("click", submit);
codeInput.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
</script>
</body>
</html>`;
}

// Forced MFA enrollment (v1.4): served instead of appPage() when
// session.mfaSetupRequired is true (see onRequest's gate) — a master_admin
// marked this account's `mfaRequired` policy on, and it hasn't set up MFA
// yet. Deliberately simpler than the full Security Settings enrollment flow
// (no QR code — that library is vendored directly into appPage()'s own
// script below, and duplicating ~300 lines of it into a second standalone
// page isn't worth the risk given this file's own backslash-doubling
// GOTCHA): shows the manual secret and an otpauth:// link instead, which
// every authenticator app also supports.
function mfaSetupRequiredPage(opts = {}) {
  const csrf = htmlEscape(opts.csrf || '');
  const nonce = htmlEscape(opts.nonce || '');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BBSFirewall - Config Editor</title>
<link rel="icon" href="/favicon.ico">
<style>${BASE_CSS}</style>
</head>
<body>
<div class="wrap" style="max-width:460px;margin-top:6vh">
  <div class="brand"><img class="logo" src="/assets/logo.svg" alt="BBSFirewall"><span class="tag">config editor</span></div>
  <div class="card">
    <div id="notice"></div>
    <h3 style="margin-top:0">Two-factor authentication required</h3>
    <p class="muted">An administrator has required MFA on this account. Set it up now to continue — you cannot use the config editor until this is done.</p>
    <div id="setup-step">
      <p class="muted">Loading…</p>
    </div>
  </div>
  <p class="statline">This session is restricted to trusted hosts.</p>
  <p class="footer-credit">Created with love <span class="heart">&#10084;&#65039;</span> by Mark Laudenbach in Iowa, USA.<br>
    <a href="https://github.com/SysopNetwork/BBSFirewall" target="_blank" rel="noopener noreferrer">github.com/SysopNetwork/BBSFirewall</a></p>
</div>
<script nonce="${nonce}">
const CSRF = "${csrf}";
const stepEl = document.getElementById("setup-step");
const noticeEl = document.getElementById("notice");
function esc(s) { return String(s).replace(/[&<>"']/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function showError(msg) { noticeEl.innerHTML = '<div class="notice err">' + esc(msg) + '</div>'; }
async function post(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
    body: JSON.stringify(body || {}),
  });
  let data = null;
  try { data = await res.json(); } catch (e) {}
  return { ok: res.ok, status: res.status, data };
}
function renderCodeStep(secret, otpauthUrl) {
  stepEl.innerHTML =
    '<div class="field"><label>Secret (enter into your authenticator app)</label>' +
    '<div class="kv"><div><span class="muted" style="word-break:break-all">' + esc(secret) + '</span></div></div></div>' +
    '<p class="muted"><a href="' + esc(otpauthUrl) + '">Open in authenticator app</a> (works on the same device).</p>' +
    '<div class="field"><label for="setup-code">6-digit code</label>' +
    '<input id="setup-code" type="text" inputmode="numeric" autocomplete="one-time-code" autofocus></div>' +
    '<button class="primary" id="setup-confirm" type="button" style="width:100%">Verify &amp; continue</button>';
  const codeInput = document.getElementById("setup-code");
  let busy = false;
  async function confirm() {
    if (busy) return;
    const code = codeInput.value.trim();
    if (!code) return;
    busy = true;
    const r = await post("api/security/mfa/confirm", { code: code });
    if (r.ok && r.data && r.data.ok) { renderBackupCodes(r.data.backupCodes); return; }
    if (r.status === 401 && r.data && r.data.error === "MFA setup is required before continuing.") { location.href = "login"; return; }
    showError((r.data && r.data.error) || "Invalid code.");
    codeInput.value = "";
    codeInput.focus();
    busy = false;
  }
  document.getElementById("setup-confirm").addEventListener("click", confirm);
  codeInput.addEventListener("keydown", (e) => { if (e.key === "Enter") confirm(); });
}
function renderBackupCodes(codes) {
  stepEl.innerHTML =
    '<p class="muted">MFA is now enabled. Save these backup codes somewhere safe — each works once, and this is the only time they will be shown.</p>' +
    '<div class="backup-codes">' + codes.map((c) => "<div>" + esc(c) + "</div>").join("") + "</div>" +
    '<label class="toggle-row" style="margin-top:14px"><input type="checkbox" id="codes-ack"> I have saved these codes</label>' +
    '<button class="primary" id="codes-done" type="button" style="width:100%;margin-top:12px" disabled>Continue</button>';
  document.getElementById("codes-ack").addEventListener("change", (e) => { document.getElementById("codes-done").disabled = !e.target.checked; });
  document.getElementById("codes-done").addEventListener("click", () => { location.href = "/"; });
}
(async function start() {
  const r = await post("api/security/mfa/setup", {});
  if (r.ok && r.data && r.data.ok) { renderCodeStep(r.data.secret, r.data.otpauthUrl); return; }
  if (r.status === 401) { location.href = "login"; return; }
  stepEl.innerHTML = "";
  showError((r.data && r.data.error) || "Could not start MFA setup.");
})();
</script>
</body>
</html>`;
}

function appPage(opts = {}) {
  const csrf = htmlEscape(opts.csrf || '');
  const user = htmlEscape(opts.username || '');
  const nonce = htmlEscape(opts.nonce || '');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BBSFirewall - Config Editor</title>
<link rel="icon" href="/favicon.ico">
<style>${BASE_CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="brand">
    <span class="brand-home" id="brand-home" role="button" tabindex="0" title="Back to Settings">
      <img class="logo" src="/assets/logo.svg" alt="BBSFirewall">
      <span class="tag">config editor</span>
      <span class="tag" id="hdr-ver"></span>
    </span>
    <span class="spacer"></span>
    <div class="user-menu" id="user-menu">
      <button class="user-menu-trigger" id="user-menu-trigger" type="button" aria-haspopup="true" aria-expanded="false">
        ${user}<span class="caret">&#9662;</span>
      </button>
      <div class="user-menu-panel hidden" id="user-menu-panel" role="menu">
        <button type="button" id="menu-security" role="menuitem">Security Settings</button>
        <button type="button" id="menu-logout" role="menuitem">Log out</button>
      </div>
    </div>
  </div>

  <div id="notice"></div>

  <div class="tabs" id="tabs">
    <button data-tab="settings" class="active">Settings</button>
    <button data-tab="lists">Lists</button>
    <button data-tab="tools">Tools</button>
    <button data-tab="performance">System Stats</button>
    <button data-tab="logs">Logs</button>
  </div>

  <div id="tab-settings">
    <div class="row" style="margin-bottom:10px">
      <span class="spacer"></span>
      <button class="small" id="settings-expand-all" type="button">Expand all</button>
      <button class="small" id="settings-collapse-all" type="button">Collapse all</button>
    </div>
    <div id="settings-sections"></div>
  </div>

  <div id="tab-lists" class="hidden">
    ${[
      ['whitelist', 'Whitelist', true],
      ['blocklist', 'Blocklist', true],
      ['trustedhosts', 'Trusted Hosts', false],
      ['triggers', 'Triggers', false],
      ['apihosts', 'API Trusted Hosts', false],
      ['statushosts', 'Status Endpoint Trusted Hosts', false],
    ].map(([n, label, addIp]) => `
    <details class="sec">
      <summary>${label}<span class="sec-count" id="path-${n}"></span></summary>
      <div class="sec-body">
        ${addIp ? `<div class="row" style="margin-bottom:8px">
          <button class="small" type="button" data-add-ip="${n}" data-cidr="">Add my IP</button>
          <button class="small" type="button" data-add-ip="${n}" data-cidr="24">Add my IP /24</button>
          <button class="small" type="button" data-add-ip="${n}" data-cidr="29">Add my IP /29</button>
        </div>` : ''}
        <textarea id="ta-${n}" aria-label="${label} contents" spellcheck="false"></textarea>
        <div class="help muted" id="hint-${n}"></div>
        <div id="warn-${n}"></div>
      </div>
    </details>`).join('')}
  </div>

  <div id="tab-tools" class="hidden">
    <div class="card">
      <h3 style="margin-top:0">${toolsIcon('globe')}GeoIP database (country blocking)</h3>
      <div class="kv" id="geoip-kv"></div>
      <div class="row" style="margin-top:10px">
        <button class="primary" id="btn-geoip-dl">Download database</button>
        <button id="btn-geoip-up">Update database</button>
      </div>
      <div class="help muted">Needs <code>MAXMIND_LICENSE_KEY</code> set and saved in the Settings tab.</div>
      <div class="console hidden" id="geoip-out"></div>
    </div>

    <div class="card">
      <h3 style="margin-top:0">${toolsIcon('key')}SSH host key (terminate mode)</h3>
      <div class="kv" id="sshkey-kv"></div>
      <div class="row" style="margin-top:10px">
        <button class="primary" id="btn-sshkey">Generate host key</button>
        <label class="row" style="font-weight:400;gap:6px;margin:0">
          <input type="checkbox" id="sshkey-ed25519" style="width:auto"> ed25519 instead of RSA
        </label>
        <label class="row" style="font-weight:400;gap:6px;margin:0">
          <input type="checkbox" id="sshkey-overwrite" style="width:auto"> overwrite if one exists
        </label>
      </div>
      <div class="help muted">Only needed when <code>SSH_MODE=terminate</code>. RSA is the safest choice for old BBS clients.</div>
      <div class="console hidden" id="sshkey-out"></div>
    </div>

    <div class="card">
      <h3 style="margin-top:0">${toolsIcon('lock')}TLS certificates (Let's Encrypt)</h3>
      <div class="kv" id="cert-kv"></div>
      <div class="row" style="margin-top:10px">
        <button class="primary" id="btn-cert-editor">Issue cert for this editor</button>
        <button id="btn-cert-redirect">Issue cert for web redirect</button>
      </div>
      <div class="help muted">Set the cert domain (and optional email) in the Config Editor / Web Redirect
        sections and Save first. Port 80 must be reachable and DNS must point here. Certbot is installed
        automatically if missing.</div>
      <div class="console hidden" id="cert-out"></div>
    </div>

    <div class="card">
      <h3 style="margin-top:0">${toolsIcon('refresh')}Updates</h3>
      <div class="kv" id="update-kv"></div>
      <div class="row" style="margin-top:10px">
        <button id="btn-update-check">Check for updates</button>
        <button class="primary hidden" id="btn-update-apply">Update now</button>
      </div>
      <div class="help muted" id="update-note"></div>
      <div class="console hidden" id="update-notes-out"></div>
      <div id="update-backups-wrap" class="hidden" style="margin-top:14px">
        <div style="font-weight:600;margin-bottom:6px">Backups</div>
        <div id="update-backups-list" class="kv"></div>
      </div>
    </div>
  </div>

  <div id="tab-performance" class="hidden">
    <div class="card">
      <div class="row">
        <h3 style="margin:0">Live server stats</h3>
        <span class="spacer"></span>
        <label class="row" style="font-weight:400;gap:6px;margin:0">
          <input type="checkbox" id="perf-auto" checked style="width:auto"> auto-refresh
        </label>
        <button class="small" id="perf-refresh">Refresh now</button>
      </div>
      <div class="grid" id="perf-grid" style="margin-top:14px"></div>
      <div class="statline" id="perf-when"></div>
    </div>
    <div class="card">
      <h3 style="margin-top:0">Network interfaces</h3>
      <div class="kv" id="perf-net"></div>
    </div>
    <div class="card">
      <h3 style="margin-top:0">Firewall</h3>
      <div class="kv" id="perf-fw"></div>
    </div>
  </div>

  <div id="tab-logs" class="hidden">
    <div class="card">
      <div class="row">
        <h3 style="margin:0">Log files</h3>
        <span class="spacer"></span>
        <button class="small" id="logs-refresh">Refresh</button>
      </div>
      <div class="help muted" id="logs-note" style="margin-top:8px"></div>
      <div class="logtable-wrap" id="logs-table" style="margin-top:10px"></div>
    </div>
    <div class="card hidden" id="logs-view-card">
      <div class="row">
        <h3 style="margin:0" id="logs-view-title">Log file</h3>
        <span class="spacer"></span>
        <button class="small" id="logs-view-close">Close</button>
      </div>
      <div class="help muted" id="logs-view-meta"></div>
      <div class="console" id="logs-view-content"></div>
    </div>
  </div>

  <p class="statline" id="statline"></p>
  <p class="footer-credit">Created with love <span class="heart">&#10084;&#65039;</span> by Mark Laudenbach in Iowa, USA.<br>
    <a href="https://github.com/SysopNetwork/BBSFirewall" target="_blank" rel="noopener noreferrer">github.com/SysopNetwork/BBSFirewall</a></p>
</div>

<div class="bar">
  <div class="inner">
    <button class="primary" id="btn-save">Save changes</button>
    <button id="btn-restart">Restart firewall</button>
    <span class="spacer"></span>
  </div>
</div>

<div id="modal-root"></div>

<script nonce="${nonce}">
const CSRF = "${csrf}";
const $ = (s) => document.querySelector(s);
const el = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e; };
let DATA = null;
let perfTimer = null;

// Small inline-SVG section/card icons, keyed by an id (ENV_SCHEMA's icon
// field for Settings sections; hardcoded per-card below for the static Tools
// tab). Schema-driven lookup rather than name-keyed, so renaming a section
// doesn't silently lose its icon. Genuinely simple single-stroke outlines —
// decoration, not the load-bearing part of the release.
function svgIcon(inner) {
  return '<svg class="icon" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.6" ' +
    'stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + inner + "</svg>";
}
const ICONS = {
  network: svgIcon('<circle cx="10" cy="10" r="2"/><circle cx="4" cy="4" r="1.6"/><circle cx="16" cy="4" r="1.6"/><circle cx="10" cy="17" r="1.6"/><path d="M10 8L5.2 5.2M10 8l4.8-2.8M10 12v3.3"/>'),
  limit: svgIcon('<path d="M10 3l7 4-7 4-7-4 7-4z"/><path d="M3 11l7 4 7-4"/><path d="M3 15l7 4 7-4"/>'),
  globe: svgIcon('<circle cx="10" cy="10" r="7"/><path d="M3 10h14M10 3c2.5 2 2.5 12 0 14M10 3c-2.5 2-2.5 12 0 14"/>'),
  list: svgIcon('<path d="M6 5h10M6 10h10M6 15h10"/><circle cx="2.5" cy="5" r="1"/><circle cx="2.5" cy="10" r="1"/><circle cx="2.5" cy="15" r="1"/>'),
  gauge: svgIcon('<path d="M3 15a7 7 0 0114 0"/><path d="M10 15L13.5 8.5"/><circle cx="10" cy="15" r="1"/>'),
  alert: svgIcon('<path d="M10 3l8.5 14.5H1.5L10 3z"/><path d="M10 8.5v4"/><circle cx="10" cy="14.5" r="0.9"/>'),
  exchange: svgIcon('<path d="M4 7h11M15 7l-3-3M15 7l-3 3"/><path d="M16 13H5M5 13l3 3M5 13l3-3"/>'),
  redirect: svgIcon('<path d="M8 5H4v11h11v-4"/><path d="M11 4h5v5"/><path d="M16 4L8.5 11.5"/>'),
  lock: svgIcon('<rect x="4.5" y="9" width="11" height="8" rx="1.5"/><path d="M6.5 9V6.5a3.5 3.5 0 017 0V9"/>'),
  key: svgIcon('<circle cx="6" cy="14" r="3"/><path d="M8.2 11.8L16 4M13 7l2 2M15.5 4.5l2 2"/>'),
  file: svgIcon('<path d="M6 3h6l4 4v10H6z"/><path d="M12 3v4h4"/><path d="M8 11h6M8 14h6"/>'),
  terminal: svgIcon('<rect x="3" y="4" width="14" height="12" rx="1.5"/><path d="M6 8l3 3-3 3M11 14h4"/>'),
  refresh: svgIcon('<path d="M4 10a6 6 0 0110-4.2M16 10a6 6 0 01-10 4.2"/><path d="M14 3v3h-3M6 17v-3h3"/>'),
};

const HINTS = {
  whitelist: "One IP or CIDR per line. Listed IPs bypass every firewall rule.",
  blocklist: "One IP or CIDR per line. Listed IPs are refused permanently. Auto-block (blocklist mode) appends here.",
  trustedhosts: "IPv4/IPv6, one IP or CIDR per line. Only these hosts may reach this editor. Empty = nobody, after the next restart.",
  triggers: "One pattern per line. Plain text is a case-insensitive substring; /regex/flags is a JS regex. Hex and control-character escapes are supported in plain patterns for binary probes (see triggers.txt.example). A caller who sends a match in its first bytes is auto-blocked — enable it in the Auto-Block Triggers section. Applies live on save.",
  apihosts: "IPv4/IPv6, one IP or CIDR per line. Source IPs allowed to call the management API. Empty = any IP may call (the API key still applies). Independent of trustedhosts.txt above. Applies live on save.",
  statushosts: "IPv4/IPv6, one IP or CIDR per line. Source IPs allowed to call the unauthenticated GET /status endpoint (for uptime monitors like Uptime Kuma) — there is no API key on this one, so empty = NOBODY may call it, same fail-closed rule as Trusted Hosts above. Independent of trustedhosts.txt and API Trusted Hosts. Applies live on save.",
};

function esc(s) { return String(s == null ? "" : s).replace(/[&<>"'\`]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "\`": "&#96;" }[c])); }

function notice(kind, msg) {
  $("#notice").innerHTML = msg ? '<div class="notice ' + kind + '">' + esc(msg) + "</div>" : "";
  if (msg) window.scrollTo({ top: 0, behavior: "smooth" });
}

function fmtBytes(n) {
  if (n == null) return "n/a";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0; let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v : v.toFixed(1)) + " " + u[i];
}
function fmtMbit(bytesPerSec) {
  if (bytesPerSec == null) return "n/a";
  return ((bytesPerSec * 8) / 1e6).toFixed(2) + " Mbit/s";
}
function fmtDur(sec) {
  if (sec == null) return "n/a";
  sec = Math.floor(sec);
  const d = Math.floor(sec / 86400); sec -= d * 86400;
  const h = Math.floor(sec / 3600); sec -= h * 3600;
  const m = Math.floor(sec / 60); sec -= m * 60;
  return [d && d + "d", h && h + "h", m && m + "m", sec + "s"].filter(Boolean).join(" ");
}

/* ---------- Settings tab ---------- */

function fieldControl(f) {
  const id = "f_" + f.key;
  const val = f.value == null ? "" : String(f.value);
  const ph = f.placeholder ? ' placeholder="' + esc(f.placeholder) + '"' : "";
  if (f.type === "bool") {
    return '<select id="' + id + '" data-key="' + f.key + '">' +
      '<option value="true"' + (val === "true" ? " selected" : "") + ">true</option>" +
      '<option value="false"' + (val === "true" ? "" : " selected") + ">false</option></select>";
  }
  if (f.type === "enum") {
    return '<select id="' + id + '" data-key="' + f.key + '">' +
      f.options.map((o) => "<option" + (o === val ? " selected" : "") + ">" + esc(o) + "</option>").join("") +
      "</select>";
  }
  if (f.type === "secret") {
    return '<div class="pw-wrap"><input id="' + id + '" data-key="' + f.key + '" type="password" value="' +
      esc(val) + '"' + ph + '><button type="button" class="pw-toggle">show</button></div>';
  }
  const inputType = (f.type === "port" || f.type === "int") ? "number" : "text";
  return '<input id="' + id + '" data-key="' + f.key + '" type="' + inputType + '" value="' + esc(val) + '"' + ph + ">";
}

// Section open/closed state survives re-renders (e.g. after Save reloads DATA) —
// only cleared by a full page load. Empty on first render, so every section
// starts collapsed; a section stays open across saves once the admin opens it.
const OPEN_SECTIONS = new Set();

function renderSettings() {
  const host = $("#settings-sections");
  host.innerHTML = "";
  for (const sec of DATA.sections) {
    const details = el("details", "sec");
    if (OPEN_SECTIONS.has(sec.name)) details.open = true;
    details.innerHTML = '<summary>' + (ICONS[sec.icon] || "") + esc(sec.name) +
      '<span class="sec-count">' + sec.fields.length + (sec.fields.length === 1 ? " setting" : " settings") + "</span></summary>";
    details.addEventListener("toggle", () => {
      if (details.open) OPEN_SECTIONS.add(sec.name); else OPEN_SECTIONS.delete(sec.name);
    });

    const body = el("div", "sec-body");
    if (sec.help) body.appendChild(el("div", "sec-help", esc(sec.help)));
    for (const f of sec.fields) {
      const div = el("div", "field" + (f.required || f.enabled ? "" : " optional-off"));
      let head;
      if (f.required) {
        head = '<label for="f_' + f.key + '">' + esc(f.label) + ' <span class="muted">(' + f.key + ")</span></label>";
      } else {
        head = '<div class="toggle-row"><input type="checkbox" id="en_' + f.key + '" data-en="' + f.key + '"' +
          (f.enabled ? " checked" : "") + '><label for="en_' + f.key + '" style="margin:0">' +
          esc(f.label) + ' <span class="muted">(' + f.key + ")</span></label></div>";
      }
      let extra = f.help ? '<div class="help">' + esc(f.help) + "</div>" : "";
      if (f.helpLong) {
        extra += '<details class="more"><summary>more</summary><div class="body">' + esc(f.helpLong) + "</div></details>";
      }
      div.innerHTML = head + fieldControl(f) + extra;
      body.appendChild(div);
    }
    details.appendChild(body);
    host.appendChild(details);
  }
  host.querySelectorAll("[data-en]").forEach((cb) => {
    const sync = () => {
      const wrap = cb.closest(".field");
      const ctrl = wrap.querySelector("[data-key]");
      ctrl.disabled = !cb.checked;
      wrap.classList.toggle("optional-off", !cb.checked);
    };
    cb.addEventListener("change", sync);
    sync();
  });
}

/* ---------- list-file tabs ---------- */

function renderFiles() {
  for (const name of ["whitelist", "blocklist", "trustedhosts", "triggers", "apihosts", "statushosts"]) {
    const info = (DATA.files || {})[name] || {};
    $("#ta-" + name).value = info.content || "";
    $("#path-" + name).textContent = info.path ? "(" + info.path + (info.exists ? "" : " - not created yet") + ")" : "";
    $("#hint-" + name).textContent = HINTS[name] || "";
  }
  checkTrustedHosts();
  checkApiHosts();
  checkStatusHosts();
}

function checkTrustedHosts() {
  const lines = $("#ta-trustedhosts").value.split(/\\r?\\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  $("#warn-trustedhosts").innerHTML = lines.length === 0
    ? '<div class="notice warn">This list has no entries. Saving it will lock every host out of the editor after the next restart.</div>'
    : "";
}

function checkApiHosts() {
  const lines = $("#ta-apihosts").value.split(/\\r?\\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  $("#warn-apihosts").innerHTML = lines.length === 0
    ? '<div class="notice">Empty list: any source IP may call the management API (the API key is still required).</div>'
    : "";
}

function checkStatusHosts() {
  const lines = $("#ta-statushosts").value.split(/\\r?\\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  $("#warn-statushosts").innerHTML = lines.length === 0
    ? '<div class="notice warn">This list has no entries. Saving it will block every caller from GET /status — there is no API key fallback on this endpoint.</div>'
    : "";
}

/* ---------- "Add my IP" quick-add buttons (whitelist/blocklist) ---------- */

function isIPv4(ip) { return /^\\d{1,3}(\\.\\d{1,3}){3}$/.test(ip); }
function ipv4ToInt(ip) { return ip.split(".").reduce((a, o) => (a << 8) + parseInt(o, 10), 0) >>> 0; }
function intToIPv4(n) { return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join("."); }
function cidrNetwork(ip, bits) {
  const n = ipv4ToInt(ip);
  const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
  return intToIPv4(n & mask) + "/" + bits;
}

// IPv6 CIDR truncation isn't implemented (not worth the bit-math for a
// convenience button) - IPv6 callers only get the bare-IP button; the /24 and
// /29 buttons are hidden for them, see updateAddIpButtons().
function updateAddIpButtons() {
  const ip = (DATA.status || {}).ip || "";
  const v4 = isIPv4(ip);
  document.querySelectorAll("[data-add-ip]").forEach((b) => {
    if (b.dataset.cidr && !v4) b.classList.add("hidden");
    else b.classList.remove("hidden");
  });
}

document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-add-ip]");
  if (!btn) return;
  const name = btn.dataset.addIp;
  const cidrRaw = btn.dataset.cidr;
  const ip = (DATA.status || {}).ip;
  if (!ip) { notice("err", "Your IP address isn't available yet — reload the page."); return; }
  let line = ip;
  if (cidrRaw) {
    if (!isIPv4(ip)) return; // CIDR buttons are hidden for IPv6 callers; guard anyway
    line = cidrNetwork(ip, parseInt(cidrRaw, 10));
  }
  const ta = $("#ta-" + name);
  const lines = ta.value.split(/\\r?\\n/).map((l) => l.trim());
  if (lines.includes(line)) { notice("ok", line + " is already in the list."); return; }
  ta.value = (ta.value && !ta.value.endsWith("\\n") ? ta.value + "\\n" : ta.value) + line + "\\n";
  notice("ok", "Added " + line + " — click Save to apply.");
});

/* ---------- Tools tab ---------- */

function pill(ok, textOk, textBad, warn) {
  const cls = ok ? "good" : (warn ? "warn" : "bad");
  return '<span class="pill ' + cls + '">' + esc(ok ? textOk : textBad) + "</span>";
}

function renderTools() {
  const h = DATA.health || {};
  const g = h.geoip || {};
  $("#geoip-kv").innerHTML =
    "<div><b>Database</b>" + (g.exists ? esc(fmtBytes(g.sizeBytes)) + ", " + g.ageDays + " day(s) old" : pill(false, "", "not downloaded")) + "</div>" +
    "<div><b>License key</b>" + pill(!!g.licenseKeySet, "set", "not set") + "</div>" +
    "<div><b>Path</b><span class='muted'>" + esc(g.dbPath || "") + "</span></div>";

  const s = h.sshHostKey || {};
  $("#sshkey-kv").innerHTML =
    "<div><b>Host key</b>" + (s.exists ? pill(true, (s.type || "present"), "") : pill(false, "", "not created", true)) + "</div>" +
    (s.fingerprint ? "<div><b>Fingerprint</b><span class='muted'>" + esc(s.fingerprint) + "</span></div>" : "") +
    "<div><b>Path</b><span class='muted'>" + esc(s.path || "") + "</span></div>" +
    "<div><b>SSH_MODE</b><span class='muted'>" + esc(h.sshMode || "off") + "</span></div>";

  const c = h.certs || {};
  const certRow = (label, ci, domain) => {
    if (!ci) return "";
    let v;
    if (!ci.exists) v = pill(false, "", "not present", true);
    else v = esc((ci.selfSigned ? "self-signed" : "CA") + (ci.daysLeft != null ? ", " + ci.daysLeft + "d left" : "")) +
      (ci.subject ? " <span class='muted'>" + esc(ci.subject) + "</span>" : "");
    return "<div><b>" + esc(label) + "</b>" + v + "</div>" +
      "<div><b>&nbsp;&nbsp;domain</b><span class='muted'>" + esc(domain || "(not set)") + "</span></div>";
  };
  $("#cert-kv").innerHTML =
    "<div><b>certbot</b>" + pill(!!h.certbotInstalled, "installed", "not installed (auto-installs on issue)", true) + "</div>" +
    certRow("This editor", c.editor, (h.domains || {}).editor) +
    certRow("Web redirect", c.redirect, (h.domains || {}).redirect);
}

async function runTool(btn, outSel, url, body) {
  const out = $(outSel);
  out.classList.remove("hidden");
  out.textContent = "Working... this can take a minute.";
  document.querySelectorAll("#tab-tools button").forEach((b) => (b.disabled = true));
  try {
    const r = await api(url, body);
    const d = r.data || {};
    out.textContent = (d.output || d.error || ("HTTP " + r.status)).trim();
    if (r.ok && d.ok) {
      notice("ok", "Done.");
      await loadHealth();
    } else {
      notice("err", d.error || "Action failed — see console output in the Tools tab.");
    }
  } catch (e) {
    out.textContent = "Request failed: " + e.message;
  } finally {
    document.querySelectorAll("#tab-tools button").forEach((b) => (b.disabled = false));
  }
}

/* ---------- Updates ---------- */

// Own endpoint (not folded into /api/health) since it calls out to GitHub —
// a slow/unreachable GitHub should never hold up the rest of the Tools tab.
async function loadUpdateInfo() {
  try {
    const res = await fetch("api/update/check", { headers: { "X-CSRF-Token": CSRF } });
    if (res.status === 401) { location.href = "login"; return; }
    if (!res.ok) return;
    DATA.update = await res.json();
    renderUpdate();
  } catch (e) { /* Tools tab just keeps showing its last-known state */ }
}

function renderUpdate() {
  const u = DATA.update;
  const applyBtn = $("#btn-update-apply");
  const note = $("#update-note");
  const notesOut = $("#update-notes-out");
  const backupsWrap = $("#update-backups-wrap");
  const backupsList = $("#update-backups-list");

  if (!u) {
    $("#update-kv").innerHTML = "<div><b>Current version</b><span class='muted'>v" +
      esc((DATA.status || {}).version || "?") + "</span></div>";
    applyBtn.classList.add("hidden");
    note.textContent = "";
    notesOut.classList.add("hidden");
    backupsWrap.classList.add("hidden");
    return;
  }

  $("#update-kv").innerHTML =
    "<div><b>Current version</b><span class='muted'>v" + esc(u.currentVersion || "?") + "</span></div>" +
    "<div><b>Latest release</b>" + (u.error
      ? pill(false, "", "check failed", true)
      : (u.updateAvailable ? pill(false, "", "v" + esc(u.latestVersion) + " available", true) : pill(true, "up to date", ""))) + "</div>";

  if (u.error) {
    note.textContent = "Could not check GitHub: " + u.error;
  } else if (!u.platformSupported) {
    note.textContent = u.updateAvailable
      ? "v" + u.latestVersion + " is available, but self-update is only supported on Linux hosts — update this install manually."
      : "Self-update is only supported on Linux hosts.";
  } else if (!u.tarAvailable) {
    note.textContent = 'The "tar" command was not found on this host — self-update needs it.';
  } else {
    note.textContent = "";
  }

  const canApply = !!(u.updateAvailable && !u.error && u.platformSupported && u.tarAvailable);
  applyBtn.classList.toggle("hidden", !canApply);
  applyBtn.textContent = "Update to v" + (u.latestVersion || "?");

  if (u.releaseNotes) {
    notesOut.textContent = u.releaseNotes.trim();
    notesOut.classList.remove("hidden");
  } else {
    notesOut.classList.add("hidden");
  }

  const backups = u.backups || [];
  if (backups.length) {
    backupsWrap.classList.remove("hidden");
    backupsList.innerHTML = backups.map((name) =>
      "<div class='row' style='justify-content:space-between'><span class='muted'>" + esc(name) + "</span>" +
      "<button class='small' data-rollback='" + esc(name) + "'>Roll back to this</button></div>"
    ).join("");
  } else {
    backupsWrap.classList.add("hidden");
  }
}

$("#btn-update-check").addEventListener("click", async () => {
  $("#btn-update-check").disabled = true;
  await loadUpdateInfo();
  $("#btn-update-check").disabled = false;
  if (!DATA.update || DATA.update.error) notice("err", (DATA.update && DATA.update.error) || "Could not check for updates.");
  else notice("ok", DATA.update.updateAvailable ? "Update available." : "Up to date.");
});

// Same .modal-bg/.modal pattern (and the same "stay signed in" checkbox) as
// the restart confirmation below — apply/rollback both restart on success.
function confirmUpdateModal(title, warning, actionLabel, onGo) {
  const root = $("#modal-root");
  root.innerHTML =
    '<div class="modal-bg"><div class="modal">' +
    "<h3 style='margin-top:0'>" + esc(title) + "</h3>" +
    "<p class='muted'>" + esc(warning) + "</p>" +
    "<label class='row' style='font-weight:400;gap:8px'>" +
    "<input type='checkbox' id='upd-keep-session' checked style='width:auto'> Stay signed in after restart</label>" +
    "<div class='row' style='margin-top:18px;justify-content:flex-end'>" +
    "<button id='upd-cancel'>Cancel</button>" +
    "<button class='danger' id='upd-go'>" + esc(actionLabel) + "</button></div>" +
    "</div></div>";
  $("#upd-cancel").onclick = () => (root.innerHTML = "");
  $("#upd-go").onclick = () => {
    const keep = $("#upd-keep-session").checked;
    root.innerHTML = "";
    onGo(keep);
  };
}

async function runUpdateAction(url, body, workingMsg) {
  notice("warn", workingMsg);
  document.querySelectorAll("#tab-tools button").forEach((b) => (b.disabled = true));
  const r = await api(url, body);
  const d = r.data || {};
  if (!(r.ok && d.ok)) {
    document.querySelectorAll("#tab-tools button").forEach((b) => (b.disabled = false));
    notice("err", d.error || "Action failed.");
    await loadUpdateInfo();
    return;
  }
  if (!d.restarting) {
    document.querySelectorAll("#tab-tools button").forEach((b) => (b.disabled = false));
    notice("ok", d.message || "Done.");
    await loadUpdateInfo();
    return;
  }
  if (!d.keepSession) {
    notice("ok", d.message || "Restarting — you will be signed out.");
    setTimeout(() => (location.href = "login"), 3000);
    return;
  }
  notice("ok", d.message || "Restarting…");
  waitForReconnect();
}

$("#btn-update-apply").addEventListener("click", () => {
  const u = DATA.update || {};
  confirmUpdateModal(
    "Update BBSFirewall to v" + (u.latestVersion || "?") + "?",
    "Active telnet/SSH connections will drop and the firewall restarts. A backup of the current version is made automatically and restored if anything fails.",
    "Update now",
    (keep) => runUpdateAction("api/update/apply", { keepSession: keep }, "Updating…")
  );
});

$("#update-backups-list").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-rollback]");
  if (!btn) return;
  const name = btn.dataset.rollback;
  confirmUpdateModal(
    "Roll back to " + name + "?",
    "This restores that backup's code, reinstalls its dependencies, and restarts the firewall. Active connections will drop.",
    "Roll back now",
    (keep) => runUpdateAction("api/update/rollback", { backup: name, keepSession: keep }, "Rolling back…")
  );
});

/* ---------- Performance tab ---------- */

function meterClass(pct) { return pct >= 90 ? "meter crit" : pct >= 75 ? "meter warn" : "meter"; }

function statCard(k, v, sub, pct) {
  let m = "";
  if (pct != null) m = '<div class="' + meterClass(pct) + '"><i style="width:' + Math.max(0, Math.min(100, pct)) + '%"></i></div>';
  return '<div class="stat"><div class="k">' + esc(k) + '</div><div class="v">' + esc(v) + "</div>" +
    (sub ? '<div class="sub">' + esc(sub) + "</div>" : "") + m + "</div>";
}

async function refreshPerf() {
  let d;
  try {
    const r = await fetch("api/stats", { headers: { "X-CSRF-Token": CSRF } });
    if (r.status === 401) { location.href = "login"; return; }
    d = await r.json();
  } catch (e) { $("#perf-when").textContent = "stats unavailable: " + e.message; return; }

  const host = d.host || {}; const proc = d.process || {};
  const memUsed = host.memTotalBytes - host.memFreeBytes;
  const memPct = host.memTotalBytes ? Math.round((memUsed / host.memTotalBytes) * 100) : null;
  const cpuPct = host.cpu && host.cpu.percent != null ? host.cpu.percent : null;
  const load1 = (host.loadavg || [])[0];
  const loadPct = host.cpu && host.cpu.cores ? Math.round((load1 / host.cpu.cores) * 100) : null;

  const cards = [
    statCard("CPU", cpuPct == null ? "sampling…" : cpuPct + " %",
      (host.cpu && host.cpu.cores ? host.cpu.cores + " cores" : "") + (host.cpu && host.cpu.model ? " · " + host.cpu.model : ""), cpuPct),
    statCard("Load avg", (host.loadavg || []).join("  "), "1 / 5 / 15 min", loadPct),
    statCard("Memory", fmtBytes(memUsed) + " / " + fmtBytes(host.memTotalBytes), "free " + fmtBytes(host.memFreeBytes), memPct),
    statCard("Process RSS", fmtBytes(proc.rssBytes), "heap " + fmtBytes(proc.heapUsedBytes) + " / " + fmtBytes(proc.heapTotalBytes)),
    statCard("Active connections", d.firewall ? d.firewall.activeTotal : "n/a",
      d.firewall ? ("accepted " + d.firewall.totals.accepted + " · rejected " + d.firewall.totals.rejected) : ""),
    statCard("Uptime", fmtDur(host.procUptimeSec), "host up " + fmtDur(host.osUptimeSec)),
  ];
  if (d.disk) {
    const dPct = d.disk.totalBytes ? Math.round((d.disk.usedBytes / d.disk.totalBytes) * 100) : null;
    cards.push(statCard("Disk", fmtBytes(d.disk.usedBytes) + " / " + fmtBytes(d.disk.totalBytes), "free " + fmtBytes(d.disk.freeBytes), dPct));
  }
  const rate = (d.firewall && d.firewall.rate) || {};
  const cur = rate.current || {}; const max = rate.max || {};
  const curTotal = (cur.fromClient || 0) + (cur.fromBackend || 0);
  const maxTotal = (max.fromClient || 0) + (max.fromBackend || 0);
  cards.push(statCard("Bandwidth", fmtMbit(curTotal),
    "peak " + fmtMbit(maxTotal) + " · avg " + (d.firewall && d.firewall.avgMbit != null ? d.firewall.avgMbit.toFixed(2) + " Mbit/s" : "n/a")));
  if (d.firewall && d.firewall.bytes) {
    cards.push(statCard("Data transferred", fmtBytes((d.firewall.bytes.fromClient || 0) + (d.firewall.bytes.fromBackend || 0)),
      "in " + fmtBytes(d.firewall.bytes.fromClient) + " · out " + fmtBytes(d.firewall.bytes.fromBackend)));
  }
  if (d.folder) {
    cards.push(statCard("Folder size", fmtBytes(d.folder.totalBytes), "BBSFirewall directory, excludes node_modules"));
  }
  if (d.logsBytes != null) {
    cards.push(statCard("Log files", fmtBytes(d.logsBytes), "all rotated per-proxy logs"));
  }
  cards.push(statCard("Node", host.nodeVersion || "?", host.platform || ""));
  $("#perf-grid").innerHTML = cards.join("");

  if (d.network && Object.keys(d.network).length) {
    $("#perf-net").innerHTML = Object.entries(d.network).map(([iface, r]) =>
      "<div><b>" + esc(iface) + "</b>&#8595; " + fmtBytes(r.rxBytesPerSec) + "/s &nbsp; &#8593; " + fmtBytes(r.txBytesPerSec) + "/s</div>"
    ).join("");
  } else {
    $("#perf-net").innerHTML = "<div class='muted'>" + (d.network ? "sampling…" : "per-interface rates need Linux /proc") + "</div>";
  }

  const fw = d.firewall || {}; const ipf = fw.ipfilter || {};
  $("#perf-fw").innerHTML =
    "<div><b>Active total</b>" + (fw.activeTotal != null ? fw.activeTotal : "n/a") + "</div>" +
    "<div><b>By proxy</b><span class='muted'>" + esc(JSON.stringify(fw.active || {})) + "</span></div>" +
    "<div><b>Accepted / rejected</b>" + (fw.totals ? fw.totals.accepted + " / " + fw.totals.rejected : "n/a") + "</div>" +
    "<div><b>Whitelist / blocklist</b>" + (ipf.whitelistSize != null ? ipf.whitelistSize + " / " + ipf.blocklistSize : "n/a") + "</div>" +
    "<div><b>Temp-blocked IPs</b>" + (ipf.temporarilyBlockedIPs != null ? ipf.temporarilyBlockedIPs : "n/a") + "</div>" +
    "<div><b>Tracked IPs</b>" + (ipf.trackedIPs != null ? ipf.trackedIPs : "n/a") + "</div>" +
    "<div><b>Trigger patterns</b>" + (ipf.triggerCount != null ? ipf.triggerCount : "n/a") + "</div>" +
    "<div><b>Auto-blocked (triggers)</b>" + (ipf.autoBlocked != null ? ipf.autoBlocked : "n/a") +
      (fw.totals && fw.totals.triggerBlocks != null ? " (" + fw.totals.triggerBlocks + " hits)" : "") + "</div>";

  $("#perf-when").textContent = "updated " + new Date().toLocaleTimeString();
}

function perfLoop(on) {
  if (perfTimer) { clearInterval(perfTimer); perfTimer = null; }
  if (on) { refreshPerf(); perfTimer = setInterval(refreshPerf, 4000); }
}

/* ---------- Logs tab ---------- */

function fmtDate(iso) {
  if (!iso) return "";
  try { return new Date(iso).toLocaleString(); } catch (e) { return iso; }
}

function fileWord(n) { return n + " file" + (n === 1 ? "" : "s"); }

// Grouping below is purely cosmetic (client-side) — /api/logs still returns one
// flat list. LOG_RETENTION_DAYS can be set far past 30 (up to 3650), so a board
// left running a long time can build up a tail of old files well past the usual
// 30-day window; splitting those into per-month buckets keeps the common case
// (everything within 30 days) looking exactly like a short flat list per type,
// and only grows a "folder" for old files when there's actually a long tail.
const LOG_RECENT_DAYS = 30;

// Reuses the same icon language as the Settings sections (network = telnet,
// terminal = SSH, redirect = web redirect, file = generic/fallback).
const LOG_TYPE_ICONS = { telnet: "network", ssh: "terminal", "ssh-passthrough": "terminal", web: "redirect" };

// Plain display names for the raw proxy/folder names, same "label by name, not
// filename" convention as the Lists tab sections.
const LOG_TYPE_LABELS = { telnet: "Telnet", ssh: "SSH", "ssh-passthrough": "SSH Passthrough", web: "Web Redirect" };
function logTypeLabel(proxy) { return LOG_TYPE_LABELS[proxy] || proxy; }

function monthLabel(monthKey) {
  const [y, m] = monthKey.split("-").map(Number);
  return new Date(Date.UTC(y, m - 1, 1)).toLocaleDateString(undefined, { year: "numeric", month: "long", timeZone: "UTC" });
}

function groupLogFiles(files) {
  const cutoff = new Date(Date.now() - LOG_RECENT_DAYS * 86400000).toISOString().slice(0, 10);
  const byProxy = new Map();
  for (const f of files) {
    if (!byProxy.has(f.proxy)) byProxy.set(f.proxy, []);
    byProxy.get(f.proxy).push(f);
  }
  const groups = [];
  for (const [proxy, list] of byProxy) {
    list.sort((a, b) => b.date.localeCompare(a.date));
    const recent = list.filter((f) => f.date >= cutoff);
    const byMonth = new Map();
    for (const f of list) {
      if (f.date >= cutoff) continue;
      const key = f.date.slice(0, 7);
      if (!byMonth.has(key)) byMonth.set(key, []);
      byMonth.get(key).push(f);
    }
    const months = [...byMonth.entries()].sort((a, b) => b[0].localeCompare(a[0]))
      .map(([key, monthFiles]) => ({ label: monthLabel(key), files: monthFiles }));
    groups.push({
      proxy, recent, months,
      count: list.length,
      totalSize: list.reduce((n, f) => n + f.size, 0),
    });
  }
  groups.sort((a, b) => a.proxy.localeCompare(b.proxy));
  return groups;
}

function logRow(f) {
  return "<tr><td>" + esc(f.file) + "</td><td>" + esc(fmtBytes(f.size)) + "</td><td>" + esc(fmtDate(f.mtime)) + "</td><td>" +
    '<button class="small" data-log-view data-proxy="' + esc(f.proxy) + '" data-file="' + esc(f.file) + '">View</button> ' +
    '<button class="small danger" data-log-del data-proxy="' + esc(f.proxy) + '" data-file="' + esc(f.file) + '">Delete</button>' +
    "</td></tr>";
}

function logTable(list) {
  if (!list.length) return "";
  return '<div class="logtable-wrap"><table class="logtable"><thead><tr><th>File</th><th>Size</th><th>Modified</th><th></th></tr></thead>' +
    "<tbody>" + list.map(logRow).join("") + "</tbody></table></div>";
}

function renderLogsTable(files) {
  if (!files.length) {
    $("#logs-table").innerHTML = '<div class="muted">No log files found.</div>';
    return;
  }
  const groups = groupLogFiles(files);
  $("#logs-table").innerHTML = groups.map((g) => {
    const icon = ICONS[LOG_TYPE_ICONS[g.proxy]] || ICONS.file;
    const monthsHtml = g.months.map((m) =>
      '<details class="sec-sub">' +
        "<summary>" + esc(m.label) + '<span class="sec-count">' + fileWord(m.files.length) + "</span></summary>" +
        '<div class="sec-body">' + logTable(m.files) + "</div>" +
      "</details>"
    ).join("");
    return '<details class="sec" open>' +
      "<summary>" + icon + esc(logTypeLabel(g.proxy)) +
      '<span class="sec-count">' + fileWord(g.count) + " · " + esc(fmtBytes(g.totalSize)) + "</span>" +
      "</summary>" +
      '<div class="sec-body">' +
        (g.recent.length ? logTable(g.recent) : '<div class="muted">No files in the last ' + LOG_RECENT_DAYS + ' days.</div>') +
        (g.months.length ? '<div class="log-older-label">Older than ' + LOG_RECENT_DAYS + ' days</div>' + monthsHtml : "") +
      "</div>" +
    "</details>";
  }).join("");
}

async function refreshLogs() {
  $("#logs-table").innerHTML = '<div class="muted">Loading…</div>';
  let r, d;
  try {
    r = await fetch("api/logs", { headers: { "X-CSRF-Token": CSRF } });
    if (r.status === 401) { location.href = "login"; return; }
    d = await r.json();
  } catch (e) {
    $("#logs-table").innerHTML = '<div class="notice err">' + esc(e.message) + "</div>";
    return;
  }
  if (!r.ok) {
    $("#logs-table").innerHTML = '<div class="notice err">' + esc(d.error || "Failed to load logs.") + "</div>";
    return;
  }
  const files = d.files || [];
  const types = new Set(files.map((f) => f.proxy)).size;
  const totalSize = files.reduce((n, f) => n + f.size, 0);
  const stats = files.length ? " — " + types + " type" + (types === 1 ? "" : "s") + " · " +
    fileWord(files.length) + " · " + fmtBytes(totalSize) + " total" : "";
  $("#logs-note").textContent = (d.enabled
    ? "Directory: " + d.dir
    : "File logging is currently off (LOG_FILE_ENABLED in Settings) — no new files are being written. Existing files below can still be viewed or deleted.")
    + stats;
  renderLogsTable(files);
}

async function viewLogFile(proxy, file) {
  $("#logs-view-card").classList.remove("hidden");
  $("#logs-view-title").textContent = proxy + "/" + file;
  $("#logs-view-meta").textContent = "Loading…";
  $("#logs-view-content").textContent = "";
  try {
    const r = await fetch("api/logs/view?proxy=" + encodeURIComponent(proxy) + "&file=" + encodeURIComponent(file),
      { headers: { "X-CSRF-Token": CSRF } });
    const d = await r.json();
    if (!r.ok) { $("#logs-view-meta").textContent = d.error || ("HTTP " + r.status); return; }
    $("#logs-view-meta").textContent = fmtBytes(d.size) +
      (d.truncated ? " — file is larger; showing the last " + fmtBytes(512 * 1024) : "");
    $("#logs-view-content").textContent = d.content || "(empty)";
  } catch (e) {
    $("#logs-view-meta").textContent = "Request failed: " + e.message;
  }
}

function confirmDeleteLog(proxy, file) {
  const root = $("#modal-root");
  root.innerHTML =
    '<div class="modal-bg"><div class="modal">' +
    "<h3 style='margin-top:0'>Delete log file?</h3>" +
    "<p class='muted'>" + esc(proxy + "/" + file) + " will be permanently deleted. This cannot be undone.</p>" +
    "<div class='row' style='margin-top:18px;justify-content:flex-end'>" +
    "<button id='logdel-cancel'>Cancel</button>" +
    "<button class='danger' id='logdel-go'>Delete</button></div>" +
    "</div></div>";
  $("#logdel-cancel").onclick = () => (root.innerHTML = "");
  $("#logdel-go").onclick = async () => {
    root.innerHTML = "";
    const r = await api("api/logs/delete", { proxy, file });
    const d = r.data || {};
    if (r.ok && d.ok) {
      notice("ok", "Deleted " + proxy + "/" + file + ".");
      if ($("#logs-view-title").textContent === proxy + "/" + file) $("#logs-view-card").classList.add("hidden");
      refreshLogs();
    } else {
      notice("err", d.error || "Delete failed.");
    }
  };
}

document.addEventListener("click", (e) => {
  const v = e.target.closest && e.target.closest("[data-log-view]");
  if (v) { viewLogFile(v.dataset.proxy, v.dataset.file); return; }
  const del = e.target.closest && e.target.closest("[data-log-del]");
  if (del) confirmDeleteLog(del.dataset.proxy, del.dataset.file);
});

/* ---------- shared ---------- */

function collect() {
  const env = {};
  document.querySelectorAll("#tab-settings [data-key]").forEach((ctrl) => {
    const key = ctrl.dataset.key;
    const cb = document.getElementById("en_" + key);
    env[key] = { value: ctrl.value, enabled: cb ? cb.checked : true, required: !cb };
  });
  return {
    env,
    files: {
      whitelist: $("#ta-whitelist").value,
      blocklist: $("#ta-blocklist").value,
      trustedhosts: $("#ta-trustedhosts").value,
      triggers: $("#ta-triggers").value,
      apihosts: $("#ta-apihosts").value,
      statushosts: $("#ta-statushosts").value,
    },
  };
}

async function api(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": CSRF },
    body: JSON.stringify(body || {}),
  });
  let data = null;
  try { data = await res.json(); } catch (e) {}
  return { ok: res.ok, status: res.status, data };
}

// /api/health is served separately from /api/config: it's the one endpoint
// that shells out (ssh-keygen / openssl / certbot) to build the Tools tab's
// data, and bundling it into /api/config used to hold up the Settings
// sections and the header version behind however long those probes took.
async function loadHealth() {
  try {
    const res = await fetch("api/health", { headers: { "X-CSRF-Token": CSRF } });
    if (res.status === 401) { location.href = "login"; return; }
    if (!res.ok) return;
    DATA.health = await res.json();
    renderTools();
  } catch (e) { /* Tools tab just keeps showing its last-known state */ }
}

async function load() {
  const res = await fetch("api/config", { headers: { "X-CSRF-Token": CSRF } });
  if (res.status === 401) { location.href = "login"; return; }
  DATA = await res.json();
  renderSettings();
  renderFiles();
  renderTools();
  const st = DATA.status || {};
  $("#hdr-ver").textContent = "v" + (st.version || "?");
  $("#statline").textContent = "BBSFirewall v" + (st.version || "?") + " · pid " + st.pid +
    " · uptime " + st.uptimeHuman +
    " · pm2: " + (st.pm2 ? "available" : "not detected") + " · .env: " + st.envPath;
  updateAddIpButtons();
  renderUpdate();
  loadHealth(); // don't await — Tools-tab data can arrive after the rest of the page
  loadUpdateInfo(); // same — hits GitHub, must not hold up the rest of the page
}

/* ---------- tab switching ---------- */
const TAB_NAMES = ["settings", "lists", "tools", "performance", "logs"];
function activateTab(name) {
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  for (const n of TAB_NAMES) $("#tab-" + n).classList.toggle("hidden", n !== name);
  perfLoop(name === "performance" && $("#perf-auto").checked);
  if (name === "logs") refreshLogs();
}
$("#tabs").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-tab]");
  if (btn) activateTab(btn.dataset.tab);
});

/* Header brand: click / Enter / Space returns to the Settings tab. */
const brandHome = $("#brand-home");
if (brandHome) {
  brandHome.addEventListener("click", () => activateTab("settings"));
  brandHome.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); activateTab("settings"); }
  });
}

document.addEventListener("input", (e) => {
  if (e.target && e.target.id === "ta-trustedhosts") checkTrustedHosts();
  if (e.target && e.target.id === "ta-apihosts") checkApiHosts();
  if (e.target && e.target.id === "ta-statushosts") checkStatusHosts();
});
document.addEventListener("click", (e) => {
  const b = e.target.closest && e.target.closest(".pw-toggle");
  if (!b) return;
  const inp = b.previousElementSibling;
  inp.type = inp.type === "password" ? "text" : "password";
  b.textContent = inp.type === "password" ? "show" : "hide";
});

/* ---------- actions ---------- */

$("#btn-save").addEventListener("click", async () => {
  notice("", "");
  $("#btn-save").disabled = true;
  const r = await api("api/save", collect());
  $("#btn-save").disabled = false;
  if (r.ok && r.data && r.data.ok) {
    notice("ok", "Saved." + (r.data.backup ? " Backup: " + r.data.backup + "." : "") +
      " Restart the firewall to apply .env changes.");
    await load();
  } else {
    const d = r.data || {};
    notice("err", d.error || (d.errors || []).join("\\n") || ("Save failed (HTTP " + r.status + ")"));
  }
});

$("#btn-geoip-dl").addEventListener("click", () => runTool(null, "#geoip-out", "api/geoip", { action: "download" }));
$("#btn-geoip-up").addEventListener("click", () => runTool(null, "#geoip-out", "api/geoip", { action: "update" }));
$("#btn-sshkey").addEventListener("click", () => runTool(null, "#sshkey-out", "api/sshkey", {
  type: $("#sshkey-ed25519").checked ? "ed25519" : "rsa",
  overwrite: $("#sshkey-overwrite").checked,
}));
$("#btn-cert-editor").addEventListener("click", () => runTool(null, "#cert-out", "api/cert", { target: "editor" }));
$("#btn-cert-redirect").addEventListener("click", () => runTool(null, "#cert-out", "api/cert", { target: "redirect" }));

$("#perf-refresh").addEventListener("click", refreshPerf);
$("#perf-auto").addEventListener("change", (e) => perfLoop(e.target.checked));

$("#settings-expand-all").addEventListener("click", () => {
  for (const sec of DATA.sections) OPEN_SECTIONS.add(sec.name);
  $("#tab-settings").querySelectorAll("details.sec").forEach((d) => (d.open = true));
});
$("#settings-collapse-all").addEventListener("click", () => {
  OPEN_SECTIONS.clear();
  $("#tab-settings").querySelectorAll("details.sec").forEach((d) => (d.open = false));
});

$("#logs-refresh").addEventListener("click", refreshLogs);
$("#logs-view-close").addEventListener("click", () => $("#logs-view-card").classList.add("hidden"));

/* ---------- restart with the keep-session choice ---------- */

$("#btn-restart").addEventListener("click", () => {
  const root = $("#modal-root");
  root.innerHTML =
    '<div class="modal-bg"><div class="modal">' +
    "<h3 style='margin-top:0'>Restart BBSFirewall?</h3>" +
    "<p class='muted'>Active telnet/SSH connections will drop. The firewall comes back in a few seconds.</p>" +
    "<label class='row' style='font-weight:400;gap:8px'>" +
    "<input type='checkbox' id='keep-session' checked style='width:auto'> Stay signed in after restart</label>" +
    "<div class='row' style='margin-top:18px;justify-content:flex-end'>" +
    "<button id='rs-cancel'>Cancel</button>" +
    "<button class='danger' id='rs-go'>Restart now</button></div>" +
    "</div></div>";
  $("#rs-cancel").onclick = () => (root.innerHTML = "");
  $("#rs-go").onclick = async () => {
    const keep = $("#keep-session").checked;
    root.innerHTML = "";
    notice("warn", "Restarting…");
    $("#btn-restart").disabled = true;
    const r = await api("api/restart", { keepSession: keep });
    const d = r.data || {};
    if (!(r.ok && d.ok)) {
      $("#btn-restart").disabled = false;
      notice("err", d.error || "Restart failed.");
      return;
    }
    if (!d.restarting) { notice("warn", d.message || "pm2 not available."); $("#btn-restart").disabled = false; return; }
    if (!d.keepSession) { notice("ok", "Restarting — you will be signed out."); setTimeout(() => (location.href = "login"), 3000); return; }
    waitForReconnect();
  };
});

async function waitForReconnect() {
  notice("warn", "Restarting — waiting for the editor to come back…");
  const deadline = Date.now() + 60000;
  await new Promise((r) => setTimeout(r, 3000));
  while (Date.now() < deadline) {
    try {
      const r = await fetch("api/config", { headers: { "X-CSRF-Token": CSRF }, cache: "no-store" });
      if (r.status === 200) { notice("ok", "Reconnected."); location.reload(); return; }
      if (r.status === 401) { location.href = "login"; return; }
    } catch (e) { /* still down */ }
    await new Promise((r) => setTimeout(r, 2000));
  }
  notice("err", "Editor did not come back within 60s. Reload the page manually.");
  $("#btn-restart").disabled = false;
}

async function doLogout() {
  await api("logout", {});
  location.href = "login";
}

/* ---------- header user menu ---------- */
const userMenuPanel = $("#user-menu-panel");
const userMenuTrigger = $("#user-menu-trigger");
function closeUserMenu() {
  userMenuPanel.classList.add("hidden");
  userMenuTrigger.setAttribute("aria-expanded", "false");
}
function toggleUserMenu() {
  const willOpen = userMenuPanel.classList.contains("hidden");
  userMenuPanel.classList.toggle("hidden", !willOpen);
  userMenuTrigger.setAttribute("aria-expanded", String(willOpen));
}
userMenuTrigger.addEventListener("click", (e) => { e.stopPropagation(); toggleUserMenu(); });
document.addEventListener("click", (e) => {
  if (!$("#user-menu").contains(e.target)) closeUserMenu();
});
document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeUserMenu(); });
$("#menu-logout").addEventListener("click", () => { closeUserMenu(); doLogout(); });
$("#menu-security").addEventListener("click", () => { closeUserMenu(); openSecuritySettings(); });

/* ---------- vendored QR encoder (MFA setup) ----------
   QR Code Generator for JavaScript, Copyright (c) 2009 Kazuhiko Arase,
   http://www.d-project.com/, MIT licensed
   (http://www.opensource.org/licenses/mit-license.php). 'QR Code' is a
   registered trademark of DENSO WAVE INCORPORATED. Vendored and trimmed to
   byte-mode + auto-version only (no numeric/alphanumeric/Kanji modes, no
   image-rendering helpers) — verified module-for-module identical output
   against the untrimmed upstream library before inlining. */
var qrcode = function() {

  var qrcode = function(typeNumber, errorCorrectionLevel) {

    var PAD0 = 0xEC;
    var PAD1 = 0x11;

    var _typeNumber = typeNumber;
    var _errorCorrectionLevel = QRErrorCorrectionLevel[errorCorrectionLevel];
    var _modules = null;
    var _moduleCount = 0;
    var _dataCache = null;
    var _dataList = [];

    var _this = {};

    var makeImpl = function(test, maskPattern) {

      _moduleCount = _typeNumber * 4 + 17;
      _modules = function(moduleCount) {
        var modules = new Array(moduleCount);
        for (var row = 0; row < moduleCount; row += 1) {
          modules[row] = new Array(moduleCount);
          for (var col = 0; col < moduleCount; col += 1) {
            modules[row][col] = null;
          }
        }
        return modules;
      }(_moduleCount);

      setupPositionProbePattern(0, 0);
      setupPositionProbePattern(_moduleCount - 7, 0);
      setupPositionProbePattern(0, _moduleCount - 7);
      setupPositionAdjustPattern();
      setupTimingPattern();
      setupTypeInfo(test, maskPattern);

      if (_typeNumber >= 7) {
        setupTypeNumber(test);
      }

      if (_dataCache == null) {
        _dataCache = createData(_typeNumber, _errorCorrectionLevel, _dataList);
      }

      mapData(_dataCache, maskPattern);
    };

    var setupPositionProbePattern = function(row, col) {

      for (var r = -1; r <= 7; r += 1) {

        if (row + r <= -1 || _moduleCount <= row + r) continue;

        for (var c = -1; c <= 7; c += 1) {

          if (col + c <= -1 || _moduleCount <= col + c) continue;

          if ( (0 <= r && r <= 6 && (c == 0 || c == 6) )
              || (0 <= c && c <= 6 && (r == 0 || r == 6) )
              || (2 <= r && r <= 4 && 2 <= c && c <= 4) ) {
            _modules[row + r][col + c] = true;
          } else {
            _modules[row + r][col + c] = false;
          }
        }
      }
    };

    var getBestMaskPattern = function() {

      var minLostPoint = 0;
      var pattern = 0;

      for (var i = 0; i < 8; i += 1) {

        makeImpl(true, i);

        var lostPoint = QRUtil.getLostPoint(_this);

        if (i == 0 || minLostPoint > lostPoint) {
          minLostPoint = lostPoint;
          pattern = i;
        }
      }

      return pattern;
    };

    var setupTimingPattern = function() {

      for (var r = 8; r < _moduleCount - 8; r += 1) {
        if (_modules[r][6] != null) {
          continue;
        }
        _modules[r][6] = (r % 2 == 0);
      }

      for (var c = 8; c < _moduleCount - 8; c += 1) {
        if (_modules[6][c] != null) {
          continue;
        }
        _modules[6][c] = (c % 2 == 0);
      }
    };

    var setupPositionAdjustPattern = function() {

      var pos = QRUtil.getPatternPosition(_typeNumber);

      for (var i = 0; i < pos.length; i += 1) {

        for (var j = 0; j < pos.length; j += 1) {

          var row = pos[i];
          var col = pos[j];

          if (_modules[row][col] != null) {
            continue;
          }

          for (var r = -2; r <= 2; r += 1) {

            for (var c = -2; c <= 2; c += 1) {

              if (r == -2 || r == 2 || c == -2 || c == 2
                  || (r == 0 && c == 0) ) {
                _modules[row + r][col + c] = true;
              } else {
                _modules[row + r][col + c] = false;
              }
            }
          }
        }
      }
    };

    var setupTypeNumber = function(test) {

      var bits = QRUtil.getBCHTypeNumber(_typeNumber);

      for (var i = 0; i < 18; i += 1) {
        var mod = (!test && ( (bits >> i) & 1) == 1);
        _modules[Math.floor(i / 3)][i % 3 + _moduleCount - 8 - 3] = mod;
      }

      for (var i = 0; i < 18; i += 1) {
        var mod = (!test && ( (bits >> i) & 1) == 1);
        _modules[i % 3 + _moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
      }
    };

    var setupTypeInfo = function(test, maskPattern) {

      var data = (_errorCorrectionLevel << 3) | maskPattern;
      var bits = QRUtil.getBCHTypeInfo(data);

      // vertical
      for (var i = 0; i < 15; i += 1) {

        var mod = (!test && ( (bits >> i) & 1) == 1);

        if (i < 6) {
          _modules[i][8] = mod;
        } else if (i < 8) {
          _modules[i + 1][8] = mod;
        } else {
          _modules[_moduleCount - 15 + i][8] = mod;
        }
      }

      // horizontal
      for (var i = 0; i < 15; i += 1) {

        var mod = (!test && ( (bits >> i) & 1) == 1);

        if (i < 8) {
          _modules[8][_moduleCount - i - 1] = mod;
        } else if (i < 9) {
          _modules[8][15 - i - 1 + 1] = mod;
        } else {
          _modules[8][15 - i - 1] = mod;
        }
      }

      // fixed module
      _modules[_moduleCount - 8][8] = (!test);
    };

    var mapData = function(data, maskPattern) {

      var inc = -1;
      var row = _moduleCount - 1;
      var bitIndex = 7;
      var byteIndex = 0;
      var maskFunc = QRUtil.getMaskFunction(maskPattern);

      for (var col = _moduleCount - 1; col > 0; col -= 2) {

        if (col == 6) col -= 1;

        while (true) {

          for (var c = 0; c < 2; c += 1) {

            if (_modules[row][col - c] == null) {

              var dark = false;

              if (byteIndex < data.length) {
                dark = ( ( (data[byteIndex] >>> bitIndex) & 1) == 1);
              }

              var mask = maskFunc(row, col - c);

              if (mask) {
                dark = !dark;
              }

              _modules[row][col - c] = dark;
              bitIndex -= 1;

              if (bitIndex == -1) {
                byteIndex += 1;
                bitIndex = 7;
              }
            }
          }

          row += inc;

          if (row < 0 || _moduleCount <= row) {
            row -= inc;
            inc = -inc;
            break;
          }
        }
      }
    };

    var createBytes = function(buffer, rsBlocks) {

      var offset = 0;

      var maxDcCount = 0;
      var maxEcCount = 0;

      var dcdata = new Array(rsBlocks.length);
      var ecdata = new Array(rsBlocks.length);

      for (var r = 0; r < rsBlocks.length; r += 1) {

        var dcCount = rsBlocks[r].dataCount;
        var ecCount = rsBlocks[r].totalCount - dcCount;

        maxDcCount = Math.max(maxDcCount, dcCount);
        maxEcCount = Math.max(maxEcCount, ecCount);

        dcdata[r] = new Array(dcCount);

        for (var i = 0; i < dcdata[r].length; i += 1) {
          dcdata[r][i] = 0xff & buffer.getBuffer()[i + offset];
        }
        offset += dcCount;

        var rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
        var rawPoly = qrPolynomial(dcdata[r], rsPoly.getLength() - 1);

        var modPoly = rawPoly.mod(rsPoly);
        ecdata[r] = new Array(rsPoly.getLength() - 1);
        for (var i = 0; i < ecdata[r].length; i += 1) {
          var modIndex = i + modPoly.getLength() - ecdata[r].length;
          ecdata[r][i] = (modIndex >= 0)? modPoly.getAt(modIndex) : 0;
        }
      }

      var totalCodeCount = 0;
      for (var i = 0; i < rsBlocks.length; i += 1) {
        totalCodeCount += rsBlocks[i].totalCount;
      }

      var data = new Array(totalCodeCount);
      var index = 0;

      for (var i = 0; i < maxDcCount; i += 1) {
        for (var r = 0; r < rsBlocks.length; r += 1) {
          if (i < dcdata[r].length) {
            data[index] = dcdata[r][i];
            index += 1;
          }
        }
      }

      for (var i = 0; i < maxEcCount; i += 1) {
        for (var r = 0; r < rsBlocks.length; r += 1) {
          if (i < ecdata[r].length) {
            data[index] = ecdata[r][i];
            index += 1;
          }
        }
      }

      return data;
    };

    var createData = function(typeNumber, errorCorrectionLevel, dataList) {

      var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, errorCorrectionLevel);

      var buffer = qrBitBuffer();

      for (var i = 0; i < dataList.length; i += 1) {
        var data = dataList[i];
        buffer.put(data.getMode(), 4);
        buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );
        data.write(buffer);
      }

      // calc num max data.
      var totalDataCount = 0;
      for (var i = 0; i < rsBlocks.length; i += 1) {
        totalDataCount += rsBlocks[i].dataCount;
      }

      if (buffer.getLengthInBits() > totalDataCount * 8) {
        throw 'code length overflow. ('
          + buffer.getLengthInBits()
          + '>'
          + totalDataCount * 8
          + ')';
      }

      // end code
      if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
        buffer.put(0, 4);
      }

      // padding
      while (buffer.getLengthInBits() % 8 != 0) {
        buffer.putBit(false);
      }

      // padding
      while (true) {

        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD0, 8);

        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD1, 8);
      }

      return createBytes(buffer, rsBlocks);
    };

    // Byte mode only — this app only ever feeds it an otpauth:// URI.
    _this.addData = function(data) {
      var newData = qr8BitByte(data);
      _dataList.push(newData);
      _dataCache = null;
    };

    _this.isDark = function(row, col) {
      if (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {
        throw row + ',' + col;
      }
      return _modules[row][col];
    };

    _this.getModuleCount = function() {
      return _moduleCount;
    };

    _this.make = function() {
      if (_typeNumber < 1) {
        var typeNumber = 1;

        for (; typeNumber < 40; typeNumber++) {
          var rsBlocks = QRRSBlock.getRSBlocks(typeNumber, _errorCorrectionLevel);
          var buffer = qrBitBuffer();

          for (var i = 0; i < _dataList.length; i++) {
            var data = _dataList[i];
            buffer.put(data.getMode(), 4);
            buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber) );
            data.write(buffer);
          }

          var totalDataCount = 0;
          for (var i = 0; i < rsBlocks.length; i++) {
            totalDataCount += rsBlocks[i].dataCount;
          }

          if (buffer.getLengthInBits() <= totalDataCount * 8) {
            break;
          }
        }

        _typeNumber = typeNumber;
      }

      makeImpl(false, getBestMaskPattern() );
    };

    return _this;
  };

  qrcode.stringToBytes = function(s) {
    var bytes = [];
    for (var i = 0; i < s.length; i += 1) {
      var c = s.charCodeAt(i);
      bytes.push(c & 0xff);
    }
    return bytes;
  };

  var QRMode = {
    MODE_NUMBER :    1 << 0,
    MODE_ALPHA_NUM : 1 << 1,
    MODE_8BIT_BYTE : 1 << 2,
    MODE_KANJI :     1 << 3
  };

  var QRErrorCorrectionLevel = {
    L : 1,
    M : 0,
    Q : 3,
    H : 2
  };

  var QRMaskPattern = {
    PATTERN000 : 0,
    PATTERN001 : 1,
    PATTERN010 : 2,
    PATTERN011 : 3,
    PATTERN100 : 4,
    PATTERN101 : 5,
    PATTERN110 : 6,
    PATTERN111 : 7
  };

  var QRUtil = function() {

    var PATTERN_POSITION_TABLE = [
      [],
      [6, 18],
      [6, 22],
      [6, 26],
      [6, 30],
      [6, 34],
      [6, 22, 38],
      [6, 24, 42],
      [6, 26, 46],
      [6, 28, 50],
      [6, 30, 54],
      [6, 32, 58],
      [6, 34, 62],
      [6, 26, 46, 66],
      [6, 26, 48, 70],
      [6, 26, 50, 74],
      [6, 30, 54, 78],
      [6, 30, 56, 82],
      [6, 30, 58, 86],
      [6, 34, 62, 90],
      [6, 28, 50, 72, 94],
      [6, 26, 50, 74, 98],
      [6, 30, 54, 78, 102],
      [6, 28, 54, 80, 106],
      [6, 32, 58, 84, 110],
      [6, 30, 58, 86, 114],
      [6, 34, 62, 90, 118],
      [6, 26, 50, 74, 98, 122],
      [6, 30, 54, 78, 102, 126],
      [6, 26, 52, 78, 104, 130],
      [6, 30, 56, 82, 108, 134],
      [6, 34, 60, 86, 112, 138],
      [6, 30, 58, 86, 114, 142],
      [6, 34, 62, 90, 118, 146],
      [6, 30, 54, 78, 102, 126, 150],
      [6, 24, 50, 76, 102, 128, 154],
      [6, 28, 54, 80, 106, 132, 158],
      [6, 32, 58, 84, 110, 136, 162],
      [6, 26, 54, 82, 110, 138, 166],
      [6, 30, 58, 86, 114, 142, 170]
    ];
    var G15 = (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0);
    var G18 = (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0);
    var G15_MASK = (1 << 14) | (1 << 12) | (1 << 10) | (1 << 4) | (1 << 1);

    var _this = {};

    var getBCHDigit = function(data) {
      var digit = 0;
      while (data != 0) {
        digit += 1;
        data >>>= 1;
      }
      return digit;
    };

    _this.getBCHTypeInfo = function(data) {
      var d = data << 10;
      while (getBCHDigit(d) - getBCHDigit(G15) >= 0) {
        d ^= (G15 << (getBCHDigit(d) - getBCHDigit(G15) ) );
      }
      return ( (data << 10) | d) ^ G15_MASK;
    };

    _this.getBCHTypeNumber = function(data) {
      var d = data << 12;
      while (getBCHDigit(d) - getBCHDigit(G18) >= 0) {
        d ^= (G18 << (getBCHDigit(d) - getBCHDigit(G18) ) );
      }
      return (data << 12) | d;
    };

    _this.getPatternPosition = function(typeNumber) {
      return PATTERN_POSITION_TABLE[typeNumber - 1];
    };

    _this.getMaskFunction = function(maskPattern) {

      switch (maskPattern) {

      case QRMaskPattern.PATTERN000 :
        return function(i, j) { return (i + j) % 2 == 0; };
      case QRMaskPattern.PATTERN001 :
        return function(i, j) { return i % 2 == 0; };
      case QRMaskPattern.PATTERN010 :
        return function(i, j) { return j % 3 == 0; };
      case QRMaskPattern.PATTERN011 :
        return function(i, j) { return (i + j) % 3 == 0; };
      case QRMaskPattern.PATTERN100 :
        return function(i, j) { return (Math.floor(i / 2) + Math.floor(j / 3) ) % 2 == 0; };
      case QRMaskPattern.PATTERN101 :
        return function(i, j) { return (i * j) % 2 + (i * j) % 3 == 0; };
      case QRMaskPattern.PATTERN110 :
        return function(i, j) { return ( (i * j) % 2 + (i * j) % 3) % 2 == 0; };
      case QRMaskPattern.PATTERN111 :
        return function(i, j) { return ( (i * j) % 3 + (i + j) % 2) % 2 == 0; };

      default :
        throw 'bad maskPattern:' + maskPattern;
      }
    };

    _this.getErrorCorrectPolynomial = function(errorCorrectLength) {
      var a = qrPolynomial([1], 0);
      for (var i = 0; i < errorCorrectLength; i += 1) {
        a = a.multiply(qrPolynomial([1, QRMath.gexp(i)], 0) );
      }
      return a;
    };

    _this.getLengthInBits = function(mode, type) {

      if (1 <= type && type < 10) {

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 10;
        case QRMode.MODE_ALPHA_NUM : return 9;
        case QRMode.MODE_8BIT_BYTE : return 8;
        case QRMode.MODE_KANJI     : return 8;
        default :
          throw 'mode:' + mode;
        }

      } else if (type < 27) {

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 12;
        case QRMode.MODE_ALPHA_NUM : return 11;
        case QRMode.MODE_8BIT_BYTE : return 16;
        case QRMode.MODE_KANJI     : return 10;
        default :
          throw 'mode:' + mode;
        }

      } else if (type < 41) {

        switch(mode) {
        case QRMode.MODE_NUMBER    : return 14;
        case QRMode.MODE_ALPHA_NUM : return 13;
        case QRMode.MODE_8BIT_BYTE : return 16;
        case QRMode.MODE_KANJI     : return 12;
        default :
          throw 'mode:' + mode;
        }

      } else {
        throw 'type:' + type;
      }
    };

    _this.getLostPoint = function(qrcode) {

      var moduleCount = qrcode.getModuleCount();

      var lostPoint = 0;

      // LEVEL1

      for (var row = 0; row < moduleCount; row += 1) {
        for (var col = 0; col < moduleCount; col += 1) {

          var sameCount = 0;
          var dark = qrcode.isDark(row, col);

          for (var r = -1; r <= 1; r += 1) {

            if (row + r < 0 || moduleCount <= row + r) {
              continue;
            }

            for (var c = -1; c <= 1; c += 1) {

              if (col + c < 0 || moduleCount <= col + c) {
                continue;
              }

              if (r == 0 && c == 0) {
                continue;
              }

              if (dark == qrcode.isDark(row + r, col + c) ) {
                sameCount += 1;
              }
            }
          }

          if (sameCount > 5) {
            lostPoint += (3 + sameCount - 5);
          }
        }
      };

      // LEVEL2

      for (var row = 0; row < moduleCount - 1; row += 1) {
        for (var col = 0; col < moduleCount - 1; col += 1) {
          var count = 0;
          if (qrcode.isDark(row, col) ) count += 1;
          if (qrcode.isDark(row + 1, col) ) count += 1;
          if (qrcode.isDark(row, col + 1) ) count += 1;
          if (qrcode.isDark(row + 1, col + 1) ) count += 1;
          if (count == 0 || count == 4) {
            lostPoint += 3;
          }
        }
      }

      // LEVEL3

      for (var row = 0; row < moduleCount; row += 1) {
        for (var col = 0; col < moduleCount - 6; col += 1) {
          if (qrcode.isDark(row, col)
              && !qrcode.isDark(row, col + 1)
              &&  qrcode.isDark(row, col + 2)
              &&  qrcode.isDark(row, col + 3)
              &&  qrcode.isDark(row, col + 4)
              && !qrcode.isDark(row, col + 5)
              &&  qrcode.isDark(row, col + 6) ) {
            lostPoint += 40;
          }
        }
      }

      for (var col = 0; col < moduleCount; col += 1) {
        for (var row = 0; row < moduleCount - 6; row += 1) {
          if (qrcode.isDark(row, col)
              && !qrcode.isDark(row + 1, col)
              &&  qrcode.isDark(row + 2, col)
              &&  qrcode.isDark(row + 3, col)
              &&  qrcode.isDark(row + 4, col)
              && !qrcode.isDark(row + 5, col)
              &&  qrcode.isDark(row + 6, col) ) {
            lostPoint += 40;
          }
        }
      }

      // LEVEL4

      var darkCount = 0;

      for (var col = 0; col < moduleCount; col += 1) {
        for (var row = 0; row < moduleCount; row += 1) {
          if (qrcode.isDark(row, col) ) {
            darkCount += 1;
          }
        }
      }

      var ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
      lostPoint += ratio * 10;

      return lostPoint;
    };

    return _this;
  }();

  var QRMath = function() {

    var EXP_TABLE = new Array(256);
    var LOG_TABLE = new Array(256);

    // initialize tables
    for (var i = 0; i < 8; i += 1) {
      EXP_TABLE[i] = 1 << i;
    }
    for (var i = 8; i < 256; i += 1) {
      EXP_TABLE[i] = EXP_TABLE[i - 4]
        ^ EXP_TABLE[i - 5]
        ^ EXP_TABLE[i - 6]
        ^ EXP_TABLE[i - 8];
    }
    for (var i = 0; i < 255; i += 1) {
      LOG_TABLE[EXP_TABLE[i] ] = i;
    }

    var _this = {};

    _this.glog = function(n) {

      if (n < 1) {
        throw 'glog(' + n + ')';
      }

      return LOG_TABLE[n];
    };

    _this.gexp = function(n) {

      while (n < 0) {
        n += 255;
      }

      while (n >= 256) {
        n -= 255;
      }

      return EXP_TABLE[n];
    };

    return _this;
  }();

  function qrPolynomial(num, shift) {

    if (typeof num.length == 'undefined') {
      throw num.length + '/' + shift;
    }

    var _num = function() {
      var offset = 0;
      while (offset < num.length && num[offset] == 0) {
        offset += 1;
      }
      var _num = new Array(num.length - offset + shift);
      for (var i = 0; i < num.length - offset; i += 1) {
        _num[i] = num[i + offset];
      }
      return _num;
    }();

    var _this = {};

    _this.getAt = function(index) {
      return _num[index];
    };

    _this.getLength = function() {
      return _num.length;
    };

    _this.multiply = function(e) {

      var num = new Array(_this.getLength() + e.getLength() - 1);

      for (var i = 0; i < _this.getLength(); i += 1) {
        for (var j = 0; j < e.getLength(); j += 1) {
          num[i + j] ^= QRMath.gexp(QRMath.glog(_this.getAt(i) ) + QRMath.glog(e.getAt(j) ) );
        }
      }

      return qrPolynomial(num, 0);
    };

    _this.mod = function(e) {

      if (_this.getLength() - e.getLength() < 0) {
        return _this;
      }

      var ratio = QRMath.glog(_this.getAt(0) ) - QRMath.glog(e.getAt(0) );

      var num = new Array(_this.getLength() );
      for (var i = 0; i < _this.getLength(); i += 1) {
        num[i] = _this.getAt(i);
      }

      for (var i = 0; i < e.getLength(); i += 1) {
        num[i] ^= QRMath.gexp(QRMath.glog(e.getAt(i) ) + ratio);
      }

      // recursive call
      return qrPolynomial(num, 0).mod(e);
    };

    return _this;
  };

  var QRRSBlock = function() {

    var RS_BLOCK_TABLE = [

      // L
      // M
      // Q
      // H

      // 1
      [1, 26, 19],
      [1, 26, 16],
      [1, 26, 13],
      [1, 26, 9],

      // 2
      [1, 44, 34],
      [1, 44, 28],
      [1, 44, 22],
      [1, 44, 16],

      // 3
      [1, 70, 55],
      [1, 70, 44],
      [2, 35, 17],
      [2, 35, 13],

      // 4
      [1, 100, 80],
      [2, 50, 32],
      [2, 50, 24],
      [4, 25, 9],

      // 5
      [1, 134, 108],
      [2, 67, 43],
      [2, 33, 15, 2, 34, 16],
      [2, 33, 11, 2, 34, 12],

      // 6
      [2, 86, 68],
      [4, 43, 27],
      [4, 43, 19],
      [4, 43, 15],

      // 7
      [2, 98, 78],
      [4, 49, 31],
      [2, 32, 14, 4, 33, 15],
      [4, 39, 13, 1, 40, 14],

      // 8
      [2, 121, 97],
      [2, 60, 38, 2, 61, 39],
      [4, 40, 18, 2, 41, 19],
      [4, 40, 14, 2, 41, 15],

      // 9
      [2, 146, 116],
      [3, 58, 36, 2, 59, 37],
      [4, 36, 16, 4, 37, 17],
      [4, 36, 12, 4, 37, 13],

      // 10
      [2, 86, 68, 2, 87, 69],
      [4, 69, 43, 1, 70, 44],
      [6, 43, 19, 2, 44, 20],
      [6, 43, 15, 2, 44, 16],

      // 11
      [4, 101, 81],
      [1, 80, 50, 4, 81, 51],
      [4, 50, 22, 4, 51, 23],
      [3, 36, 12, 8, 37, 13],

      // 12
      [2, 116, 92, 2, 117, 93],
      [6, 58, 36, 2, 59, 37],
      [4, 46, 20, 6, 47, 21],
      [7, 42, 14, 4, 43, 15],

      // 13
      [4, 133, 107],
      [8, 59, 37, 1, 60, 38],
      [8, 44, 20, 4, 45, 21],
      [12, 33, 11, 4, 34, 12],

      // 14
      [3, 145, 115, 1, 146, 116],
      [4, 64, 40, 5, 65, 41],
      [11, 36, 16, 5, 37, 17],
      [11, 36, 12, 5, 37, 13],

      // 15
      [5, 109, 87, 1, 110, 88],
      [5, 65, 41, 5, 66, 42],
      [5, 54, 24, 7, 55, 25],
      [11, 36, 12, 7, 37, 13],

      // 16
      [5, 122, 98, 1, 123, 99],
      [7, 73, 45, 3, 74, 46],
      [15, 43, 19, 2, 44, 20],
      [3, 45, 15, 13, 46, 16],

      // 17
      [1, 135, 107, 5, 136, 108],
      [10, 74, 46, 1, 75, 47],
      [1, 50, 22, 15, 51, 23],
      [2, 42, 14, 17, 43, 15],

      // 18
      [5, 150, 120, 1, 151, 121],
      [9, 69, 43, 4, 70, 44],
      [17, 50, 22, 1, 51, 23],
      [2, 42, 14, 19, 43, 15],

      // 19
      [3, 141, 113, 4, 142, 114],
      [3, 70, 44, 11, 71, 45],
      [17, 47, 21, 4, 48, 22],
      [9, 39, 13, 16, 40, 14],

      // 20
      [3, 135, 107, 5, 136, 108],
      [3, 67, 41, 13, 68, 42],
      [15, 54, 24, 5, 55, 25],
      [15, 43, 15, 10, 44, 16],

      // 21
      [4, 144, 116, 4, 145, 117],
      [17, 68, 42],
      [17, 50, 22, 6, 51, 23],
      [19, 46, 16, 6, 47, 17],

      // 22
      [2, 139, 111, 7, 140, 112],
      [17, 74, 46],
      [7, 54, 24, 16, 55, 25],
      [34, 37, 13],

      // 23
      [4, 151, 121, 5, 152, 122],
      [4, 75, 47, 14, 76, 48],
      [11, 54, 24, 14, 55, 25],
      [16, 45, 15, 14, 46, 16],

      // 24
      [6, 147, 117, 4, 148, 118],
      [6, 73, 45, 14, 74, 46],
      [11, 54, 24, 16, 55, 25],
      [30, 46, 16, 2, 47, 17],

      // 25
      [8, 132, 106, 4, 133, 107],
      [8, 75, 47, 13, 76, 48],
      [7, 54, 24, 22, 55, 25],
      [22, 45, 15, 13, 46, 16],

      // 26
      [10, 142, 114, 2, 143, 115],
      [19, 74, 46, 4, 75, 47],
      [28, 50, 22, 6, 51, 23],
      [33, 46, 16, 4, 47, 17],

      // 27
      [8, 152, 122, 4, 153, 123],
      [22, 73, 45, 3, 74, 46],
      [8, 53, 23, 26, 54, 24],
      [12, 45, 15, 28, 46, 16],

      // 28
      [3, 147, 117, 10, 148, 118],
      [3, 73, 45, 23, 74, 46],
      [4, 54, 24, 31, 55, 25],
      [11, 45, 15, 31, 46, 16],

      // 29
      [7, 146, 116, 7, 147, 117],
      [21, 73, 45, 7, 74, 46],
      [1, 53, 23, 37, 54, 24],
      [19, 45, 15, 26, 46, 16],

      // 30
      [5, 145, 115, 10, 146, 116],
      [19, 75, 47, 10, 76, 48],
      [15, 54, 24, 25, 55, 25],
      [23, 45, 15, 25, 46, 16],

      // 31
      [13, 145, 115, 3, 146, 116],
      [2, 74, 46, 29, 75, 47],
      [42, 54, 24, 1, 55, 25],
      [23, 45, 15, 28, 46, 16],

      // 32
      [17, 145, 115],
      [10, 74, 46, 23, 75, 47],
      [10, 54, 24, 35, 55, 25],
      [19, 45, 15, 35, 46, 16],

      // 33
      [17, 145, 115, 1, 146, 116],
      [14, 74, 46, 21, 75, 47],
      [29, 54, 24, 19, 55, 25],
      [11, 45, 15, 46, 46, 16],

      // 34
      [13, 145, 115, 6, 146, 116],
      [14, 74, 46, 23, 75, 47],
      [44, 54, 24, 7, 55, 25],
      [59, 46, 16, 1, 47, 17],

      // 35
      [12, 151, 121, 7, 152, 122],
      [12, 75, 47, 26, 76, 48],
      [39, 54, 24, 14, 55, 25],
      [22, 45, 15, 41, 46, 16],

      // 36
      [6, 151, 121, 14, 152, 122],
      [6, 75, 47, 34, 76, 48],
      [46, 54, 24, 10, 55, 25],
      [2, 45, 15, 64, 46, 16],

      // 37
      [17, 152, 122, 4, 153, 123],
      [29, 74, 46, 14, 75, 47],
      [49, 54, 24, 10, 55, 25],
      [24, 45, 15, 46, 46, 16],

      // 38
      [4, 152, 122, 18, 153, 123],
      [13, 74, 46, 32, 75, 47],
      [48, 54, 24, 14, 55, 25],
      [42, 45, 15, 32, 46, 16],

      // 39
      [20, 147, 117, 4, 148, 118],
      [40, 75, 47, 7, 76, 48],
      [43, 54, 24, 22, 55, 25],
      [10, 45, 15, 67, 46, 16],

      // 40
      [19, 148, 118, 6, 149, 119],
      [18, 75, 47, 31, 76, 48],
      [34, 54, 24, 34, 55, 25],
      [20, 45, 15, 61, 46, 16]
    ];

    var qrRSBlock = function(totalCount, dataCount) {
      var _this = {};
      _this.totalCount = totalCount;
      _this.dataCount = dataCount;
      return _this;
    };

    var _this = {};

    var getRsBlockTable = function(typeNumber, errorCorrectionLevel) {

      switch(errorCorrectionLevel) {
      case QRErrorCorrectionLevel.L :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
      case QRErrorCorrectionLevel.M :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
      case QRErrorCorrectionLevel.Q :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
      case QRErrorCorrectionLevel.H :
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
      default :
        return undefined;
      }
    };

    _this.getRSBlocks = function(typeNumber, errorCorrectionLevel) {

      var rsBlock = getRsBlockTable(typeNumber, errorCorrectionLevel);

      if (typeof rsBlock == 'undefined') {
        throw 'bad rs block @ typeNumber:' + typeNumber +
            '/errorCorrectionLevel:' + errorCorrectionLevel;
      }

      var length = rsBlock.length / 3;

      var list = [];

      for (var i = 0; i < length; i += 1) {

        var count = rsBlock[i * 3 + 0];
        var totalCount = rsBlock[i * 3 + 1];
        var dataCount = rsBlock[i * 3 + 2];

        for (var j = 0; j < count; j += 1) {
          list.push(qrRSBlock(totalCount, dataCount) );
        }
      }

      return list;
    };

    return _this;
  }();

  var qrBitBuffer = function() {

    var _buffer = [];
    var _length = 0;

    var _this = {};

    _this.getBuffer = function() {
      return _buffer;
    };

    _this.getAt = function(index) {
      var bufIndex = Math.floor(index / 8);
      return ( (_buffer[bufIndex] >>> (7 - index % 8) ) & 1) == 1;
    };

    _this.put = function(num, length) {
      for (var i = 0; i < length; i += 1) {
        _this.putBit( ( (num >>> (length - i - 1) ) & 1) == 1);
      }
    };

    _this.getLengthInBits = function() {
      return _length;
    };

    _this.putBit = function(bit) {

      var bufIndex = Math.floor(_length / 8);
      if (_buffer.length <= bufIndex) {
        _buffer.push(0);
      }

      if (bit) {
        _buffer[bufIndex] |= (0x80 >>> (_length % 8) );
      }

      _length += 1;
    };

    return _this;
  };

  var qr8BitByte = function(data) {

    var _mode = QRMode.MODE_8BIT_BYTE;
    var _bytes = qrcode.stringToBytes(data);

    var _this = {};

    _this.getMode = function() {
      return _mode;
    };

    _this.getLength = function() {
      return _bytes.length;
    };

    _this.write = function(buffer) {
      for (var i = 0; i < _bytes.length; i += 1) {
        buffer.put(_bytes[i], 8);
      }
    };

    return _this;
  };

  return qrcode;
}();

function qrToSvg(qr) {
  var n = qr.getModuleCount();
  var scale = 5, margin = 4;
  var size = (n + margin * 2) * scale;
  var path = "";
  for (var r = 0; r < n; r += 1) {
    for (var c = 0; c < n; c += 1) {
      if (qr.isDark(r, c)) {
        var x = (c + margin) * scale, y = (r + margin) * scale;
        path += "M" + x + "," + y + "h" + scale + "v" + scale + "h-" + scale + "z";
      }
    }
  }
  return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ' + size + ' ' + size +
    '" width="' + size + '" height="' + size + '" role="img" aria-label="MFA setup QR code">' +
    '<rect width="100%" height="100%" fill="#fff"/><path d="' + path + '" fill="#000"/></svg>';
}

/* ---------- Security Settings (password, MFA, whitelist-my-ip) ---------- */

function closeModal() { $("#modal-root").innerHTML = ""; }
function modalOpen(html) {
  $("#modal-root").innerHTML = '<div class="modal-bg"><div class="modal" style="max-width:480px">' + html + "</div></div>";
}
function secNotice(msg, kind) {
  var el = $("#sec-notice");
  if (el) el.innerHTML = msg ? '<div class="notice ' + (kind || "err") + '">' + esc(msg) + "</div>" : "";
}

async function openSecuritySettings() {
  try {
    var res = await fetch("api/config", { headers: { "X-CSRF-Token": CSRF } });
    if (res.status === 401) { location.href = "login"; return; }
    if (res.ok) DATA = await res.json();
  } catch (e) { /* fall back to whatever DATA already has */ }
  renderSecurityMain();
}

function renderSecurityMain() {
  var st = DATA.status || {};
  modalOpen(
    '<h3 style="margin-top:0">Security Settings</h3>' +
    '<div id="sec-notice"></div>' +
    '<h4 style="margin-bottom:6px">Change password</h4>' +
    '<div class="field"><label for="sec-cur-pw">Current password</label><input id="sec-cur-pw" type="password" autocomplete="current-password"></div>' +
    '<div class="field"><label for="sec-new-pw">New password</label><input id="sec-new-pw" type="password" autocomplete="new-password"></div>' +
    '<div class="field"><label for="sec-new-pw2">Confirm new password</label><input id="sec-new-pw2" type="password" autocomplete="new-password"></div>' +
    '<button class="primary" id="sec-change-pw" type="button">Change password</button>' +
    '<hr style="border-color:#26374a;margin:18px 0">' +
    '<h4 style="margin-bottom:6px">Two-factor authentication (MFA)</h4>' +
    '<div class="kv">' + (st.mfaEnabled
      ? "<div><b>Status</b>" + pill(true, "enabled", "") + "</div>" +
        "<div><b>Backup codes</b>" + (st.backupCodesRemaining != null ? st.backupCodesRemaining + " remaining" : "n/a") + "</div>"
      : "<div><b>Status</b>" + pill(false, "", "not enabled", true) + "</div>") +
    "</div>" +
    '<div class="row" style="margin-top:10px">' + (st.mfaEnabled
      ? '<button class="small" id="sec-mfa-regen" type="button">Regenerate backup codes</button>' +
        '<button class="small danger" id="sec-mfa-disable" type="button">Disable MFA</button>'
      : '<button class="primary" id="sec-mfa-enable" type="button">Enable MFA</button>') +
    "</div>" +
    '<hr style="border-color:#26374a;margin:18px 0">' +
    '<h4 style="margin-bottom:6px">Access</h4>' +
    '<div class="row"><button class="small" id="sec-whitelist-me" type="button">Whitelist my IP' +
      (st.ip ? " (" + esc(st.ip) + ")" : "") + "</button></div>" +
    (st.role === "master_admin" ?
      '<hr style="border-color:#26374a;margin:18px 0">' +
      '<h4 style="margin-bottom:6px">Admin accounts</h4>' +
      '<div class="row"><button class="small" id="sec-accounts" type="button">Manage admin accounts</button></div>'
      : "") +
    '<div class="row" style="margin-top:18px;justify-content:flex-end"><button id="sec-close" type="button">Close</button></div>'
  );

  $("#sec-close").addEventListener("click", closeModal);
  if (st.role === "master_admin") $("#sec-accounts").addEventListener("click", renderAccountsList);

  $("#sec-change-pw").addEventListener("click", async () => {
    var cur = $("#sec-cur-pw").value;
    var n1 = $("#sec-new-pw").value;
    var n2 = $("#sec-new-pw2").value;
    if (n1 !== n2) { secNotice("New passwords do not match."); return; }
    if (n1.length < 12) { secNotice("New password must be at least 12 characters."); return; }
    var r = await api("api/security/change-password", { currentPassword: cur, newPassword: n1 });
    if (r.ok && r.data && r.data.ok) {
      secNotice("Password changed. Other signed-in sessions have been signed out.", "ok");
      $("#sec-cur-pw").value = ""; $("#sec-new-pw").value = ""; $("#sec-new-pw2").value = "";
    } else {
      secNotice((r.data && r.data.error) || "Password change failed.");
    }
  });

  $("#sec-whitelist-me").addEventListener("click", async () => {
    var r = await api("api/security/whitelist-me", {});
    if (r.ok && r.data && r.data.ok) {
      secNotice((r.data.added ? "Added " : "Already whitelisted: ") + r.data.ip, "ok");
    } else {
      secNotice((r.data && r.data.error) || "Failed to whitelist IP.");
    }
  });

  if (st.mfaEnabled) {
    $("#sec-mfa-regen").addEventListener("click", renderMfaRegen);
    $("#sec-mfa-disable").addEventListener("click", renderMfaDisable);
  } else {
    $("#sec-mfa-enable").addEventListener("click", startMfaSetup);
  }
}

async function startMfaSetup() {
  var r = await api("api/security/mfa/setup", {});
  if (!(r.ok && r.data && r.data.ok)) { secNotice((r.data && r.data.error) || "Could not start MFA setup."); return; }
  renderMfaSetupQr(r.data.secret, r.data.otpauthUrl);
}

function renderMfaSetupQr(secret, otpauthUrl) {
  var svg = "";
  try {
    var qr = qrcode(0, "M");
    qr.addData(otpauthUrl);
    qr.make();
    svg = qrToSvg(qr);
  } catch (e) { svg = ""; }

  modalOpen(
    '<h3 style="margin-top:0">Enable MFA</h3>' +
    '<div id="sec-notice"></div>' +
    '<p class="muted">Scan this with Google Authenticator or another TOTP app, or enter the secret manually.</p>' +
    (svg ? '<div class="qr-wrap">' + svg + "</div>" : "") +
    '<div class="field"><label>Secret (manual entry)</label><div class="kv"><div><span class="muted" style="word-break:break-all">' +
      esc(secret) + "</span></div></div></div>" +
    '<div class="field"><label for="sec-mfa-code">6-digit code</label><input id="sec-mfa-code" type="text" inputmode="numeric" autocomplete="one-time-code" autofocus></div>' +
    '<div class="row" style="justify-content:flex-end">' +
    '<button id="sec-back" type="button">Back</button>' +
    '<button class="primary" id="sec-mfa-confirm" type="button">Verify &amp; enable</button>' +
    "</div>"
  );
  $("#sec-back").addEventListener("click", renderSecurityMain);
  $("#sec-mfa-confirm").addEventListener("click", async () => {
    var code = $("#sec-mfa-code").value.trim();
    var r = await api("api/security/mfa/confirm", { code: code });
    if (r.ok && r.data && r.data.ok) {
      DATA.status.mfaEnabled = true;
      renderBackupCodes(r.data.backupCodes,
        "MFA is now enabled. Save these backup codes somewhere safe — each works once, and this is the only time they'll be shown.");
    } else {
      secNotice((r.data && r.data.error) || "Invalid code.");
    }
  });
}

function renderBackupCodes(codes, introText) {
  modalOpen(
    '<h3 style="margin-top:0">Backup codes</h3>' +
    '<p class="muted">' + esc(introText) + "</p>" +
    '<div class="backup-codes">' + codes.map(function (c) { return "<div>" + esc(c) + "</div>"; }).join("") + "</div>" +
    '<label class="toggle-row" style="margin-top:14px"><input type="checkbox" id="sec-codes-ack"> I have saved these codes</label>' +
    '<div class="row" style="margin-top:12px;justify-content:flex-end">' +
    '<button class="primary" id="sec-codes-done" type="button" disabled>Done</button>' +
    "</div>"
  );
  $("#sec-codes-ack").addEventListener("change", (e) => { $("#sec-codes-done").disabled = !e.target.checked; });
  $("#sec-codes-done").addEventListener("click", () => { closeModal(); });
}

function renderMfaRegen() {
  modalOpen(
    '<h3 style="margin-top:0">Regenerate backup codes</h3>' +
    '<div id="sec-notice"></div>' +
    '<p class="muted">Old backup codes stop working immediately. Enter your current password to confirm.</p>' +
    '<div class="field"><label for="sec-regen-pw">Current password</label><input id="sec-regen-pw" type="password" autocomplete="current-password"></div>' +
    '<div class="row" style="justify-content:flex-end">' +
    '<button id="sec-back" type="button">Back</button>' +
    '<button class="primary" id="sec-regen-go" type="button">Regenerate</button>' +
    "</div>"
  );
  $("#sec-back").addEventListener("click", renderSecurityMain);
  $("#sec-regen-go").addEventListener("click", async () => {
    var pw = $("#sec-regen-pw").value;
    var r = await api("api/security/mfa/regenerate-backup-codes", { currentPassword: pw });
    if (r.ok && r.data && r.data.ok) {
      renderBackupCodes(r.data.backupCodes, "New backup codes generated. The old ones no longer work.");
    } else {
      secNotice((r.data && r.data.error) || "Failed to regenerate codes.");
    }
  });
}

function renderMfaDisable() {
  modalOpen(
    '<h3 style="margin-top:0">Disable MFA</h3>' +
    '<div id="sec-notice"></div>' +
    '<p class="muted">Requires your password and one more code (from your authenticator app or a backup code).</p>' +
    '<div class="field"><label for="sec-dis-pw">Current password</label><input id="sec-dis-pw" type="password" autocomplete="current-password"></div>' +
    '<div class="field"><label for="sec-dis-code">6-digit code or backup code</label><input id="sec-dis-code" type="text" autocomplete="one-time-code"></div>' +
    '<div class="row" style="justify-content:flex-end">' +
    '<button id="sec-back" type="button">Back</button>' +
    '<button class="danger" id="sec-dis-go" type="button">Disable MFA</button>' +
    "</div>"
  );
  $("#sec-back").addEventListener("click", renderSecurityMain);
  $("#sec-dis-go").addEventListener("click", async () => {
    var pw = $("#sec-dis-pw").value;
    var raw = $("#sec-dis-code").value.trim();
    var body = { currentPassword: pw };
    if (raw.indexOf("-") !== -1) body.backupCode = raw; else body.code = raw;
    var r = await api("api/security/mfa/disable", body);
    if (r.ok && r.data && r.data.ok) {
      DATA.status.mfaEnabled = false;
      notice("ok", "MFA disabled.");
      renderSecurityMain();
    } else {
      secNotice((r.data && r.data.error) || "Failed to disable MFA.");
    }
  });
}

/* ---------- Admin accounts (owner only) ---------- */

async function renderAccountsList() {
  modalOpen(
    '<h3 style="margin-top:0">Admin accounts</h3>' +
    '<div id="sec-notice"></div>' +
    '<div id="accounts-table" class="muted">Loading…</div>' +
    '<div class="row" style="margin-top:14px"><button class="primary" id="acct-add" type="button">Add admin account</button></div>' +
    '<div class="row" style="margin-top:18px;justify-content:flex-end"><button id="sec-back" type="button">Back</button></div>'
  );
  $("#sec-back").addEventListener("click", renderSecurityMain);
  $("#acct-add").addEventListener("click", renderAddAccount);

  let r, d;
  try {
    r = await fetch("api/security/accounts", { headers: { "X-CSRF-Token": CSRF } });
    d = await r.json();
  } catch (e) {
    $("#accounts-table").innerHTML = '<div class="notice err">' + esc(e.message) + "</div>";
    return;
  }
  if (!r.ok) {
    $("#accounts-table").innerHTML = '<div class="notice err">' + esc((d && d.error) || "Failed to load accounts.") + "</div>";
    return;
  }
  renderAccountsTable(d.accounts || []);
}

const ROLE_LABELS = { master_admin: "Provider / Master Admin", firewall_admin: "Firewall Admin" };
function roleLabel(role) { return ROLE_LABELS[role] || role; }

function accountRow(a) {
  const isSelf = a.username === DATA.username;
  return "<tr><td>" + esc(a.username) + (isSelf ? ' <span class="muted">(you)</span>' : "") + "</td><td>" +
    esc(roleLabel(a.role)) + "</td><td>" + (a.mfaEnabled ? pill(true, "on", "") : pill(false, "", "off", true)) +
    "</td><td>" +
    '<button class="small" data-acct-mfareq="' + esc(a.username) + '" data-acct-mfareq-next="' + (a.mfaRequired ? "0" : "1") + '" type="button">' +
    (a.mfaRequired ? "Required" : "Optional") + "</button>" +
    "</td><td>" + esc(fmtDate(a.createdAt)) + "</td><td>" +
    (isSelf ? "" : '<button class="small danger" data-acct-del="' + esc(a.username) + '" data-acct-role="' + esc(a.role) + '" type="button">Delete</button>') +
    "</td></tr>";
}

function renderAccountsTable(accounts) {
  $("#accounts-table").innerHTML =
    '<div class="logtable-wrap"><table class="logtable"><thead><tr><th>Username</th><th>Role</th><th>MFA</th><th>MFA policy</th><th>Created</th><th></th></tr></thead><tbody>' +
    accounts.map(accountRow).join("") + "</tbody></table></div>";
  $("#accounts-table").querySelectorAll("[data-acct-del]").forEach((btn) => {
    btn.addEventListener("click", () => confirmDeleteAccount(btn.dataset.acctDel, btn.dataset.acctRole));
  });
  $("#accounts-table").querySelectorAll("[data-acct-mfareq]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const username = btn.dataset.acctMfareq;
      const required = btn.dataset.acctMfareqNext === "1";
      btn.disabled = true;
      const r = await api("api/security/accounts/set-mfa-required", { username: username, required: required });
      if (r.ok && r.data && r.data.ok) {
        notice("ok", 'MFA policy for "' + username + '" set to ' + (required ? "required" : "optional") + ".");
        await renderAccountsList();
      } else {
        btn.disabled = false;
        secNotice((r.data && r.data.error) || "Failed to update MFA policy.");
      }
    });
  });
}

function confirmDeleteAccount(username, role) {
  modalOpen(
    '<h3 style="margin-top:0">Delete admin account?</h3>' +
    '<p class="muted">"' + esc(username) + '" (' + esc(roleLabel(role)) + ") will lose access immediately, including any active session.</p>" +
    '<div class="row" style="margin-top:18px;justify-content:flex-end">' +
    '<button id="acctdel-cancel" type="button">Cancel</button>' +
    '<button class="danger" id="acctdel-go" type="button">Delete</button></div>'
  );
  $("#acctdel-cancel").addEventListener("click", renderAccountsList);
  $("#acctdel-go").addEventListener("click", async () => {
    const r = await api("api/security/accounts/delete", { username: username });
    await renderAccountsList();
    if (r.ok && r.data && r.data.ok) notice("ok", 'Deleted admin account "' + username + '".');
    else secNotice((r.data && r.data.error) || "Failed to delete account.");
  });
}

function renderAddAccount() {
  modalOpen(
    '<h3 style="margin-top:0">Add admin account</h3>' +
    '<div id="sec-notice"></div>' +
    '<div class="field"><label for="acct-user">Username</label><input id="acct-user" type="text" autocomplete="off"></div>' +
    '<div class="field"><label for="acct-pw">Password</label><input id="acct-pw" type="password" autocomplete="new-password"></div>' +
    '<div class="field"><label for="acct-pw2">Confirm password</label><input id="acct-pw2" type="password" autocomplete="new-password"></div>' +
    '<div class="field"><label for="acct-role">Role</label><select id="acct-role">' +
    '<option value="firewall_admin">Firewall Admin (day-to-day admin access)</option>' +
    '<option value="master_admin">Provider / Master Admin (can also manage other admin accounts)</option>' +
    "</select></div>" +
    '<label class="toggle-row"><input type="checkbox" id="acct-mfa-required"> Require MFA on this account</label>' +
    '<div class="row" style="justify-content:flex-end">' +
    '<button id="sec-back" type="button">Back</button>' +
    '<button class="primary" id="acct-create" type="button">Create</button>' +
    "</div>"
  );
  $("#sec-back").addEventListener("click", renderAccountsList);
  $("#acct-create").addEventListener("click", async () => {
    const username = $("#acct-user").value.trim();
    const pw1 = $("#acct-pw").value;
    const pw2 = $("#acct-pw2").value;
    const role = $("#acct-role").value;
    const mfaRequired = $("#acct-mfa-required").checked;
    if (!username) { secNotice("Username cannot be empty."); return; }
    if (pw1 !== pw2) { secNotice("Passwords do not match."); return; }
    if (pw1.length < 12) { secNotice("Password must be at least 12 characters."); return; }
    const r = await api("api/security/accounts/create", { username: username, password: pw1, role: role, mfaRequired: mfaRequired });
    if (r.ok && r.data && r.data.ok) {
      notice("ok", 'Admin account "' + username + '" created.');
      await renderAccountsList();
    } else {
      secNotice((r.data && r.data.error) || "Failed to create account.");
    }
  });
}

load().catch((e) => notice("err", "Failed to load: " + e.message));
</script>
</body>
</html>`;
}

module.exports = { loginPage, mfaPage, mfaSetupRequiredPage, appPage, htmlEscape };
