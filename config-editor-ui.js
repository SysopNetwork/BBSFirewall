/**
 * BBSFirewall - Config editor HTML views
 *
 * Two server-rendered pages: a login screen and the editor application shell.
 * All CSS and client JavaScript is inlined so there is no build step and no
 * static asset routes to secure. The app shell pulls its data from
 * /api/config after load and posts changes back to /api/save; the Performance
 * tab polls /api/stats; the Tools tab drives /api/geoip, /api/sshkey and
 * /api/cert.
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

const BASE_CSS = `
  * { box-sizing: border-box; }
  body { margin: 0; background: #0f1720; color: #d7e0ea;
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  a { color: #6fb3ff; }
  h1, h2, h3 { color: #f2f6fb; font-weight: 600; }
  .wrap { max-width: 960px; margin: 0 auto; padding: 24px 20px 96px; }
  .card { background: #16212e; border: 1px solid #26374a; border-radius: 10px; padding: 20px; margin-bottom: 16px; }
  .brand { display: flex; align-items: baseline; gap: 10px; margin-bottom: 18px; }
  .brand .name { font-size: 20px; font-weight: 700; color: #f2f6fb; }
  .brand .tag { font-size: 12px; color: #7f93a8; }
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
  fieldset { border: 1px solid #26374a; border-radius: 9px; margin: 0 0 18px; padding: 12px 18px 6px; }
  legend { padding: 0 8px; font-weight: 700; color: #f2f6fb; }
  .sec-help { color: #93a7bc; font-size: 12.5px; margin: 0 0 12px; }
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
`;

function loginPage(opts = {}) {
  const err = opts.error ? `<div class="notice err">${htmlEscape(opts.error)}</div>` : '';
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BBSFirewall - Config Editor</title>
<style>${BASE_CSS}</style>
</head>
<body>
<div class="wrap" style="max-width:420px;margin-top:9vh">
  <div class="brand"><span class="name">BBSFirewall</span><span class="tag">config editor</span></div>
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
</div>
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
<style>${BASE_CSS}</style>
</head>
<body>
<div class="wrap">
  <div class="brand">
    <span class="name">BBSFirewall</span>
    <span class="tag">config editor</span>
    <span class="spacer"></span>
    <span class="muted">signed in as ${user}</span>
  </div>

  <div id="notice"></div>

  <div class="tabs" id="tabs">
    <button data-tab="settings" class="active">Settings</button>
    <button data-tab="tools">Tools</button>
    <button data-tab="performance">Performance</button>
    <button data-tab="whitelist">whitelist.txt</button>
    <button data-tab="blocklist">blocklist.txt</button>
    <button data-tab="trustedhosts">trustedhosts.txt</button>
    <button data-tab="triggers">triggers.txt</button>
  </div>

  <div id="tab-settings"></div>

  <div id="tab-tools" class="hidden">
    <div class="card">
      <h3 style="margin-top:0">GeoIP database (country blocking)</h3>
      <div class="kv" id="geoip-kv"></div>
      <div class="row" style="margin-top:10px">
        <button class="primary" id="btn-geoip-dl">Download database</button>
        <button id="btn-geoip-up">Update database</button>
      </div>
      <div class="help muted">Needs <code>MAXMIND_LICENSE_KEY</code> set and saved in the Settings tab.</div>
      <div class="console hidden" id="geoip-out"></div>
    </div>

    <div class="card">
      <h3 style="margin-top:0">SSH host key (terminate mode)</h3>
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
      <h3 style="margin-top:0">TLS certificates (Let's Encrypt)</h3>
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

  ${['whitelist', 'blocklist', 'trustedhosts', 'triggers'].map((n) => `
  <div id="tab-${n}" class="hidden">
    <div class="card">
      <label for="ta-${n}">${n}.txt <span class="muted" id="path-${n}"></span></label>
      <textarea id="ta-${n}" spellcheck="false"></textarea>
      <div class="help muted" id="hint-${n}"></div>
      <div id="warn-${n}"></div>
    </div>
  </div>`).join('')}

  <p class="statline" id="statline"></p>
</div>

<div class="bar">
  <div class="inner">
    <button class="primary" id="btn-save">Save changes</button>
    <button id="btn-restart">Restart firewall</button>
    <span class="spacer"></span>
    <button class="danger" id="btn-logout">Log out</button>
  </div>
</div>

<div id="modal-root"></div>

<script nonce="${nonce}">
const CSRF = "${csrf}";
const $ = (s) => document.querySelector(s);
const el = (t, c, h) => { const e = document.createElement(t); if (c) e.className = c; if (h != null) e.innerHTML = h; return e; };
let DATA = null;
let perfTimer = null;

const HINTS = {
  whitelist: "One IP or CIDR per line. Listed IPs bypass every firewall rule.",
  blocklist: "One IP or CIDR per line. Listed IPs are refused permanently. Auto-block (blocklist mode) appends here.",
  trustedhosts: "IPv4/IPv6, one IP or CIDR per line. Only these hosts may reach this editor. Empty = nobody, after the next restart.",
  triggers: "One pattern per line. Plain text is a case-insensitive substring; /regex/flags is a JS regex. Hex and control-character escapes are supported in plain patterns for binary probes (see triggers.txt.example). A caller who sends a match in its first bytes is auto-blocked — enable it in the Auto-Block Triggers section. Applies live on save.",
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

function renderSettings() {
  const host = $("#tab-settings");
  host.innerHTML = "";
  for (const sec of DATA.sections) {
    const fs = el("fieldset");
    fs.appendChild(el("legend", null, esc(sec.name)));
    if (sec.help) fs.appendChild(el("div", "sec-help", esc(sec.help)));
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
      fs.appendChild(div);
    }
    host.appendChild(fs);
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
  for (const name of ["whitelist", "blocklist", "trustedhosts", "triggers"]) {
    const info = (DATA.files || {})[name] || {};
    $("#ta-" + name).value = info.content || "";
    $("#path-" + name).textContent = info.path ? "(" + info.path + (info.exists ? "" : " - not created yet") + ")" : "";
    $("#hint-" + name).textContent = HINTS[name] || "";
  }
  checkTrustedHosts();
}

function checkTrustedHosts() {
  const lines = $("#ta-trustedhosts").value.split(/\\r?\\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
  $("#warn-trustedhosts").innerHTML = lines.length === 0
    ? '<div class="notice warn">This list has no entries. Saving it will lock every host out of the editor after the next restart.</div>'
    : "";
}

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
      // refresh health snapshot
      const cfg = await fetch("api/config", { headers: { "X-CSRF-Token": CSRF } });
      if (cfg.ok) { DATA = await cfg.json(); renderTools(); }
    } else {
      notice("err", d.error || "Action failed — see console output in the Tools tab.");
    }
  } catch (e) {
    out.textContent = "Request failed: " + e.message;
  } finally {
    document.querySelectorAll("#tab-tools button").forEach((b) => (b.disabled = false));
  }
}

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

async function load() {
  const res = await fetch("api/config", { headers: { "X-CSRF-Token": CSRF } });
  if (res.status === 401) { location.href = "login"; return; }
  DATA = await res.json();
  renderSettings();
  renderFiles();
  renderTools();
  const st = DATA.status || {};
  $("#statline").textContent = "pid " + st.pid + " · uptime " + st.uptimeHuman +
    " · pm2: " + (st.pm2 ? "available" : "not detected") + " · .env: " + st.envPath;
}

/* ---------- tab switching ---------- */
$("#tabs").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-tab]");
  if (!btn) return;
  document.querySelectorAll("#tabs button").forEach((b) => b.classList.toggle("active", b === btn));
  const names = ["settings", "tools", "performance", "whitelist", "blocklist", "trustedhosts", "triggers"];
  for (const n of names) $("#tab-" + n).classList.toggle("hidden", n !== btn.dataset.tab);
  perfLoop(btn.dataset.tab === "performance" && $("#perf-auto").checked);
});

document.addEventListener("input", (e) => {
  if (e.target && e.target.id === "ta-trustedhosts") checkTrustedHosts();
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

$("#btn-logout").addEventListener("click", async () => {
  await api("logout", {});
  location.href = "login";
});

load().catch((e) => notice("err", "Failed to load: " + e.message));
</script>
</body>
</html>`;
}

module.exports = { loginPage, appPage, htmlEscape };
