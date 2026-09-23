/**
 * BBSFirewall - Web-based configuration editor
 *
 * An HTTPS admin UI, on its own port and its own TLS certificate, for editing
 * the .env file and the whitelist / blocklist / trustedhosts list files without
 * shelling into the box. Two independent gates protect it:
 *
 *   1. Trusted-host allowlist  - TRUSTEDHOSTS.TXT (IPv4/IPv6 CIDR). An address
 *      that is not listed never gets past the socket handler. An empty or
 *      missing list denies everyone.
 *   2. Login session           - username/password from .env, checked with a
 *      constant-time compare, exchanged for a random session cookie
 *      (HttpOnly, Secure, SameSite=Strict) with idle and absolute timeouts.
 *
 * Mutating requests additionally require a per-session CSRF token header.
 *
 * A missing or unreadable certificate logs an error and skips the editor; the
 * telnet proxy and everything else keep running.
 *
 * The request router keeps every /api/* route in one place so a future
 * key-authenticated management API can be added alongside the browser routes.
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const https = require('https');
const net = require('net');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { execFile, execFileSync } = require('child_process');
const execFileAsync = promisify(execFile);

const logger = require('./logger');
const { config } = require('./config');
const trustedhosts = require('./trustedhosts');
const views = require('./config-editor-ui');
const metrics = require('./metrics');
const security = require('./security');
const updater = require('./updater');
const webRedirect = require('./web-redirect');

const log = logger.getLogger('config-editor');

const ABSOLUTE_SESSION_MS = 12 * 60 * 60 * 1000; // hard cap regardless of activity
const LOGIN_MAX_FAILS = 5;
const LOGIN_LOCK_MS = 15 * 60 * 1000;
const MFA_MAX_FAILS = 5;
const MFA_LOCK_MS = 15 * 60 * 1000;
const MAX_BODY_BYTES = 512 * 1024;
const ENV_BACKUPS_KEPT = 15;
const ENV_BACKUP_DIRNAME = 'ENVBACKUPS';
const ACTION_TIMEOUT_MS = 240 * 1000; // long-running shell actions (certbot, geoip)
const SESSION_STORE = path.join(__dirname, '.config-editor-sessions.json');
// __Host- prefix: the browser only accepts this cookie when it is Secure, has
// Path=/ and carries no Domain attribute — which is exactly how it is set.
const COOKIE_NAME = '__Host-bbsfw_admin';
const TOKEN_RE = /^[0-9a-f]{64}$/;
const SECRET_FILE_MODE = 0o600;

// Site branding assets. A fixed, small map (not a general static-file route)
// so there is no path-traversal surface — pathname is looked up, never joined
// onto a filesystem path.
const STATIC_ASSETS = {
  '/favicon.ico': { file: path.join(__dirname, 'assets', 'favicon.ico'), type: 'image/x-icon' },
  '/assets/logo.svg': { file: path.join(__dirname, 'assets', 'logo-dark.svg'), type: 'image/svg+xml' },
};

let server = null;      // the https.Server (services connections handed to it by muxServer)
let muxServer = null;    // the net.Server that actually listens on CONFIG_EDITOR_PORT
let sweepTimer = null;
let lastCpuSample = null;   // for CPU-% deltas
let lastNetSample = null;   // for network throughput deltas
let proxyHeaderWarned = false;
let firewallInstance = null; // set by startConfigEditorServer(firewall) — see /status handler

const sessions = new Map();   // token -> { username, ip, created, lastSeen, csrf, mfaVerified }
const loginFails = new Map(); // ip  -> { count, until } — browser login
const apiFails = new Map();   // ip  -> { count, until } — management API key (kept separate
                              // so a dashboard flooding a bad key can't lock a human admin
                              // out of the web UI from the same source IP)
const mfaFails = new Map();   // ip  -> { count, until } — MFA code/backup-code attempts,
                              // kept separate so guessing MFA codes can't also burn through
                              // the (looser) password-lockout budget for the same IP
const busy = new Set();       // in-flight mutating operations (one at a time)

// ---------------------------------------------------------------------------
// .env field schema — drives the settings form. Keys not listed here are still
// preserved on save (the writer works off the raw file), they just do not get
// a dedicated widget.
// ---------------------------------------------------------------------------
const ENV_SCHEMA = [
  { name: 'Network', icon: 'network',
    help: 'Where the firewall listens for callers and which BBS it forwards them to.',
    fields: [
      { key: 'LISTEN_PORT', type: 'port', label: 'Telnet listen port', def: '23', required: true,
        help: 'TCP port callers connect to. 23 is standard telnet; ports below 1024 need the process to run as root.' },
      { key: 'BACKEND_HOST', type: 'string', label: 'Backend host', def: '127.0.0.1', required: true,
        help: 'Hostname or IP of the BBS the firewall forwards accepted connections to.' },
      { key: 'BACKEND_PORT', type: 'port', label: 'Backend port', def: '23', required: true,
        help: 'Port the BBS listens on (usually 23 for telnet).' },
      { key: 'ENCODING_DETECTION', type: 'bool', label: 'Encoding-based backend routing', def: 'false',
        help: 'Send UTF-8 and CP437 callers to different backend ports.',
        helpLong: 'When on, the firewall guesses the caller’s character encoding and routes CP437 (DOS/ANSI) clients to BACKEND_PORT_CP437 and UTF-8 clients to BACKEND_PORT_UTF8, instead of the single BACKEND_PORT. Only reliable for SSH callers (telnet gives nothing to sniff, so telnet always uses the CP437 port).' },
      { key: 'BACKEND_PORT_CP437', type: 'port', label: 'CP437 backend port', def: '2323',
        help: 'Backend port for CP437/DOS clients when encoding routing is on.' },
      { key: 'BACKEND_PORT_UTF8', type: 'port', label: 'UTF-8 backend port', def: '2423',
        help: 'Backend port for UTF-8/Unicode clients when encoding routing is on.' },
    ]},
  { name: 'Connection Limits', icon: 'limit',
    help: 'Caps on how many connections the firewall will carry at once.',
    fields: [
      { key: 'MAX_CONNECTIONS', type: 'int', label: 'Max total connections', def: '100', required: true,
        help: 'Hard ceiling on simultaneous connections across all callers. New connections past this are dropped immediately.' },
      { key: 'MAX_CONNECTIONS_PER_IP', type: 'int', label: 'Max connections per IP (0 = unlimited)', def: '3', required: true,
        help: 'How many simultaneous connections one IP may hold. 0 disables the per-IP cap. Whitelisted IPs are exempt.' },
      { key: 'CONNECTION_TIMEOUT', type: 'int', label: 'Idle timeout (ms, 0 = off)', def: '300000', required: true,
        help: 'Drop a connection after this many milliseconds with no traffic. 300000 = 5 minutes. 0 disables it.' },
    ]},
  { name: 'Country Blocking', icon: 'globe',
    help: 'Refuse callers by country using a local MaxMind GeoLite2 database. Needs the database downloaded (see the Tools tab) and a MaxMind license key.',
    fields: [
      { key: 'MAXMIND_LICENSE_KEY', type: 'secret', label: 'MaxMind license key', def: '',
        help: 'Free key from maxmind.com. Once set (and saved), use the Tools tab to download or update the GeoIP database.' },
      { key: 'BLOCKED_COUNTRIES', type: 'csv', label: 'Blocked country codes', def: '',
        help: 'Comma-separated ISO 3166-1 alpha-2 codes, e.g. CN,RU,KP,IR. Callers geolocated to one of these are refused.' },
      { key: 'BLOCK_UNKNOWN_COUNTRIES', type: 'bool', label: 'Block when country is unknown', def: 'false',
        help: 'Also refuse callers whose IP cannot be geolocated. Off by default so unusual-but-legitimate IPs still get through.' },
    ]},
  { name: 'IP Lists', icon: 'list',
    help: 'Files listing IPs/CIDRs. Edit their contents in the Whitelist / Blocklist sections below.',
    fields: [
      { key: 'WHITELIST_PATH', type: 'string', label: 'Whitelist file path', def: './whitelist.txt',
        help: 'IPs in this file bypass every firewall rule — rate limit, per-IP cap, country block, and the blocklist.' },
      { key: 'BLOCKLIST_PATH', type: 'string', label: 'Blocklist file path', def: './blocklist.txt',
        help: 'IPs in this file are refused outright, permanently, unless also whitelisted.' },
    ]},
  { name: 'Rate Limiting', icon: 'gauge',
    help: 'Flood protection: temporarily block an IP that reconnects too fast.',
    fields: [
      { key: 'RATE_LIMIT_ENABLED', type: 'bool', label: 'Enable rate limiting', def: 'true', required: true,
        help: 'Master switch for the sliding-window flood protection below.' },
      { key: 'MAX_CONNECTIONS_PER_WINDOW', type: 'int', label: 'Max attempts per window', def: '10', required: true,
        help: 'Connection attempts one IP may make within the window before it is temporarily blocked.' },
      { key: 'RATE_LIMIT_WINDOW_MS', type: 'int', label: 'Window length (ms)', def: '60000', required: true,
        help: 'Length of the sliding window, in milliseconds. 60000 = 1 minute. Minimum 1000.' },
      { key: 'RATE_LIMIT_BLOCK_DURATION_MS', type: 'int', label: 'Block duration (ms)', def: '300000', required: true,
        help: 'How long an IP stays blocked after tripping the limit. 300000 = 5 minutes.' },
    ]},
  { name: 'Auto-Block Triggers', icon: 'alert',
    help: 'Scan the first bytes a caller sends for known bot / scanner / exploit strings and blacklist the source IP on a match. Edit the pattern list in the Triggers section below. Whitelisted IPs are never auto-blocked.',
    fields: [
      { key: 'TRIGGER_BLOCK_ENABLED', type: 'bool', label: 'Enable auto-block on trigger match', def: 'false',
        help: 'Off by default. A real caller who sends one of these strings in the first few bytes would be blocked too — keep the list tight.' },
      { key: 'TRIGGER_LIST_PATH', type: 'string', label: 'Trigger list file', def: './triggers.txt',
        help: 'One pattern per line. Plain text = case-insensitive substring; /regex/flags = JS regex; \\xNN \\r \\n \\t \\0 escapes work in plain patterns (for binary probes).' },
      { key: 'TRIGGER_SCAN_BYTES', type: 'int', label: 'Bytes scanned per connection', def: '1024',
        help: 'Only the first N bytes the caller sends are checked (16-65536). Scanners send their probe immediately; a real session sails past this and is never scanned again.' },
      { key: 'TRIGGER_BLOCK_MODE', type: 'enum', label: 'Block mode', def: 'blocklist', options: ['blocklist', 'temp'],
        help: 'blocklist = append the IP to blocklist.txt permanently (also blocked in memory right away). temp = in-memory block only, for the duration below.' },
      { key: 'TRIGGER_BLOCK_DURATION_MS', type: 'int', label: 'Temp block duration (ms)', def: '86400000',
        help: 'Used when mode is temp. 86400000 = 24 hours.' },
    ]},
  { name: 'PROXY Protocol', icon: 'exchange',
    help: 'Optional way to tell the backend the real caller IP.',
    fields: [
      { key: 'PROXY_PROTOCOL_ENABLED', type: 'bool', label: 'Send PROXY Protocol v1 to telnet backend', def: 'false',
        help: 'Prepend a PROXY v1 header so the BBS sees the caller’s IP instead of the firewall’s.',
        helpLong: 'Only enable this if the backend BBS (or a companion module) understands PROXY Protocol v1. Sent to a backend that does not, the header is read as session garbage and every connection breaks.' },
    ]},
  { name: 'Web Redirect', icon: 'redirect',
    help: 'Optional tiny web server so browsers that hit the firewall’s IP get bounced to your real site. Use the Tools tab to issue a Let’s Encrypt certificate for port 443.',
    fields: [
      { key: 'WEB_REDIRECT_ENABLED', type: 'bool', label: 'Enable HTTP (port 80) redirect', def: 'false',
        help: 'Serve a 301 redirect on port 80. Also serves Let’s Encrypt ACME challenges for cert issuance.' },
      { key: 'WEB_REDIRECT_URL', type: 'string', label: 'Redirect destination URL', def: '',
        help: 'Where to send visitors, e.g. https://www.yourbbs.com. Used by both the HTTP and HTTPS redirect.' },
      { key: 'HTTPS_REDIRECT_ENABLED', type: 'bool', label: 'Enable HTTPS (port 443) redirect', def: 'false',
        help: 'Also redirect on port 443. Requires the certificate paths below.' },
      { key: 'HTTPS_REDIRECT_PORT', type: 'port', label: 'HTTPS redirect port', def: '443',
        help: 'Port for the HTTPS redirect listener.' },
      { key: 'HTTPS_CERT_PATH', type: 'string', label: 'HTTPS redirect cert path', def: './certs/fullchain.pem',
        help: 'Path to the fullchain PEM for the port-443 redirect. setup-certs.sh / the Tools tab write this.' },
      { key: 'HTTPS_KEY_PATH', type: 'string', label: 'HTTPS redirect key path', def: './certs/privkey.pem',
        help: 'Path to the private key PEM for the port-443 redirect.' },
      { key: 'HTTPS_CERT_DOMAIN', type: 'string', label: 'Redirect cert domain', def: '',
        help: 'Public hostname (DNS must point here) the Tools tab issues the port-443 Let’s Encrypt certificate for.' },
      { key: 'HTTPS_CERT_EMAIL', type: 'string', label: 'Redirect cert contact email', def: '',
        help: 'Optional. Certbot sends expiry warnings here.' },
    ]},
  { name: 'Config Editor', icon: 'lock',
    help: 'This admin UI. Changing the port or certificate takes effect after a restart. The admin ' +
      'username/password and MFA are no longer set here — run "node setup-admin.js" once to create the ' +
      'account, then use Security Settings (top-right of the header) to change the password or enable MFA.',
    fields: [
      { key: 'CONFIG_EDITOR_ENABLED', type: 'bool', label: 'Enable this editor', def: 'false', required: true,
        help: 'Turn the editor on. Disabling it here means you cannot get back in without SSH.' },
      { key: 'CONFIG_EDITOR_PORT', type: 'port', label: 'Editor listen port', def: '8443', required: true,
        help: 'HTTPS port for this UI. Must differ from LISTEN_PORT and the SSH port.' },
      { key: 'CONFIG_EDITOR_BIND', type: 'string', label: 'Bind address', def: '0.0.0.0',
        help: '0.0.0.0 listens on every interface; set a specific IP to limit it, or 127.0.0.1 to require an SSH tunnel.' },
      { key: 'CONFIG_EDITOR_CERT_PATH', type: 'string', label: 'Editor cert path', def: './certs/config-editor/fullchain.pem',
        help: 'Fullchain PEM for this UI’s HTTPS. Written by setup-config-cert.sh / the Tools tab.' },
      { key: 'CONFIG_EDITOR_KEY_PATH', type: 'string', label: 'Editor key path', def: './certs/config-editor/privkey.pem',
        help: 'Private key PEM for this UI’s HTTPS.' },
      { key: 'CONFIG_EDITOR_CERT_DOMAIN', type: 'string', label: 'Editor cert domain', def: '',
        help: 'Public hostname the Tools tab issues this UI’s Let’s Encrypt certificate for.' },
      { key: 'CONFIG_EDITOR_CERT_EMAIL', type: 'string', label: 'Editor cert contact email', def: '',
        help: 'Optional certbot contact email for the editor certificate.' },
      { key: 'CONFIG_EDITOR_TRUSTEDHOSTS_PATH', type: 'string', label: 'Trusted hosts file path', def: './trustedhosts.txt',
        help: 'File of IPs/CIDRs allowed to reach this UI at all. Edit its contents in the Trusted Hosts section below. Empty = nobody.' },
      { key: 'CONFIG_EDITOR_SESSION_TIMEOUT_MS', type: 'int', label: 'Session idle timeout (ms)', def: '1800000',
        help: 'Log an idle admin out after this long. 1800000 = 30 minutes. Minimum 60000.' },
      { key: 'CONFIG_EDITOR_HTTP_REDIRECT_ENABLED', type: 'bool', label: 'Redirect plain HTTP to HTTPS', def: 'true',
        help: 'On by default. When a browser hits this editor’s port with plain http:// (no TLS), answer with a 301 to the https:// URL instead of failing the handshake (ERR_EMPTY_RESPONSE). Same port — no extra listener. Set false to just drop such requests.' },
    ]},
  { name: 'Management API', icon: 'key',
    help: 'Key-authenticated REST access to everything on this page (config, list files, restart, tools, stats) for a remote dashboard. Rides on this editor’s HTTPS port under /api/*, so the editor must be enabled. Authenticated by the bearer key below; optionally restricted by source IP in the API Trusted Hosts section below. This is a separate lane — an API caller does NOT need to be in trustedhosts.txt.',
    fields: [
      { key: 'API_ENABLED', type: 'bool', label: 'Enable the management API', def: 'false',
        help: 'Needs this config editor enabled — the API has no listener of its own.' },
      { key: 'API_KEY', type: 'secret', label: 'API bearer key', def: '',
        help: 'Sent by clients as "Authorization: Bearer <key>" or "X-API-Key: <key>". Minimum 24 characters. Restart to apply a change.' },
      { key: 'API_TRUSTEDHOSTS_PATH', type: 'string', label: 'API IP allowlist file', def: './api-trustedhosts.txt',
        help: 'IPs/CIDRs allowed to call the API. Edit its contents in the API Trusted Hosts section below. Empty or missing = any IP may call (the key still applies).' },
    ]},
  { name: 'Logging', icon: 'file',
    help: 'Console verbosity and per-proxy log files (on by default).',
    fields: [
      { key: 'LOG_LEVEL', type: 'enum', label: 'Console log level', def: 'info', options: ['debug', 'info', 'warn', 'error'],
        help: 'How much the process prints to its stdout/pm2 log. debug is very noisy.' },
      { key: 'LOG_FILE_ENABLED', type: 'bool', label: 'Enable per-proxy file logging', def: 'true',
        help: 'Write a daily-rotated log file per proxy service under the log directory. On by default; old files are pruned automatically (see Retention below).' },
      { key: 'LOG_DIR', type: 'string', label: 'Log directory', def: './logs',
        help: 'Base directory for the per-proxy log folders.' },
      { key: 'LOG_FILE_LEVEL', type: 'enum', label: 'Default file log level', def: 'connections',
        options: ['off', 'blocked', 'connections', 'info', 'debug'],
        help: 'Event detail written to the files. Each level includes the ones before it: blocked → connections → info → debug.' },
      { key: 'LOG_RETENTION_DAYS', type: 'int', label: 'Log retention (days)', def: '30',
        help: 'Delete rotated log files older than this many days. 1-3650 (10 years). Checked once a day, so a lowered value can take up to 24h to take effect.' },
    ]},
  { name: 'SSH', icon: 'terminal',
    help: 'Optional SSH front door on its own port. Pick a mode below — the two modes do very different things.',
    fields: [
      { key: 'SSH_MODE', type: 'enum', label: 'SSH mode', def: 'off', options: ['off', 'terminate', 'passthrough'],
        help: 'off = no SSH listener. terminate = the firewall IS the SSH server. passthrough = the firewall is a plain pipe to a backend that runs its own SSH.',
        helpLong: 'TERMINATE — the firewall speaks SSH itself, accepts any username/password, decrypts the session, and opens a plain telnet connection to BACKEND_HOST:BACKEND_PORT. Use this when the BBS only does telnet. Needs an SSH host key (generate one on the Tools tab) and a cipher list for old terminal clients. Encoding detection works here. Trade-offs: no public-key / passwordless login, no SFTP, and Zmodem/Ymodem file transfers are unreliable over the bridge — the firewall→backend hop is plain telnet.\n\nPASSTHROUGH — the firewall does NOT decrypt anything. It runs the same IP-layer checks as the telnet proxy (whitelist, blocklist, rate limit, country block, per-IP cap) and forwards the still-encrypted stream to a backend that runs its own SSH daemon (SSH_BACKEND_HOST:SSH_BACKEND_PORT). Preserves public-key login, SFTP, and reliable file transfers because the client is really talking to the backend’s sshd. No host key or cipher settings needed here; encoding detection is off (nothing to sniff).\n\nRule of thumb: backend is telnet-only → terminate. Backend already has sshd → passthrough.' },
      { key: 'SSH_LISTEN_PORT', type: 'port', label: 'SSH listen port', def: '2222',
        help: 'Port the SSH front door listens on (both modes use this).' },
      { key: 'SSH_HOST_KEY', type: 'string', label: 'SSH host key path', def: './ssh_host_key',
        help: 'terminate mode only. Path to the firewall’s SSH private host key. Generate one on the Tools tab if you do not have it.' },
      { key: 'SSH_BACKEND_HOST', type: 'string', label: 'SSH backend host', def: '',
        help: 'passthrough mode only. The backend that runs its own SSH server. Defaults to BACKEND_HOST if left unset.' },
      { key: 'SSH_BACKEND_PORT', type: 'port', label: 'SSH backend port', def: '22',
        help: 'passthrough mode only. Port of the backend SSH daemon.' },
      { key: 'SSH_PROXY_PROTOCOL', type: 'bool', label: 'Send PROXY Protocol v1 to SSH backend', def: 'false',
        help: 'passthrough mode only. Prepend a PROXY v1 header for the backend sshd. Only enable if that sshd understands it — a plain SSH server drops the handshake otherwise.' },
    ]},
];

const SCHEMA_KEYS = new Set(ENV_SCHEMA.flatMap((s) => s.fields.map((f) => f.key)));

// ---------------------------------------------------------------------------
// .env parsing / writing
// ---------------------------------------------------------------------------

const ENV_LINE_RE = /^(\s*)(#\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$/;

function stripEnvValue(raw) {
  let v = raw.trim();
  if (v.length >= 2 &&
      ((v[0] === '"' && v[v.length - 1] === '"') || (v[0] === "'" && v[v.length - 1] === "'"))) {
    const quote = v[0];
    v = v.slice(1, -1);
    if (quote === '"') {
      v = v.replace(/\\n/g, '\n').replace(/\\r/g, '\r').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    }
    return v;
  }
  // unquoted: cut an inline comment introduced by whitespace + '#'
  const m = v.match(/\s#/);
  if (m) v = v.slice(0, m.index).trim();
  return v;
}

function serializeEnvValue(v) {
  if (/[\r\n]/.test(v)) throw new Error('value must not contain a newline');
  if (v === '') return '';
  if (/^\s|\s$|[#"'`\\$]/.test(v)) {
    return '"' + v.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
  }
  return v;
}

// Parse .env text into { active: {K:v}, commented: {K:v} }.
function parseEnvText(text) {
  const active = {};
  const commented = {};
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(ENV_LINE_RE);
    if (!m) continue;
    const key = m[3];
    const val = stripEnvValue(m[4]);
    if (m[2]) {
      if (!(key in commented) && !(key in active)) commented[key] = val;
    } else {
      active[key] = val;
    }
  }
  return { active, commented };
}

// Apply { KEY: { value, enabled } } to raw .env text, preserving comments and
// layout. enabled=false comments the line out; new keys are appended.
function applyEnvUpdates(originalText, updates) {
  const eol = originalText.includes('\r\n') ? '\r\n' : '\n';
  const lines = originalText.split(/\r?\n/);
  const handled = new Set();

  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(ENV_LINE_RE);
    if (!m) continue;
    const key = m[3];
    if (!(key in updates)) continue;

    const indent = m[1];
    const u = updates[key];

    if (handled.has(key)) {
      // A later duplicate definition — neutralise it so there is no ambiguity.
      if (!m[2]) lines[i] = `${indent}# ${key}=${m[4].trim()}`;
      continue;
    }
    handled.add(key);

    if (u.enabled === false) {
      const keep = (u.value !== undefined && u.value !== '') ? serializeEnvValue(u.value) : m[4].trim();
      lines[i] = `${indent}# ${key}=${keep}`;
    } else {
      lines[i] = `${indent}${key}=${serializeEnvValue(u.value == null ? '' : String(u.value))}`;
    }
  }

  const appended = [];
  for (const [key, u] of Object.entries(updates)) {
    if (handled.has(key)) continue;
    if (u.enabled === false) continue;
    if (u.value == null || u.value === '') continue;
    appended.push(`${key}=${serializeEnvValue(String(u.value))}`);
  }

  if (appended.length) {
    if (lines.length && lines[lines.length - 1].trim() !== '') lines.push('');
    lines.push('# ---------------------------------------------------------------------------');
    lines.push('# Added by the BBSFirewall config editor');
    lines.push('# ---------------------------------------------------------------------------');
    lines.push(...appended);
  }

  return lines.join(eol);
}

// ---------------------------------------------------------------------------
// Small inline validation (fast feedback). The authoritative check is a child
// `node -e "require('./config').validateConfig()"` against the written file.
// ---------------------------------------------------------------------------
function inlineValidate(map) {
  const errors = [];
  const asInt = (k) => (map[k] && map[k].enabled !== false ? Number(map[k].value) : undefined);
  const port = (k, label) => {
    const v = asInt(k);
    if (v === undefined || map[k].value === '') return;
    if (!Number.isInteger(v) || v < 1 || v > 65535) errors.push(`${label} must be an integer 1-65535`);
  };
  port('LISTEN_PORT', 'LISTEN_PORT');
  port('BACKEND_PORT', 'BACKEND_PORT');
  port('CONFIG_EDITOR_PORT', 'CONFIG_EDITOR_PORT');
  port('SSH_LISTEN_PORT', 'SSH_LISTEN_PORT');
  port('HTTPS_REDIRECT_PORT', 'HTTPS_REDIRECT_PORT');

  if (map.CONFIG_EDITOR_PORT && map.LISTEN_PORT &&
      map.CONFIG_EDITOR_PORT.value && map.LISTEN_PORT.value &&
      Number(map.CONFIG_EDITOR_PORT.value) === Number(map.LISTEN_PORT.value)) {
    errors.push('CONFIG_EDITOR_PORT must differ from LISTEN_PORT');
  }

  if (map.SSH_MODE && !['off', 'terminate', 'passthrough'].includes(map.SSH_MODE.value)) {
    errors.push('SSH_MODE must be one of: off, terminate, passthrough');
  }

  const retentionDays = asInt('LOG_RETENTION_DAYS');
  if (retentionDays !== undefined && map.LOG_RETENTION_DAYS.value !== '' &&
      (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650)) {
    errors.push('LOG_RETENTION_DAYS must be an integer 1-3650');
  }
  return errors;
}

// Pull the human-readable lines out of a failed validateConfig() child. Its
// stderr is a full Node stack trace wrapped around the message we want.
function extractValidationErrors(err) {
  const stderr = (err && err.stderr && err.stderr.toString()) || '';
  // Anchor on the thrown message line ("Error: Configuration validation
  // failed:"), not the identical text in Node's code-frame echo above it.
  const m = stderr.match(/\bError:\s*Configuration validation failed:\r?\n/);
  if (m) {
    const after = stderr.slice(m.index + m[0].length);
    const lines = [];
    for (const raw of after.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      if (/^at\s/.test(line) || line.startsWith('Node.js v') || line === '^') break;
      lines.push(line);
    }
    if (lines.length) return lines.join('\n');
  }
  if (err && err.signal === 'SIGTERM') return 'validation timed out';
  return (err && err.message) || 'unknown validation error';
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function clientIp(req) {
  const raw = (req.socket && req.socket.remoteAddress) || '';
  return raw.replace(/^::ffff:/i, '');
}

// Neutralise control characters before putting attacker-influenced text (a
// submitted username) into a log line, so it cannot forge log entries.
function sanitizeForLog(s) {
  return String(s == null ? '' : s).replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, 200);
}

// Simple one-at-a-time lock for mutating operations (save, restart, the Tools
// actions). Each spawns a subprocess and/or rewrites files; overlapping runs
// invite corruption and resource exhaustion.
function acquire(res, name) {
  if (busy.has(name)) {
    sendJson(res, 429, { error: `A "${name}" operation is already running — wait for it to finish.` });
    return false;
  }
  busy.add(name);
  return true;
}
function release(name) { busy.delete(name); }

function chmodQuiet(p, mode) {
  try { fs.chmodSync(p, mode); } catch (_) { /* best effort (e.g. Windows) */ }
}

function safeEqual(a, b) {
  const ab = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ab.length !== bb.length) {
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    let val = part.slice(idx + 1).trim();
    try { val = decodeURIComponent(val); } catch (_) { /* malformed %xx — keep raw */ }
    out[part.slice(0, idx).trim()] = val;
  }
  return out;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('request body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

// Render an HTML page with a fresh per-response script nonce, so the CSP can
// use 'nonce-...' for scripts instead of 'unsafe-inline'. buildHtml(nonce) must
// put nonce="<nonce>" on the single inline <script>.
function sendPage(res, status, buildHtml) {
  const nonce = crypto.randomBytes(16).toString('base64url');
  const html = buildHtml(nonce);
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(html),
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy':
      `default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}'; img-src 'self'; ` +
      "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
  });
  res.end(html);
}

// Cached on first read: these files ship with the release and never change
// while the process runs, so there's no point re-reading disk on every hit.
const staticAssetCache = new Map();
function serveStaticAsset(res, pathname) {
  const asset = STATIC_ASSETS[pathname];
  if (!asset) {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('Not found');
  }
  let data = staticAssetCache.get(pathname);
  if (!data) {
    try {
      data = fs.readFileSync(asset.file);
    } catch (_) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not found');
    }
    staticAssetCache.set(pathname, data);
  }
  res.writeHead(200, {
    'Content-Type': asset.type,
    'Content-Length': data.length,
    'Cache-Control': 'public, max-age=86400',
    'X-Content-Type-Options': 'nosniff',
  });
  res.end(data);
}

function redirect(res, location) {
  res.writeHead(302, { Location: location, 'Cache-Control': 'no-store' });
  res.end();
}

function cookieHeader(token, maxAgeSec) {
  const parts = [
    `${COOKIE_NAME}=${token}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Strict',
  ];
  if (maxAgeSec === 0) parts.push('Max-Age=0');
  return parts.join('; ');
}

// ---------------------------------------------------------------------------
// session management
// ---------------------------------------------------------------------------

// mfaVerified starts false when the account has MFA enabled (the router
// gate below then restricts this session to the MFA-verify/logout routes
// until it passes) and true otherwise, so the gate is a no-op when MFA is
// off.
//
// `role` ('owner'/'provider') is captured once here, the same "decided at
// login, never re-checked" pattern mfaVerified already uses above - the only
// way it can go stale is the account being deleted out from under the
// session, and handleDeleteAccount revokes that account's sessions directly.
function createSession(username, ip, mfaVerified, role) {
  const token = crypto.randomBytes(32).toString('hex');
  const csrf = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  sessions.set(token, { username, ip, created: now, lastSeen: now, csrf, mfaVerified: !!mfaVerified, role: role || 'owner' });
  return { token, csrf };
}

// Signs out every OTHER session belonging to `username` (own account only -
// NOT a global sign-everyone-out, now that more than one admin account can
// exist). Pass `exceptToken: null` to revoke every session for that user,
// including their own (used when deleting an account outright).
function revokeOtherSessionsForUser(username, exceptToken) {
  for (const [token, s] of sessions) {
    if (token !== exceptToken && s.username === username) sessions.delete(token);
  }
}

function getSession(req) {
  const token = parseCookies(req)[COOKIE_NAME];
  if (!token || !TOKEN_RE.test(token)) return null;
  const s = sessions.get(token);
  if (!s) return null;

  const now = Date.now();
  if (now - s.lastSeen > config.configEditor.sessionTimeoutMs ||
      now - s.created > ABSOLUTE_SESSION_MS ||
      s.ip !== clientIp(req)) {
    sessions.delete(token);
    return null;
  }
  s.lastSeen = now;
  return { token, ...s };
}

function destroySession(req) {
  const token = parseCookies(req)[COOKIE_NAME];
  if (token) sessions.delete(token);
}

function sweepSessions() {
  const now = Date.now();
  for (const [token, s] of sessions) {
    if (now - s.lastSeen > config.configEditor.sessionTimeoutMs ||
        now - s.created > ABSOLUTE_SESSION_MS) {
      sessions.delete(token);
    }
  }
  for (const [ip, f] of loginFails) {
    if (now > f.until) loginFails.delete(ip);
  }
  for (const [ip, f] of apiFails) {
    if (now > f.until) apiFails.delete(ip);
  }
  for (const [ip, f] of mfaFails) {
    if (now > f.until) mfaFails.delete(ip);
  }
}

function isLocked(map, ip, maxFails = LOGIN_MAX_FAILS) {
  const f = map.get(ip);
  if (!f) return false;
  if (Date.now() > f.until) { map.delete(ip); return false; }
  return f.count >= maxFails;
}

function recordFail(map, ip, lockMs = LOGIN_LOCK_MS) {
  const f = map.get(ip) || { count: 0, until: 0 };
  f.count += 1;
  f.until = Date.now() + lockMs;
  map.set(ip, f);
}

const loginLocked = (ip) => isLocked(loginFails, ip);
const recordLoginFail = (ip) => recordFail(loginFails, ip);
const apiLocked = (ip) => isLocked(apiFails, ip);
const recordApiFail = (ip) => recordFail(apiFails, ip);
const mfaLocked = (ip) => isLocked(mfaFails, ip, MFA_MAX_FAILS);
const recordMfaFail = (ip) => recordFail(mfaFails, ip, MFA_LOCK_MS);

// ---------------------------------------------------------------------------
// runtime status
// ---------------------------------------------------------------------------

let pm2Available = null;
// Only a SUCCESSFUL detection is cached (permanently — pm2 isn't going to
// vanish once found). A failure is never cached: the startup warm-up call
// below is fire-and-forget, so a request landing in the first instant after
// boot can race it and see pm2Available still null; spawning the pm2 CLI can
// also just be transiently slow right after this process itself restarted
// (small/busy box). Caching that as a permanent "not found" wedged the
// Restart button with a false "pm2 was not found on this host" for the rest
// of the process's life — observed for real, not just in theory.
async function hasPm2() {
  if (pm2Available) return true;
  try {
    await execFileAsync('pm2', ['-v'], { timeout: 4000 });
    pm2Available = true;
    return true;
  } catch (_) {
    return false;
  }
}

function humanUptime(sec) {
  sec = Math.floor(sec);
  const d = Math.floor(sec / 86400); sec -= d * 86400;
  const h = Math.floor(sec / 3600); sec -= h * 3600;
  const m = Math.floor(sec / 60); sec -= m * 60;
  return [d && `${d}d`, h && `${h}h`, m && `${m}m`, `${sec}s`].filter(Boolean).join(' ');
}

let cachedVersion = null;
function appVersion() {
  if (cachedVersion !== null) return cachedVersion;
  try {
    cachedVersion = String(require('./package.json').version || '');
  } catch (_) {
    cachedVersion = '';
  }
  return cachedVersion;
}

function readFileSafe(p) {
  try {
    return { content: fs.readFileSync(path.resolve(p), 'utf-8'), exists: true };
  } catch (err) {
    if (err.code === 'ENOENT') return { content: '', exists: false };
    return { content: '', exists: false, error: err.message };
  }
}

// Read the value of one key from the .env file (fresh from disk, so a value the
// admin just saved but hasn't restarted into is still seen).
function envFileValue(key) {
  try {
    const parsed = parseEnvText(fs.readFileSync(path.resolve(config.configEditor.envPath), 'utf-8'));
    return parsed.active[key];
  } catch (_) {
    return undefined;
  }
}

// --- health probes (folded into /api/config) ---------------------------------

function geoipStatus() {
  const dbPath = path.join(__dirname, 'data', 'GeoLite2-Country.mmdb');
  const out = { dbPath, exists: false, sizeBytes: 0, ageDays: null, licenseKeySet: false };
  out.licenseKeySet = !!(envFileValue('MAXMIND_LICENSE_KEY') || '').trim();
  try {
    const st = fs.statSync(dbPath);
    out.exists = true;
    out.sizeBytes = st.size;
    out.ageDays = Math.floor((Date.now() - st.mtimeMs) / 86400000);
  } catch (_) { /* not downloaded yet */ }
  return out;
}

// These two probes shell out (`ssh-keygen -l`, `openssl x509`). /api/config
// folds them in via buildHealth(), and an API client may poll it — so cache the
// results briefly. Tools actions that change a key/cert call invalidateHealthCache().
const HEALTH_CACHE_TTL_MS = 4000;
let sshHostKeyCache = null;       // { at, value }
let certInfoCache = new Map();    // resolved path -> { at, value }

function invalidateHealthCache() {
  sshHostKeyCache = null;
  certInfoCache = new Map();
}

async function sshHostKeyStatus() {
  if (sshHostKeyCache && Date.now() - sshHostKeyCache.at < HEALTH_CACHE_TTL_MS) {
    return sshHostKeyCache.value;
  }
  const value = await sshHostKeyStatusFresh();
  sshHostKeyCache = { at: Date.now(), value };
  return value;
}

async function sshHostKeyStatusFresh() {
  const keyPath = path.resolve(envFileValue('SSH_HOST_KEY') || config.sshHostKey || './ssh_host_key');
  const out = { path: keyPath, exists: false, fingerprint: null, type: null };
  try {
    fs.statSync(keyPath);
    out.exists = true;
    try {
      const { stdout } = await execFileAsync('ssh-keygen', ['-l', '-f', keyPath], { timeout: 4000 });
      const r = stdout.toString().trim();
      // "3072 SHA256:abc... comment (RSA)"
      const m = r.match(/^(\d+)\s+(\S+)\s+.*\((\w+)\)\s*$/);
      if (m) { out.fingerprint = m[2]; out.type = m[3]; }
      else out.fingerprint = r;
    } catch (_) { /* ssh-keygen missing or unreadable key */ }
  } catch (_) { /* no key yet */ }
  return out;
}

async function certInfo(certPath) {
  const abs = certPath ? path.resolve(certPath) : '';
  const cached = certInfoCache.get(abs);
  if (cached && Date.now() - cached.at < HEALTH_CACHE_TTL_MS) return cached.value;
  const value = await certInfoFresh(certPath);
  certInfoCache.set(abs, value);
  return value;
}

async function certInfoFresh(certPath) {
  const out = { path: certPath, exists: false, subject: null, notAfter: null, daysLeft: null, selfSigned: null };
  let abs;
  try { abs = path.resolve(certPath); fs.statSync(abs); out.exists = true; }
  catch (_) { return out; }
  try {
    const { stdout } = await execFileAsync('openssl', ['x509', '-in', abs, '-noout', '-subject', '-issuer', '-enddate'],
      { timeout: 4000 });
    const txt = stdout.toString();
    const sub = txt.match(/^subject=(.*)$/m);
    const iss = txt.match(/^issuer=(.*)$/m);
    const end = txt.match(/^notAfter=(.*)$/m);
    if (sub) out.subject = sub[1].trim();
    if (end) {
      out.notAfter = end[1].trim();
      const t = Date.parse(out.notAfter);
      if (!Number.isNaN(t)) out.daysLeft = Math.round((t - Date.now()) / 86400000);
    }
    if (sub && iss) out.selfSigned = sub[1].trim() === iss[1].trim();
  } catch (_) { /* openssl missing */ }
  return out;
}

let certbotAvailable = null;
// Same reasoning as hasPm2() above — only a successful detection sticks.
async function hasCertbot() {
  if (certbotAvailable) return true;
  try {
    await execFileAsync('certbot', ['--version'], { timeout: 5000 });
    certbotAvailable = true;
    return true;
  } catch (_) {
    return false;
  }
}

// Runs the shelled-out probes concurrently — each is a separate child process,
// so there is no reason to make a caller wait for them one after another (that
// used to serialize up to ~4 blocking execFileSync calls behind /api/config,
// stalling the Settings tab and header version behind whichever probe was
// slowest AND blocking the Node event loop for every other connection while
// any one of them ran).
async function buildHealth() {
  const ce = config.configEditor;
  const [sshHostKey, editorCert, redirectCert, certbotInstalled] = await Promise.all([
    sshHostKeyStatus(),
    certInfo(envFileValue('CONFIG_EDITOR_CERT_PATH') || ce.certPath),
    certInfo(envFileValue('HTTPS_CERT_PATH') || config.httpsCertPath),
    hasCertbot(),
  ]);
  return {
    geoip: geoipStatus(),
    sshHostKey,
    certs: { editor: editorCert, redirect: redirectCert },
    certbotInstalled,
    domains: {
      editor: envFileValue('CONFIG_EDITOR_CERT_DOMAIN') || '',
      redirect: envFileValue('HTTPS_CERT_DOMAIN') || '',
    },
    sshMode: envFileValue('SSH_MODE') || config.sshMode || 'off',
  };
}

// ---------------------------------------------------------------------------
// /api/config — current values for the form
// ---------------------------------------------------------------------------
// Fast and synchronous except for hasPm2(), whose successful result is cached
// (warmed at startup — see startConfigEditorServer) so this stays non-blocking
// in practice; a not-yet-warmed or transiently-failed check just re-runs next
// call rather than wedging the result. Health data (ssh-keygen/openssl/certbot probes)
// lives behind the separate /api/health endpoint so a slow probe never delays
// the Settings sections or the header version — see buildHealth().
async function buildConfigPayload(session) {
  const secrets = security.readSecrets(session.username);
  const envPath = path.resolve(config.configEditor.envPath);
  let envText = '';
  try { envText = fs.readFileSync(envPath, 'utf-8'); } catch (_) {}
  const parsed = parseEnvText(envText);

  const sections = ENV_SCHEMA.map((sec) => ({
    name: sec.name,
    help: sec.help || null,
    icon: sec.icon || null,
    fields: sec.fields.map((f) => {
      const active = Object.prototype.hasOwnProperty.call(parsed.active, f.key);
      return {
        key: f.key,
        type: f.type,
        label: f.label,
        help: f.help || null,
        helpLong: f.helpLong || null,
        required: !!f.required,
        options: f.options || null,
        enabled: f.required ? true : active,
        value: active ? parsed.active[f.key] : (f.required ? (parsed.commented[f.key] || f.def || '') : ''),
        placeholder: !active ? (parsed.commented[f.key] || f.def || '') : '',
      };
    }),
  }));

  const files = {};
  for (const [name, p] of [
    ['whitelist', config.whitelistPath || './whitelist.txt'],
    ['blocklist', config.blocklistPath || './blocklist.txt'],
    ['trustedhosts', config.configEditor.trustedHostsPath || './trustedhosts.txt'],
    ['triggers', config.triggerBlock.listPath || './triggers.txt'],
    ['apihosts', config.api.trustedHostsPath || './api-trustedhosts.txt'],
    ['statushosts', config.status.trustedHostsPath || './status-trustedhosts.txt'],
  ]) {
    const r = readFileSafe(p);
    files[name] = { path: p, content: r.content, exists: r.exists };
  }

  return {
    csrf: session.csrf,
    username: session.username,
    sections,
    files,
    status: {
      pid: process.pid,
      version: appVersion(),
      uptimeHuman: humanUptime(process.uptime()),
      pm2: await hasPm2(),
      envPath,
      ip: session.ip,
      role: session.role || 'owner',
      mfaEnabled: !!(secrets && secrets.mfa && secrets.mfa.enabled),
      backupCodesRemaining: secrets ? secrets.backupCodes.filter((c) => !c.usedAt).length : 0,
    },
  };
}

// ---------------------------------------------------------------------------
// /api/save
// Timestamped .env backups are kept in an ENVBACKUPS/ folder next to .env,
// newest ENV_BACKUPS_KEPT retained.
// ---------------------------------------------------------------------------
function pruneBackups(backupDir, base) {
  try {
    const backups = fs.readdirSync(backupDir)
      .filter((n) => n.startsWith(base + '.bak.'))
      .sort();
    while (backups.length > ENV_BACKUPS_KEPT) {
      fs.unlinkSync(path.join(backupDir, backups.shift()));
    }
  } catch (_) { /* best effort */ }
}

// Earlier versions wrote .env backups next to .env. Move any that are still
// there into the ENVBACKUPS folder so everything lives in one place.
function migrateLegacyBackups(dir, backupDir, base) {
  try {
    for (const n of fs.readdirSync(dir)) {
      if (!n.startsWith(base + '.bak.')) continue;
      try { fs.renameSync(path.join(dir, n), path.join(backupDir, n)); } catch (_) {}
    }
  } catch (_) { /* best effort */ }
}

async function handleSave(req, res, session) {
  if (!acquire(res, 'save')) return;
  try {
    await doSave(req, res, session);
  } finally {
    release('save');
  }
}

async function doSave(req, res, session) {
  let payload;
  try {
    payload = JSON.parse(await readBody(req));
  } catch (err) {
    return sendJson(res, 400, { error: 'Invalid request body' });
  }

  const envInput = (payload && payload.env) || {};
  const filesInput = (payload && payload.files) || {};

  // Build the update map from submitted schema fields only.
  const updates = {};
  for (const [key, entry] of Object.entries(envInput)) {
    if (!SCHEMA_KEYS.has(key)) continue;
    if (typeof entry !== 'object' || entry === null) continue;
    const value = entry.value == null ? '' : String(entry.value);
    if (/[\r\n]/.test(value)) return sendJson(res, 400, { error: `${key} must not contain a newline` });
    const enabled = entry.required ? true : entry.enabled !== false;
    updates[key] = { value, enabled };
  }

  const inlineErrors = inlineValidate(updates);
  if (inlineErrors.length) return sendJson(res, 400, { errors: inlineErrors });

  // Validate the trusted hosts text before we let it through.
  if (typeof filesInput.trustedhosts === 'string') {
    const check = trustedhosts.validateText(filesInput.trustedhosts);
    if (check.invalid.length) {
      return sendJson(res, 400, {
        error: 'trustedhosts.txt has unparseable lines: ' + check.invalid.slice(0, 5).join(', '),
      });
    }
  }

  // Same check for the API IP allowlist (same file format).
  if (typeof filesInput.apihosts === 'string') {
    const check = trustedhosts.validateText(filesInput.apihosts);
    if (check.invalid.length) {
      return sendJson(res, 400, {
        error: 'api-trustedhosts.txt has unparseable lines: ' + check.invalid.slice(0, 5).join(', '),
      });
    }
  }

  // Same check for the /status endpoint's IP allowlist (same file format).
  if (typeof filesInput.statushosts === 'string') {
    const check = trustedhosts.validateText(filesInput.statushosts);
    if (check.invalid.length) {
      return sendJson(res, 400, {
        error: 'status-trustedhosts.txt has unparseable lines: ' + check.invalid.slice(0, 5).join(', '),
      });
    }
  }

  // Validate the trigger patterns: reject unparseable lines and regexes that
  // backtrack pathologically (a ReDoS the scan would run against every caller).
  if (typeof filesInput.triggers === 'string') {
    let tv = { invalid: [], slow: [] };
    try { tv = require('./ipfilter').validateTriggerText(filesInput.triggers); } catch (_) {}
    if (tv.invalid && tv.invalid.length) {
      return sendJson(res, 400, {
        error: 'triggers.txt has unparseable lines: ' + tv.invalid.slice(0, 5).join(', '),
      });
    }
    if (tv.slow && tv.slow.length) {
      return sendJson(res, 400, {
        error: 'triggers.txt has a regex that backtracks dangerously (possible ReDoS): ' +
          tv.slow.slice(0, 3).join(', '),
      });
    }
  }

  const envPath = path.resolve(config.configEditor.envPath);
  const dir = path.dirname(envPath);
  const base = path.basename(envPath);

  let originalText = '';
  try { originalText = fs.readFileSync(envPath, 'utf-8'); }
  catch (err) {
    if (err.code !== 'ENOENT') return sendJson(res, 500, { error: 'Cannot read .env: ' + err.message });
  }

  let newText;
  try {
    newText = applyEnvUpdates(originalText, updates);
  } catch (err) {
    return sendJson(res, 400, { error: err.message });
  }

  // Back up (into ENVBACKUPS/), then write.
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupDir = path.join(dir, ENV_BACKUP_DIRNAME);
  const backupPath = path.join(backupDir, `${base}.bak.${stamp}`);
  let backupMade = false;
  try {
    if (originalText !== '') {
      fs.mkdirSync(backupDir, { recursive: true, mode: 0o700 });
      migrateLegacyBackups(dir, backupDir, base);
      fs.copyFileSync(envPath, backupPath);
      chmodQuiet(backupPath, SECRET_FILE_MODE);
      backupMade = true;
    }
    fs.writeFileSync(envPath, newText, { mode: SECRET_FILE_MODE });
    chmodQuiet(envPath, SECRET_FILE_MODE); // mode: only applies on create; enforce on overwrite too
  } catch (err) {
    return sendJson(res, 500, { error: 'Write failed: ' + err.message });
  }

  // Authoritative validation: a fresh process loading the new file. The child
  // must see the file's values, not this process's — dotenv does not override
  // an env var that is already set, and every key that was in .env at startup
  // is still in our process.env. Strip every key either .env mentions so the
  // child's dotenv repopulates them from the new file (a key the user removed
  // then reads as unset, which is what we want to validate).
  const staleKeys = new Set(SCHEMA_KEYS);
  for (const src of [originalText, newText]) {
    for (const line of src.split(/\r?\n/)) {
      const m = line.match(ENV_LINE_RE);
      if (m) staleKeys.add(m[3]);
    }
  }
  const childEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (!staleKeys.has(k)) childEnv[k] = v;
  }
  childEnv.DOTENV_CONFIG_QUIET = 'true';

  try {
    execFileSync(process.execPath, ['-e', 'require("./config").validateConfig()'], {
      cwd: __dirname,
      stdio: 'pipe',
      timeout: 8000,
      env: childEnv,
    });
  } catch (err) {
    if (backupMade) {
      try { fs.copyFileSync(backupPath, envPath); } catch (_) {}
    } else {
      try { fs.unlinkSync(envPath); } catch (_) {}
    }
    pruneBackups(backupDir, base);
    const detail = extractValidationErrors(err);
    return sendJson(res, 400, { error: 'Configuration rejected, .env restored:\n' + detail });
  }

  pruneBackups(backupDir, base);

  // Write the list files after the .env passes.
  const fileResults = {};
  for (const [name, target] of [
    ['whitelist', config.whitelistPath || './whitelist.txt'],
    ['blocklist', config.blocklistPath || './blocklist.txt'],
    ['trustedhosts', config.configEditor.trustedHostsPath || './trustedhosts.txt'],
    ['triggers', config.triggerBlock.listPath || './triggers.txt'],
    ['apihosts', config.api.trustedHostsPath || './api-trustedhosts.txt'],
    ['statushosts', config.status.trustedHostsPath || './status-trustedhosts.txt'],
  ]) {
    if (typeof filesInput[name] !== 'string') continue;
    try {
      let text = filesInput[name].replace(/\r\n/g, '\n');
      if (text !== '' && !text.endsWith('\n')) text += '\n';
      const abs = path.resolve(target);
      fs.writeFileSync(abs, text, { mode: SECRET_FILE_MODE });
      chmodQuiet(abs, SECRET_FILE_MODE);
      fileResults[name] = 'saved';
    } catch (err) {
      fileResults[name] = 'error: ' + err.message;
    }
  }

  // Reload the trusted-host allowlist so the change takes effect immediately.
  loadedTrustedHosts = trustedhosts.loadTrustedHosts(config.configEditor.trustedHostsPath);
  // Same for the API IP allowlist.
  loadedApiHosts = trustedhosts.loadTrustedHosts(config.api.trustedHostsPath);
  // Same for the /status endpoint's IP allowlist.
  loadedStatusHosts = trustedhosts.loadTrustedHosts(config.status.trustedHostsPath);

  // Reload the ipfilter list files that changed, so edits apply without a restart.
  try {
    const ipf = require('./ipfilter').getIPFilter();
    if (ipf) {
      if (typeof filesInput.whitelist === 'string' && ipf.reloadWhitelist) ipf.reloadWhitelist();
      if (typeof filesInput.blocklist === 'string' && ipf.reloadBlocklist) ipf.reloadBlocklist();
      if (typeof filesInput.triggers === 'string' && ipf.reloadTriggers) ipf.reloadTriggers();
    }
  } catch (_) { /* ipfilter not ready — restart will pick it up */ }

  log.info(`Config saved by "${sanitizeForLog(session.username)}" from ${clientIp(req)}`);

  return sendJson(res, 200, {
    ok: true,
    backup: backupMade ? `${ENV_BACKUP_DIRNAME}/${path.basename(backupPath)}` : null,
    files: fileResults,
    trustedHostCount: loadedTrustedHosts.entries.length,
  });
}

// ---------------------------------------------------------------------------
// session persistence across a restart
// The restart button can carry the current admin session over the pm2 restart
// so the admin is not bounced to the login screen. Sessions are written to a
// root-only file next to .env and read back exactly once, at startup.
// ---------------------------------------------------------------------------
function persistSessions() {
  try {
    const out = [];
    for (const [token, s] of sessions) {
      out.push({ token, username: s.username, ip: s.ip, created: s.created, lastSeen: s.lastSeen, csrf: s.csrf,
        mfaVerified: !!s.mfaVerified, role: s.role });
    }
    fs.writeFileSync(SESSION_STORE, JSON.stringify({ savedAt: Date.now(), sessions: out }), { mode: 0o600 });
    return out.length;
  } catch (err) {
    log.warn(`Config editor: could not persist sessions — ${err.message}`);
    return 0;
  }
}

function loadPersistedSessions() {
  let raw;
  try {
    raw = fs.readFileSync(SESSION_STORE, 'utf-8');
  } catch (_) {
    return 0; // nothing to restore
  }
  // Single-use: delete immediately so a later crash-restart can't resurrect them.
  try { fs.unlinkSync(SESSION_STORE); } catch (_) {}

  let data;
  try { data = JSON.parse(raw); } catch (_) { return 0; }
  const now = Date.now();
  let restored = 0;
  for (const s of (data.sessions || [])) {
    if (!s || !TOKEN_RE.test(String(s.token || '')) || !TOKEN_RE.test(String(s.csrf || ''))) continue;
    if (!Number.isFinite(s.lastSeen) || !Number.isFinite(s.created)) continue;
    if (now - s.lastSeen > config.configEditor.sessionTimeoutMs) continue;
    if (now - s.created > ABSOLUTE_SESSION_MS) continue;
    sessions.set(s.token, {
      username: String(s.username || ''),
      ip: String(s.ip || ''),
      created: s.created,
      lastSeen: s.lastSeen,
      csrf: s.csrf,
      // Preserve MFA-verified status across the carry-over: this is the same
      // already-authenticated admin restarting their own firewall, not a new
      // login, so it should not re-challenge for MFA. Defaults to false (the
      // safer state) for an older persisted session that predates this field.
      mfaVerified: !!s.mfaVerified,
      // Defaults to 'owner' for a session persisted before roles existed -
      // matches normalizeAccount()'s same default for a pre-role account.
      role: security.ROLES.includes(s.role) ? s.role : 'owner',
    });
    restored++;
  }
  return restored;
}

// ---------------------------------------------------------------------------
// /api/restart
// ---------------------------------------------------------------------------
async function handleRestart(req, res, session) {
  if (!acquire(res, 'restart')) return;
  const name = config.configEditor.pm2AppName || 'bbsfirewall';

  let keepSession = true;
  try {
    const body = JSON.parse(await readBody(req) || '{}');
    if (body && body.keepSession === false) keepSession = false;
  } catch (_) { /* default keepSession = true */ }

  if (!(await hasPm2())) {
    release('restart');
    return sendJson(res, 200, {
      ok: true,
      restarting: false,
      message: 'pm2 was not found on this host. Restart BBSFirewall manually to apply .env changes.',
    });
  }
  // Lock stays held: the process is about to exit, which clears it anyway.

  let carried = 0;
  if (keepSession) {
    carried = persistSessions();
  } else {
    try { fs.unlinkSync(SESSION_STORE); } catch (_) {}
    // Log this admin out NOW, not just on the next process's empty session
    // map — the old process keeps running for a few seconds while pm2 tears
    // it down (see stopConfigEditorServer's comment), and without this it
    // stays fully authenticated on any request that reaches it during that
    // window, which is the opposite of what "don't keep me signed in" asked
    // for. Only this one session is touched, not the whole Map, so it can't
    // reintroduce the false-401 bug that removing the blanket clear fixed.
    destroySession(req);
  }

  log.warn(`Restart requested by "${sanitizeForLog(session.username)}" from ${clientIp(req)} ` +
    `(pm2 restart ${name}, keepSession=${keepSession})`);
  sendJson(res, 200, {
    ok: true,
    restarting: true,
    keepSession,
    message: keepSession
      ? `Restarting "${name}". Your session will carry over — the page reconnects on its own in a few seconds.`
      : `Restarting "${name}". You will be signed out; sign in again in a few seconds.`,
  });

  // Fire after the response has flushed — this also restarts the editor itself.
  setTimeout(() => {
    execFile('pm2', ['restart', name, '--update-env'], { timeout: 20000 }, (err) => {
      if (err) {
        log.error(`pm2 restart failed: ${err.message}`);
        release('restart'); // let the admin try again; we did not actually restart
      }
    });
  }, 750);
}

// ---------------------------------------------------------------------------
// shell-backed actions (Tools tab): run a command, capture output, return it.
// ---------------------------------------------------------------------------
function runAction(file, args, opts, cb) {
  const started = Date.now();
  execFile(file, args, {
    cwd: __dirname,
    timeout: (opts && opts.timeout) || ACTION_TIMEOUT_MS,
    maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, DOTENV_CONFIG_QUIET: 'true' },
  }, (err, stdout, stderr) => {
    const output = ((stdout || '') + (stderr || '')).replace(/\x1b\[[0-9;]*m/g, '');
    cb({
      ok: !err,
      exitCode: err ? (err.code == null ? -1 : err.code) : 0,
      timedOut: !!(err && err.killed),
      ms: Date.now() - started,
      output: output.trim(),
    });
  });
}

// ---------------------------------------------------------------------------
// /api/geoip  { action: 'download' | 'update' }
// ---------------------------------------------------------------------------
async function handleGeoip(req, res, session) {
  if (!acquire(res, 'geoip')) return;
  let action = 'download';
  try {
    const b = JSON.parse(await readBody(req) || '{}');
    if (b && b.action === 'update') action = 'update';
  } catch (_) {}

  if (!(envFileValue('MAXMIND_LICENSE_KEY') || '').trim()) {
    release('geoip');
    return sendJson(res, 400, {
      error: 'Set MAXMIND_LICENSE_KEY in the Country Blocking section and Save before downloading the database.',
    });
  }

  const args = ['download-geoip.js'];
  if (action === 'update') args.push('--force');

  log.info(`GeoIP ${action} requested by "${sanitizeForLog(session.username)}" from ${clientIp(req)}`);
  runAction(process.execPath, args, { timeout: ACTION_TIMEOUT_MS }, async (r) => {
    release('geoip');
    if (r.ok) {
      try {
        await require('./geoip').reloadGeoIP();
        r.output += '\n\nGeoIP database reloaded into the running firewall.';
      } catch (e) {
        r.output += `\n\nDownloaded, but live reload failed (${e.message}). Restart to load it.`;
      }
    }
    sendJson(res, r.ok ? 200 : 400, {
      ok: r.ok,
      action,
      exitCode: r.exitCode,
      output: r.output,
      geoip: geoipStatus(),
    });
  });
}

// ---------------------------------------------------------------------------
// /api/sshkey  { overwrite?: bool, type?: 'rsa' | 'ed25519' }
// ---------------------------------------------------------------------------
async function handleSshKey(req, res, session) {
  if (!acquire(res, 'sshkey')) return;
  let overwrite = false;
  let type = 'rsa';
  try {
    const b = JSON.parse(await readBody(req) || '{}');
    if (b && b.overwrite === true) overwrite = true;
    if (b && b.type === 'ed25519') type = 'ed25519';
  } catch (_) {}

  const keyPath = path.resolve(envFileValue('SSH_HOST_KEY') || config.sshHostKey || './ssh_host_key');

  // This handler deletes keyPath (+ .pub) before generating. Refuse to point
  // that at anything outside the app directory or at a source/config file — a
  // typo'd SSH_HOST_KEY should never let the button delete .env or a .js file.
  const relToApp = path.relative(__dirname, keyPath);
  const bad = relToApp.startsWith('..') || path.isAbsolute(relToApp) ||
    /\.(env|js|json|sh|pem|cjs|mjs)$/i.test(path.basename(keyPath)) ||
    path.basename(keyPath).startsWith('.env');
  if (bad) {
    release('sshkey');
    return sendJson(res, 400, {
      error: `Refusing to use SSH_HOST_KEY path "${keyPath}". Set it to a plain filename ` +
        `inside the BBSFirewall directory (e.g. ./ssh_host_key) and Save first.`,
    });
  }

  if (fs.existsSync(keyPath) && !overwrite) {
    release('sshkey');
    return sendJson(res, 409, {
      error: `A host key already exists at ${keyPath}. Re-run with "overwrite" to replace it (existing SSH clients will see a changed host key).`,
      sshHostKey: await sshHostKeyStatus(),
    });
  }

  try {
    if (fs.existsSync(keyPath)) fs.unlinkSync(keyPath);
    if (fs.existsSync(keyPath + '.pub')) fs.unlinkSync(keyPath + '.pub');
    const dir = path.dirname(keyPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  } catch (err) {
    release('sshkey');
    return sendJson(res, 500, { error: `Could not clear the old key: ${err.message}` });
  }

  const args = type === 'ed25519'
    ? ['-t', 'ed25519', '-N', '', '-C', 'bbsfirewall-host-key', '-f', keyPath]
    : ['-t', 'rsa', '-b', '3072', '-m', 'PEM', '-N', '', '-C', 'bbsfirewall-host-key', '-f', keyPath];

  log.info(`SSH host key (${type}) generation requested by "${sanitizeForLog(session.username)}" from ${clientIp(req)}`);
  runAction('ssh-keygen', args, { timeout: 30000 }, async (r) => {
    release('sshkey');
    if (r.ok) {
      try { fs.chmodSync(keyPath, 0o600); } catch (_) {}
      invalidateHealthCache();
    }
    sendJson(res, r.ok ? 200 : 500, {
      ok: r.ok,
      output: r.output || (r.ok ? `Host key written to ${keyPath}` : 'ssh-keygen failed'),
      sshHostKey: await sshHostKeyStatus(),
      note: r.ok ? 'Set SSH_MODE=terminate (if not already) and restart to use it.' : undefined,
    });
  });
}

// ---------------------------------------------------------------------------
// /api/cert  { target: 'editor' | 'redirect' }
// Runs the matching setup script in Let's Encrypt mode. The scripts install
// certbot themselves if it is missing.
// ---------------------------------------------------------------------------
async function handleCert(req, res, session) {
  if (!acquire(res, 'cert')) return;
  let target = 'editor';
  try {
    const b = JSON.parse(await readBody(req) || '{}');
    if (b && b.target === 'redirect') target = 'redirect';
  } catch (_) {}

  const domain = ((target === 'editor'
    ? envFileValue('CONFIG_EDITOR_CERT_DOMAIN')
    : envFileValue('HTTPS_CERT_DOMAIN')) || '').trim();
  const email = ((target === 'editor'
    ? envFileValue('CONFIG_EDITOR_CERT_EMAIL')
    : envFileValue('HTTPS_CERT_EMAIL')) || '').trim();

  if (!domain) {
    release('cert');
    return sendJson(res, 400, {
      error: target === 'editor'
        ? 'Set CONFIG_EDITOR_CERT_DOMAIN in the Config Editor section and Save first.'
        : 'Set HTTPS_CERT_DOMAIN in the Web Redirect section and Save first.',
    });
  }
  if (!/^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i.test(domain)) {
    release('cert');
    return sendJson(res, 400, { error: `"${domain}" does not look like a hostname.` });
  }
  if (email && !/^[^\s@"]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(email)) {
    release('cert');
    return sendJson(res, 400, { error: `"${email}" does not look like an email address.` });
  }

  const script = target === 'editor' ? 'setup-config-cert.sh' : 'setup-certs.sh';
  const args = [script, domain];
  if (email) args.push('--email', email);

  log.warn(`Let's Encrypt issuance for ${target} (${domain}) requested by "${sanitizeForLog(session.username)}" from ${clientIp(req)}`);
  runAction('bash', args, { timeout: ACTION_TIMEOUT_MS }, async (r) => {
    release('cert');
    if (r.ok) invalidateHealthCache();
    let reloaded = false;
    if (r.ok && target === 'editor') {
      reloaded = reloadEditorCert();
      r.output += reloaded
        ? '\n\nNew certificate loaded into the running editor — no restart needed.'
        : '\n\nCertificate issued. Restart to load it into the editor.';
    }
    if (r.ok && target === 'redirect') {
      r.output += '\n\nCertificate issued. Restart the firewall to load it into the port-443 redirect.';
    }
    const health = await buildHealth();
    sendJson(res, r.ok ? 200 : 400, {
      ok: r.ok,
      target,
      domain,
      exitCode: r.exitCode,
      certbotInstalled: health.certbotInstalled,
      output: r.output || (r.ok ? 'done' : 'certbot failed — see console output above'),
      health,
    });
  });
}

// ---------------------------------------------------------------------------
// /api/update/* — self-update via updater.js (see its header for the full
// backup -> download -> overlay -> npm install -> validateConfig() ->
// restart, with an automatic rollback on any failure).
// ---------------------------------------------------------------------------
const UPDATE_CACHE_TTL_MS = 60 * 1000; // GitHub's unauthenticated API is rate-limited to 60 req/hr
let updateCheckCache = null; // { at, value }

function invalidateUpdateCache() { updateCheckCache = null; }

async function handleUpdateCheck(req, res) {
  if (updateCheckCache && Date.now() - updateCheckCache.at < UPDATE_CACHE_TTL_MS) {
    return sendJson(res, 200, updateCheckCache.value);
  }
  const info = await updater.checkForUpdate(__dirname);
  const value = {
    ...info,
    platformSupported: !updater.checkPlatform(),
    tarAvailable: await updater.hasTar(),
    backups: updater.listBackups(__dirname),
  };
  updateCheckCache = { at: Date.now(), value };
  sendJson(res, info.error ? 502 : 200, value);
}

// Fire the pm2 restart after the HTTP response has flushed — same pattern
// and same session carry-over as handleRestart, since a successful update
// always needs a restart to actually run the new code.
function restartAfterUpdate(req, keepSession) {
  const name = config.configEditor.pm2AppName || 'bbsfirewall';
  if (keepSession) {
    persistSessions();
  } else {
    try { fs.unlinkSync(SESSION_STORE); } catch (_) {}
    destroySession(req);
  }
  setTimeout(() => {
    execFile('pm2', ['restart', name, '--update-env'], { timeout: 20000 }, (err) => {
      if (err) {
        log.error(`pm2 restart after update failed: ${err.message}`);
        release('update'); // let the admin try again; the code was already updated on disk
      }
    });
  }, 750);
}

async function handleUpdateApply(req, res, session) {
  if (!acquire(res, 'update')) return;
  let tag;
  let keepSession = true;
  try {
    const b = JSON.parse(await readBody(req) || '{}');
    if (b && typeof b.tag === 'string') tag = b.tag;
    if (b && b.keepSession === false) keepSession = false;
  } catch (_) {}

  log.warn(`Update ${tag ? `to "${sanitizeForLog(tag)}" ` : ''}requested by "${sanitizeForLog(session.username)}" from ${clientIp(req)}`);
  const result = await updater.applyUpdate({ tag, appDir: __dirname });
  invalidateUpdateCache();

  if (!result.ok) {
    release('update');
    return sendJson(res, 400, result);
  }

  if (!(await updater.hasPm2())) {
    release('update');
    return sendJson(res, 200, {
      ...result,
      restarting: false,
      message: `Updated to v${result.newVersion}. pm2 was not found on this host — restart BBSFirewall manually to run the new version.`,
    });
  }

  // Lock stays held: the process is about to exit, which clears it anyway.
  sendJson(res, 200, {
    ...result,
    restarting: true,
    keepSession,
    message: keepSession
      ? `Updated to v${result.newVersion}. Restarting — the page reconnects on its own in a few seconds.`
      : `Updated to v${result.newVersion}. Restarting — you will be signed out; sign in again in a few seconds.`,
  });
  restartAfterUpdate(req, keepSession);
}

async function handleUpdateRollback(req, res, session) {
  if (!acquire(res, 'update')) return;
  let backup;
  let keepSession = true;
  try {
    const b = JSON.parse(await readBody(req) || '{}');
    backup = b && b.backup;
    if (b && b.keepSession === false) keepSession = false;
  } catch (_) {}

  if (!backup) {
    release('update');
    return sendJson(res, 400, { error: 'Missing "backup" name.' });
  }

  log.warn(`Rollback to "${sanitizeForLog(backup)}" requested by "${sanitizeForLog(session.username)}" from ${clientIp(req)}`);
  const result = await updater.rollbackToBackup(backup, __dirname);
  invalidateUpdateCache();

  if (!result.ok) {
    release('update');
    return sendJson(res, 400, result);
  }

  if (!(await updater.hasPm2())) {
    release('update');
    return sendJson(res, 200, {
      ...result,
      restarting: false,
      message: `Restored v${result.newVersion}. pm2 was not found on this host — restart BBSFirewall manually to run it.`,
    });
  }

  sendJson(res, 200, {
    ...result,
    restarting: true,
    keepSession,
    message: keepSession
      ? `Restored v${result.newVersion}. Restarting — the page reconnects on its own in a few seconds.`
      : `Restored v${result.newVersion}. Restarting — you will be signed out; sign in again in a few seconds.`,
  });
  restartAfterUpdate(req, keepSession);
}

// Hot-swap the editor's own TLS certificate without a restart.
function reloadEditorCert() {
  if (!server || typeof server.setSecureContext !== 'function') return false;
  try {
    const ce = config.configEditor;
    const key = fs.readFileSync(path.resolve(envFileValue('CONFIG_EDITOR_KEY_PATH') || ce.keyPath));
    const cert = fs.readFileSync(path.resolve(envFileValue('CONFIG_EDITOR_CERT_PATH') || ce.certPath));
    server.setSecureContext({ key, cert });
    log.info('Config editor: TLS certificate reloaded');
    return true;
  } catch (err) {
    log.warn(`Config editor: cert reload failed — ${err.message}`);
    return false;
  }
}

// ---------------------------------------------------------------------------
// /api/stats — live performance numbers for the Performance tab
// ---------------------------------------------------------------------------
function cpuPercent() {
  const cpus = os.cpus();
  let idle = 0, total = 0;
  for (const c of cpus) {
    for (const k of Object.keys(c.times)) total += c.times[k];
    idle += c.times.idle;
  }
  let pct = null;
  if (lastCpuSample) {
    const dIdle = idle - lastCpuSample.idle;
    const dTotal = total - lastCpuSample.total;
    if (dTotal > 0) pct = Math.max(0, Math.min(100, Math.round((1 - dIdle / dTotal) * 100)));
  }
  lastCpuSample = { idle, total };
  return { percent: pct, cores: cpus.length, model: cpus[0] ? cpus[0].model.trim() : null };
}

function networkRates() {
  // Linux only. Returns per-interface bytes/sec since the last call.
  let text;
  try { text = fs.readFileSync('/proc/net/dev', 'utf-8'); }
  catch (_) { return null; }

  const now = Date.now();
  const cur = {};
  for (const line of text.split('\n')) {
    const m = line.match(/^\s*([^:]+):\s*(\d+)(?:\s+\d+){7}\s+(\d+)/);
    if (!m) continue;
    const iface = m[1].trim();
    if (iface === 'lo') continue;
    cur[iface] = { rx: Number(m[2]), tx: Number(m[3]) };
  }

  let rates = null;
  if (lastNetSample && lastNetSample.at) {
    const dt = (now - lastNetSample.at) / 1000;
    if (dt > 0) {
      rates = {};
      for (const iface of Object.keys(cur)) {
        const prev = lastNetSample.data[iface];
        if (!prev) continue;
        rates[iface] = {
          rxBytesPerSec: Math.max(0, Math.round((cur[iface].rx - prev.rx) / dt)),
          txBytesPerSec: Math.max(0, Math.round((cur[iface].tx - prev.tx) / dt)),
        };
      }
    }
  }
  lastNetSample = { at: now, data: cur };
  return rates;
}

function diskInfo() {
  try {
    if (typeof fs.statfsSync === 'function') {
      const s = fs.statfsSync(__dirname);
      const total = s.blocks * s.bsize;
      const free = s.bavail * s.bsize;
      return { totalBytes: total, freeBytes: free, usedBytes: total - free, path: __dirname };
    }
  } catch (_) {}
  return null;
}

// Recursive size of the BBSFirewall install directory, excluding node_modules
// and .git (the numbers a sysop actually cares about — "how much am I using
// beyond dependencies I didn't put there") and symlinks (avoids cycles).
// Cached briefly: a full recursive walk on every 4s /api/stats poll is real
// disk I/O, especially once node_modules is excluded but everything else
// (certs, ENVBACKUPS, data/, logs/) still gets walked.
const FOLDER_SIZE_CACHE_MS = 60 * 1000;
let folderSizeCache = null; // { at, bytes }
const FOLDER_SIZE_EXCLUDE = new Set(['node_modules', '.git']);

function folderSize(dir) {
  let total = 0;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return 0; }
  for (const entry of entries) {
    if (FOLDER_SIZE_EXCLUDE.has(entry.name)) continue;
    if (entry.isSymbolicLink()) continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      total += folderSize(full);
    } else if (entry.isFile()) {
      try { total += fs.statSync(full).size; } catch (_) {}
    }
  }
  return total;
}

function cachedFolderSize() {
  const now = Date.now();
  if (folderSizeCache && now - folderSizeCache.at < FOLDER_SIZE_CACHE_MS) {
    return folderSizeCache.bytes;
  }
  const bytes = folderSize(__dirname);
  folderSizeCache = { at: now, bytes };
  return bytes;
}

function handleStats(res) {
  const ipf = (() => {
    try { return require('./ipfilter').getIPFilter(); } catch (_) { return null; }
  })();

  const mem = process.memoryUsage();
  const stats = {
    now: Date.now(),
    host: {
      hostname: os.hostname(),
      version: appVersion(),
      platform: process.platform,
      osUptimeSec: Math.floor(os.uptime()),
      procUptimeSec: Math.floor(process.uptime()),
      loadavg: os.loadavg().map((n) => Math.round(n * 100) / 100),
      cpu: cpuPercent(),
      memTotalBytes: os.totalmem(),
      memFreeBytes: os.freemem(),
      nodeVersion: process.version,
    },
    process: {
      pid: process.pid,
      rssBytes: mem.rss,
      heapUsedBytes: mem.heapUsed,
      heapTotalBytes: mem.heapTotal,
    },
    network: networkRates(),
    disk: diskInfo(),
    folder: { totalBytes: cachedFolderSize(), excludesNodeModules: true },
    logsBytes: require('./file-logger').listLogFiles().reduce((sum, f) => sum + f.size, 0),
    firewall: {
      ...metrics.snapshot(),
      ipfilter: ipf && typeof ipf.getStats === 'function' ? ipf.getStats() : null,
    },
    geoip: geoipStatus(),
  };
  sendJson(res, 200, stats);
}

// ---------------------------------------------------------------------------
// /api/logs — view/delete the per-proxy rotated log files (file-logger.js).
// Listing and viewing are plain reads; delete goes through the same one-at-a-
// time busy lock as the other mutating Tools actions.
// ---------------------------------------------------------------------------
const LOG_VIEW_MAX_BYTES = 512 * 1024;

function handleLogsList(res) {
  try {
    const files = require('./file-logger').listLogFiles();
    return sendJson(res, 200, {
      dir: path.resolve(config.fileLog.dir || './logs'),
      enabled: !!config.fileLog.enabled,
      files,
    });
  } catch (err) {
    return sendJson(res, 500, { error: 'Could not list log files: ' + err.message });
  }
}

function handleLogsView(res, query) {
  const proxy = query.get('proxy') || '';
  const file = query.get('file') || '';
  try {
    const result = require('./file-logger').readLogFile(proxy, file, { maxBytes: LOG_VIEW_MAX_BYTES });
    return sendJson(res, 200, { proxy, file, ...result });
  } catch (err) {
    if (err.code === 'ENOENT') return sendJson(res, 404, { error: 'Log file not found' });
    return sendJson(res, 400, { error: err.message });
  }
}

async function handleLogsDelete(req, res, session) {
  if (!acquire(res, 'logs')) return;
  try {
    let payload;
    try { payload = JSON.parse((await readBody(req)) || '{}'); } catch (_) {
      return sendJson(res, 400, { error: 'Invalid request body' });
    }
    const proxy = payload && payload.proxy;
    const file = payload && payload.file;
    require('./file-logger').deleteLogFile(proxy, file);
    log.info(`Log file deleted by "${sanitizeForLog(session.username)}" from ${clientIp(req)}: ${proxy}/${file}`);
    return sendJson(res, 200, { ok: true, proxy, file });
  } catch (err) {
    if (err.code === 'ENOENT') return sendJson(res, 404, { error: 'Log file not found' });
    return sendJson(res, 400, { error: err.message });
  } finally {
    release('logs');
  }
}

// ---------------------------------------------------------------------------
// login
// ---------------------------------------------------------------------------
// Fixed scrypt record used when no admin account exists yet, so
// verifyPassword() still does real scrypt work and "no admin configured"
// takes the same time as "wrong password" — never leaks setup state to an
// unauthenticated caller. Computed once (the salt/params don't need to be
// secret; nothing will ever match this hash).
const DUMMY_PASSWORD_RECORD = security.hashPassword(crypto.randomBytes(32).toString('hex'));

async function handleLoginPost(req, res, ip) {
  if (loginLocked(ip)) {
    return sendPage(res, 429, (n) => views.loginPage({ nonce: n, error: 'Too many failed attempts. Try again later.' }));
  }

  const body = await readBody(req);
  const form = new URLSearchParams(body);
  const username = form.get('username') || '';
  const password = form.get('password') || '';

  // With more than one possible account, the exact-match lookup by username
  // IS the username check - there's no separate "cfgUser" to compare against
  // anymore. Still always runs real scrypt work against SOME record (the
  // account's own, or the dummy) so response time doesn't reveal whether the
  // username exists.
  const secrets = security.readSecrets(username);
  const passRecord = secrets ? secrets.password : DUMMY_PASSWORD_RECORD;
  const passOk = security.verifyPassword(password, passRecord);
  const ok = !!secrets && passOk;
  if (!ok) {
    recordLoginFail(ip);
    log.blocked(`Failed config editor login for "${sanitizeForLog(username)}" from ${ip}`);
    return sendPage(res, 401, (n) => views.loginPage({ nonce: n, error: 'Invalid username or password.' }));
  }

  loginFails.delete(ip);
  const mfaEnabled = !!(secrets.mfa && secrets.mfa.enabled);
  const { token } = createSession(username, ip, !mfaEnabled, secrets.role);
  const maxAge = Math.floor(ABSOLUTE_SESSION_MS / 1000);
  res.writeHead(302, {
    Location: '/',
    'Set-Cookie': cookieHeader(token, maxAge) + `; Max-Age=${maxAge}`,
    'Cache-Control': 'no-store',
  });
  res.end();
  log.info(`Config editor login: "${sanitizeForLog(username)}" from ${ip}`);
}

// ---------------------------------------------------------------------------
// /api/security/* — MFA verification (completes login) + the Security
// Settings self-service actions (change password, enable/disable MFA,
// regenerate backup codes, whitelist my IP). Browser session lane only —
// deliberately not exposed on the key-authenticated Management API.
// ---------------------------------------------------------------------------

// Marks the CALLER'S OWN in-memory session verified — `session` here is the
// {token, ...} copy getSession() returns, not the object stored in the
// sessions Map, so the Map entry has to be updated directly (or a fresh
// login next request would still see mfaVerified:false).
function markSessionMfaVerified(session) {
  const stored = sessions.get(session.token);
  if (stored) stored.mfaVerified = true;
}

async function handleMfaVerifyLogin(req, res, session, ip) {
  if (mfaLocked(ip)) {
    return sendJson(res, 429, { error: 'Too many failed attempts. Try again later.' });
  }
  let body;
  try { body = JSON.parse(await readBody(req) || '{}'); } catch (_) { body = {}; }

  const secrets = security.readSecrets(session.username);
  if (!secrets || !secrets.mfa || !secrets.mfa.enabled || !secrets.mfa.secret) {
    // Shouldn't normally be reachable (mfaVerified starts true when MFA is
    // off), but fail closed rather than silently accepting anything.
    return sendJson(res, 400, { error: 'MFA is not enabled on this account.' });
  }

  let ok = false;
  if (body.backupCode) {
    ok = security.verifyAndConsumeBackupCode(secrets, String(body.backupCode));
  } else if (body.code) {
    ok = security.verifyTotp(secrets, 'secret', String(body.code));
  }

  if (!ok) {
    recordMfaFail(ip);
    log.blocked(`Failed MFA verification for "${sanitizeForLog(session.username)}" from ${ip}`);
    return sendJson(res, 401, { error: 'Invalid code.' });
  }

  mfaFails.delete(ip);
  markSessionMfaVerified(session);
  log.info(`MFA verified for "${sanitizeForLog(session.username)}" from ${ip}`);
  return sendJson(res, 200, { ok: true });
}

async function handleChangePassword(req, res, session) {
  if (!acquire(res, 'security')) return;
  let body;
  try { body = JSON.parse(await readBody(req) || '{}'); } catch (_) { body = {}; }
  const current = String(body.currentPassword || '');
  const next = String(body.newPassword || '');

  const secrets = security.readSecrets(session.username);
  if (!secrets) { release('security'); return sendJson(res, 400, { error: 'No admin account configured.' }); }
  if (!security.verifyPassword(current, secrets.password)) {
    release('security');
    return sendJson(res, 401, { error: 'Current password is incorrect.' });
  }
  if (next.length < 8) {
    release('security');
    return sendJson(res, 400, { error: 'New password must be at least 8 characters.' });
  }

  secrets.password = security.hashPassword(next);
  security.writeSecrets(secrets);

  // An attacker holding a stolen session cookie should not survive a
  // password change — drop every OTHER session for THIS account (other
  // admins' sessions are unaffected).
  revokeOtherSessionsForUser(session.username, session.token);

  release('security');
  log.info(`Password changed by "${sanitizeForLog(session.username)}" from ${clientIp(req)}`);
  return sendJson(res, 200, { ok: true });
}

async function handleMfaSetup(req, res, session) {
  if (!acquire(res, 'security')) return;
  const secrets = security.readSecrets(session.username);
  if (!secrets) { release('security'); return sendJson(res, 400, { error: 'No admin account configured.' }); }

  const pendingSecret = security.generateTotpSecret();
  secrets.mfa.pendingSecret = pendingSecret;
  security.writeSecrets(secrets);

  release('security');
  return sendJson(res, 200, {
    ok: true,
    secret: pendingSecret,
    otpauthUrl: security.otpauthUrl(secrets.username, pendingSecret),
  });
}

async function handleMfaConfirm(req, res, session) {
  if (!acquire(res, 'security')) return;
  let body;
  try { body = JSON.parse(await readBody(req) || '{}'); } catch (_) { body = {}; }

  const secrets = security.readSecrets(session.username);
  if (!secrets || !secrets.mfa.pendingSecret) {
    release('security');
    return sendJson(res, 400, { error: 'No MFA setup in progress — start from "Enable MFA" again.' });
  }
  if (!security.verifyTotp(secrets, 'pendingSecret', String(body.code || ''))) {
    release('security');
    return sendJson(res, 401, { error: 'Invalid code.' });
  }

  secrets.mfa.secret = secrets.mfa.pendingSecret;
  secrets.mfa.pendingSecret = null;
  secrets.mfa.enabled = true;
  secrets.mfa.confirmedAt = Date.now();
  const backupCodes = security.generateBackupCodes(8);
  secrets.backupCodes = backupCodes.map((c) => security.hashBackupCode(c));
  security.writeSecrets(secrets);

  // mfaVerified is decided once, at createSession() time, and never
  // re-checked against the account's current MFA state — so a session opened
  // before MFA was enabled (e.g. a leaked/stolen cookie) would otherwise keep
  // full access forever with the new second factor never enforced against
  // it. Same reasoning as handleChangePassword's revoke-the-rest above.
  revokeOtherSessionsForUser(session.username, session.token);

  release('security');
  log.info(`MFA enabled by "${sanitizeForLog(session.username)}" from ${clientIp(req)}`);
  // Plaintext codes are returned exactly once, here, and never stored or
  // logged — only their hashes persist.
  return sendJson(res, 200, { ok: true, backupCodes });
}

async function handleMfaDisable(req, res, session) {
  if (!acquire(res, 'security')) return;
  let body;
  try { body = JSON.parse(await readBody(req) || '{}'); } catch (_) { body = {}; }

  const secrets = security.readSecrets(session.username);
  if (!secrets) { release('security'); return sendJson(res, 400, { error: 'No admin account configured.' }); }
  if (!security.verifyPassword(String(body.currentPassword || ''), secrets.password)) {
    release('security');
    return sendJson(res, 401, { error: 'Current password is incorrect.' });
  }

  // Defense in depth against a stolen session cookie alone disabling MFA:
  // still requires a live TOTP code or an unused backup code, same as any
  // other MFA check.
  let factorOk = false;
  if (body.backupCode) factorOk = security.verifyAndConsumeBackupCode(secrets, String(body.backupCode));
  else if (body.code) factorOk = security.verifyTotp(secrets, 'secret', String(body.code));
  if (!factorOk) {
    release('security');
    return sendJson(res, 401, { error: 'Invalid code.' });
  }

  secrets.mfa = { enabled: false, secret: null, pendingSecret: null, confirmedAt: null };
  secrets.backupCodes = [];
  security.writeSecrets(secrets);

  // Security-posture change — same revoke-the-rest policy as password change
  // and MFA enable, above.
  revokeOtherSessionsForUser(session.username, session.token);

  release('security');
  log.warn(`MFA disabled by "${sanitizeForLog(session.username)}" from ${clientIp(req)}`);
  return sendJson(res, 200, { ok: true });
}

async function handleMfaRegenerateBackupCodes(req, res, session) {
  if (!acquire(res, 'security')) return;
  let body;
  try { body = JSON.parse(await readBody(req) || '{}'); } catch (_) { body = {}; }

  const secrets = security.readSecrets(session.username);
  if (!secrets || !secrets.mfa.enabled) {
    release('security');
    return sendJson(res, 400, { error: 'MFA is not enabled on this account.' });
  }
  if (!security.verifyPassword(String(body.currentPassword || ''), secrets.password)) {
    release('security');
    return sendJson(res, 401, { error: 'Current password is incorrect.' });
  }

  const backupCodes = security.generateBackupCodes(8);
  secrets.backupCodes = backupCodes.map((c) => security.hashBackupCode(c));
  security.writeSecrets(secrets);

  // Security-posture change — same revoke-the-rest policy as above.
  revokeOtherSessionsForUser(session.username, session.token);

  release('security');
  log.info(`Backup codes regenerated by "${sanitizeForLog(session.username)}" from ${clientIp(req)}`);
  return sendJson(res, 200, { ok: true, backupCodes });
}

// ---------------------------------------------------------------------------
// /api/security/accounts* — owner-only admin-account management (v1.4,
// [[roadmap-hosted-platform]] item 4). A 'provider' account manages only its
// OWN password/MFA above; only 'owner' can see, add, or remove OTHER admin
// accounts. Browser session lane only, same as the rest of /api/security/*.
// ---------------------------------------------------------------------------
function requireOwner(res, session) {
  if (session.role === 'owner') return true;
  sendJson(res, 403, { error: 'Only an owner account can manage admin accounts.' });
  return false;
}

function accountSummary(a) {
  return { username: a.username, role: a.role, createdAt: a.createdAt, mfaEnabled: !!(a.mfa && a.mfa.enabled) };
}

async function handleListAccounts(req, res, session) {
  if (!requireOwner(res, session)) return;
  return sendJson(res, 200, { accounts: security.listAccounts().map(accountSummary) });
}

async function handleCreateAccount(req, res, session) {
  if (!requireOwner(res, session)) return;
  if (!acquire(res, 'security')) return;
  let body;
  try { body = JSON.parse(await readBody(req) || '{}'); } catch (_) { body = {}; }

  let account;
  try {
    account = security.createAccount(String(body.username || ''), String(body.password || ''), String(body.role || 'provider'));
  } catch (err) {
    release('security');
    return sendJson(res, 400, { error: err.message });
  }

  release('security');
  log.info(`Admin account "${sanitizeForLog(account.username)}" (${account.role}) created by ` +
    `"${sanitizeForLog(session.username)}" from ${clientIp(req)}`);
  return sendJson(res, 200, { ok: true, account: accountSummary(account) });
}

async function handleDeleteAccount(req, res, session) {
  if (!requireOwner(res, session)) return;
  if (!acquire(res, 'security')) return;
  let body;
  try { body = JSON.parse(await readBody(req) || '{}'); } catch (_) { body = {}; }
  const username = String(body.username || '');

  if (username === session.username) {
    release('security');
    return sendJson(res, 400, { error: 'You cannot delete your own account while signed in as it — have another owner remove it.' });
  }
  const accounts = security.listAccounts();
  const target = accounts.find((a) => a.username === username);
  if (target && target.role === 'owner' && accounts.filter((a) => a.role === 'owner').length <= 1) {
    release('security');
    return sendJson(res, 400, { error: 'Cannot delete the only remaining owner account.' });
  }

  try {
    security.deleteAccount(username);
  } catch (err) {
    release('security');
    return sendJson(res, 400, { error: err.message });
  }

  // The deleted account may have an active session right now — kick it
  // immediately rather than waiting for it to time out on its own.
  revokeOtherSessionsForUser(username, null);

  release('security');
  log.warn(`Admin account "${sanitizeForLog(username)}" deleted by "${sanitizeForLog(session.username)}" from ${clientIp(req)}`);
  return sendJson(res, 200, { ok: true });
}

// Appends `line` to the file at `absPath` if it is not already present as an
// exact line, chmod 600 like every other list-file write in this module.
// Shared by handleWhitelistMe so it doesn't duplicate doSave's file-write
// steps for a one-line append.
function appendUniqueLine(absPath, line) {
  let content = '';
  try { content = fs.readFileSync(absPath, 'utf8'); } catch (_) { /* file may not exist yet */ }
  const existing = content.split(/\r?\n/).map((l) => l.trim());
  if (existing.includes(line)) return false;
  const withTrailingNewline = content.length && !content.endsWith('\n') ? content + '\n' : content;
  fs.writeFileSync(absPath, withTrailingNewline + line + '\n', { mode: SECRET_FILE_MODE });
  chmodQuiet(absPath, SECRET_FILE_MODE);
  return true;
}

async function handleWhitelistMe(req, res, session) {
  if (!acquire(res, 'save')) return; // shares doSave's lock — both write whitelist.txt
  const ip = session.ip;
  const abs = path.resolve(config.whitelistPath || './whitelist.txt');
  let added;
  try {
    added = appendUniqueLine(abs, ip);
  } catch (err) {
    release('save');
    return sendJson(res, 500, { error: `Could not write whitelist.txt: ${err.message}` });
  }

  try {
    const ipf = require('./ipfilter').getIPFilter();
    if (ipf && ipf.reloadWhitelist) ipf.reloadWhitelist();
  } catch (_) { /* ipfilter not ready — restart will pick it up */ }

  release('save');
  log.info(`"${sanitizeForLog(session.username)}" whitelisted their own IP ${ip} from Security Settings`);
  return sendJson(res, 200, { ok: true, ip, added });
}

// ---------------------------------------------------------------------------
// Management API — key-authenticated lane that reuses the browser handlers.
// Runs before the trusted-host gate: an API caller is gated by the key and its
// own optional IP allowlist (api-trustedhosts.txt), independently of the
// editor's fail-closed trustedhosts.txt. A browser never sends these headers,
// so the login/session/CSRF path below is untouched.
// ---------------------------------------------------------------------------

// Pull the presented key from Authorization: Bearer <k> or X-API-Key: <k>.
// Returns null when neither header is present (→ fall through to the browser
// lane). Never read from the query string — it would land in logs/history.
function extractApiKey(req) {
  const auth = req.headers['authorization'];
  if (typeof auth === 'string') {
    const m = /^Bearer\s+(.+)$/i.exec(auth.trim());
    if (m && m[1].trim()) return m[1].trim();
  }
  const x = req.headers['x-api-key'];
  if (typeof x === 'string' && x.trim()) return x.trim();
  return null;
}

async function handleApiRequest(req, res, ip, presentedKey) {
  // Brute-force lockout (5 fails / 15 min per IP). Its own counter — a bad-key
  // flood must not lock a human admin out of the browser login from the same IP.
  if (apiLocked(ip)) {
    return sendJson(res, 429, { error: 'Too many failed attempts. Try again later.' });
  }

  // Optional source-IP allowlist. Empty/missing list => any IP may call.
  if (loadedApiHosts && loadedApiHosts.entries.length > 0 &&
      !trustedhosts.isTrusted(ip, loadedApiHosts)) {
    log.blocked(`API: rejected IP ${ip} (${req.method} ${req.url})`);
    return sendJson(res, 403, { error: 'Forbidden' });
  }

  if (!config.api.key || !safeEqual(presentedKey, config.api.key)) {
    recordApiFail(ip);
    log.blocked(`API: bad key from ${ip} (${req.method} ${req.url})`);
    return sendJson(res, 401, { error: 'Invalid API key' });
  }
  apiFails.delete(ip);

  let pathname, query;
  try {
    const u = new URL(req.url, 'https://localhost');
    pathname = decodeURIComponent(u.pathname);
    query = u.searchParams;
  } catch (_) {
    pathname = req.url.split('?')[0];
    query = new URLSearchParams();
  }
  const method = req.method;

  if (!pathname.startsWith('/api/')) {
    return sendJson(res, 404, { error: 'Not found' });
  }

  // Stand-in for a browser session: handlers only read .username (logging) and
  // .csrf (buildConfigPayload — harmless when null). No CSRF check: this lane
  // authenticates per-request with the key and carries no cookie.
  const session = { username: 'api', csrf: null, ip, isApi: true };

  if (pathname === '/api/config' && method === 'GET') {
    return sendJson(res, 200, await buildConfigPayload(session));
  }
  if (pathname === '/api/health' && method === 'GET') {
    return sendJson(res, 200, await buildHealth());
  }
  if (pathname === '/api/stats' && method === 'GET') {
    return handleStats(res);
  }
  if (pathname === '/api/save' && method === 'POST') {
    return handleSave(req, res, session);
  }
  if (pathname === '/api/restart' && method === 'POST') {
    return handleRestart(req, res, session);
  }
  if (pathname === '/api/geoip' && method === 'POST') {
    return handleGeoip(req, res, session);
  }
  if (pathname === '/api/sshkey' && method === 'POST') {
    return handleSshKey(req, res, session);
  }
  if (pathname === '/api/cert' && method === 'POST') {
    return handleCert(req, res, session);
  }
  if (pathname === '/api/update/check' && method === 'GET') {
    return handleUpdateCheck(req, res);
  }
  if (pathname === '/api/update/apply' && method === 'POST') {
    return handleUpdateApply(req, res, session);
  }
  if (pathname === '/api/update/rollback' && method === 'POST') {
    return handleUpdateRollback(req, res, session);
  }
  if (pathname === '/api/logs' && method === 'GET') {
    return handleLogsList(res);
  }
  if (pathname === '/api/logs/view' && method === 'GET') {
    return handleLogsView(res, query);
  }
  if (pathname === '/api/logs/delete' && method === 'POST') {
    return handleLogsDelete(req, res, session);
  }
  return sendJson(res, 404, { error: 'Not found' });
}

// ---------------------------------------------------------------------------
// main request handler
// ---------------------------------------------------------------------------
let loadedTrustedHosts = null;
let loadedApiHosts = null;
let loadedStatusHosts = null;

// ---------------------------------------------------------------------------
// GET /status — unauthenticated (no session, no CSRF, no API key), gated only
// by status-trustedhosts.txt. For uptime monitors (e.g. Uptime Kuma) that
// shouldn't need to manage an API key or admin-UI access just to poll
// liveness. `ok` reflects the telnet listener specifically — the app's core
// job — while `listeners` gives a per-service breakdown for a more detailed
// JSON-query check. Real listener state (not config-flag guessing): `.server`/
// `.sshServer`/`.sshPassthroughServer` come from the BBSFirewall instance
// handed to startConfigEditorServer(); the web redirect's state comes from
// web-redirect.js's own isHttpUp()/isHttpsUp() (its servers are module-private
// there, not exposed any other way).
// ---------------------------------------------------------------------------
function buildStatusPayload() {
  const f = firewallInstance;
  const telnetUp = !!(f && f.server && f.server.listening);
  const sshUp = !!(f && (
    (f.sshServer && f.sshServer.listening) ||
    (f.sshPassthroughServer && f.sshPassthroughServer.listening)
  ));
  return {
    ok: telnetUp,
    version: appVersion(),
    uptimeSec: Math.floor(process.uptime()),
    listeners: {
      telnet: telnetUp,
      ssh: sshUp,
      webRedirect: webRedirect.isHttpUp() || webRedirect.isHttpsUp(),
      configEditor: true, // answering this request is proof it's up
    },
  };
}

function handleStatusEndpoint(req, res, ip) {
  if (!trustedhosts.isTrusted(ip, loadedStatusHosts)) {
    log.blocked(`Status endpoint: rejected untrusted host ${ip}`);
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    return res.end('Forbidden');
  }
  sendJson(res, 200, buildStatusPayload());
}

async function onRequest(req, res) {
  const ip = clientIp(req);

  // Status lane: checked first, before the Management API key lane and the
  // browser trusted-host gate below — so GET /status behaves identically
  // whether or not a caller happens to send an Authorization header, and
  // status-trustedhosts.txt is the only thing that gates it.
  if (req.method === 'GET' && req.url.split('?')[0] === '/status') {
    return handleStatusEndpoint(req, res, ip);
  }

  // The trusted-host gate keys off the real socket peer. If a proxy/load
  // balancer is in front, every request appears to come from that one IP and
  // the gate is meaningless — warn once so a misdeployment is visible.
  if (!proxyHeaderWarned && (req.headers['x-forwarded-for'] || req.headers['forwarded'] ||
      req.headers['x-real-ip'])) {
    proxyHeaderWarned = true;
    log.warn('Config editor: a request carried a forwarding header (X-Forwarded-For / ' +
      'Forwarded / X-Real-IP). The editor must be exposed DIRECTLY — the trusted-host ' +
      'gate uses the real socket peer and ignores these headers, so a reverse proxy ' +
      'breaks it. Bind CONFIG_EDITOR_BIND to a private interface or remove the proxy.');
  }

  // Management API lane: a request carrying an API key is handled here, gated by
  // the key + api-trustedhosts.txt only — not the browser trusted-host gate
  // below. If the API is disabled, fall through (the browser gate then applies).
  const apiKey = extractApiKey(req);
  if (apiKey !== null && config.api.enabled) {
    return handleApiRequest(req, res, ip, apiKey);
  }

  // Gate 1: trusted-host allowlist. Empty/missing list => nobody gets in.
  if (!trustedhosts.isTrusted(ip, loadedTrustedHosts)) {
    log.blocked(`Config editor: rejected untrusted host ${ip} (${req.method} ${req.url})`);
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('Forbidden');
    return;
  }

  let pathname, query;
  try {
    const u = new URL(req.url, 'https://localhost');
    pathname = decodeURIComponent(u.pathname);
    query = u.searchParams;
  } catch (_) {
    pathname = req.url.split('?')[0];
    query = new URLSearchParams();
  }
  const method = req.method;

  try {
    // --- unauthenticated routes ---
    if (method === 'GET' && STATIC_ASSETS[pathname]) {
      return serveStaticAsset(res, pathname);
    }
    if (pathname === '/login' && method === 'GET') {
      if (getSession(req)) return redirect(res, '/');
      return sendPage(res, 200, (n) => views.loginPage({ nonce: n }));
    }
    if (pathname === '/login' && method === 'POST') {
      return handleLoginPost(req, res, ip);
    }

    // --- everything below requires a session ---
    const session = getSession(req);
    const wantsJson = pathname.startsWith('/api/');

    if (!session) {
      if (wantsJson) return sendJson(res, 401, { error: 'Not authenticated' });
      return redirect(res, '/login');
    }

    // CSRF: every authenticated POST (including /logout) must carry the token.
    // SameSite=Strict already blocks cross-site requests; this is defence in depth.
    if (method === 'POST') {
      const header = req.headers['x-csrf-token'] || '';
      if (!safeEqual(header, session.csrf)) {
        res.writeHead(403, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
        return res.end(JSON.stringify({ error: 'Bad or missing CSRF token' }));
      }
    }

    if (pathname === '/logout' && method === 'POST') {
      destroySession(req);
      res.writeHead(302, { Location: '/login', 'Set-Cookie': cookieHeader('', 0), 'Cache-Control': 'no-store' });
      res.end();
      return;
    }

    // MFA gate: a session that hasn't verified its second factor yet (only
    // possible when the account has MFA enabled — see createSession) may
    // only reach the verify endpoint, to complete login, and the app root,
    // to be served the MFA challenge page. Everything else — including
    // /api/config — 401s until it passes. /logout above is unaffected by
    // this gate on purpose, so a stuck MFA prompt always has a way out.
    if (!session.mfaVerified) {
      if (pathname === '/api/security/mfa/verify-login' && method === 'POST') {
        return handleMfaVerifyLogin(req, res, session, ip);
      }
      if (pathname === '/' && method === 'GET') {
        return sendPage(res, 200, (n) => views.mfaPage({ csrf: session.csrf, nonce: n }));
      }
      if (wantsJson) return sendJson(res, 401, { error: 'MFA verification required' });
      return redirect(res, '/');
    }

    if (pathname === '/' && method === 'GET') {
      return sendPage(res, 200, (n) => views.appPage({ csrf: session.csrf, username: session.username, nonce: n }));
    }
    if (pathname === '/api/config' && method === 'GET') {
      return sendJson(res, 200, await buildConfigPayload(session));
    }
    if (pathname === '/api/health' && method === 'GET') {
      return sendJson(res, 200, await buildHealth());
    }
    if (pathname === '/api/stats' && method === 'GET') {
      return handleStats(res);
    }
    if (pathname === '/api/save' && method === 'POST') {
      return handleSave(req, res, session);
    }
    if (pathname === '/api/restart' && method === 'POST') {
      return handleRestart(req, res, session);
    }
    if (pathname === '/api/geoip' && method === 'POST') {
      return handleGeoip(req, res, session);
    }
    if (pathname === '/api/security/change-password' && method === 'POST') {
      return handleChangePassword(req, res, session);
    }
    if (pathname === '/api/security/mfa/setup' && method === 'POST') {
      return handleMfaSetup(req, res, session);
    }
    if (pathname === '/api/security/mfa/confirm' && method === 'POST') {
      return handleMfaConfirm(req, res, session);
    }
    if (pathname === '/api/security/mfa/disable' && method === 'POST') {
      return handleMfaDisable(req, res, session);
    }
    if (pathname === '/api/security/mfa/regenerate-backup-codes' && method === 'POST') {
      return handleMfaRegenerateBackupCodes(req, res, session);
    }
    if (pathname === '/api/security/whitelist-me' && method === 'POST') {
      return handleWhitelistMe(req, res, session);
    }
    if (pathname === '/api/security/accounts' && method === 'GET') {
      return handleListAccounts(req, res, session);
    }
    if (pathname === '/api/security/accounts/create' && method === 'POST') {
      return handleCreateAccount(req, res, session);
    }
    if (pathname === '/api/security/accounts/delete' && method === 'POST') {
      return handleDeleteAccount(req, res, session);
    }
    if (pathname === '/api/sshkey' && method === 'POST') {
      return handleSshKey(req, res, session);
    }
    if (pathname === '/api/cert' && method === 'POST') {
      return handleCert(req, res, session);
    }
    if (pathname === '/api/update/check' && method === 'GET') {
      return handleUpdateCheck(req, res);
    }
    if (pathname === '/api/update/apply' && method === 'POST') {
      return handleUpdateApply(req, res, session);
    }
    if (pathname === '/api/update/rollback' && method === 'POST') {
      return handleUpdateRollback(req, res, session);
    }
    if (pathname === '/api/logs' && method === 'GET') {
      return handleLogsList(res);
    }
    if (pathname === '/api/logs/view' && method === 'GET') {
      return handleLogsView(res, query);
    }
    if (pathname === '/api/logs/delete' && method === 'POST') {
      return handleLogsDelete(req, res, session);
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not found');
  } catch (err) {
    log.error(`Config editor request error: ${err.message}`);
    if (!res.headersSent) {
      sendJson(res, 500, { error: 'Internal error' });
    } else {
      res.end();
    }
  }
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------
function startConfigEditorServer(firewall) {
  const ce = config.configEditor;
  firewallInstance = firewall || null;
  if (!ce.enabled) {
    log.info('Config editor is disabled');
    return;
  }

  loadedTrustedHosts = trustedhosts.loadTrustedHosts(ce.trustedHostsPath);
  if (loadedTrustedHosts.error) {
    log.warn(`Config editor: trusted hosts file error — ${loadedTrustedHosts.error}`);
  }
  if (loadedTrustedHosts.invalid.length) {
    log.warn(`Config editor: ${loadedTrustedHosts.invalid.length} unparseable trusted-host line(s) ignored`);
  }
  if (loadedTrustedHosts.entries.length === 0) {
    log.warn(`Config editor: trusted hosts list is empty (${path.resolve(ce.trustedHostsPath)}) — ` +
      'the editor will reject every request until at least one entry is added');
  } else {
    log.info(`Config editor: ${loadedTrustedHosts.entries.length} trusted host entr(y/ies) loaded`);
  }

  loadedApiHosts = trustedhosts.loadTrustedHosts(config.api.trustedHostsPath);
  if (loadedApiHosts.invalid.length) {
    log.warn(`Management API: ${loadedApiHosts.invalid.length} unparseable api-trustedhosts line(s) ignored`);
  }
  if (config.api.enabled) {
    log.info(`Management API: enabled on /api/* — ${loadedApiHosts.entries.length
      ? `${loadedApiHosts.entries.length} allowed IP entr(y/ies)`
      : 'no source-IP restriction'}`);
  } else {
    log.info('Management API is disabled');
  }

  loadedStatusHosts = trustedhosts.loadTrustedHosts(config.status.trustedHostsPath);
  if (loadedStatusHosts.invalid.length) {
    log.warn(`Status endpoint: ${loadedStatusHosts.invalid.length} unparseable status-trustedhosts line(s) ignored`);
  }
  if (loadedStatusHosts.entries.length === 0) {
    log.warn(`Status endpoint: trusted hosts list is empty (${path.resolve(config.status.trustedHostsPath)}) — ` +
      'GET /status will reject every request until at least one entry is added');
  } else {
    log.info(`Status endpoint: ${loadedStatusHosts.entries.length} trusted host entr(y/ies) loaded`);
  }

  const restored = loadPersistedSessions();
  if (restored) {
    log.info(`Config editor: ${restored} admin session(s) carried over the restart`);
  }

  // Warm the forever-caches now so the first /api/config or /api/restart
  // request doesn't pay for the pm2/certbot presence check.
  hasPm2().catch(() => {});
  hasCertbot().catch(() => {});

  let tlsKey, tlsCert;
  try {
    tlsKey = fs.readFileSync(path.resolve(ce.keyPath));
    tlsCert = fs.readFileSync(path.resolve(ce.certPath));
  } catch (err) {
    log.error(`Config editor: failed to load TLS certificate — ${err.message}`);
    log.error('Run setup-config-cert.sh to create one, then restart.');
    return;
  }

  try {
    server = https.createServer({
      key: tlsKey,
      cert: tlsCert,
      minVersion: 'TLSv1.2',
      honorCipherOrder: true,
    }, (req, res) => {
      onRequest(req, res).catch((err) => {
        log.error(`Config editor unhandled error: ${err.message}`);
        try { res.destroy(); } catch (_) {}
      });
    });
  } catch (err) {
    log.error(`Config editor: could not create HTTPS server — ${err.message}`);
    return;
  }

  // Tighten the slowloris window (defaults are generous). The Tools actions are
  // slow on the RESPONSE side, not the request, so a short request timeout is fine.
  server.headersTimeout = 15000;
  server.requestTimeout = 30000;
  server.keepAliveTimeout = 10000;

  server.on('error', (err) => {
    log.error(`Config editor server error: ${err.message}`);
  });

  // Reject any non-HTTP/garbage on the socket quietly (e.g. a port scanner).
  server.on('clientError', (err, socket) => {
    try { socket.destroy(); } catch (_) {}
  });

  // The https.Server does not listen directly. muxServer owns the port: it peeks
  // the first byte and hands TLS connections (0x16 = handshake record) to the
  // https server untouched, while a plain-HTTP request gets a 301 to https://.
  // Uses 'readable' + read() (paused mode) so no bytes are lost across the
  // emit('connection') handoff — 'data' would put the socket in flowing mode.
  muxServer = net.createServer((socket) => {
    socket.setTimeout(15000, () => socket.destroy());
    socket.once('error', () => { try { socket.destroy(); } catch (_) {} });
    const onReadable = () => {
      const chunk = socket.read();
      if (!chunk || chunk.length === 0) { socket.once('readable', onReadable); return; }
      if (chunk[0] === 0x16) {
        socket.unshift(chunk);
        socket.setTimeout(0);          // hand off; the https server manages timeouts
        server.emit('connection', socket);
      } else if (ce.httpRedirectEnabled) {
        respondPlainRedirect(socket, chunk, ce);
      } else {
        socket.destroy();              // pre-fix behaviour: drop non-TLS
      }
    };
    socket.once('readable', onReadable);
  });

  muxServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      log.error(`Config editor: port ${ce.port} is already in use`);
    } else {
      log.error(`Config editor listener error: ${err.message}`);
    }
  });

  muxServer.listen(ce.port, ce.bindAddress, () => {
    log.info(`Config editor listening on https://${ce.bindAddress}:${ce.port}` +
      (ce.httpRedirectEnabled ? ' (plain HTTP on this port 301s to HTTPS)' : ''));
  });

  sweepTimer = setInterval(sweepSessions, 60000);
  if (sweepTimer.unref) sweepTimer.unref();
}

// Answer a plaintext HTTP request that landed on the TLS port with a raw 301 to
// the https:// URL, then close. Host: prefer CONFIG_EDITOR_CERT_DOMAIN (its cert
// is valid for that name); else the request's Host header; else the bind address.
function respondPlainRedirect(socket, firstChunk, ce) {
  try {
    const head = firstChunk.toString('latin1', 0, Math.min(firstChunk.length, 8192));
    const reqLine = head.split('\r\n', 1)[0] || '';
    const m = /^[A-Z]+\s+(\S+)\s+HTTP\/1\.[01]$/i.exec(reqLine);
    let target = (m && m[1]) || '/';
    if (!target.startsWith('/') || target.length > 2000) target = '/';   // ignore absolute/CONNECT forms

    let host = (envFileValue('CONFIG_EDITOR_CERT_DOMAIN') || ce.certDomain || '').trim();
    if (!host) {
      const hh = (head.match(/\r\nHost:[ \t]*([^\r\n]+)/i) || [])[1] || '';
      host = hh.replace(/:\d+$/, '').trim();
    }
    if (!host) host = (ce.bindAddress && ce.bindAddress !== '0.0.0.0' && ce.bindAddress !== '::')
      ? ce.bindAddress : 'localhost';

    const portPart = ce.port === 443 ? '' : ':' + ce.port;
    const location = `https://${host}${portPart}${target}`;
    socket.end(
      'HTTP/1.1 301 Moved Permanently\r\n' +
      `Location: ${location}\r\n` +
      'Cache-Control: no-store\r\n' +
      'Content-Length: 0\r\n' +
      'Connection: close\r\n\r\n'
    );
  } catch (_) {
    try { socket.destroy(); } catch (_) {}
  }
}

function stopConfigEditorServer() {
  return new Promise((resolve) => {
    if (sweepTimer) { clearInterval(sweepTimer); sweepTimer = null; }
    // Deliberately NOT sessions.clear() here: muxServer.close() only stops
    // NEW connections — an already-open keep-alive socket (e.g. a browser
    // tab's fetch) keeps being served by this still-alive process until it
    // finishes draining, which can take several seconds. Wiping the map
    // immediately made every request on such a socket 401 for that whole
    // window, which is exactly the request /api/restart's keepSession carry-
    // over (persistSessions/loadPersistedSessions, above) exists to avoid.
    // The Map disappears on its own once the process actually exits.
    server = null; // https.Server never listened on a port; nothing to close
    if (muxServer) {
      muxServer.close(() => { log.info('Config editor server closed'); resolve(); });
      muxServer = null;
    } else {
      resolve();
    }
  });
}

module.exports = { startConfigEditorServer, stopConfigEditorServer };
