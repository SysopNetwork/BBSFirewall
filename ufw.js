/**
 * BBSFirewall - UFW (host firewall) integration
 *
 * Optional, off by default. Reconciles a tagged subset of the host's `ufw`
 * rules against BBSFirewall's own config — the public listeners (telnet, SSH,
 * web redirect) open to anyone, the config editor and the admin SSH port
 * scoped to trustedhosts.txt. Every rule this module creates carries
 * `comment 'bbsfw'`; only rules bearing that exact tag are ever considered
 * "ours" to diff or remove — everything else on the box, tagged or not, is
 * invisible to it.
 *
 * SAFETY BOUNDARY: this module never enables or disables ufw itself (`ufw
 * enable`/`ufw disable`) — turning ufw on is a one-time step the sysop does
 * outside BBSFirewall. Everything below only ever adds/removes individual
 * tagged rules within an already-active ufw.
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const fs = require('fs');
const { execFile } = require('child_process');
const { promisify } = require('util');
const execFileAsync = promisify(execFile);

const TAG = 'bbsfw';
const TAG_AUTO = 'bbsfw-auto'; // kernel-level block rules pushed by ufw-blocks.js

// ---------------------------------------------------------------------------
// Mutation lock. Two independent callers change ufw rules - the Phase 1
// manual Apply (config-editor.js) and the automatic block push
// (ufw-blocks.js) - and each `ufw` invocation rewrites /etc/ufw/user.rules
// and reloads, so two running at once can interleave and lose a change.
// Every mutating call goes through here and runs strictly one at a time.
// A failed fn never poisons the chain for the next caller.
// ---------------------------------------------------------------------------
let ufwChain = Promise.resolve();
function withUfwLock(fn) {
  const run = ufwChain.then(fn, fn);
  ufwChain = run.catch(() => {});
  return run;
}

// ---------------------------------------------------------------------------
// feature detection - same shape as config-editor.js's hasPm2()/hasCertbot()
// and updater.js's hasTar()/hasPm2(): only a SUCCESSFUL detection is cached
// (forever). A failure is never cached, since a transiently slow/busy box
// right after this process restarts can make a real install look absent -
// see those functions' own comments for the production incident that
// taught this the hard way (v1.3.6, restart button false-negative).
// ---------------------------------------------------------------------------
let ufwAvailable = false;
async function hasUfw() {
  if (ufwAvailable) return true;
  try {
    await execFileAsync('ufw', ['--version'], { timeout: 4000 });
    ufwAvailable = true;
    return true;
  } catch (_) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// IPv6 capability - unlike hasUfw() above,
// deliberately NEVER cached: this is a configuration value a sysop could
// flip at any time (same reasoning as config-editor.js's pm2StartupStatus()
// not caching - it can legitimately change mid-session), and it's cheap
// enough (one small file read) that there is no cost to always checking
// fresh. `ufw`'s own default is IPV6=yes, but a sysop can set it to no, in
// which case ufw only filters IPv6 on loopback - proposing/applying IPv6
// rules on such a host would be silently unenforced, not actually wrong but
// misleading, so desiredRules() must be told to skip them entirely rather
// than generate rules that look applied but do nothing.
// ---------------------------------------------------------------------------
function hasIpv6Support() {
  try {
    const text = fs.readFileSync('/etc/default/ufw', 'utf8');
    for (const line of text.split('\n')) {
      const trimmed = line.trim();
      if (trimmed.startsWith('#')) continue;
      const m = /^IPV6\s*=\s*"?(\w+)"?$/i.exec(trimmed);
      if (m) return m[1].toLowerCase() === 'yes';
    }
    return false; // key not present - ufw treats missing as not enabled
  } catch (_) {
    return false; // can't read it - don't assume support that might not be there
  }
}

// ---------------------------------------------------------------------------
// `ufw status numbered` parsing
//
// Real `ufw status numbered` output (ufw 0.36.2) this was built and verified
// against - column widths vary, but columns are always separated by
// 2+ spaces while values within a column (e.g. "728/tcp", "LIMIT IN") never
// contain a run of 2+ spaces, which is what the split below relies on:
//
//   Status: active
//
//        To                         Action      From
//        --                         ------      ----
//   [ 1] 728/tcp                    LIMIT IN    172.56.0.0/16              # bbsfw
//   [ 2] 728/tcp                    LIMIT IN    172.58.0.0/16              # bbsfw
//   [ 3] 23/tcp                     ALLOW IN    Anywhere                   # bbsfw
//   [ 4] 8443/tcp                   ALLOW IN    172.56.0.0/16              # bbsfw
//   [ 5] 8443/tcp                   ALLOW IN    172.58.0.0/16              # bbsfw
//   [ 6] 23/tcp (v6)                ALLOW IN    Anywhere (v6)              # bbsfw
//
// ufw appends " (v6)" to BOTH the To and From columns for an
// IPv6 rule, never just one - hence checking/stripping it from both below.
// ---------------------------------------------------------------------------
const NUMBERED_LINE_RE = /^\[\s*(\d+)\]\s+(.*)$/;

function stripV6Marker(s) {
  return s.replace(/\s*\(v6\)\s*$/, '').trim();
}

function parseUfwStatusNumbered(text) {
  const active = /^Status:\s*active/m.test(text);
  const rules = [];

  for (const line of String(text || '').split('\n')) {
    const m = NUMBERED_LINE_RE.exec(line);
    if (!m) continue;
    const number = parseInt(m[1], 10);
    let rest = m[2];

    let comment = null;
    const hashIdx = rest.indexOf('#');
    if (hashIdx !== -1) {
      comment = rest.slice(hashIdx + 1).trim();
      rest = rest.slice(0, hashIdx);
    }

    // <to>  <action> <in|out>  <from>  - columns separated by 2+ spaces.
    const cols = rest.trim().split(/\s{2,}/).filter(Boolean);
    if (cols.length < 3) continue; // an exotic/unrecognized line - not ours, skip defensively

    const toRaw = cols[0];
    const actionDir = cols[1].trim().split(/\s+/);
    const fromRaw = cols[2];

    const action = (actionDir[0] || '').toUpperCase();
    const direction = (actionDir[1] || '').toUpperCase();
    // ufw only appends " (v6)" for the "Anywhere" wildcard case - an explicit
    // IPv6 source (e.g. "::1") is printed as the raw address with NO (v6)
    // marker in either column. Relying on the marker alone parsed
    // "8443/tcp ALLOW IN ::1" as an IPv4 rule, so the diff never matched it
    // and every preview showed the same "add ::1, remove ::1" phantom diff.
    // Falling back to "does the from address itself contain a colon" catches
    // the case the (v6) marker misses (CIDR/plain-v4 from-addresses never
    // contain a colon, so this can't misfire the other way).
    const ipv6 = /\(v6\)/.test(toRaw) || /\(v6\)/.test(fromRaw) || fromRaw.includes(':');

    rules.push({
      number,
      to: stripV6Marker(toRaw),
      action, // ALLOW | DENY | REJECT | LIMIT
      direction, // IN | OUT
      from: stripV6Marker(fromRaw),
      ipv6,
      comment,
    });
  }

  return { active, rules };
}

async function getCurrentRules() {
  const { stdout } = await execFileAsync('ufw', ['status', 'numbered'], { timeout: 8000 });
  return parseUfwStatusNumbered(stdout);
}

// ---------------------------------------------------------------------------
// desired state - pure function, no side effects, easy to unit-test in
// isolation from any real ufw/host. Returns the full set of rules BBSFirewall
// wants present, each shaped like one parsed rule (minus `number`, which only
// exists for rules that are actually applied).
//
// Trust boundary: the admin SSH port's rule IS one of ours (tagged, managed,
// togglable between allow/limit) - what's protected is not "BBSFirewall never
// writes this rule" but "a diff can never leave this port without an
// allow/limit". It shares the trusted-hosts scope with the config editor
// (adminTrustedHosts below) rather than being open to the world.
//
// Loopback is excluded from that default scope: trustedhosts.txt commonly
// lists 127.0.0.1/::1 so the config editor is reachable for on-box testing,
// but nobody manages a remote box over SSH from its own loopback address, and
// reusing that list verbatim would add an IPv6 rule to the admin port on
// hosts that don't want IPv6 there at all. A caller that passes
// adminTrustedHosts explicitly gets exactly what it passes, unfiltered - the
// filtering only applies to the convenience default below.
// ---------------------------------------------------------------------------
function isLoopback(entry) {
  if (!entry) return false;
  if (entry.version === 4) return (entry.value >> 24n) === 127n; // 127.0.0.0/8
  return entry.value === 1n; // ::1
}

// The config editor port serves three audiences, each with its own allowlist
// in the app: browser admins (trustedhosts.txt), uptime monitors hitting
// GET /status (status-trustedhosts.txt) and, when API_ENABLED, Management API
// callers (api-trustedhosts.txt — where EMPTY means any IP, key required).
// The kernel rule has to admit all three or it silently breaks the app's own
// allowlists: an Uptime Kuma box listed only in the status list would be
// dropped before the app ever saw it. Returns { hosts } or { anywhere: true }.
function editorPortSources(opts) {
  const lists = [(opts && opts.trustedHosts) || [], (opts && opts.statusHosts) || []];
  if (opts && opts.apiEnabled) {
    if (!(opts.apiHosts || []).length) return { anywhere: true };
    lists.push(opts.apiHosts);
  }
  const seen = new Set();
  const hosts = [];
  for (const h of lists.flat()) {
    const key = `${h.version}|${canonicalSource(h)}`;
    if (seen.has(key)) continue;
    seen.add(key);
    hosts.push(h);
  }
  return { hosts };
}

function desiredRules(config, opts) {
  const trustedHosts = (opts && opts.trustedHosts) || []; // config editor scope - array of {raw} from trustedhosts.js
  const adminTrustedHosts = (opts && opts.adminTrustedHosts) || trustedHosts.filter((h) => !isLoopback(h));
  const adminPort = opts && opts.adminSshPort;

  const rules = [];
  const allowAnywhere = (port) => {
    rules.push({ to: `${port}/tcp`, action: 'ALLOW', direction: 'IN', from: 'Anywhere', ipv6: false, comment: TAG });
    rules.push({ to: `${port}/tcp`, action: 'ALLOW', direction: 'IN', from: 'Anywhere', ipv6: true, comment: TAG });
  };
  // `from` is always spelled the way `ufw status` prints it (see
  // sourceLabel()), never as typed in a list file: ufw prints "1.2.3.4/32" as
  // "1.2.3.4" and "0.0.0.0/0" as "Anywhere", so comparing the raw text
  // produced a permanent phantom diff - and Apply would then delete the very
  // rules it had just added.
  const scopedTo = (port, action, hosts) => {
    for (const h of hosts) {
      rules.push({
        to: `${port}/tcp`, action, direction: 'IN', from: sourceLabel(h), ipv6: h.version === 6, comment: TAG,
      });
    }
  };

  // Public listeners - reachable by anyone, same as the app itself allows.
  allowAnywhere(config.listenPort); // telnet
  if (config.sshMode && config.sshMode !== 'off') allowAnywhere(config.sshListenPort);
  if (config.webRedirectEnabled) allowAnywhere(80);
  if (config.httpsRedirectEnabled) allowAnywhere(config.httpsRedirectPort || 443);

  // Admin-facing surfaces - scoped to trusted networks, not the world.
  if (config.configEditor && config.configEditor.enabled) {
    const editor = editorPortSources(opts);
    if (editor.anywhere) allowAnywhere(config.configEditor.port);
    else scopedTo(config.configEditor.port, 'ALLOW', editor.hosts);
  }
  if (adminPort) {
    scopedTo(adminPort, 'ALLOW', adminTrustedHosts);
  }

  // Default true so existing callers/tests that don't pass this keep working -
  // callers that care (computeUfwState()) pass ufw.hasIpv6Support() explicitly.
  // Dropped here rather than never generated above so every rule-building
  // helper stays simple; only one filter point to reason about.
  const ipv6Supported = opts && opts.ipv6Supported === false ? false : true;
  return ipv6Supported ? rules : rules.filter((r) => !r.ipv6);
}

// ---------------------------------------------------------------------------
// diff - only ever compares/touches rules tagged TAG (TAG_AUTO block rules
// belong to ufw-blocks.js). Matching key is (to, action, from, ipv6) - action
// is part of the key on purpose so e.g. an ALLOW->LIMIT change on the same
// port shows as one remove + one add, not a silent no-op (even though ufw's
// CLI replaces same-port rules in place when applied, the diff should still
// say plainly what changed).
// ---------------------------------------------------------------------------
function ruleKey(r) {
  return [r.to, r.action, r.from, r.ipv6 ? 'v6' : 'v4'].join('|');
}

function diffRules(current, desired) {
  const ours = current.filter((r) => r.comment === TAG);
  const currentKeys = new Map(ours.map((r) => [ruleKey(r), r]));
  const desiredKeys = new Map(desired.map((r) => [ruleKey(r), r]));

  const toAdd = [];
  const toRemove = [];

  for (const [key, rule] of desiredKeys) {
    if (!currentKeys.has(key)) toAdd.push(rule);
  }
  for (const [key, rule] of currentKeys) {
    if (!desiredKeys.has(key)) toRemove.push(rule);
  }

  return { toAdd, toRemove };
}

// ---------------------------------------------------------------------------
// sshd lockout guard. The admin-port rail (config-editor.js adminRuleOk) only
// checks the CONFIGURED HOST_ADMIN_SSH_PORT. Change that setting before sshd
// has actually moved and the diff deletes the only rule for the port sshd is
// really on. So ask the host which ports sshd listens on, and refuse any
// removal that would leave one of them with no BBSFirewall rule at all.
// ---------------------------------------------------------------------------

// `ss -Htlnp` lines: "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))"
function parseSshdPorts(ssOutput) {
  const ports = new Set();
  for (const line of String(ssOutput || '').split('\n')) {
    if (!/"sshd"/.test(line)) continue;
    const cols = line.trim().split(/\s+/);
    const local = cols[3] || '';
    const port = parseInt(local.slice(local.lastIndexOf(':') + 1), 10);
    if (port > 0 && port < 65536) ports.add(port);
  }
  return [...ports];
}

// Resolves to the port list, or null when it can't be determined (no `ss`,
// not root) - callers then warn instead of claiming the check passed.
async function listeningSshdPorts() {
  try {
    const { stdout } = await execFileAsync('ss', ['-Htlnp'], { timeout: 4000 });
    return parseSshdPorts(stdout);
  } catch (_) {
    return null;
  }
}

// Removals in `diff` that would leave a live sshd port with no rule in `desired`.
function sshdLockoutRemovals(diff, desired, sshdPorts) {
  const keeps = new Set(desired.map((r) => r.to));
  return diff.toRemove.filter((r) => {
    const port = parseInt(r.to, 10);
    return (sshdPorts || []).includes(port) && !keeps.has(r.to);
  });
}

// ---------------------------------------------------------------------------
// apply - NOT wired into any endpoint or UI yet. Adds before it ever removes,
// so there is never a window with no valid rule for a port both the old and
// new desired state agree should be open. dryRun (default true) never shells
// out to `ufw` at all - just returns what it WOULD do, matching the
// "phase 1 is dry-run only" rollout decision.
// ---------------------------------------------------------------------------
async function applyDiff(diff, opts) {
  const dryRun = !opts || opts.dryRun !== false; // default true - see file header
  if (!dryRun) return withUfwLock(() => applyDiffNow(diff, false));
  return applyDiffNow(diff, true);
}

// One rule, one address family. "Anywhere" is sent as 0.0.0.0/0 or ::/0
// rather than the bare `ufw allow 23/tcp` form, because the bare form acts on
// BOTH families at once: deleting only the IPv4 "Anywhere" rule used to take
// the IPv6 one with it. Verified on ufw 0.36.2: the family-specific form
// adds/deletes exactly one rule, prints identically ("Anywhere" /
// "Anywhere (v6)"), and matches rules created the bare way.
function ruleSpec(rule) {
  const [port, proto] = rule.to.split('/');
  const src = rule.from === 'Anywhere' ? (rule.ipv6 ? '::/0' : '0.0.0.0/0') : rule.from;
  return ['from', src, 'to', 'any', 'port', port, 'proto', proto || 'tcp'];
}

async function applyDiffNow(diff, dryRun) {
  const log = [];

  for (const rule of diff.toAdd) {
    const action = rule.action === 'LIMIT' ? 'limit' : 'allow';
    const args = [action, ...ruleSpec(rule), 'comment', TAG];
    log.push({ op: 'add', args });
    if (!dryRun) await execFileAsync('ufw', args, { timeout: 8000 });
  }

  for (const rule of diff.toRemove) {
    // Delete by exact rule spec (not by number - numbers shift as other
    // rules are added/removed in the same pass), same syntax used to add it.
    const action = rule.action === 'LIMIT' ? 'limit' : 'allow';
    const args = ['delete', action, ...ruleSpec(rule)];
    log.push({ op: 'remove', args });
    if (!dryRun) await execFileAsync('ufw', ['--force', ...args], { timeout: 8000 });
  }

  return { dryRun, changes: log };
}

// ---------------------------------------------------------------------------
// Kernel-level block rules (ufw-blocks.js). One rule per blocked address or
// CIDR, `deny from <addr>` to every port, tagged TAG_AUTO and PREPENDED so it
// is evaluated before the TAG allow rules above (ufw is first-match; an
// appended deny would sit behind "23/tcp ALLOW IN Anywhere" and never fire).
// `prepend` is family-aware - it inserts at the top of the v4 or v6 list as
// appropriate - which `insert 1` is not (it refuses a v6 rule at a position
// held by a v4 one).
//
// Addresses are canonicalized before they are sent, and every parsed rule's
// source is canonicalized again before comparing, so "1.2.3.4/32" in
// blocklist.txt, "1.2.3.4" in ufw's output, "2001:DB8:0::1" and
// "2001:db8::1" all compare equal and never produce a phantom add/remove
// pair (the same class of bug as the (v6)-marker one in
// parseUfwStatusNumbered above).
// ---------------------------------------------------------------------------
function formatIpv4(value) {
  return [24n, 16n, 8n, 0n].map((s) => String((value >> s) & 255n)).join('.');
}

// RFC 5952 form (lowercase, no leading zeros, longest run of 2+ zero groups
// collapsed to "::", first such run on a tie) - what ufw prints.
function formatIpv6(value) {
  const groups = [];
  for (let i = 7; i >= 0; i--) groups.push(Number((value >> BigInt(i * 16)) & 0xffffn));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLen && j - i >= 2) { bestStart = i; bestLen = j - i; }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestStart === -1) return hex.join(':');
  const head = hex.slice(0, bestStart).join(':');
  const tail = hex.slice(bestStart + bestLen).join(':');
  return `${head}::${tail}`;
}

// Parsed entry ({version, value, prefix, bits} from trustedhosts.parseEntry)
// -> canonical ufw source string: host bits masked off, full-length prefix
// dropped. Returns null for anything unparseable.
function canonicalSource(entry) {
  if (!entry) return null;
  const shift = BigInt(entry.bits - entry.prefix);
  const net = (entry.value >> shift) << shift;
  const addr = entry.version === 4 ? formatIpv4(net) : formatIpv6(net);
  return entry.prefix === entry.bits ? addr : `${addr}/${entry.prefix}`;
}

// How `ufw status` prints a parsed list entry as a rule source.
function sourceLabel(entry) {
  return entry.prefix === 0 ? 'Anywhere' : canonicalSource(entry);
}

function blockKey(source, ipv6) {
  return `${ipv6 ? 'v6' : 'v4'}|${source}`;
}

// The TAG_AUTO block rules currently in ufw, keyed like blockKey(). A rule
// whose source won't parse is still returned (keyed by its raw text) so a
// reconcile can remove it rather than leave an unknowable rule behind.
function currentBlockRules(rules, parseEntry) {
  const out = new Map();
  for (const r of rules) {
    if (r.comment !== TAG_AUTO) continue;
    const canon = canonicalSource(parseEntry(r.from)) || r.from;
    out.set(blockKey(canon, r.ipv6), { source: canon, raw: r.from, ipv6: r.ipv6, action: r.action });
  }
  return out;
}

async function addBlockRule(source) {
  return withUfwLock(() => execFileAsync('ufw', ['prepend', 'deny', 'from', source, 'comment', TAG_AUTO], { timeout: 15000 }));
}

// `raw` is the source exactly as ufw printed it - deleting by ufw's own
// spelling is what guarantees the delete matches the stored rule.
async function removeBlockRule(raw) {
  return withUfwLock(() => execFileAsync('ufw', ['--force', 'delete', 'deny', 'from', raw], { timeout: 15000 }));
}

// ---------------------------------------------------------------------------
// Recent drop/allow log: a connection ufw blocks at the kernel level never
// reaches BBSFirewall at all, so it's otherwise invisible in the app's own
// logs - traffic just vanishes with no record. Standard Ubuntu path via the
// shipped /etc/rsyslog.d/20-ufw.conf - not something
// BBSFirewall's own config needs to make configurable, since it's a fixed
// consequence of `ufw logging on` + Ubuntu's default rsyslog setup, the same
// way /etc/default/ufw's path is fixed for hasIpv6Support() above. Tails the
// last maxBytes like file-logger.js's readLogFile() does for the app's own
// log files - this file is rsyslog/logrotate-managed, not ours to rotate or
// delete, so this only ever reads it.
// ---------------------------------------------------------------------------
const UFW_LOG_PATH = '/var/log/ufw.log';

function getRecentLog(opts) {
  const maxBytes = (opts && opts.maxBytes) || 256 * 1024;
  let stat;
  try {
    stat = fs.statSync(UFW_LOG_PATH);
  } catch (_) {
    return { exists: false, content: '', truncated: false };
  }
  if (stat.size <= maxBytes) {
    return { exists: true, content: fs.readFileSync(UFW_LOG_PATH, 'utf8'), truncated: false, size: stat.size };
  }
  const fd = fs.openSync(UFW_LOG_PATH, 'r');
  try {
    const buf = Buffer.alloc(maxBytes);
    fs.readSync(fd, buf, 0, maxBytes, stat.size - maxBytes);
    let text = buf.toString('utf8');
    const nl = text.indexOf('\n');
    if (nl !== -1) text = text.slice(nl + 1); // drop the partial first line
    return { exists: true, content: text, truncated: true, size: stat.size };
  } finally {
    fs.closeSync(fd);
  }
}

module.exports = {
  TAG,
  TAG_AUTO,
  hasUfw,
  hasIpv6Support,
  parseUfwStatusNumbered,
  getCurrentRules,
  desiredRules,
  diffRules,
  parseSshdPorts,
  listeningSshdPorts,
  sshdLockoutRemovals,
  applyDiff,
  getRecentLog,
  withUfwLock,
  formatIpv4,
  formatIpv6,
  canonicalSource,
  blockKey,
  currentBlockRules,
  addBlockRule,
  removeBlockRule,
};
