/**
 * BBSFirewall - kernel-level block push (UFW)
 *
 * Optional, off by default (UFW_PUSH_BLOCKS, which also needs UFW_ENABLED).
 * Mirrors BBSFirewall's own block decisions down into the host firewall as
 * `ufw deny from <addr>` rules tagged `bbsfw-auto`, so a blocked caller is
 * dropped by the kernel before it ever reaches Node — including while
 * BBSFirewall itself is restarting or busy.
 *
 * What gets pushed:
 *   - every blocklist.txt entry (manual lines and trigger auto-blocks alike)
 *   - trigger auto-blocks in TRIGGER_BLOCK_MODE=temp, removed again when the
 *     in-app block expires
 * What does NOT: rate-limit blocks. They are short and land on ordinary
 * callers who reconnect too quickly; they stay app-level only.
 *
 * Safety rails (a deny rule covers EVERY port, including the admin's SSH):
 *   - refuses to push anything while trustedhosts.txt is empty — without it
 *     there is nothing to protect the admin's own address with
 *   - never pushes an entry that overlaps a trusted host (Trusted Hosts, the
 *     Status allowlist, or the API allowlist when the API is on), a whitelist entry,
 *     or loopback — the whole overlap is skipped, not just the shared part,
 *     and each skip is reported so the sysop can see why
 *   - caps the number of pushed rules (UFW_BLOCK_MAX_RULES); over the cap,
 *     temp blocks win, then CIDRs, then the NEWEST exact IPs
 *   - only ever touches rules tagged `bbsfw-auto`; never enables/disables ufw
 *
 * Reconcile model: the full desired set is recomputed from ipfilter.js's live
 * state and diffed against the tagged rules actually in ufw. Runs on startup,
 * shortly after any block/list change (debounced), when a temp block is due
 * to expire, and on a slow periodic timer that also repairs outside drift.
 * Turning the flag off stops reconciling but leaves already-pushed rules in
 * place (no surprise changes from a checkbox) — the Tools tab offers an
 * explicit "remove pushed rules" action for that.
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const { config } = require('./config');
const logger = require('./logger');
const trustedhosts = require('./trustedhosts');
const ufw = require('./ufw');

const log = logger.getLogger('ufw');

const DEBOUNCE_MS = 2000;               // coalesce bursts (a scanner tripping triggers from many IPs)
const RESYNC_INTERVAL_MS = 15 * 60 * 1000;
const MAX_TIMER_MS = 2147483647;        // setTimeout's own ceiling (~24.8 days)
const MAX_ERRORS_KEPT = 20;

// Always protected, regardless of trustedhosts.txt contents.
const LOOPBACK = [trustedhosts.parseEntry('127.0.0.0/8'), trustedhosts.parseEntry('::1')];

// Two parsed entries overlap when they share a family and agree on every bit
// of the shorter prefix — i.e. one contains the other.
function entriesOverlap(a, b) {
  if (!a || !b || a.version !== b.version) return false;
  const p = Math.min(a.prefix, b.prefix);
  if (p === 0) return true;
  const shift = BigInt(a.bits - p);
  return (a.value >> shift) === (b.value >> shift);
}

// Pure function: turn an ipfilter snapshot into the rule set to push.
//   snapshot  - ipfilter.getKernelBlockSnapshot()
//   protect   - parsed entries that must never be denied (trusted hosts)
//   opts      - { maxRules, ipv6Supported }
// Returns { desired: Map(key -> {source, ipv6, kind, until?}), skipped* }.
function computeDesiredBlocks(snapshot, protect, opts) {
  const maxRules = (opts && opts.maxRules) || 1000;
  const ipv6Supported = !(opts && opts.ipv6Supported === false);

  const protectedEntries = [...LOOPBACK, ...(protect || [])];
  const whitelistEntries = (snapshot.whitelist || []).map((w) => trustedhosts.parseEntry(w)).filter(Boolean);

  const desired = new Map();
  const skippedProtected = [];
  let skippedOverCap = 0;
  let skippedIpv6 = 0;
  let skippedInvalid = 0;
  let skippedCovered = 0;
  const pushedCidrs = [];

  const consider = (raw, kind, until) => {
    const entry = trustedhosts.parseEntry(raw);
    if (!entry) { skippedInvalid++; return; }
    const source = ufw.canonicalSource(entry);
    const ipv6 = entry.version === 6;
    const key = ufw.blockKey(source, ipv6);
    if (desired.has(key)) return;

    if (protectedEntries.some((p) => entriesOverlap(entry, p))) {
      skippedProtected.push({ source, reason: 'overlaps a Trusted Hosts / Status / API allowlist entry or loopback' });
      return;
    }
    if (whitelistEntries.some((w) => entriesOverlap(entry, w))) {
      skippedProtected.push({ source, reason: 'overlaps a whitelist entry' });
      return;
    }
    if (ipv6 && !ipv6Supported) { skippedIpv6++; return; }
    // An exact IP already inside a pushed CIDR needs no rule of its own.
    if (kind === 'ip' && pushedCidrs.some((c) => entriesOverlap(entry, c))) { skippedCovered++; return; }
    if (desired.size >= maxRules) { skippedOverCap++; return; }

    desired.set(key, { source, ipv6, kind, until });
    if (kind === 'cidr') pushedCidrs.push(entry);
  };

  for (const t of snapshot.temp || []) consider(t.ip, 'temp', t.until);
  for (const c of snapshot.permanentCidrs || []) consider(c, 'cidr');
  const ips = snapshot.permanentIps || [];
  for (let i = ips.length - 1; i >= 0; i--) consider(ips[i], 'ip'); // newest first

  return { desired, skippedProtected, skippedOverCap, skippedIpv6, skippedInvalid, skippedCovered };
}

// Every address BBSFirewall itself is configured to let in on the editor port:
// Trusted Hosts, the GET /status monitors, and (when the API is on) API
// callers. A kernel deny covers every port, so one of these landing on the
// blocklist (an auto-block from a shared address, say) would otherwise
// silently cut off an uptime monitor or dashboard the app still allows.
function protectedHostEntries() {
  const lists = [config.configEditor.trustedHostsPath, config.status.trustedHostsPath];
  if (config.api && config.api.enabled) lists.push(config.api.trustedHostsPath);
  return lists.flatMap((p) => trustedhosts.loadTrustedHosts(p).entries);
}

// ---------------------------------------------------------------------------
// sync engine
// ---------------------------------------------------------------------------
let ipFilter = null;
let running = false;
let pending = false;
let debounceTimer = null;
let expiryTimer = null;
let resyncTimer = null;
let progress = null;       // { done, total } while a sync is applying changes
let lastResult = null;     // summary of the most recent sync attempt

function isEnabled() {
  return !!(config.ufw && config.ufw.enabled && config.ufw.pushBlocks);
}

function requestSync() {
  if (!isEnabled() || !ipFilter) return;
  if (debounceTimer) return;
  debounceTimer = setTimeout(() => {
    debounceTimer = null;
    syncNow().catch((err) => log.error(`UFW block sync failed: ${err.message}`));
  }, DEBOUNCE_MS);
  if (debounceTimer.unref) debounceTimer.unref();
}

// Runs a sync now (or queues exactly one more if one is already running, so
// a change that lands mid-sync is never lost). Resolves with the summary.
async function syncNow() {
  if (running) { pending = true; return lastResult; }
  running = true;
  try {
    do {
      pending = false;
      const prevError = lastResult && lastResult.error;
      lastResult = await syncOnce();
      // A sync that can't run at all (ufw off, Trusted Hosts empty...) is
      // logged once per distinct reason, not on every periodic retry.
      if (lastResult.error && lastResult.error !== prevError) {
        log.warn(`UFW block push not applied: ${lastResult.error}`);
      }
    } while (pending && isEnabled());
  } finally {
    running = false;
    progress = null;
  }
  return lastResult;
}

async function syncOnce() {
  const result = {
    at: new Date().toISOString(),
    ok: false,
    added: 0,
    removed: 0,
    errors: [],
    pushed: 0,
    desired: 0,
    skippedProtected: [],
    skippedOverCap: 0,
    skippedIpv6: 0,
    skippedInvalid: 0,
    skippedCovered: 0,
  };

  if (!isEnabled()) { result.error = 'Block push is disabled.'; return result; }
  if (!ipFilter) { result.error = 'IP filter not initialized yet.'; return result; }
  if (!(await ufw.hasUfw())) { result.error = 'ufw is not installed on this host.'; return result; }

  let current;
  try {
    current = await ufw.getCurrentRules();
  } catch (err) {
    result.error = `Could not read ufw status: ${err.message}`;
    return result;
  }
  if (!current.active) {
    result.error = 'ufw is installed but not enabled on this host — nothing pushed.';
    return result;
  }

  const trusted = trustedhosts.loadTrustedHosts(config.configEditor.trustedHostsPath);
  if (!trusted.entries.length) {
    result.error = 'Trusted Hosts is empty — refusing to push deny rules, since there would be ' +
      'nothing protecting your own admin address from them.';
    return result;
  }

  const computed = computeDesiredBlocks(ipFilter.getKernelBlockSnapshot(), protectedHostEntries(), {
    maxRules: config.ufw.maxBlockRules,
    ipv6Supported: ufw.hasIpv6Support(),
  });
  Object.assign(result, {
    desired: computed.desired.size,
    skippedProtected: computed.skippedProtected,
    skippedOverCap: computed.skippedOverCap,
    skippedIpv6: computed.skippedIpv6,
    skippedInvalid: computed.skippedInvalid,
    skippedCovered: computed.skippedCovered,
  });

  const have = ufw.currentBlockRules(current.rules, trustedhosts.parseEntry);
  const toRemove = [...have.entries()].filter(([key]) => !computed.desired.has(key)).map(([, r]) => r);
  const toAdd = [...computed.desired.entries()].filter(([key]) => !have.has(key)).map(([, r]) => r);

  progress = { done: 0, total: toRemove.length + toAdd.length };
  const fail = (what, err) => {
    const msg = `${what}: ${(err.stderr || err.message || '').toString().trim()}`;
    if (result.errors.length < MAX_ERRORS_KEPT) result.errors.push(msg);
    log.error(`UFW block push — ${msg}`);
  };

  // Removals first: they are always safe (they only ever re-open access) and
  // keep the rule count - and so each later ufw reload - smaller.
  for (const r of toRemove) {
    try {
      await ufw.removeBlockRule(r.raw);
      result.removed++;
      log.info(`UFW: removed kernel block for ${r.source}`);
    } catch (err) { fail(`remove ${r.source}`, err); }
    progress.done++;
  }
  for (const r of toAdd) {
    if (!isEnabled()) break; // switched off mid-run - stop adding
    try {
      await ufw.addBlockRule(r.source);
      result.added++;
      log.blocked(`UFW: kernel-blocked ${r.source}${r.kind === 'temp' ? ` until ${new Date(r.until).toISOString()}` : ''}`);
    } catch (err) { fail(`add ${r.source}`, err); }
    progress.done++;
  }

  result.pushed = have.size - result.removed + result.added;
  result.ok = result.errors.length === 0;
  if (result.added || result.removed || result.errors.length) {
    log.warn(`UFW block sync: +${result.added} / -${result.removed}, ${result.pushed} pushed` +
      (result.errors.length ? `, ${result.errors.length} error(s)` : '') +
      (result.skippedOverCap ? `, ${result.skippedOverCap} over the ${config.ufw.maxBlockRules}-rule cap` : ''));
  }
  scheduleExpiry(computed.desired);
  return result;
}

// Wake up just after the soonest temp block expires so its kernel rule goes
// away with it, instead of lingering until the next periodic resync.
function scheduleExpiry(desired) {
  if (expiryTimer) { clearTimeout(expiryTimer); expiryTimer = null; }
  let soonest = Infinity;
  for (const r of desired.values()) {
    if (r.kind === 'temp' && r.until < soonest) soonest = r.until;
  }
  if (soonest === Infinity) return;
  const delay = Math.min(Math.max(soonest - Date.now() + 1000, 1000), MAX_TIMER_MS);
  expiryTimer = setTimeout(() => { expiryTimer = null; requestSync(); }, delay);
  if (expiryTimer.unref) expiryTimer.unref();
}

// Called once from server.js after the IP filter exists. Safe to call when
// the feature is off — it just subscribes and waits, so enabling it later
// from the editor only needs the restart that any .env change already needs.
function start(ipf) {
  ipFilter = ipf;
  if (!ipFilter) return;
  ipFilter.onChange(requestSync);
  if (!isEnabled()) return;
  log.info(`UFW block push enabled (cap ${config.ufw.maxBlockRules} rules)`);
  requestSync();
  resyncTimer = setInterval(requestSync, RESYNC_INTERVAL_MS);
  if (resyncTimer.unref) resyncTimer.unref();
}

function stop() {
  for (const t of [debounceTimer, expiryTimer]) if (t) clearTimeout(t);
  if (resyncTimer) clearInterval(resyncTimer);
  debounceTimer = expiryTimer = resyncTimer = null;
}

// Live, read-only view for the Tools tab — counts the tagged rules actually
// in ufw right now (so leftovers show up even with the feature switched off).
async function getStatus() {
  const status = {
    enabled: isEnabled(),
    running,
    progress,
    last: lastResult,
    maxRules: config.ufw.maxBlockRules,
  };
  if (!(await ufw.hasUfw())) { status.available = false; return status; }
  status.available = true;
  try {
    const current = await ufw.getCurrentRules();
    status.ufwActive = current.active;
    status.pushedNow = current.rules.filter((r) => r.comment === ufw.TAG_AUTO).length;
  } catch (err) {
    status.readError = err.message;
  }
  return status;
}

// Remove every bbsfw-auto rule. Only allowed with the push switched OFF —
// otherwise the next sync would just put them straight back.
async function removeAll() {
  if (isEnabled()) throw new Error('Turn off "Push blocks to ufw" first — otherwise the next sync re-adds them.');
  if (running) throw new Error('A sync is still running — try again in a moment.');
  const current = await ufw.getCurrentRules();
  const have = ufw.currentBlockRules(current.rules, trustedhosts.parseEntry);
  let removed = 0;
  const errors = [];
  for (const r of have.values()) {
    try {
      await ufw.removeBlockRule(r.raw);
      removed++;
    } catch (err) {
      if (errors.length < MAX_ERRORS_KEPT) errors.push(`${r.source}: ${(err.stderr || err.message || '').toString().trim()}`);
    }
  }
  return { removed, errors };
}

module.exports = {
  computeDesiredBlocks,
  entriesOverlap,
  protectedHostEntries,
  start,
  stop,
  requestSync,
  syncNow,
  getStatus,
  removeAll,
};
