/**
 * BBSFirewall - IP filtering, rate limiting, and connection tracking
 * https://github.com/SysopNetwork/BBSFirewall
 */

const fs = require('fs');
const path = require('path');
const logger = require('./logger');

function ipToInt(ip) {
  const parts = String(ip).split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value * 256) + n;
  }
  return value >>> 0;
}

// IPv4-only. Returns false (not a string-equality fallback) for anything that
// does not parse, so a malformed line can't accidentally match.
function ipMatchesCIDR(ip, cidr) {
  const slash = cidr.indexOf('/');
  if (slash === -1) return ip === cidr;

  const range = cidr.slice(0, slash);
  const bitsStr = cidr.slice(slash + 1);
  if (!/^\d{1,2}$/.test(bitsStr)) return false;
  const bits = Number(bitsStr);
  if (bits > 32) return false;
  if (bits === 0) return true; // /0 matches every address

  const ipInt = ipToInt(ip);
  const rangeInt = ipToInt(range);
  if (ipInt === null || rangeInt === null) return false;

  const mask = (0xFFFFFFFF << (32 - bits)) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

// Expand \xNN, \r, \n, \t, \0, \\ escapes so plain trigger patterns can match
// binary probes (TLS ClientHello, null padding, ...).
function unescapePattern(s) {
  return s
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\r/g, '\r')
    .replace(/\\n/g, '\n')
    .replace(/\\t/g, '\t')
    .replace(/\\0/g, '\0')
    .replace(/\\\\/g, '\\');
}

// Compile one trigger line. "/pat/flags" -> regex; anything else -> a
// case-insensitive substring (after unescaping). Returns null if unusable.
function compileTrigger(raw) {
  const t = String(raw || '').trim();
  if (!t) return null;

  // Treat as /regex/flags only when the trailing part is a valid JS flag set —
  // otherwise "/bin/sh" or "/etc/passwd" would be misread as a regex and lost.
  const m = t.match(/^\/(.+)\/([a-z]*)$/i);
  if (m && m[1].length <= 400 && /^[dgimsuy]*$/.test(m[2])) {
    try {
      return { raw: t, kind: 'regex', re: new RegExp(m[1], m[2]) };
    } catch (_) {
      /* not a valid regex body — fall through and treat it as a literal */
    }
  }

  const lit = unescapePattern(t);
  if (!lit) return null;
  return { raw: t, kind: 'substr', lit: lit.toLowerCase() };
}

// The classic exponential-backtracking shape: an unbounded quantifier applied
// to a group or character class that ITSELF contains an unbounded quantifier —
// (a+)+  (a*)*  (.+)+  ([a-z]+)*  (\w*){2,} ... We check this STATICALLY; never
// run an untrusted regex against a probe string (doing so IS the ReDoS).
const NESTED_QUANT_RE =
  /(\([^()]*[*+][^()]*\)|\[[^\]]*[*+][^\]]*\]|\([^()]*\)[*+])[*+{]/;

// Compile-check trigger text and flag patterns that will not parse or that
// look like a ReDoS. Used by the config editor before it writes triggers.txt.
function validateTriggerText(text) {
  const invalid = [];
  const slow = [];
  let count = 0;
  for (const line of String(text || '').split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const c = compileTrigger(t);
    if (!c) { invalid.push(t); continue; }
    count++;
    if (c.kind === 'regex') {
      const body = c.re.source;
      if (body.length > 400 || NESTED_QUANT_RE.test(body)) slow.push(t);
    }
  }
  return { count, invalid, slow };
}

class IPFilter {
  constructor(config) {
    this.config = config;
    // Exact IPs go in the Set (O(1) lookup); CIDR entries go in the *Cidr array
    // and are the only ones the per-connection match loop has to walk. Without
    // this split, a blocklist that grows (trigger auto-block in 'blocklist'
    // mode appends forever) makes every allowed connection an O(N) scan.
    this.blocklist = new Set();
    this.blocklistCidr = [];
    this.whitelist = new Set();
    this.whitelistCidr = [];
    this.triggers = [];                    // compiled auto-block trigger patterns
    this.autoBlockCount = 0;               // IPs auto-blocked by a trigger this run
    this.connectionAttempts = new Map();   // IP -> [timestamps] — rate limit tracking
    this.blockedIPs = new Map();           // IP -> {blockedUntil, reason} — temporary blocks
    this.activeConnectionsByIP = new Map(); // IP -> active connection count
    this.cleanupInterval = null;
  }

  initialize() {
    if (this.config.whitelistPath) {
      this.loadWhitelist(this.config.whitelistPath);
    }

    if (this.config.blocklistPath) {
      this.loadBlocklist(this.config.blocklistPath);
    }

    const tb = this.config.triggerBlock;
    if (tb && tb.enabled && tb.listPath) {
      this.loadTriggers(tb.listPath);
    }

    this.cleanupInterval = setInterval(() => {
      this.cleanupOldAttempts();
    }, 60000);

    logger.info('IP filter initialized', {
      whitelistSize: this.whitelist.size + this.whitelistCidr.length,
      blocklistSize: this.blocklist.size + this.blocklistCidr.length,
      rateLimitEnabled: this.config.rateLimitEnabled,
      maxConnectionsPerWindow: this.config.maxConnectionsPerWindow,
      rateLimitWindowMs: this.config.rateLimitWindowMs,
      maxConnectionsPerIP: this.config.maxConnectionsPerIP === 0
        ? 'unlimited'
        : this.config.maxConnectionsPerIP,
    });
  }

  loadWhitelist(whitelistPath) {
    try {
      const fullPath = path.resolve(whitelistPath);

      if (!fs.existsSync(fullPath)) {
        logger.warn(`Whitelist file not found: ${fullPath}`);
        return;
      }

      const content = fs.readFileSync(fullPath, 'utf-8');
      let count = 0;

      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const token = trimmed.split('#')[0].trim();
        if (!token) continue;
        if (token.includes('/')) this.whitelistCidr.push(token);
        else this.whitelist.add(token);
        count++;
      }

      logger.info(`Loaded ${count} entries from whitelist: ${fullPath}`);
    } catch (err) {
      logger.error(`Failed to load whitelist: ${err.message}`);
    }
  }

  loadBlocklist(blocklistPath) {
    try {
      const fullPath = path.resolve(blocklistPath);

      if (!fs.existsSync(fullPath)) {
        logger.warn(`Blocklist file not found: ${fullPath}`);
        return;
      }

      const content = fs.readFileSync(fullPath, 'utf-8');
      let count = 0;

      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        // A trailing "# reason timestamp" comment is written by autoBlockIP.
        const token = trimmed.split('#')[0].trim();
        if (!token) continue;
        if (token.includes('/')) this.blocklistCidr.push(token);
        else this.blocklist.add(token);
        count++;
      }

      logger.info(`Loaded ${count} IPs from blocklist: ${fullPath}`);
    } catch (err) {
      logger.error(`Failed to load blocklist: ${err.message}`);
    }
  }

  reloadWhitelist() {
    if (!this.config.whitelistPath) return;
    this.whitelist.clear();
    this.whitelistCidr = [];
    this.loadWhitelist(this.config.whitelistPath);
  }

  reloadBlocklist() {
    if (!this.config.blocklistPath) return;
    this.blocklist.clear();
    this.blocklistCidr = [];
    this.loadBlocklist(this.config.blocklistPath);
  }

  loadTriggers(triggerPath) {
    try {
      const fullPath = path.resolve(triggerPath);

      if (!fs.existsSync(fullPath)) {
        logger.warn(`Trigger list file not found: ${fullPath}`);
        return;
      }

      const content = fs.readFileSync(fullPath, 'utf-8');
      let count = 0;
      let bad = 0;

      let slow = 0;
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const compiled = compileTrigger(trimmed);
        if (!compiled) { bad++; continue; }
        // Same ReDoS guard the config editor applies on save — a hand-edited
        // triggers.txt bypasses that path, and matchTrigger() runs every
        // pattern against every caller's first bytes.
        if (compiled.kind === 'regex' &&
            (compiled.re.source.length > 400 || NESTED_QUANT_RE.test(compiled.re.source))) {
          slow++;
          continue;
        }
        this.triggers.push(compiled);
        count++;
      }

      logger.info(`Loaded ${count} auto-block trigger(s) from: ${fullPath}` +
        (bad ? ` (${bad} unparseable line(s) skipped)` : '') +
        (slow ? ` (${slow} pattern(s) skipped — catastrophic-backtracking regex)` : ''));
    } catch (err) {
      logger.error(`Failed to load trigger list: ${err.message}`);
    }
  }

  reloadTriggers() {
    this.triggers = [];
    const tb = this.config.triggerBlock;
    if (tb && tb.enabled && tb.listPath) {
      this.loadTriggers(tb.listPath);
    }
  }

  // Return the raw text of the first trigger `text` matches, or null.
  matchTrigger(text) {
    if (!this.triggers.length || !text) return null;
    const lower = text.toLowerCase();
    for (const t of this.triggers) {
      if (t.kind === 'substr') {
        if (lower.includes(t.lit)) return t.raw;
      } else {
        t.re.lastIndex = 0;
        if (t.re.test(text)) return t.raw;
      }
    }
    return null;
  }

  // Blacklist an IP that tripped a trigger. Mode 'blocklist' adds it to
  // blocklist.txt (and memory) permanently; mode 'temp' is an in-memory block
  // for TRIGGER_BLOCK_DURATION_MS. Whitelisted IPs are never blocked.
  autoBlockIP(ipAddress, triggerRaw) {
    const cleanIp = (ipAddress || '').replace(/^::ffff:/i, '');
    if (!cleanIp) return { blocked: false };
    if (this.isIPWhitelisted(ipAddress)) return { blocked: false, whitelisted: true };

    const tb = this.config.triggerBlock || {};
    const reason = `auto-block: trigger ${JSON.stringify(triggerRaw)}`;
    this.autoBlockCount++;

    if (tb.mode === 'temp') {
      this.blockIP(cleanIp, tb.durationMs || 86400000, reason);
      return { blocked: true, mode: 'temp' };
    }

    // Default: 'blocklist' — effective immediately in memory, persisted to file.
    const already = this.blocklist.has(cleanIp);
    this.blocklist.add(cleanIp);

    let persisted = false;
    if (!already && this.config.blocklistPath) {
      try {
        fs.appendFileSync(
          path.resolve(this.config.blocklistPath),
          `${cleanIp}  # ${reason} ${new Date().toISOString()}\n`
        );
        persisted = true;
      } catch (err) {
        logger.error(`Failed to persist auto-block for ${cleanIp}: ${err.message}`);
      }
    }

    logger.warn(`Auto-blocked ${cleanIp} (${reason})${persisted ? ' — added to blocklist.txt' : ''}`);
    return { blocked: true, mode: 'blocklist', persisted };
  }

  isIPWhitelisted(ipAddress) {
    if (!ipAddress || typeof ipAddress !== 'string') return false;

    const cleanIp = ipAddress.replace(/^::ffff:/i, '');

    if (this.whitelist.has(cleanIp) || this.whitelist.has(ipAddress)) return true;

    for (const entry of this.whitelistCidr) {
      if (ipMatchesCIDR(cleanIp, entry)) return true;
    }

    return false;
  }

  isIPInBlocklist(ipAddress) {
    if (!ipAddress || typeof ipAddress !== 'string') return false;

    const cleanIp = ipAddress.replace(/^::ffff:/i, '');

    if (this.blocklist.has(cleanIp) || this.blocklist.has(ipAddress)) return true;

    for (const entry of this.blocklistCidr) {
      if (ipMatchesCIDR(cleanIp, entry)) return true;
    }

    return false;
  }

  recordConnectionAttempt(ipAddress) {
    if (!this.config.rateLimitEnabled) return false;
    if (!ipAddress || typeof ipAddress !== 'string') return false;

    const now = Date.now();
    const cleanIp = ipAddress.replace(/^::ffff:/i, '');

    if (!this.connectionAttempts.has(cleanIp)) {
      this.connectionAttempts.set(cleanIp, []);
    }

    const attempts = this.connectionAttempts.get(cleanIp);
    attempts.push(now);

    const windowStart = now - this.config.rateLimitWindowMs;
    const recentAttempts = attempts.filter(time => time > windowStart);
    this.connectionAttempts.set(cleanIp, recentAttempts);

    if (recentAttempts.length > this.config.maxConnectionsPerWindow) {
      this.blockIP(
        cleanIp,
        this.config.rateLimitBlockDurationMs,
        `Rate limit exceeded: ${recentAttempts.length} connections in ${this.config.rateLimitWindowMs}ms`
      );
      return true;
    }

    return false;
  }

  blockIP(ipAddress, durationMs, reason) {
    const cleanIp = ipAddress.replace(/^::ffff:/i, '');
    const blockedUntil = Date.now() + durationMs;

    this.blockedIPs.set(cleanIp, {
      blockedUntil,
      reason,
      blockedAt: Date.now(),
    });

    const durationMin = Math.round(durationMs / 60000);
    logger.warn(`Blocked IP ${cleanIp} for ${durationMin} minutes: ${reason}`);
  }

  isIPBlocked(ipAddress) {
    if (!ipAddress || typeof ipAddress !== 'string') return { blocked: false };

    const cleanIp = ipAddress.replace(/^::ffff:/i, '');

    const blockInfo = this.blockedIPs.get(cleanIp);
    if (blockInfo) {
      if (Date.now() < blockInfo.blockedUntil) {
        return { blocked: true, reason: blockInfo.reason, temporary: true };
      } else {
        this.blockedIPs.delete(cleanIp);
      }
    }

    if (this.isIPInBlocklist(ipAddress)) {
      return { blocked: true, reason: 'IP in blocklist', temporary: false };
    }

    return { blocked: false };
  }

  shouldAllowConnection(ipAddress) {
    if (!ipAddress || typeof ipAddress !== 'string') {
      logger.warn('Connection attempt with invalid/undefined IP address');
      return { allowed: false, reason: 'Invalid IP address' };
    }

    // Whitelisted IPs bypass all other checks
    if (this.isIPWhitelisted(ipAddress)) {
      logger.debug(`Connection from whitelisted IP: ${ipAddress}`);
      return { allowed: true, whitelisted: true };
    }

    const blockCheck = this.isIPBlocked(ipAddress);
    if (blockCheck.blocked) {
      logger.info(`Blocked connection from ${ipAddress}: ${blockCheck.reason}`);
      return { allowed: false, reason: blockCheck.reason };
    }

    const rateLimitExceeded = this.recordConnectionAttempt(ipAddress);
    if (rateLimitExceeded) {
      return { allowed: false, reason: 'Rate limit exceeded' };
    }

    return { allowed: true };
  }

  // --- Per-IP concurrent connection tracking ---

  trackConnectionOpen(ipAddress) {
    const cleanIp = (ipAddress || '').replace(/^::ffff:/i, '');
    if (!cleanIp) return;
    const current = this.activeConnectionsByIP.get(cleanIp) || 0;
    this.activeConnectionsByIP.set(cleanIp, current + 1);
    logger.debug(`Active connections for ${cleanIp}: ${current + 1}`);
  }

  trackConnectionClose(ipAddress) {
    const cleanIp = (ipAddress || '').replace(/^::ffff:/i, '');
    if (!cleanIp) return;
    const current = this.activeConnectionsByIP.get(cleanIp) || 0;
    if (current <= 1) {
      this.activeConnectionsByIP.delete(cleanIp);
    } else {
      this.activeConnectionsByIP.set(cleanIp, current - 1);
    }
    logger.debug(`Active connections for ${cleanIp}: ${Math.max(0, current - 1)}`);
  }

  // Returns true if this IP has reached or exceeded the per-IP connection limit.
  // A limit of 0 means unlimited (always returns false).
  isConnectionLimitExceeded(ipAddress) {
    if (!this.config.maxConnectionsPerIP || this.config.maxConnectionsPerIP === 0) {
      return false;
    }
    const cleanIp = (ipAddress || '').replace(/^::ffff:/i, '');
    const current = this.activeConnectionsByIP.get(cleanIp) || 0;
    return current >= this.config.maxConnectionsPerIP;
  }

  // ---

  cleanupOldAttempts() {
    const now = Date.now();
    const windowStart = now - this.config.rateLimitWindowMs;

    for (const [ip, attempts] of this.connectionAttempts.entries()) {
      const recentAttempts = attempts.filter(time => time > windowStart);
      if (recentAttempts.length === 0) {
        this.connectionAttempts.delete(ip);
      } else {
        this.connectionAttempts.set(ip, recentAttempts);
      }
    }

    for (const [ip, blockInfo] of this.blockedIPs.entries()) {
      if (now >= blockInfo.blockedUntil) {
        this.blockedIPs.delete(ip);
        logger.debug(`Unblocked IP ${ip} (temporary block expired)`);
      }
    }
  }

  getStats() {
    return {
      whitelistSize: this.whitelist.size + this.whitelistCidr.length,
      blocklistSize: this.blocklist.size + this.blocklistCidr.length,
      temporarilyBlockedIPs: this.blockedIPs.size,
      trackedIPs: this.connectionAttempts.size,
      activeIPConnections: this.activeConnectionsByIP.size,
      triggerCount: this.triggers.length,
      autoBlocked: this.autoBlockCount,
    };
  }

  shutdown() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
    }
  }
}

let ipFilterInstance = null;

function initializeIPFilter(config) {
  if (!ipFilterInstance) {
    ipFilterInstance = new IPFilter(config);
    ipFilterInstance.initialize();
  }
  return ipFilterInstance;
}

function getIPFilter() {
  return ipFilterInstance;
}

module.exports = { initializeIPFilter, getIPFilter, validateTriggerText };
