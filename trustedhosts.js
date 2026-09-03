/**
 * BBSFirewall - Trusted host matching for the web config editor
 *
 * Loads a plain-text allowlist (one IP or CIDR per line, IPv4 and IPv6) and
 * answers "is this client address trusted?". Matching is done on the numeric
 * address so CIDR prefixes work for both families. An empty or missing list
 * means "trust nobody" — the config editor denies every request until at
 * least one entry is added.
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const fs = require('fs');
const path = require('path');

// --- address parsing -------------------------------------------------------

function ipv4ToBigInt(str) {
  const parts = str.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value << 8n) | BigInt(n);
  }
  return value;
}

function ipv6ToBigInt(str) {
  let s = str.trim();
  if (!s) return null;

  // Drop a zone index (fe80::1%eth0)
  const pct = s.indexOf('%');
  if (pct !== -1) s = s.slice(0, pct);

  // Expand an embedded IPv4 tail (::ffff:192.0.2.1) into two hextets
  const lastColon = s.lastIndexOf(':');
  if (lastColon !== -1 && s.slice(lastColon + 1).includes('.')) {
    const v4 = ipv4ToBigInt(s.slice(lastColon + 1));
    if (v4 === null) return null;
    const hi = (v4 >> 16n) & 0xffffn;
    const lo = v4 & 0xffffn;
    s = s.slice(0, lastColon + 1) + hi.toString(16) + ':' + lo.toString(16);
  }

  const halves = s.split('::');
  if (halves.length > 2) return null;

  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : null;

  let groups;
  if (tail === null) {
    groups = head;
  } else {
    const missing = 8 - head.length - tail.length;
    if (missing < 1) return null; // "::" must stand for at least one group
    groups = [...head, ...Array(missing).fill('0'), ...tail];
  }
  if (groups.length !== 8) return null;

  let value = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    value = (value << 16n) | BigInt(parseInt(g, 16));
  }
  return value;
}

// Classify a raw remote address string into { version, value }.
function classifyAddress(addr) {
  if (typeof addr !== 'string' || !addr) return null;
  let s = addr.trim();

  const pct = s.indexOf('%');
  if (pct !== -1) s = s.slice(0, pct);

  // IPv4-mapped IPv6 (::ffff:1.2.3.4) is treated as plain IPv4
  const mapped = s.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (mapped) {
    const v = ipv4ToBigInt(mapped[1]);
    return v === null ? null : { version: 4, value: v };
  }

  if (s.includes(':')) {
    const v = ipv6ToBigInt(s);
    return v === null ? null : { version: 6, value: v };
  }

  const v = ipv4ToBigInt(s);
  return v === null ? null : { version: 4, value: v };
}

// Parse one allowlist entry ("203.0.113.0/24", "2001:db8::/32", "10.0.0.1").
function parseEntry(entry) {
  const raw = String(entry || '').trim();
  if (!raw) return null;

  let addr = raw;
  let prefixStr = null;
  const slash = raw.indexOf('/');
  if (slash !== -1) {
    addr = raw.slice(0, slash).trim();
    prefixStr = raw.slice(slash + 1).trim();
  }

  const info = classifyAddress(addr);
  if (!info) return null;

  const bits = info.version === 4 ? 32 : 128;
  let prefix = bits;
  if (prefixStr !== null) {
    if (!/^\d{1,3}$/.test(prefixStr)) return null;
    prefix = Number(prefixStr);
    if (prefix > bits) return null;
  }

  return { version: info.version, value: info.value, prefix, bits, raw };
}

function entryMatches(clientInfo, entry) {
  if (!clientInfo || !entry) return false;
  if (clientInfo.version !== entry.version) return false;
  if (entry.prefix === 0) return true;
  const shift = BigInt(entry.bits - entry.prefix);
  return (clientInfo.value >> shift) === (entry.value >> shift);
}

// --- file loading --------------------------------------------------------

function loadTrustedHosts(filePath) {
  const result = {
    path: filePath,
    resolvedPath: filePath ? path.resolve(filePath) : null,
    exists: false,
    entries: [],
    invalid: [],
    error: null,
  };

  if (!filePath) return result;

  try {
    if (!fs.existsSync(result.resolvedPath)) return result;
    result.exists = true;

    const content = fs.readFileSync(result.resolvedPath, 'utf-8');
    for (const line of content.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;

      // allow a trailing inline comment: "10.0.0.0/8   # office LAN"
      const token = trimmed.split('#')[0].trim();
      if (!token) continue;

      const parsed = parseEntry(token);
      if (parsed) result.entries.push(parsed);
      else result.invalid.push(trimmed);
    }
  } catch (err) {
    result.error = err.message;
  }

  return result;
}

// Is `addr` allowed by an already-loaded list? Empty list => false (deny all).
function isTrusted(addr, loaded) {
  if (!loaded || !Array.isArray(loaded.entries) || loaded.entries.length === 0) {
    return false;
  }
  const info = classifyAddress(addr);
  if (!info) return false;
  return loaded.entries.some((e) => entryMatches(info, e));
}

// Validate raw text (used by the editor before saving). Returns the count of
// valid entries and the list of lines it could not parse.
function validateText(text) {
  const valid = [];
  const invalid = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const token = trimmed.split('#')[0].trim();
    if (!token) continue;
    if (parseEntry(token)) valid.push(token);
    else invalid.push(trimmed);
  }
  return { validCount: valid.length, invalid };
}

module.exports = {
  classifyAddress,
  parseEntry,
  entryMatches,
  loadTrustedHosts,
  isTrusted,
  validateText,
};
