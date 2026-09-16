/**
 * BBSFirewall - Per-proxy file logging
 *
 * Writes a daily-rotated log file per proxy service (telnet, ssh,
 * ssh-passthrough, web) into its own subfolder under LOG_DIR:
 *
 *     logs/telnet/telnet-2026-07-08.log
 *     logs/ssh/ssh-2026-07-08.log
 *     logs/ssh-passthrough/ssh-passthrough-2026-07-08.log
 *     logs/web/web-2026-07-08.log
 *
 * Verbosity is event-based (not severity-based). Each tier includes the ones
 * below it:
 *
 *     off         nothing
 *     blocked     denials/blocks + errors                    (default)
 *     connections + accepted connections, disconnects, warnings
 *     info        + general informational lines
 *     debug       + every action, including byte-level traces
 *
 * This is an additive layer on top of the console logger — console output is
 * still governed independently by LOG_LEVEL.
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const fs = require('fs');
const path = require('path');
const { config } = require('./config');

// Ordered verbosity scale — higher value writes strictly more.
const LEVELS = {
  off: 0,
  blocked: 1,
  connections: 2,
  info: 3,
  debug: 4,
};

// Minimum configured level at which a given event category is written.
const CATEGORY_MIN_LEVEL = {
  blocked: LEVELS.blocked,
  error: LEVELS.blocked,
  connection: LEVELS.connections,
  warn: LEVELS.connections,
  info: LEVELS.info,
  debug: LEVELS.debug,
};

// proxyName -> { stream, date }
const streams = new Map();

function levelValue(name) {
  const v = LEVELS[String(name || '').toLowerCase()];
  return v === undefined ? LEVELS.blocked : v;
}

// Resolve the effective file-logging settings for a proxy: the master switch
// gates everything, then per-proxy overrides fall back to the global default.
function resolveProxy(proxyName) {
  if (!config.fileLog || !config.fileLog.enabled) {
    return { enabled: false, level: 'off' };
  }
  const override = (config.fileLog.proxies && config.fileLog.proxies[proxyName]) || {};
  const enabled = override.enabled === undefined ? true : override.enabled;
  const level = override.level || config.fileLog.defaultLevel || 'blocked';
  return { enabled, level };
}

function shouldWrite(proxyName, category) {
  const { enabled, level } = resolveProxy(proxyName);
  if (!enabled) return false;
  const configured = levelValue(level);
  if (configured <= LEVELS.off) return false;
  const min = CATEGORY_MIN_LEVEL[category] === undefined ? LEVELS.debug : CATEGORY_MIN_LEVEL[category];
  return configured >= min;
}

// UTC date (matches the ISO timestamps written on each line) for the filename.
function currentDate() {
  return new Date().toISOString().slice(0, 10);
}

// Return an append stream for today's file, rotating when the date rolls over.
function getStream(proxyName) {
  const date = currentDate();
  const existing = streams.get(proxyName);
  if (existing && existing.date === date) {
    return existing.stream;
  }
  if (existing) {
    existing.stream.end();
  }

  const dir = path.join(path.resolve(config.fileLog.dir || './logs'), proxyName);
  fs.mkdirSync(dir, { recursive: true });

  const file = path.join(dir, `${proxyName}-${date}.log`);
  const stream = fs.createWriteStream(file, { flags: 'a' });
  stream.on('error', (err) => {
    // Never let a logging failure take down a proxy — fall back to console.
    console.error(`[file-logger] write error for ${proxyName}: ${err.message}`);
  });

  streams.set(proxyName, { stream, date });
  return stream;
}

function formatData(data) {
  if (data === undefined || data === null) return '';
  if (typeof data === 'string') return ` ${data}`;
  try {
    return ` ${JSON.stringify(data)}`;
  } catch (_) {
    return '';
  }
}

/**
 * Write one line to a proxy's log file if its configured level permits the
 * event category. Cheap no-op when the proxy has file logging disabled.
 */
function write(proxyName, category, message, data) {
  if (!shouldWrite(proxyName, category)) return;
  const line = `[${new Date().toISOString()}] [${category.toUpperCase()}] ${message}${formatData(data)}\n`;
  try {
    getStream(proxyName).write(line);
  } catch (err) {
    console.error(`[file-logger] failed to log for ${proxyName}: ${err.message}`);
  }
}

// Flush and close all open log streams (called on graceful shutdown).
function closeAll() {
  for (const { stream } of streams.values()) {
    stream.end();
  }
  streams.clear();
}

// Matches exactly the names getStream() creates: "<proxy>-<YYYY-MM-DD>.log",
// with the proxy folder name repeated in the filename.
const LOG_FILENAME_RE = /^([a-z0-9-]+)-(\d{4}-\d{2}-\d{2})\.log$/;

function logsRoot() {
  return path.resolve(config.fileLog.dir || './logs');
}

/**
 * List every rotated log file on disk, across all proxy subfolders, newest
 * first within each proxy. Used by the config editor / management API — not
 * on any request-handling hot path.
 */
function listLogFiles() {
  const root = logsRoot();
  let proxyDirs;
  try {
    proxyDirs = fs.readdirSync(root, { withFileTypes: true }).filter((d) => d.isDirectory());
  } catch (err) {
    if (err.code === 'ENOENT') return [];
    throw err;
  }
  const out = [];
  for (const d of proxyDirs) {
    const proxyName = d.name;
    let names;
    try { names = fs.readdirSync(path.join(root, proxyName)); } catch (_) { continue; }
    for (const name of names) {
      const m = LOG_FILENAME_RE.exec(name);
      if (!m || m[1] !== proxyName) continue; // ignore anything not shaped like our own output
      let stat;
      try { stat = fs.statSync(path.join(root, proxyName, name)); } catch (_) { continue; }
      if (!stat.isFile()) continue;
      out.push({ proxy: proxyName, file: name, date: m[2], size: stat.size, mtime: stat.mtime.toISOString() });
    }
  }
  out.sort((a, b) => (a.proxy === b.proxy ? b.date.localeCompare(a.date) : a.proxy.localeCompare(b.proxy)));
  return out;
}

// Resolve a (proxy, file) pair to an absolute path, refusing anything that
// isn't an exact, well-formed log filename under its matching proxy folder —
// the filename's own proxy prefix must equal the requested proxy, and both
// are restricted to LOG_FILENAME_RE's [a-z0-9-] charset, so this can never
// escape logsRoot() regardless of what a caller passes in.
function resolveLogFile(proxyName, fileName) {
  if (typeof proxyName !== 'string' || typeof fileName !== 'string') {
    throw new Error('proxy and file are required');
  }
  const m = LOG_FILENAME_RE.exec(fileName);
  if (!m || m[1] !== proxyName) {
    throw new Error('invalid log file name');
  }
  return path.join(logsRoot(), proxyName, fileName);
}

/**
 * Read a log file's content for display. Files at or under maxBytes are
 * returned whole; larger ones are tailed to the last maxBytes (rounded down
 * to a full line) so viewing a multi-day debug-level file can't blow up
 * memory or the response.
 */
function readLogFile(proxyName, fileName, opts = {}) {
  const full = resolveLogFile(proxyName, fileName);
  const stat = fs.statSync(full); // throws ENOENT (caller maps to 404) if missing
  const maxBytes = opts.maxBytes || 512 * 1024;
  if (stat.size <= maxBytes) {
    return { content: fs.readFileSync(full, 'utf8'), truncated: false, size: stat.size };
  }
  const fd = fs.openSync(full, 'r');
  try {
    const buf = Buffer.alloc(maxBytes);
    fs.readSync(fd, buf, 0, maxBytes, stat.size - maxBytes);
    let text = buf.toString('utf8');
    const nl = text.indexOf('\n');
    if (nl !== -1) text = text.slice(nl + 1); // drop the partial first line
    return { content: text, truncated: true, size: stat.size };
  } finally {
    fs.closeSync(fd);
  }
}

/**
 * Delete a rotated log file. If it's the proxy's currently-open file, close
 * the write stream first — an open write handle can otherwise keep the file
 * alive under the caller (and blocks the unlink outright on Windows); the
 * next write for that proxy just reopens a fresh file as usual.
 */
function deleteLogFile(proxyName, fileName) {
  const full = resolveLogFile(proxyName, fileName);
  const active = streams.get(proxyName);
  if (active && full === path.join(logsRoot(), proxyName, `${proxyName}-${currentDate()}.log`)) {
    active.stream.end();
    streams.delete(proxyName);
  }
  fs.unlinkSync(full);
}

/**
 * Delete every rotated log file older than config.fileLog.retentionDays.
 * Reads the retention value fresh on each call (not cached at startup) so a
 * value lowered from the config editor takes effect on the next tick without
 * a restart. Reuses listLogFiles()/deleteLogFile() rather than a second
 * enumeration/deletion path.
 */
function pruneOldLogs() {
  const retentionDays = (config.fileLog && config.fileLog.retentionDays) || 30;
  const cutoff = new Date(Date.now() - retentionDays * 86400000).toISOString().slice(0, 10);
  let deleted = 0;
  for (const f of listLogFiles()) {
    if (f.date < cutoff) {
      try {
        deleteLogFile(f.proxy, f.file);
        deleted += 1;
      } catch (err) {
        console.error(`[file-logger] prune failed for ${f.proxy}/${f.file}: ${err.message}`);
      }
    }
  }
  return deleted;
}

let pruneTimer = null;

// Runs pruneOldLogs() once immediately (so a freshly-lowered retention value
// doesn't wait a full interval) and then on a recurring timer. Independent of
// the config editor — called once from server.js at startup so pruning runs
// even with the editor disabled. unref'd so it never keeps the process alive.
function startPruning(intervalMs) {
  if (pruneTimer) clearInterval(pruneTimer);
  pruneOldLogs();
  pruneTimer = setInterval(pruneOldLogs, intervalMs);
  if (pruneTimer.unref) pruneTimer.unref();
}

module.exports = { write, closeAll, LEVELS, listLogFiles, readLogFile, deleteLogFile, pruneOldLogs, startPruning };
