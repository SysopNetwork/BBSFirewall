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
// Log text often carries caller-controlled values (an SSH username, a
// terminal type, an exec command). A raw CR/LF in one would start a forged
// log line - e.g. a fake "[BLOCKED]" or "Config editor login" entry that the
// Logs tab and search then show as real. Control characters other than tab
// are written as \xNN instead. keepNewlines (console only) keeps a message's
// own line breaks readable - a multi-line startup error - but indents each
// continuation line so it can never pass for a real "[timestamp] [LEVEL]" entry.
function escapeControl(text, keepNewlines) {
  let s = String(text);
  if (keepNewlines) s = s.replace(/\r?\n/g, '\n    ');
  return s.replace(keepNewlines ? /[\x00-\x08\x0b-\x1f\x7f]/g : /[\x00-\x08\x0a-\x1f\x7f]/g,
    (c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'));
}

function write(proxyName, category, message, data) {
  if (!shouldWrite(proxyName, category)) return;
  const line = `[${new Date().toISOString()}] [${category.toUpperCase()}] ${escapeControl(message + formatData(data))}\n`;
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

// ---------------------------------------------------------------------------
// Ranged reads for the Logs-tab viewer: page backwards through a big file,
// follow today's file live, or open a window around one line (a search hit).
// Every result carries byte offsets (start/end) so the client can ask for
// the next page, plus firstLine (1-based line number of the first returned
// line, or null when counting would cost too much) for line numbers.
// ---------------------------------------------------------------------------
const VIEW_CHUNK_BYTES = 512 * 1024;
const LINE_COUNT_MAX_BYTES = 64 * 1024 * 1024; // beyond this, skip line numbers

// Count newlines in [0, offset) by streaming — never reads the file whole.
async function countLinesBefore(full, offset) {
  if (offset <= 0) return 0;
  if (offset > LINE_COUNT_MAX_BYTES) return null;
  let n = 0;
  const stream = fs.createReadStream(full, { start: 0, end: offset - 1 });
  for await (const chunk of stream) {
    let i = chunk.indexOf(10);
    while (i !== -1) { n++; i = chunk.indexOf(10, i + 1); }
  }
  return n;
}

function readBytes(full, start, end) {
  const len = Math.max(0, end - start);
  const buf = Buffer.alloc(len);
  if (!len) return buf;
  const fd = fs.openSync(full, 'r');
  try {
    fs.readSync(fd, buf, 0, len, start);
  } finally {
    fs.closeSync(fd);
  }
  return buf;
}

/**
 * opts (at most one of):
 *   before: byte offset — the chunk of up to VIEW_CHUNK_BYTES ending there
 *   after:  byte offset — new COMPLETE lines from there to EOF (follow mode)
 *   (none)  — the last VIEW_CHUNK_BYTES of the file (the default view)
 * Chunk edges are snapped to whole lines. Returns
 *   { content, start, end, size, firstLine, atStart, reset? }
 */
async function readLogRange(proxyName, fileName, opts = {}) {
  const full = resolveLogFile(proxyName, fileName);
  const size = fs.statSync(full).size; // ENOENT -> caller maps to 404

  if (opts.after !== undefined) {
    let after = Number(opts.after);
    if (!Number.isFinite(after) || after < 0) throw new Error('invalid offset');
    // The file shrank (deleted and recreated) — tell the client to reload.
    if (after > size) return { content: '', start: size, end: size, size, firstLine: null, atStart: false, reset: true };
    const end = Math.min(size, after + VIEW_CHUNK_BYTES);
    const buf = readBytes(full, after, end);
    const lastNl = buf.lastIndexOf(10);
    const usable = lastNl === -1 ? 0 : lastNl + 1; // a half-written last line waits for the next poll
    return {
      content: buf.subarray(0, usable).toString('utf8'),
      start: after,
      end: after + usable,
      size,
      firstLine: null, // the client already knows where it left off
      atStart: after === 0,
    };
  }

  let end = size;
  if (opts.before !== undefined) {
    end = Number(opts.before);
    if (!Number.isFinite(end) || end < 0 || end > size) throw new Error('invalid offset');
  }
  let start = Math.max(0, end - VIEW_CHUNK_BYTES);
  const buf = readBytes(full, start, end);
  let text = buf;
  if (start > 0) {
    const nl = buf.indexOf(10);
    if (nl === -1) { text = Buffer.alloc(0); start = end; } else { text = buf.subarray(nl + 1); start += nl + 1; }
  }
  const before = await countLinesBefore(full, start);
  return {
    content: text.toString('utf8'),
    start,
    end,
    size,
    firstLine: before === null ? null : before + 1,
    atStart: start === 0,
  };
}

/**
 * A window of lines centred on `line` (1-based) — what a search hit opens.
 * Streams to the target, so it is linear in the file up to that point.
 * Returns the same shape as readLogRange() plus targetLine.
 */
async function readLogAroundLine(proxyName, fileName, line, context = 150) {
  const full = resolveLogFile(proxyName, fileName);
  const size = fs.statSync(full).size;
  const target = parseInt(line, 10);
  if (!Number.isFinite(target) || target < 1) throw new Error('invalid line');
  const from = Math.max(1, target - context);
  const to = target + context;

  const readline = require('readline');
  const stream = fs.createReadStream(full);
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  const lines = [];
  let lineNo = 0;
  let offset = 0;
  let start = 0;
  let end = 0;
  try {
    for await (const l of rl) {
      lineNo++;
      const len = Buffer.byteLength(l) + 1;
      if (lineNo === from) start = offset;
      offset += len;
      if (lineNo >= from) { lines.push(l); end = offset; }
      if (lineNo >= to) break;
    }
  } finally {
    rl.close();
    stream.destroy();
  }
  if (!lines.length) throw new Error('line is past the end of the file');
  return {
    content: lines.join('\n') + '\n',
    start,
    end: Math.min(end, size),
    size,
    firstLine: from,
    atStart: start === 0,
    targetLine: target,
  };
}

// Absolute path of a validated log file, for streaming a download.
function logFilePath(proxyName, fileName) {
  const full = resolveLogFile(proxyName, fileName);
  fs.statSync(full); // ENOENT -> caller maps to 404
  return full;
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

// ---------------------------------------------------------------------------
// Search across every rotated log file.
//
// Query syntax (case-insensitive): every bare word must appear somewhere in
// the line; "a quoted phrase" must appear as-is; a leading "-" (-debug,
// -"rate limit") excludes lines containing it. Plain substring matching only
// — no user-supplied regex, since a catastrophic pattern would freeze the
// whole firewall (single event loop) for as long as the scan ran.
//
// Files are streamed line by line (never read whole) newest date first, and
// the scan stops at `limit` matches or `maxBytes` scanned, whichever comes
// first. Within a file only the LAST matches are kept when the limit bites,
// so results are always the newest ones.
// ---------------------------------------------------------------------------
const SEARCH_LEVELS = ['BLOCKED', 'ERROR', 'CONNECTION', 'WARN', 'INFO', 'DEBUG'];
const SEARCH_MAX_LINE = 2000;

function parseQuery(q) {
  const include = [];
  const exclude = [];
  const s = String(q || '');
  let i = 0;
  while (i < s.length) {
    while (i < s.length && /\s/.test(s[i])) i++;
    if (i >= s.length) break;
    let neg = false;
    if (s[i] === '-' && i + 1 < s.length && !/\s/.test(s[i + 1])) { neg = true; i++; }
    let term;
    if (s[i] === '"') {
      const end = s.indexOf('"', i + 1);
      term = end === -1 ? s.slice(i + 1) : s.slice(i + 1, end);
      i = end === -1 ? s.length : end + 1;
    } else {
      const start = i;
      while (i < s.length && !/\s/.test(s[i])) i++;
      term = s.slice(start, i);
    }
    term = term.toLowerCase();
    if (term) (neg ? exclude : include).push(term);
  }
  return { include, exclude };
}

function lineMatches(line, parsed, levelTag) {
  if (levelTag && !line.includes(levelTag)) return false;
  const lower = line.toLowerCase();
  for (const t of parsed.include) if (!lower.includes(t)) return false;
  for (const t of parsed.exclude) if (lower.includes(t)) return false;
  return true;
}

async function searchFile(full, parsed, levelTag, keep, onBytes) {
  const readline = require('readline');
  const stream = fs.createReadStream(full, { encoding: 'utf8' });
  const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
  const hits = [];
  let total = 0;
  let lineNo = 0;
  try {
    for await (const line of rl) {
      lineNo++;
      onBytes(Buffer.byteLength(line) + 1);
      if (!lineMatches(line, parsed, levelTag)) continue;
      total++;
      hits.push({ line: lineNo, text: line.length > SEARCH_MAX_LINE ? line.slice(0, SEARCH_MAX_LINE) + ' …' : line });
      if (hits.length > keep) hits.shift();
    }
  } finally {
    rl.close();
    stream.destroy();
  }
  return { hits, total };
}

/**
 * opts: { q, proxy, level, from, to, limit, maxBytes }
 *   proxy       - one proxy folder name, or empty for all
 *   level       - one of SEARCH_LEVELS, or empty for any
 *   from / to   - inclusive YYYY-MM-DD bounds on the file date
 */
async function searchLogs(opts = {}) {
  const parsed = parseQuery(opts.q);
  const level = String(opts.level || '').toUpperCase();
  if (level && !SEARCH_LEVELS.includes(level)) throw new Error('invalid level');
  const levelTag = level ? `] [${level}] ` : '';
  if (!parsed.include.length && !parsed.exclude.length && !levelTag) {
    throw new Error('Enter something to search for, or pick a level');
  }
  const dateRe = /^\d{4}-\d{2}-\d{2}$/;
  for (const k of ['from', 'to']) {
    if (opts[k] && !dateRe.test(opts[k])) throw new Error(`invalid ${k} date`);
  }
  const limit = Math.min(Math.max(parseInt(opts.limit, 10) || 500, 1), 2000);
  const maxBytes = opts.maxBytes || 256 * 1024 * 1024;

  const files = listLogFiles()
    .filter((f) => !opts.proxy || f.proxy === opts.proxy)
    .filter((f) => (!opts.from || f.date >= opts.from) && (!opts.to || f.date <= opts.to))
    .sort((a, b) => b.date.localeCompare(a.date) || a.proxy.localeCompare(b.proxy));

  const matches = [];
  let totalMatches = 0;
  let bytesScanned = 0;
  let filesScanned = 0;
  let limitReached = false;
  let bytesCapReached = false;

  for (const f of files) {
    if (matches.length >= limit) { limitReached = true; break; }
    if (bytesScanned >= maxBytes) { bytesCapReached = true; break; }
    let res;
    try {
      res = await searchFile(resolveLogFile(f.proxy, f.file), parsed, levelTag, limit - matches.length,
        (n) => { bytesScanned += n; });
    } catch (_) {
      continue; // pruned/deleted mid-search — skip it
    }
    filesScanned++;
    totalMatches += res.total;
    if (res.total > res.hits.length) limitReached = true;
    for (let i = res.hits.length - 1; i >= 0; i--) {
      matches.push({ proxy: f.proxy, file: f.file, date: f.date, ...res.hits[i] });
    }
  }

  return {
    terms: parsed,
    matches,
    totalMatches,
    filesScanned,
    filesTotal: files.length,
    bytesScanned,
    limit,
    limitReached,
    bytesCapReached,
  };
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

module.exports = {
  write, escapeControl, closeAll, LEVELS, listLogFiles, readLogFile, deleteLogFile, pruneOldLogs, startPruning,
  searchLogs, parseQuery, SEARCH_LEVELS,
  readLogRange, readLogAroundLine, logFilePath,
};
