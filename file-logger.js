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

module.exports = { write, closeAll, LEVELS };
