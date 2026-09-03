/**
 * BBSFirewall - Logging utility
 *
 * Console logging is a severity filter (debug/info/warn/error) governed by the
 * global LOG_LEVEL. Per-proxy file logging is a separate, additive layer — get
 * a proxy-scoped logger with getLogger('telnet' | 'ssh' | 'ssh-passthrough' |
 * 'web'). Scoped loggers add two event-category helpers — blocked() and
 * connection() — so the file tier can decide what to write deterministically
 * rather than by matching message text.
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const { config } = require('./config');
const fileLogger = require('./file-logger');

const LOG_LEVELS = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const currentLevel = LOG_LEVELS[config.logLevel] || LOG_LEVELS.info;

// Console emission — unchanged behavior, governed by LOG_LEVEL.
function emit(level, message, data = null) {
  if (LOG_LEVELS[level] >= currentLevel) {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [${level.toUpperCase()}] ${message}`;

    if (data) {
      console.log(logMessage, data);
    } else {
      console.log(logMessage);
    }
  }
}

/**
 * Return a logger scoped to a proxy service. Severity methods behave exactly
 * like the default logger on the console; every call also feeds the per-proxy
 * file log under the appropriate event category.
 *
 * Category → console severity mapping keeps console output readable:
 *   blocked    -> WARN   (a denied/blocked connection)
 *   connection -> INFO   (accept / open / close lifecycle)
 */
function getLogger(proxyName) {
  const scoped = (severity, category, msg, data) => {
    emit(severity, msg, data);
    fileLogger.write(proxyName, category, msg, data);
  };

  return {
    debug:      (msg, data) => scoped('debug', 'debug', msg, data),
    info:       (msg, data) => scoped('info',  'info',  msg, data),
    warn:       (msg, data) => scoped('warn',  'warn',  msg, data),
    error:      (msg, data) => scoped('error', 'error', msg, data),
    blocked:    (msg, data) => scoped('warn',  'blocked',    msg, data),
    connection: (msg, data) => scoped('info',  'connection', msg, data),
  };
}

module.exports = {
  // Default (console-only) logger — used for server-wide startup/shutdown logs
  // that don't belong to any single proxy.
  debug: (msg, data) => emit('debug', msg, data),
  info:  (msg, data) => emit('info',  msg, data),
  warn:  (msg, data) => emit('warn',  msg, data),
  error: (msg, data) => emit('error', msg, data),
  getLogger,
};
