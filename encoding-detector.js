/**
 * BBS Firewall - Encoding detection (UTF-8 vs CP437)
 * Routes clients to the appropriate backend port based on their terminal encoding.
 * https://github.com/SysopNetwork/BBSFirewall
 */

const logger = require('./logger');

function detectFromSSHEnvironment(env) {
  if (!env) return 'cp437';

  const langVars = ['LANG', 'LC_ALL', 'LC_CTYPE'];

  for (const varName of langVars) {
    const value = env[varName];
    if (value && typeof value === 'string') {
      const upper = value.toUpperCase();
      if (upper.includes('UTF-8') || upper.includes('UTF8')) {
        logger.debug(`Detected UTF-8 from ${varName}=${value}`);
        return 'utf8';
      }
    }
  }

  logger.debug('No UTF-8 indicators in SSH environment, defaulting to CP437');
  return 'cp437';
}

function detectFromTerminalType(termType) {
  if (!termType || typeof termType !== 'string') return 'cp437';

  const term = termType.toLowerCase();

  const utf8Terminals = [
    'xterm-256color', 'xterm-color', 'xterm',
    'screen-256color', 'screen',
    'rxvt-unicode', 'konsole', 'gnome',
    'linux', 'vt220', 'vt100',
  ];

  const cp437Terminals = [
    'ansi', 'ansi-bbs', 'ansi-mono', 'ansi-color',
    'pcansi', 'scoansi',
  ];

  for (const t of utf8Terminals) {
    if (term.includes(t)) {
      logger.debug(`Detected UTF-8 from terminal type: ${termType}`);
      return 'utf8';
    }
  }

  for (const t of cp437Terminals) {
    if (term.includes(t)) {
      logger.debug(`Detected CP437 from terminal type: ${termType}`);
      return 'cp437';
    }
  }

  logger.debug(`Unknown terminal type: ${termType}, defaulting to CP437`);
  return 'cp437';
}

function detectFromTelnetNegotiation(termType) {
  return detectFromTerminalType(termType);
}

function getBackendPortForEncoding(encoding, config) {
  if (!config.encodingDetection) return config.backendPort;

  if (encoding === 'utf8') {
    logger.debug(`Using UTF-8 backend port: ${config.backendPortUTF8}`);
    return config.backendPortUTF8;
  } else {
    logger.debug(`Using CP437 backend port: ${config.backendPortCP437}`);
    return config.backendPortCP437;
  }
}

module.exports = {
  detectFromSSHEnvironment,
  detectFromTerminalType,
  detectFromTelnetNegotiation,
  getBackendPortForEncoding,
};
