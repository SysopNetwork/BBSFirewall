/**
 * BBSFirewall - Configuration
 * https://github.com/SysopNetwork/BBSFirewall
 */

// override: true makes .env the single source of truth. Without it, dotenv
// leaves any variable already present in the environment untouched — and pm2
// caches the shell environment from `pm2 start`, so a value set once (e.g.
// SSH_MODE) sticks across `pm2 restart` and silently wins over an edited .env.
// The web config editor rewrites this file and restarts, so the file must win.
require('dotenv').config({ quiet: true, override: true });

// Only for the cheap existence check in validateConfig() below — avoids
// duplicating the .admin-security.json path constant. security.js does no
// crypto work just to answer secretsExist(), so this stays a fast require.
const security = require('./security');

// Valid per-proxy file-logging verbosity tiers, lowest to highest.
const FILE_LOG_LEVELS = ['off', 'blocked', 'connections', 'info', 'debug'];

// Resolve a proxy's file-logging overrides from <PREFIX>_LOG_ENABLED /
// <PREFIX>_LOG_LEVEL. `undefined` means "inherit the global default".
function resolveProxyLog(prefix) {
  const enabledRaw = process.env[`${prefix}_LOG_ENABLED`];
  const levelRaw = process.env[`${prefix}_LOG_LEVEL`];
  return {
    enabled: enabledRaw === undefined ? undefined : enabledRaw === 'true',
    level: levelRaw ? levelRaw.toLowerCase() : undefined,
  };
}

const config = {
  // Port to listen on for incoming telnet connections
  listenPort: parseInt(process.env.LISTEN_PORT || '23', 10),

  // Backend BBS server to forward connections to
  backendHost: process.env.BACKEND_HOST || '127.0.0.1',
  backendPort: parseInt(process.env.BACKEND_PORT || '2323', 10),

  // Encoding-based backend routing (route CP437 and UTF-8 clients to separate ports)
  encodingDetection: process.env.ENCODING_DETECTION === 'true',
  backendPortCP437: parseInt(process.env.BACKEND_PORT_CP437 || '2323', 10),
  backendPortUTF8: parseInt(process.env.BACKEND_PORT_UTF8 || '2423', 10),

  // Maximum total simultaneous connections across all clients
  maxConnections: parseInt(process.env.MAX_CONNECTIONS || '100', 10),

  // Maximum simultaneous connections from a single client IP address
  // Set to 0 to disable the limit and allow unlimited connections per IP
  maxConnectionsPerIP: parseInt(process.env.MAX_CONNECTIONS_PER_IP || '0', 10),

  // Connection timeout in milliseconds (0 to disable)
  connectionTimeout: parseInt(process.env.CONNECTION_TIMEOUT || '300000', 10),

  // How long to wait for the backend TCP connection to establish before giving
  // up on a session (ms, 0 to disable). Without this, a backend that silently
  // drops SYN leaves the client paused, holding a global + per-IP slot, until
  // the OS TCP timeout (~20-120s).
  backendConnectTimeout: parseInt(process.env.BACKEND_CONNECT_TIMEOUT_MS || '10000', 10),

  // Country blocking — comma-separated ISO 3166-1 alpha-2 codes (e.g. CN,RU,KP)
  blockedCountries: process.env.BLOCKED_COUNTRIES
    ? process.env.BLOCKED_COUNTRIES.split(',').map(c => c.trim().toUpperCase()).filter(c => c)
    : [],

  // Block connections when the client country cannot be determined
  blockUnknownCountries: process.env.BLOCK_UNKNOWN_COUNTRIES === 'true',

  // Path to IP blocklist file (permanent blocks, supports CIDR)
  blocklistPath: process.env.BLOCKLIST_PATH || '',

  // Path to IP whitelist file (these IPs bypass all firewall rules)
  whitelistPath: process.env.WHITELIST_PATH || '',

  // Auto-block triggers — scan the first bytes a telnet/SSH caller sends for
  // known bot / scanner / exploit strings and blacklist the source IP on a hit.
  // Patterns live in TRIGGER_LIST_PATH (plain substring, or /regex/). Off by
  // default: a real caller sending one of these strings early would be blocked
  // too. Whitelisted IPs are exempt.
  triggerBlock: {
    enabled: process.env.TRIGGER_BLOCK_ENABLED === 'true',
    listPath: process.env.TRIGGER_LIST_PATH || './triggers.txt',
    scanBytes: parseInt(process.env.TRIGGER_SCAN_BYTES || '1024', 10),
    // 'blocklist' — append the IP to blocklist.txt (permanent) + block in memory.
    // 'temp'      — in-memory block only, for durationMs.
    mode: (process.env.TRIGGER_BLOCK_MODE || 'blocklist').toLowerCase(),
    durationMs: parseInt(process.env.TRIGGER_BLOCK_DURATION_MS || '86400000', 10),
  },

  // Rate limiting — blocks IPs that connect too frequently within a time window
  rateLimitEnabled: process.env.RATE_LIMIT_ENABLED !== 'false',
  maxConnectionsPerWindow: parseInt(process.env.MAX_CONNECTIONS_PER_WINDOW || '10', 10),
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
  rateLimitBlockDurationMs: parseInt(process.env.RATE_LIMIT_BLOCK_DURATION_MS || '300000', 10),

  // PROXY Protocol v1 — prepends the real client IP to the backend TCP stream.
  // Only enable this if your backend BBS (or a companion module) supports PROXY Protocol.
  // Without a compatible backend, enabling this will break all connections.
  proxyProtocolEnabled: process.env.PROXY_PROTOCOL_ENABLED === 'true',

  // Web redirect server — redirects HTTP traffic on port 80 to a configured URL
  // Useful when clients browse to the firewall IP in a web browser
  webRedirectEnabled: process.env.WEB_REDIRECT_ENABLED === 'true',
  webRedirectUrl: process.env.WEB_REDIRECT_URL || '',

  // HTTPS redirect server — same redirect but on port 443 with TLS
  // Requires a certificate. Run setup-certs.sh to get one from Let's Encrypt.
  httpsRedirectEnabled: process.env.HTTPS_REDIRECT_ENABLED === 'true',
  httpsRedirectPort: parseInt(process.env.HTTPS_REDIRECT_PORT || '443', 10),
  httpsCertPath: process.env.HTTPS_CERT_PATH || './certs/fullchain.pem',
  httpsKeyPath: process.env.HTTPS_KEY_PATH || './certs/privkey.pem',

  // Domain + contact email the config editor's "Issue Let's Encrypt certificate"
  // button uses when it runs setup-certs.sh for the port-443 web redirect.
  httpsCertDomain: process.env.HTTPS_CERT_DOMAIN || '',
  httpsCertEmail: process.env.HTTPS_CERT_EMAIL || '',

  // Directory where certbot writes ACME challenge files during cert issuance/renewal.
  // The HTTP redirect server serves files from this path so certbot can verify
  // your domain without stopping BBSFirewall. setup-certs.sh handles this automatically.
  acmeWebroot: process.env.ACME_WEBROOT || './certs/webroot',

  // Web-based configuration editor — an HTTPS admin UI on its own port with its
  // own TLS certificate for editing this .env and the whitelist/blocklist/
  // trustedhosts files. Gated by BOTH a trusted-host allowlist
  // (TRUSTEDHOSTS.TXT, IPv4/IPv6 CIDR — empty means nobody) and a
  // username/password + optional MFA login (node setup-admin.js, security.js).
  // Run setup-config-cert.sh for the certificate.
  configEditor: {
    enabled: process.env.CONFIG_EDITOR_ENABLED === 'true',
    port: parseInt(process.env.CONFIG_EDITOR_PORT || '8443', 10),
    bindAddress: process.env.CONFIG_EDITOR_BIND || '0.0.0.0',
    certPath: process.env.CONFIG_EDITOR_CERT_PATH || './certs/config-editor/fullchain.pem',
    keyPath: process.env.CONFIG_EDITOR_KEY_PATH || './certs/config-editor/privkey.pem',
    // Admin username/password + MFA live in .admin-security.json (security.js),
    // not .env — see setup-admin.js and the "Config Editor" ENV_SCHEMA help text.
    trustedHostsPath: process.env.CONFIG_EDITOR_TRUSTEDHOSTS_PATH || './trustedhosts.txt',
    sessionTimeoutMs: parseInt(process.env.CONFIG_EDITOR_SESSION_TIMEOUT_MS || '1800000', 10),
    envPath: process.env.CONFIG_EDITOR_ENV_PATH || './.env',
    pm2AppName: process.env.CONFIG_EDITOR_PM2_APP || 'bbsfirewall',
    // Domain + contact email the "Issue Let's Encrypt certificate" button uses
    // when it runs setup-config-cert.sh for this editor's own certificate.
    certDomain: process.env.CONFIG_EDITOR_CERT_DOMAIN || '',
    certEmail: process.env.CONFIG_EDITOR_CERT_EMAIL || '',
    // Answer plain-HTTP requests that land on the editor's HTTPS port with a
    // 301 to the https:// URL, instead of failing the TLS handshake
    // (ERR_EMPTY_RESPONSE). Same port — no extra listener. On by default; set
    // CONFIG_EDITOR_HTTP_REDIRECT_ENABLED=false to just drop such requests.
    httpRedirectEnabled: process.env.CONFIG_EDITOR_HTTP_REDIRECT_ENABLED !== 'false',
    // Full OS-level reboot from the Tools tab (Provider / Master Admin only,
    // see config-editor.js's handleRebootServer). Off by default, same
    // opt-in shape as API_ENABLED/SSH_ENABLED/TRIGGER_BLOCK_ENABLED — a
    // meaningfully higher-blast-radius action than the always-available
    // pm2-level restart, so it has to be turned on deliberately, not just
    // reached by role. Even when this is true, the handler still hard-blocks
    // unless a live pm2-boot-service check passes at request time.
    rebootEnabled: process.env.REBOOT_ENABLED === 'true',
  },

  // Management API — key-authenticated REST access to everything the config
  // editor UI can do, on the editor's own HTTPS listener under /api/*. Off by
  // default. Needs configEditor.enabled (the API has no listener of its own).
  // API_TRUSTEDHOSTS_PATH is an OPTIONAL source-IP allowlist: empty or missing
  // means any IP may call the API (the key still applies), unlike the editor's
  // fail-closed trustedhosts.txt.
  api: {
    enabled: process.env.API_ENABLED === 'true',
    key: process.env.API_KEY || '',
    trustedHostsPath: process.env.API_TRUSTEDHOSTS_PATH || './api-trustedhosts.txt',
  },

  // Unauthenticated GET /status for uptime monitors (e.g. Uptime Kuma), on the
  // editor's own HTTPS listener under /status. No API key, no session — gated
  // ONLY by STATUS_TRUSTEDHOSTS_PATH, which is fail-CLOSED like trustedhosts.txt
  // (empty/missing = nobody), unlike api-trustedhosts.txt's fail-open default —
  // there is no key here to fall back on. Needs configEditor.enabled (no
  // listener of its own).
  status: {
    trustedHostsPath: process.env.STATUS_TRUSTEDHOSTS_PATH || './status-trustedhosts.txt',
  },

  // Console logging level: debug, info, warn, error
  logLevel: process.env.LOG_LEVEL || 'info',

  // Per-proxy file logging — daily-rotated file per proxy service in its own
  // subfolder under LOG_DIR. LOG_FILE_ENABLED is the master switch (on by
  // default — set LOG_FILE_ENABLED=false to turn it off); each proxy inherits
  // LOG_FILE_LEVEL unless it sets its own <PROXY>_LOG_LEVEL, and can be turned
  // off individually with <PROXY>_LOG_ENABLED=false.
  // Levels (each includes those below): off, blocked, connections, info, debug.
  // Retention (LOG_RETENTION_DAYS, 1-3650) is safe to leave on by default
  // because file-logger.js prunes files older than it once a day.
  fileLog: {
    enabled: process.env.LOG_FILE_ENABLED !== 'false',
    dir: process.env.LOG_DIR || './logs',
    defaultLevel: (process.env.LOG_FILE_LEVEL || 'connections').toLowerCase(),
    retentionDays: parseInt(process.env.LOG_RETENTION_DAYS, 10) || 30,
    proxies: {
      telnet:            resolveProxyLog('TELNET'),
      ssh:               resolveProxyLog('SSH'),
      'ssh-passthrough': resolveProxyLog('SSH_PASSTHROUGH'),
      web:               resolveProxyLog('WEB'),
      'config-editor':   resolveProxyLog('CONFIG_EDITOR'),
    },
  },

  // SSH mode selects what sits on the SSH port:
  //   off         — no SSH listener
  //   terminate   — firewall IS the SSH server; accepts any credentials and
  //                 forwards a plaintext session to the telnet backend
  //   passthrough — firewall filters at the IP layer only and forwards the
  //                 encrypted SSH stream to a backend that has its own SSH
  //                 server (preserves pubkey/passwordless login, SFTP, Zmodem)
  // Falls back to the legacy SSH_ENABLED flag (true => terminate) when SSH_MODE
  // is not set, so existing .env files keep working.
  sshMode: (process.env.SSH_MODE
    || (process.env.SSH_ENABLED === 'true' ? 'terminate' : 'off')).toLowerCase(),
  sshListenPort: parseInt(process.env.SSH_LISTEN_PORT || '2222', 10),

  // Passthrough backend — the SSH server on your BBS that the firewall forwards
  // the encrypted stream to. Defaults the host to the telnet BACKEND_HOST.
  sshBackendHost: process.env.SSH_BACKEND_HOST || process.env.BACKEND_HOST || '127.0.0.1',
  sshBackendPort: parseInt(process.env.SSH_BACKEND_PORT || '22', 10),
  // Send a PROXY Protocol v1 header to the SSH backend. Off by default — a plain
  // SSH server treats the header as protocol garbage and drops the handshake.
  // Only enable if the SSH backend understands PROXY Protocol.
  sshProxyProtocol: process.env.SSH_PROXY_PROTOCOL === 'true',

  // SSH host key (terminate mode only)
  sshHostKey: process.env.SSH_HOST_KEY || './ssh_host_key',

  // SSH cipher list — includes modern and legacy ciphers for old BBS terminal clients
  sshCiphers: process.env.SSH_CIPHERS
    ? process.env.SSH_CIPHERS.split(',').map(c => c.trim()).filter(c => c)
    : [
        'aes128-gcm@openssh.com',
        'aes256-gcm@openssh.com',
        'aes128-ctr',
        'aes192-ctr',
        'aes256-ctr',
        'aes128-cbc',
        'aes192-cbc',
        'aes256-cbc',
        '3des-cbc',
      ],
};

function validateConfig() {
  const errors = [];

  if (config.listenPort < 1 || config.listenPort > 65535) {
    errors.push('LISTEN_PORT must be between 1 and 65535');
  }

  if (config.backendPort < 1 || config.backendPort > 65535) {
    errors.push('BACKEND_PORT must be between 1 and 65535');
  }

  if (!config.backendHost) {
    errors.push('BACKEND_HOST is required');
  }

  if (config.maxConnectionsPerWindow < 1) {
    errors.push('MAX_CONNECTIONS_PER_WINDOW must be at least 1');
  }

  if (config.rateLimitWindowMs < 1000) {
    errors.push('RATE_LIMIT_WINDOW_MS must be at least 1000ms');
  }

  if (config.maxConnectionsPerIP < 0) {
    errors.push('MAX_CONNECTIONS_PER_IP must be 0 (unlimited) or a positive integer');
  }

  if (config.triggerBlock.enabled) {
    if (!['blocklist', 'temp'].includes(config.triggerBlock.mode)) {
      errors.push("TRIGGER_BLOCK_MODE must be 'blocklist' or 'temp'");
    }
    if (config.triggerBlock.scanBytes < 16 || config.triggerBlock.scanBytes > 65536) {
      errors.push('TRIGGER_SCAN_BYTES must be between 16 and 65536');
    }
    if (config.triggerBlock.mode === 'temp' && config.triggerBlock.durationMs < 1000) {
      errors.push('TRIGGER_BLOCK_DURATION_MS must be at least 1000');
    }
  }

  if (config.webRedirectEnabled && !config.webRedirectUrl) {
    errors.push('WEB_REDIRECT_URL is required when WEB_REDIRECT_ENABLED is true');
  }

  if (config.httpsRedirectEnabled) {
    if (!config.webRedirectUrl) {
      errors.push('WEB_REDIRECT_URL is required when HTTPS_REDIRECT_ENABLED is true');
    }
    if (config.httpsRedirectPort < 1 || config.httpsRedirectPort > 65535) {
      errors.push('HTTPS_REDIRECT_PORT must be between 1 and 65535');
    }
    if (!config.httpsCertPath) {
      errors.push('HTTPS_CERT_PATH is required when HTTPS_REDIRECT_ENABLED is true');
    }
    if (!config.httpsKeyPath) {
      errors.push('HTTPS_KEY_PATH is required when HTTPS_REDIRECT_ENABLED is true');
    }
  }

  if (config.configEditor.enabled) {
    const ce = config.configEditor;
    if (ce.port < 1 || ce.port > 65535) {
      errors.push('CONFIG_EDITOR_PORT must be between 1 and 65535');
    }
    if (ce.port === config.listenPort) {
      errors.push('CONFIG_EDITOR_PORT must differ from LISTEN_PORT');
    }
    if (config.sshMode !== 'off' && ce.port === config.sshListenPort) {
      errors.push('CONFIG_EDITOR_PORT must differ from SSH_LISTEN_PORT');
    }
    if (!security.secretsExist()) {
      errors.push('No admin account configured for the config editor — run "node setup-admin.js" first');
    }
    if (!ce.certPath) {
      errors.push('CONFIG_EDITOR_CERT_PATH is required when CONFIG_EDITOR_ENABLED is true');
    }
    if (!ce.keyPath) {
      errors.push('CONFIG_EDITOR_KEY_PATH is required when CONFIG_EDITOR_ENABLED is true');
    }
    if (ce.sessionTimeoutMs < 60000) {
      errors.push('CONFIG_EDITOR_SESSION_TIMEOUT_MS must be at least 60000');
    }
  }

  if (!Number.isInteger(config.backendConnectTimeout) || config.backendConnectTimeout < 0) {
    errors.push('BACKEND_CONNECT_TIMEOUT_MS must be 0 (disabled) or a positive integer');
  }

  if (config.api.enabled) {
    if (!config.configEditor.enabled) {
      errors.push('API_ENABLED requires CONFIG_EDITOR_ENABLED=true (the API shares the editor’s HTTPS listener)');
    }
    if (!config.api.key) {
      errors.push('API_KEY is required when API_ENABLED is true');
    } else if (config.api.key.length < 24) {
      errors.push('API_KEY must be at least 24 characters');
    }
  }

  if (!['off', 'terminate', 'passthrough'].includes(config.sshMode)) {
    errors.push("SSH_MODE must be one of: off, terminate, passthrough");
  }

  if (config.sshMode !== 'off') {
    if (config.sshListenPort < 1 || config.sshListenPort > 65535) {
      errors.push('SSH_LISTEN_PORT must be between 1 and 65535');
    }
  }

  if (config.sshMode === 'terminate' && !config.sshHostKey) {
    errors.push('SSH_HOST_KEY is required when SSH_MODE is terminate');
  }

  if (config.sshMode === 'passthrough') {
    if (!config.sshBackendHost) {
      errors.push('SSH_BACKEND_HOST is required when SSH_MODE is passthrough');
    }
    if (config.sshBackendPort < 1 || config.sshBackendPort > 65535) {
      errors.push('SSH_BACKEND_PORT must be between 1 and 65535');
    }
  }

  // Validate file-logging verbosity levels
  if (config.fileLog.enabled) {
    if (!FILE_LOG_LEVELS.includes(config.fileLog.defaultLevel)) {
      errors.push(`LOG_FILE_LEVEL must be one of: ${FILE_LOG_LEVELS.join(', ')}`);
    }
    for (const [name, p] of Object.entries(config.fileLog.proxies)) {
      if (p.level !== undefined && !FILE_LOG_LEVELS.includes(p.level)) {
        errors.push(`${name} log level must be one of: ${FILE_LOG_LEVELS.join(', ')}`);
      }
    }
  }
  if (config.fileLog.retentionDays < 1 || config.fileLog.retentionDays > 3650) {
    errors.push('LOG_RETENTION_DAYS must be between 1 and 3650');
  }

  if (errors.length > 0) {
    throw new Error('Configuration validation failed:\n' + errors.join('\n'));
  }

  return true;
}

module.exports = { config, validateConfig };
