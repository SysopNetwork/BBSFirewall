/**
 * BBSFirewall - Configuration
 * https://github.com/SysopNetwork/BBSFirewall
 */

require('dotenv').config({ quiet: true });

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

  // Directory where certbot writes ACME challenge files during cert issuance/renewal.
  // The HTTP redirect server serves files from this path so certbot can verify
  // your domain without stopping BBSFirewall. setup-certs.sh handles this automatically.
  acmeWebroot: process.env.ACME_WEBROOT || './certs/webroot',

  // Logging level: debug, info, warn, error
  logLevel: process.env.LOG_LEVEL || 'info',

  // SSH server — accepts any credentials and proxies to the telnet backend
  sshEnabled: process.env.SSH_ENABLED === 'true',
  sshListenPort: parseInt(process.env.SSH_LISTEN_PORT || '2222', 10),
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

  if (config.sshEnabled) {
    if (config.sshListenPort < 1 || config.sshListenPort > 65535) {
      errors.push('SSH_LISTEN_PORT must be between 1 and 65535');
    }

    if (!config.sshHostKey) {
      errors.push('SSH_HOST_KEY is required when SSH is enabled');
    }
  }

  if (errors.length > 0) {
    throw new Error('Configuration validation failed:\n' + errors.join('\n'));
  }

  return true;
}

module.exports = { config, validateConfig };
