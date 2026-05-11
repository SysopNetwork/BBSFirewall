/**
 * BBS Firewall - IP filtering, rate limiting, and connection tracking
 * https://github.com/SysopNetwork/BBSFirewall
 */

const fs = require('fs');
const path = require('path');
const logger = require('./logger');

function ipToInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  return parts.reduce((acc, part) => (acc << 8) + parseInt(part, 10), 0) >>> 0;
}

function ipMatchesCIDR(ip, cidr) {
  const [range, bits] = cidr.split('/');

  if (!bits) {
    return ip === cidr;
  }

  const ipInt = ipToInt(ip);
  const rangeInt = ipToInt(range);

  if (ipInt === null || rangeInt === null) {
    return ip === cidr;
  }

  const mask = (~0 << (32 - parseInt(bits, 10))) >>> 0;
  return (ipInt & mask) === (rangeInt & mask);
}

class IPFilter {
  constructor(config) {
    this.config = config;
    this.blocklist = new Set();
    this.whitelist = new Set();
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

    this.cleanupInterval = setInterval(() => {
      this.cleanupOldAttempts();
    }, 60000);

    logger.info('IP filter initialized', {
      whitelistSize: this.whitelist.size,
      blocklistSize: this.blocklist.size,
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
        this.whitelist.add(trimmed);
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
        this.blocklist.add(trimmed);
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
    this.loadWhitelist(this.config.whitelistPath);
  }

  reloadBlocklist() {
    if (!this.config.blocklistPath) return;
    this.blocklist.clear();
    this.loadBlocklist(this.config.blocklistPath);
  }

  isIPWhitelisted(ipAddress) {
    if (!ipAddress || typeof ipAddress !== 'string') return false;

    const cleanIp = ipAddress.replace(/^::ffff:/i, '');

    if (this.whitelist.has(cleanIp) || this.whitelist.has(ipAddress)) return true;

    for (const entry of this.whitelist) {
      if (ipMatchesCIDR(cleanIp, entry)) return true;
    }

    return false;
  }

  isIPInBlocklist(ipAddress) {
    if (!ipAddress || typeof ipAddress !== 'string') return false;

    const cleanIp = ipAddress.replace(/^::ffff:/i, '');

    if (this.blocklist.has(cleanIp) || this.blocklist.has(ipAddress)) return true;

    for (const entry of this.blocklist) {
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
      whitelistSize: this.whitelist.size,
      blocklistSize: this.blocklist.size,
      temporarilyBlockedIPs: this.blockedIPs.size,
      trackedIPs: this.connectionAttempts.size,
      activeIPConnections: this.activeConnectionsByIP.size,
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

module.exports = { initializeIPFilter, getIPFilter };
