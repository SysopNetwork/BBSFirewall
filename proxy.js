/**
 * BBS Firewall - TCP proxy connection handler
 * https://github.com/SysopNetwork/BBSFirewall
 */

const net = require('net');
const logger = require('./logger');
const { config } = require('./config');
const { getGeoIP } = require('./geoip');
const { getIPFilter } = require('./ipfilter');
const { detectFromTelnetNegotiation, getBackendPortForEncoding } = require('./encoding-detector');

class ProxyConnection {
  constructor(clientSocket, backendHost, backendPort) {
    this.clientSocket = clientSocket;
    this.backendHost = backendHost;
    this.backendPort = backendPort;
    this.backendSocket = null;
    this.clientAddress = `${clientSocket.remoteAddress || 'unknown'}:${clientSocket.remotePort || 'unknown'}`;
    this.connectionId = this.generateConnectionId();
    this.bytesFromClient = 0;
    this.bytesFromBackend = 0;
    this.isCleanedUp = false;
    this.detectedEncoding = 'cp437';
    this.terminalType = null;
    this.clientIp = null;           // set in connect() once validated
    this.connectionTracked = false; // true when trackConnectionOpen has been called
  }

  generateConnectionId() {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  }

  connect() {
    const clientIp = this.clientSocket.remoteAddress;

    if (!clientIp) {
      logger.warn(`[${this.connectionId}] Connection rejected: unable to determine client IP`);
      this.clientSocket.on('error', (err) => {
        logger.debug(`[${this.connectionId}] Client socket error during rejection: ${err.message}`);
      });
      this.clientSocket.end();
      return;
    }

    this.clientIp = clientIp;

    logger.info(`[${this.connectionId}] New connection from ${this.clientAddress}`);

    const ipFilter = getIPFilter();
    let isWhitelisted = false;

    if (ipFilter) {
      const filterResult = ipFilter.shouldAllowConnection(clientIp);
      if (!filterResult.allowed) {
        logger.warn(`[${this.connectionId}] Connection blocked by IP filter: ${filterResult.reason}`);
        this.clientSocket.on('error', (err) => {
          logger.debug(`[${this.connectionId}] Client socket error during rejection: ${err.message}`);
        });
        this.clientSocket.end();
        return;
      }
      isWhitelisted = filterResult.whitelisted || false;
    }

    // Check per-IP concurrent connection limit (whitelisted IPs are exempt)
    if (!isWhitelisted && ipFilter && ipFilter.isConnectionLimitExceeded(clientIp)) {
      logger.warn(`[${this.connectionId}] Connection rejected: per-IP limit reached for ${clientIp}`);
      this.clientSocket.on('error', (err) => {
        logger.debug(`[${this.connectionId}] Client socket error during rejection: ${err.message}`);
      });
      this.clientSocket.end();
      return;
    }

    // Check country blocking (whitelisted IPs are exempt)
    if (!isWhitelisted && this.shouldBlockConnection(clientIp)) {
      logger.warn(`[${this.connectionId}] Connection blocked by country filter`);
      this.clientSocket.on('error', (err) => {
        logger.debug(`[${this.connectionId}] Client socket error during rejection: ${err.message}`);
      });
      this.clientSocket.end();
      return;
    }

    // All checks passed — register this connection in the per-IP tracker
    if (ipFilter) {
      ipFilter.trackConnectionOpen(clientIp);
      this.connectionTracked = true;
    }

    this.clientSocket.setNoDelay(true);
    this.clientSocket.setKeepAlive(true);

    const actualBackendPort = config.encodingDetection
      ? getBackendPortForEncoding(this.detectedEncoding, config)
      : this.backendPort;

    if (config.encodingDetection) {
      logger.info(`[${this.connectionId}] Using backend port ${actualBackendPort} for encoding: ${this.detectedEncoding}`);
    }

    this.backendSocket = net.createConnection({
      host: this.backendHost,
      port: actualBackendPort,
    }, () => {
      const backendAddr = `${this.backendSocket.remoteAddress}:${this.backendSocket.remotePort}`;
      const localAddr = `${this.backendSocket.localAddress}:${this.backendSocket.localPort}`;
      logger.info(`[${this.connectionId}] Connected to backend ${backendAddr} (from ${localAddr})`);
      this.backendSocket.setNoDelay(true);
      this.backendSocket.setKeepAlive(true);
    });

    // Error handlers must be set before data pipes to catch early failures
    this.setupErrorHandlers();
    this.setupPipes();
    this.setupCloseHandlers();
  }

  shouldBlockConnection(ipAddress) {
    const geoip = getGeoIP();

    if (!geoip || !geoip.isEnabled) {
      return false;
    }

    const geoInfo = geoip.getCountryInfo(ipAddress);

    if (!geoInfo || !geoInfo.countryCode) {
      if (config.blockUnknownCountries) {
        logger.info(`[${this.connectionId}] Blocked unknown country for IP: ${ipAddress}`);
        return true;
      }
      return false;
    }

    logger.debug(`[${this.connectionId}] Connection from ${geoInfo.countryName} (${geoInfo.countryCode})`);

    if (config.blockedCountries.length > 0) {
      const isBlocked = config.blockedCountries.includes(geoInfo.countryCode.toUpperCase());
      if (isBlocked) {
        logger.info(`[${this.connectionId}] Blocked ${geoInfo.countryName} (${geoInfo.countryCode})`);
      }
      return isBlocked;
    }

    return false;
  }

  setupPipes() {
    this.clientSocket.on('data', (data) => {
      this.bytesFromClient += data.length;
      const preview = data.toString('hex').substring(0, 60);
      logger.debug(`[${this.connectionId}] Client → Backend: ${data.length} bytes [${preview}${data.length > 30 ? '...' : ''}]`);
      if (this.backendSocket && !this.backendSocket.destroyed) {
        if (!this.backendSocket.write(data)) {
          logger.debug(`[${this.connectionId}] Backend buffer full, pausing client`);
          this.clientSocket.pause();
          this.backendSocket.once('drain', () => {
            logger.debug(`[${this.connectionId}] Backend drained, resuming client`);
            this.clientSocket.resume();
          });
        }
      }
    });

    this.backendSocket.on('data', (data) => {
      this.bytesFromBackend += data.length;
      const preview = data.toString('hex').substring(0, 60);
      logger.debug(`[${this.connectionId}] Backend → Client: ${data.length} bytes [${preview}${data.length > 30 ? '...' : ''}]`);
      if (this.clientSocket && !this.clientSocket.destroyed) {
        if (!this.clientSocket.write(data)) {
          logger.debug(`[${this.connectionId}] Client buffer full, pausing backend`);
          this.backendSocket.pause();
          this.clientSocket.once('drain', () => {
            logger.debug(`[${this.connectionId}] Client drained, resuming backend`);
            this.backendSocket.resume();
          });
        }
      }
    });
  }

  setupErrorHandlers() {
    this.clientSocket.on('error', (err) => {
      logger.error(`[${this.connectionId}] Client socket error: ${err.message}`);
      this.cleanup('client-error');
    });

    this.backendSocket.on('error', (err) => {
      logger.error(`[${this.connectionId}] Backend socket error: ${err.message}`);
      this.cleanup('backend-error');
    });
  }

  setupCloseHandlers() {
    this.clientSocket.on('close', (hadError) => {
      logger.debug(`[${this.connectionId}] Client socket closed (hadError: ${hadError})`);
      this.cleanup('client-close');
    });

    this.backendSocket.on('close', (hadError) => {
      logger.debug(`[${this.connectionId}] Backend socket closed (hadError: ${hadError})`);
      this.cleanup('backend-close');
    });
  }

  cleanup(reason) {
    if (this.isCleanedUp) return;
    this.isCleanedUp = true;

    // Release the per-IP connection slot regardless of how the connection ended
    if (this.connectionTracked && this.clientIp) {
      const ipFilter = getIPFilter();
      if (ipFilter) {
        ipFilter.trackConnectionClose(this.clientIp);
      }
    }

    logger.info(`[${this.connectionId}] Connection closed (reason: ${reason}). Bytes: client→backend=${this.bytesFromClient}, backend→client=${this.bytesFromBackend}`);

    if (this.clientSocket && !this.clientSocket.destroyed) {
      this.clientSocket.destroy();
    }

    if (this.backendSocket && !this.backendSocket.destroyed) {
      this.backendSocket.destroy();
    }
  }
}

function handleConnection(clientSocket, backendHost, backendPort) {
  const proxy = new ProxyConnection(clientSocket, backendHost, backendPort);
  proxy.connect();
}

module.exports = { handleConnection };
