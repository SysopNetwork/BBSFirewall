/**
 * BBSFirewall - TCP proxy connection handler
 *
 * Shared by the telnet proxy and the SSH passthrough proxy. The passthrough
 * path forwards an already-encrypted SSH stream, so it opts out of encoding
 * detection and (by default) PROXY Protocol via the options argument.
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const net = require('net');
const logger = require('./logger');
const { config } = require('./config');
const { getGeoIP } = require('./geoip');
const { getIPFilter } = require('./ipfilter');
const metrics = require('./metrics');
const { detectFromTelnetNegotiation, getBackendPortForEncoding } = require('./encoding-detector');
const { buildHeader: buildProxyHeader } = require('./proxy-protocol');

class ProxyConnection {
  constructor(clientSocket, backendHost, backendPort, options = {}) {
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

    // Auto-block trigger scanning — telnet only (an encrypted SSH passthrough
    // stream has nothing plaintext to match). Disabled for whitelisted IPs in
    // connect(). this.triggerBuf holds the first TRIGGER_SCAN_BYTES the client
    // sends; once it fills, scanning stops for the rest of the session.
    this.triggerScan = config.triggerBlock.enabled && (options.proxyName || 'telnet') === 'telnet';
    this.triggerBuf = null;

    // Per-proxy behavior. The SSH passthrough forwards encrypted bytes, so it
    // disables encoding detection and defaults PROXY Protocol off.
    this.proxyName = options.proxyName || 'telnet';
    this.encodingDetection = options.encodingDetection !== undefined
      ? options.encodingDetection
      : config.encodingDetection;
    this.proxyProtocol = options.proxyProtocol !== undefined
      ? options.proxyProtocol
      : config.proxyProtocolEnabled;
    this.log = logger.getLogger(this.proxyName);
  }

  generateConnectionId() {
    return `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  }

  connect() {
    const clientIp = this.clientSocket.remoteAddress;

    if (!clientIp) {
      this.log.blocked(`[${this.connectionId}] Connection rejected: unable to determine client IP`);
      this.clientSocket.on('error', (err) => {
        this.log.debug(`[${this.connectionId}] Client socket error during rejection: ${err.message}`);
      });
      this.clientSocket.end();
      return;
    }

    this.clientIp = clientIp;

    this.log.connection(`[${this.connectionId}] New connection from ${this.clientAddress}`);

    const ipFilter = getIPFilter();
    let isWhitelisted = false;

    if (ipFilter) {
      const filterResult = ipFilter.shouldAllowConnection(clientIp);
      if (!filterResult.allowed) {
        this.log.blocked(`[${this.connectionId}] Connection blocked by IP filter: ${filterResult.reason}`);
        this.clientSocket.on('error', (err) => {
          this.log.debug(`[${this.connectionId}] Client socket error during rejection: ${err.message}`);
        });
        this.clientSocket.end();
        return;
      }
      isWhitelisted = filterResult.whitelisted || false;
    }

    if (isWhitelisted) this.triggerScan = false;

    // Check per-IP concurrent connection limit (whitelisted IPs are exempt)
    if (!isWhitelisted && ipFilter && ipFilter.isConnectionLimitExceeded(clientIp)) {
      this.log.blocked(`[${this.connectionId}] Connection rejected: per-IP limit reached for ${clientIp}`);
      this.clientSocket.on('error', (err) => {
        this.log.debug(`[${this.connectionId}] Client socket error during rejection: ${err.message}`);
      });
      this.clientSocket.end();
      return;
    }

    // Check country blocking (whitelisted IPs are exempt)
    if (!isWhitelisted && this.shouldBlockConnection(clientIp)) {
      this.log.blocked(`[${this.connectionId}] Connection blocked by country filter`);
      this.clientSocket.on('error', (err) => {
        this.log.debug(`[${this.connectionId}] Client socket error during rejection: ${err.message}`);
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

    // Pause client data until the backend is connected and the PROXY header
    // (if enabled) has been written.  Fast-connecting clients (fTelnet,
    // MuffTerm, MegaMUD) send telnet negotiation bytes immediately on TCP
    // connect.  Without this pause those bytes can reach the BBS before the
    // PROXY header, causing PROXCLIP to miss the header and GALTNTD to echo
    // it as raw text.
    this.clientSocket.pause();

    const actualBackendPort = this.encodingDetection
      ? getBackendPortForEncoding(this.detectedEncoding, config)
      : this.backendPort;

    if (this.encodingDetection) {
      this.log.info(`[${this.connectionId}] Using backend port ${actualBackendPort} for encoding: ${this.detectedEncoding}`);
    }

    this.backendSocket = net.createConnection({
      host: this.backendHost,
      port: actualBackendPort,
    }, () => {
      const backendAddr = `${this.backendSocket.remoteAddress}:${this.backendSocket.remotePort}`;
      const localAddr = `${this.backendSocket.localAddress}:${this.backendSocket.localPort}`;
      this.log.connection(`[${this.connectionId}] Connected to backend ${backendAddr} (from ${localAddr})`);
      this.backendSocket.setNoDelay(true);
      this.backendSocket.setKeepAlive(true);

      // Send PROXY Protocol v1 header before any BBS data flows.
      // The backend must support it — see PROXY_PROTOCOL_ENABLED in .env.
      if (this.proxyProtocol) {
        // The PROXY header describes the ORIGINAL connection from the client's
        // perspective: src = client, dst = the address on this proxy the client
        // connected to. Use the client-facing socket's local address (not the
        // backend-side one) so the two addresses share a family — an IPv6 client
        // yields a valid TCP6 line instead of a mixed-family one PROXCLIP drops.
        const header = buildProxyHeader(
          this.clientSocket.remoteAddress,
          this.clientSocket.localAddress,
          this.clientSocket.remotePort,
          this.clientSocket.localPort
        );
        this.backendSocket.write(header);
        this.log.info(`[${this.connectionId}] PROXY Protocol header sent: ${header.trim()}`);
      }

      // PROXY header is now in the send buffer (or skipped); safe to let
      // client data flow.
      this.clientSocket.resume();
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
        this.log.info(`[${this.connectionId}] Blocked unknown country for IP: ${ipAddress}`);
        return true;
      }
      return false;
    }

    this.log.debug(`[${this.connectionId}] Connection from ${geoInfo.countryName} (${geoInfo.countryCode})`);

    if (config.blockedCountries.length > 0) {
      const isBlocked = config.blockedCountries.includes(geoInfo.countryCode.toUpperCase());
      if (isBlocked) {
        this.log.info(`[${this.connectionId}] Blocked ${geoInfo.countryName} (${geoInfo.countryCode})`);
      }
      return isBlocked;
    }

    return false;
  }

  setupPipes() {
    this.clientSocket.on('data', (data) => {
      if (this.triggerScan) {
        const cap = config.triggerBlock.scanBytes;
        this.triggerBuf = this.triggerBuf ? Buffer.concat([this.triggerBuf, data]) : Buffer.from(data);
        if (this.triggerBuf.length > cap) this.triggerBuf = this.triggerBuf.subarray(0, cap);

        const ipFilter = getIPFilter();
        const hit = ipFilter && ipFilter.matchTrigger(this.triggerBuf.toString('latin1'));
        if (hit) {
          this.log.blocked(`[${this.connectionId}] Auto-block ${this.clientIp}: matched trigger ${JSON.stringify(hit)}`);
          if (ipFilter) ipFilter.autoBlockIP(this.clientIp, hit);
          metrics.incTriggerBlock();
          this.cleanup('trigger-block');
          return; // do not forward the offending bytes
        }
        if (this.triggerBuf.length >= cap) {
          this.triggerScan = false;
          this.triggerBuf = null;
        }
      }

      this.bytesFromClient += data.length;
      const preview = data.toString('hex').substring(0, 60);
      this.log.debug(`[${this.connectionId}] Client → Backend: ${data.length} bytes [${preview}${data.length > 30 ? '...' : ''}]`);
      if (this.backendSocket && !this.backendSocket.destroyed) {
        if (!this.backendSocket.write(data)) {
          this.log.debug(`[${this.connectionId}] Backend buffer full, pausing client`);
          this.clientSocket.pause();
          this.backendSocket.once('drain', () => {
            this.log.debug(`[${this.connectionId}] Backend drained, resuming client`);
            this.clientSocket.resume();
          });
        }
      }
    });

    this.backendSocket.on('data', (data) => {
      this.bytesFromBackend += data.length;
      const preview = data.toString('hex').substring(0, 60);
      this.log.debug(`[${this.connectionId}] Backend → Client: ${data.length} bytes [${preview}${data.length > 30 ? '...' : ''}]`);
      if (this.clientSocket && !this.clientSocket.destroyed) {
        if (!this.clientSocket.write(data)) {
          this.log.debug(`[${this.connectionId}] Client buffer full, pausing backend`);
          this.backendSocket.pause();
          this.clientSocket.once('drain', () => {
            this.log.debug(`[${this.connectionId}] Client drained, resuming backend`);
            this.backendSocket.resume();
          });
        }
      }
    });
  }

  setupErrorHandlers() {
    this.clientSocket.on('error', (err) => {
      this.log.error(`[${this.connectionId}] Client socket error: ${err.message}`);
      this.cleanup('client-error');
    });

    this.backendSocket.on('error', (err) => {
      this.log.error(`[${this.connectionId}] Backend socket error: ${err.message}`);
      this.cleanup('backend-error');
    });
  }

  setupCloseHandlers() {
    this.clientSocket.on('close', (hadError) => {
      this.log.debug(`[${this.connectionId}] Client socket closed (hadError: ${hadError})`);
      this.cleanup('client-close');
    });

    this.backendSocket.on('close', (hadError) => {
      this.log.debug(`[${this.connectionId}] Backend socket closed (hadError: ${hadError})`);
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

    this.log.connection(`[${this.connectionId}] Connection closed (reason: ${reason}). Bytes: client→backend=${this.bytesFromClient}, backend→client=${this.bytesFromBackend}`);

    if (this.clientSocket && !this.clientSocket.destroyed) {
      this.clientSocket.destroy();
    }

    if (this.backendSocket && !this.backendSocket.destroyed) {
      this.backendSocket.destroy();
    }
  }
}

/**
 * @param {net.Socket} clientSocket
 * @param {string} backendHost
 * @param {number} backendPort
 * @param {{proxyName?: string, encodingDetection?: boolean, proxyProtocol?: boolean}} [options]
 */
function handleConnection(clientSocket, backendHost, backendPort, options = {}) {
  const proxy = new ProxyConnection(clientSocket, backendHost, backendPort, options);
  proxy.connect();
}

module.exports = { handleConnection };
