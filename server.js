#!/usr/bin/env node

/**
 * BBSFirewall by Sysop Network
 * https://github.com/SysopNetwork/BBSFirewall
 *
 * Copyright (c) 2026 Sysop Network
 * Based on bbsfw by Ryan Fantus — https://github.com/ryanfantus/bbsfw
 * Licensed under MIT
 */

const net = require('net');
const { config, validateConfig } = require('./config');
const logger = require('./logger');
const fileLogger = require('./file-logger');
const metrics = require('./metrics');
const { handleConnection } = require('./proxy');
const { initializeGeoIP } = require('./geoip');
const { initializeIPFilter } = require('./ipfilter');
const { startSSHServer } = require('./ssh');
const { startWebRedirectServer, stopWebRedirectServer } = require('./web-redirect');
const { startConfigEditorServer, stopConfigEditorServer } = require('./config-editor');

class BBSFirewall {
  constructor() {
    this.server = null;
    this.sshServer = null;
    this.sshPassthroughServer = null;
    this.activeConnections = 0;
  }

  async start() {
    try {
      validateConfig();
    } catch (err) {
      logger.error(`Configuration error: ${err.message}`);
      process.exit(1);
    }

    logger.info('================================================');
    logger.info('  BBSFirewall by Sysop Network');
    logger.info('  https://github.com/SysopNetwork/BBSFirewall');
    logger.info('  Based on bbsfw by Ryan Fantus');
    logger.info('================================================');
    logger.info('Starting...');

    await initializeGeoIP();
    initializeIPFilter(config);
    // Daily is plenty (retention granularity is whole days anyway) and this
    // runs independently of the config editor, so pruning still happens even
    // with CONFIG_EDITOR_ENABLED=false.
    fileLogger.startPruning(24 * 60 * 60 * 1000);
    // Server-side sampler so bandwidth avg/max stay meaningful even when no
    // admin has the System Stats tab open (independent of its own 4s poll).
    metrics.startBandwidthSampler(4000);

    const configLog = {
      listenPort: config.listenPort,
      backendHost: config.backendHost,
      backendPort: config.backendPort,
      maxConnections: config.maxConnections,
      maxConnectionsPerIP: config.maxConnectionsPerIP === 0 ? 'unlimited' : config.maxConnectionsPerIP,
      blockedCountries: config.blockedCountries.length > 0
        ? config.blockedCountries.join(', ')
        : 'none',
      rateLimitEnabled: config.rateLimitEnabled,
      maxConnectionsPerWindow: config.maxConnectionsPerWindow,
      rateLimitWindowMs: `${config.rateLimitWindowMs}ms`,
      blocklistPath: config.blocklistPath || 'none',
      proxyProtocolEnabled: config.proxyProtocolEnabled,
      webRedirectEnabled: config.webRedirectEnabled,
      sshMode: config.sshMode,
      fileLog: config.fileLog.enabled ? `on (default: ${config.fileLog.defaultLevel})` : 'off',
    };

    if (config.webRedirectEnabled) {
      configLog.webRedirectUrl = config.webRedirectUrl;
    }

    if (config.httpsRedirectEnabled) {
      configLog.httpsRedirectPort = config.httpsRedirectPort;
      configLog.httpsCertPath = config.httpsCertPath;
    }

    configLog.configEditorEnabled = config.configEditor.enabled;
    if (config.configEditor.enabled) {
      configLog.configEditorPort = config.configEditor.port;
    }

    if (config.sshMode === 'terminate') {
      configLog.sshListenPort = config.sshListenPort;
      configLog.sshCiphers = config.sshCiphers.join(', ');
    } else if (config.sshMode === 'passthrough') {
      configLog.sshListenPort = config.sshListenPort;
      configLog.sshBackend = `${config.sshBackendHost}:${config.sshBackendPort}`;
    }

    logger.info('Configuration:', configLog);

    this.server = net.createServer((clientSocket) => {
      this.handleNewConnection(clientSocket, config.backendHost, config.backendPort, {
        proxyName: 'telnet',
      });
    });

    this.server.on('error', (err) => {
      logger.error(`Server error: ${err.message}`);
      if (err.code === 'EADDRINUSE') {
        logger.error(`Port ${config.listenPort} is already in use`);
        process.exit(1);
      }
    });

    this.server.listen(config.listenPort, () => {
      logger.info(`Telnet proxy listening on port ${config.listenPort}`);
      logger.info(`Forwarding connections to ${config.backendHost}:${config.backendPort}`);
    });

    this.startSSH();

    // Start web redirect server if enabled
    startWebRedirectServer();

    // Start the web config editor if enabled. Passes `this` so the /status
    // endpoint can report real telnet/SSH listener state, not just config flags.
    startConfigEditorServer(this);

    this.setupGracefulShutdown();
  }

  // Bring up whichever SSH frontend the config selected. Both listen on
  // SSH_LISTEN_PORT, so only one runs at a time.
  startSSH() {
    if (config.sshMode === 'terminate') {
      this.sshServer = startSSHServer(config, this);
      return;
    }

    if (config.sshMode === 'passthrough') {
      const log = logger.getLogger('ssh-passthrough');

      this.sshPassthroughServer = net.createServer((clientSocket) => {
        this.handleNewConnection(clientSocket, config.sshBackendHost, config.sshBackendPort, {
          proxyName: 'ssh-passthrough',
          proxyProtocol: config.sshProxyProtocol,
          encodingDetection: false, // encrypted stream — nothing to sniff
        });
      });

      this.sshPassthroughServer.on('error', (err) => {
        log.error(`SSH passthrough server error: ${err.message}`);
        if (err.code === 'EADDRINUSE') {
          log.error(`SSH port ${config.sshListenPort} is already in use`);
          process.exit(1);
        }
      });

      this.sshPassthroughServer.listen(config.sshListenPort, () => {
        log.info(`SSH passthrough listening on port ${config.sshListenPort}`);
        log.info(`Forwarding encrypted SSH to ${config.sshBackendHost}:${config.sshBackendPort}`);
      });
      return;
    }

    logger.info('SSH is disabled (SSH_MODE=off)');
  }

  handleNewConnection(clientSocket, backendHost, backendPort, options = {}) {
    const proxyName = options.proxyName || 'telnet';

    if (this.activeConnections >= config.maxConnections) {
      const log = logger.getLogger(proxyName);
      log.blocked(`Connection rejected: max connections (${config.maxConnections}) reached`);
      metrics.incRejected();
      clientSocket.end();
      return;
    }

    this.activeConnections++;
    metrics.incActive(proxyName);
    logger.debug(`Active connections: ${this.activeConnections}`);

    if (config.connectionTimeout > 0) {
      clientSocket.setTimeout(config.connectionTimeout);
      clientSocket.on('timeout', () => {
        logger.info(`Connection timeout for ${clientSocket.remoteAddress}`);
        clientSocket.destroy();
      });
    }

    handleConnection(clientSocket, backendHost, backendPort, options);

    clientSocket.on('close', () => {
      this.activeConnections--;
      metrics.decActive(proxyName);
      logger.debug(`Active connections: ${this.activeConnections}`);
    });
  }

  setupGracefulShutdown() {
    const shutdown = async () => {
      logger.info('Shutting down gracefully...');

      await stopWebRedirectServer();
      await stopConfigEditorServer();

      let serversToClose = 0;
      let serversClosed = 0;

      const onClose = () => {
        serversClosed++;
        if (serversClosed === serversToClose) {
          fileLogger.closeAll();
          process.exit(0);
        }
      };

      if (this.server) {
        serversToClose++;
        this.server.close(() => {
          logger.info('Telnet server closed');
          onClose();
        });
      }

      if (this.sshServer) {
        serversToClose++;
        this.sshServer.close(() => {
          logger.info('SSH server closed');
          onClose();
        });
      }

      if (this.sshPassthroughServer) {
        serversToClose++;
        this.sshPassthroughServer.close(() => {
          logger.info('SSH passthrough server closed');
          onClose();
        });
      }

      if (serversToClose === 0) {
        fileLogger.closeAll();
        process.exit(0);
      }

      // Force shutdown after 10 seconds if servers don't close cleanly
      setTimeout(() => {
        logger.warn('Forcing shutdown after timeout');
        fileLogger.closeAll();
        process.exit(1);
      }, 10000);
    };

    process.on('SIGTERM', shutdown);
    process.on('SIGINT', shutdown);
  }
}

if (require.main === module) {
  const firewall = new BBSFirewall();
  firewall.start();
}

module.exports = BBSFirewall;
