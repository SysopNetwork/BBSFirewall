#!/usr/bin/env node

/**
 * BBS Firewall
 * TCP proxy firewall for BBS telnet connections
 * https://github.com/SysopNetwork/BBSFirewall
 */

const net = require('net');
const { config, validateConfig } = require('./config');
const logger = require('./logger');
const { handleConnection } = require('./proxy');
const { initializeGeoIP } = require('./geoip');
const { initializeIPFilter } = require('./ipfilter');
const { startSSHServer } = require('./ssh');
const { startWebRedirectServer, stopWebRedirectServer } = require('./web-redirect');

class BBSFirewall {
  constructor() {
    this.server = null;
    this.sshServer = null;
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
    logger.info('  BBS Firewall - by Sysop Network');
    logger.info('  https://github.com/SysopNetwork/BBSFirewall');
    logger.info('================================================');
    logger.info('Starting...');

    await initializeGeoIP();
    initializeIPFilter(config);

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
      webRedirectEnabled: config.webRedirectEnabled,
      sshEnabled: config.sshEnabled,
    };

    if (config.webRedirectEnabled) {
      configLog.webRedirectUrl = config.webRedirectUrl;
    }

    if (config.sshEnabled) {
      configLog.sshListenPort = config.sshListenPort;
      configLog.sshCiphers = config.sshCiphers.join(', ');
    }

    logger.info('Configuration:', configLog);

    this.server = net.createServer((clientSocket) => {
      this.handleNewConnection(clientSocket);
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

    this.sshServer = startSSHServer(config, this);

    // Start web redirect server if enabled
    startWebRedirectServer();

    this.setupGracefulShutdown();
  }

  handleNewConnection(clientSocket) {
    if (this.activeConnections >= config.maxConnections) {
      logger.warn(`Connection rejected: max connections (${config.maxConnections}) reached`);
      clientSocket.end();
      return;
    }

    this.activeConnections++;
    logger.debug(`Active connections: ${this.activeConnections}`);

    if (config.connectionTimeout > 0) {
      clientSocket.setTimeout(config.connectionTimeout);
      clientSocket.on('timeout', () => {
        logger.info(`Connection timeout for ${clientSocket.remoteAddress}`);
        clientSocket.destroy();
      });
    }

    handleConnection(clientSocket, config.backendHost, config.backendPort);

    clientSocket.on('close', () => {
      this.activeConnections--;
      logger.debug(`Active connections: ${this.activeConnections}`);
    });
  }

  setupGracefulShutdown() {
    const shutdown = async () => {
      logger.info('Shutting down gracefully...');

      await stopWebRedirectServer();

      let serversToClose = 0;
      let serversClosed = 0;

      const onClose = () => {
        serversClosed++;
        if (serversClosed === serversToClose) {
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

      if (serversToClose === 0) {
        process.exit(0);
      }

      // Force shutdown after 10 seconds if servers don't close cleanly
      setTimeout(() => {
        logger.warn('Forcing shutdown after timeout');
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
