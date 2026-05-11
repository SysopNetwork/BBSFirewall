/**
 * BBS Firewall - SSH server
 * Accepts any credentials and proxies the session to the backend telnet server.
 * Note: Binary file transfers (Zmodem, etc.) are unreliable over SSH due to PTY processing.
 * https://github.com/SysopNetwork/BBSFirewall
 */

const ssh2 = require('ssh2');
const net = require('net');
const fs = require('fs');
const logger = require('./logger');
const { getIPFilter } = require('./ipfilter');
const { detectFromSSHEnvironment, detectFromTerminalType, getBackendPortForEncoding } = require('./encoding-detector');

function createSSHServer(config) {
  if (!config.sshEnabled) {
    return null;
  }

  let hostKey;
  try {
    hostKey = fs.readFileSync(config.sshHostKey, 'utf8');
  } catch (err) {
    logger.error(`Failed to read SSH host key from ${config.sshHostKey}: ${err.message}`);
    logger.error('Generate a host key with: ssh-keygen -t rsa -b 4096 -f ssh_host_key -N "" -m PEM');
    process.exit(1);
  }

  const server = new ssh2.Server(
    {
      hostKeys: [hostKey],
      algorithms: {
        cipher: config.sshCiphers,
      },
    },
    (client) => {
      const clientIP = client._sock?.remoteAddress;

      client.on('error', (err) => {
        logger.debug(`SSH client error: ${err.message}`);
      });

      if (!clientIP) {
        logger.warn('SSH connection rejected: unable to determine client IP');
        client.end();
        return;
      }

      logger.info(`SSH client connected from ${clientIP}`);

      const ipFilter = getIPFilter();
      let sshConnectionTracked = false;

      if (ipFilter) {
        const accessCheck = ipFilter.shouldAllowConnection(clientIP);
        if (!accessCheck.allowed) {
          logger.warn(`SSH connection blocked from ${clientIP}: ${accessCheck.reason}`);
          client.end();
          return;
        }

        // Check per-IP concurrent connection limit (whitelisted IPs are exempt)
        if (!accessCheck.whitelisted && ipFilter.isConnectionLimitExceeded(clientIP)) {
          logger.warn(`SSH connection rejected: per-IP limit reached for ${clientIP}`);
          client.end();
          return;
        }

        // Register this connection in the per-IP tracker
        ipFilter.trackConnectionOpen(clientIP);
        sshConnectionTracked = true;
      }

      client.on('authentication', (ctx) => {
        logger.info(`SSH auth from ${clientIP} (user: ${ctx.username})`);

        if (ctx.method === 'password' || ctx.method === 'none') {
          ctx.accept();
        } else {
          ctx.reject(['password', 'none']);
        }
      });

      client.on('ready', () => {
        logger.info(`SSH client ${clientIP} authenticated`);

        client.on('session', (accept, reject) => {
          logger.debug(`Session requested for ${clientIP}`);

          if (typeof accept !== 'function') {
            logger.error(`Session accept is not a function for ${clientIP}`);
            return;
          }

          const session = accept();

          let detectedEncoding = 'cp437';
          let sshEnv = {};
          let termType = null;

          session.on('env', (accept, reject, info) => {
            logger.debug(`SSH env from ${clientIP}: ${info.key}=${info.value}`);
            sshEnv[info.key] = info.value;

            if (config.encodingDetection) {
              const envDetected = detectFromSSHEnvironment(sshEnv);
              if (envDetected === 'utf8') {
                detectedEncoding = 'utf8';
                logger.info(`Detected UTF-8 encoding from SSH environment for ${clientIP}`);
              }
            }

            accept && accept();
          });

          session.on('pty', (accept, reject, info) => {
            logger.debug(`PTY requested for ${clientIP}, term: ${info.term}`);

            if (info && info.term) {
              termType = info.term;

              if (config.encodingDetection && detectedEncoding === 'cp437') {
                const termDetected = detectFromTerminalType(termType);
                if (termDetected === 'utf8') {
                  detectedEncoding = 'utf8';
                  logger.info(`Detected UTF-8 from terminal type '${termType}' for ${clientIP}`);
                }
              }
            }

            if (typeof accept === 'function') {
              accept();
            } else {
              logger.warn(`PTY accept is not a function for ${clientIP}`);
            }
          });

          session.on('window-change', (info) => {
            logger.debug(`Window change for ${clientIP}: ${info.cols}x${info.rows}`);
          });

          session.on('shell', (accept, reject) => {
            logger.debug(`Shell requested for ${clientIP}`);

            if (typeof accept !== 'function') {
              logger.error(`Shell accept is not a function for ${clientIP}`);
              return;
            }

            const stream = accept();
            logger.info(`SSH shell session started for ${clientIP}`);

            stream.allowHalfOpen = true;

            const actualBackendPort = config.encodingDetection
              ? getBackendPortForEncoding(detectedEncoding, config)
              : config.backendPort;

            if (config.encodingDetection) {
              logger.info(`SSH client ${clientIP} using backend port ${actualBackendPort} for encoding: ${detectedEncoding}`);
            }

            const backendSocket = new net.Socket();
            backendSocket.setNoDelay(true);
            backendSocket.setKeepAlive(true, 30000);

            backendSocket.connect(actualBackendPort, config.backendHost, () => {
              logger.info(`SSH client ${clientIP} connected to backend ${config.backendHost}:${actualBackendPort}`);
              backendSocket.setNoDelay(true);
            });

            let bytesFromClient = 0;
            let bytesFromBackend = 0;

            stream.on('data', (data) => {
              bytesFromClient += data.length;

              if (!backendSocket.writable || backendSocket.destroyed) {
                logger.debug(`Backend not writable, dropping ${data.length} bytes`);
                return;
              }

              if (!backendSocket.write(data)) {
                logger.debug('Backend buffer full, pausing SSH stream');
                stream.pause();
                backendSocket.once('drain', () => {
                  logger.debug('Backend drained, resuming SSH stream');
                  if (!stream.destroyed) stream.resume();
                });
              }
            });

            backendSocket.on('data', (data) => {
              bytesFromBackend += data.length;

              if (!stream.writable || stream.destroyed) {
                logger.debug(`SSH stream not writable, dropping ${data.length} bytes`);
                return;
              }

              if (!stream.write(data)) {
                logger.debug('SSH stream buffer full, pausing backend');
                backendSocket.pause();
                stream.once('drain', () => {
                  logger.debug('SSH stream drained, resuming backend');
                  if (!backendSocket.destroyed) backendSocket.resume();
                });
              }
            });

            backendSocket.on('error', (err) => {
              logger.error(`Backend error for SSH client ${clientIP}: ${err.message}`);
              stream.end();
            });

            backendSocket.on('close', () => {
              logger.info(`Backend connection closed for SSH client ${clientIP}`);
              stream.end();
            });

            stream.on('close', () => {
              logger.info(`SSH stream closed for ${clientIP}. Bytes: client→backend=${bytesFromClient}, backend→client=${bytesFromBackend}`);
              if (!backendSocket.destroyed) backendSocket.destroy();
            });

            stream.on('error', (err) => {
              logger.error(`SSH stream error for ${clientIP}: ${err.message}`);
              if (!backendSocket.destroyed) backendSocket.destroy();
            });
          });

          session.on('exec', (accept, reject, info) => {
            logger.debug(`Exec request from ${clientIP}: ${info.command}`);
            reject();
          });
        });
      });

      client.on('close', () => {
        logger.info(`SSH client ${clientIP} disconnected`);
        if (sshConnectionTracked) {
          const ipFilter = getIPFilter();
          if (ipFilter) ipFilter.trackConnectionClose(clientIP);
        }
      });
    }
  );

  return server;
}

function startSSHServer(config, activeConnectionsTracker) {
  const server = createSSHServer(config);

  if (!server) {
    logger.info('SSH server is disabled');
    return null;
  }

  server.on('error', (err) => {
    logger.error(`SSH server error: ${err.message}`);
    if (err.code === 'EADDRINUSE') {
      logger.error(`SSH port ${config.sshListenPort} is already in use`);
      process.exit(1);
    }
  });

  server.listen(config.sshListenPort, () => {
    logger.info(`SSH server listening on port ${config.sshListenPort}`);
    logger.info(`SSH connections forwarded to ${config.backendHost}:${config.backendPort}`);
  });

  return server;
}

module.exports = { createSSHServer, startSSHServer };
