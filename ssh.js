/**
 * BBSFirewall - SSH server (terminate mode)
 * Accepts any credentials and proxies the session to the backend telnet server.
 * Note: Binary file transfers (Zmodem, etc.) are unreliable over SSH due to PTY
 * processing — use SSH_MODE=passthrough with a backend that has its own SSH
 * server if you need reliable transfers.
 * https://github.com/SysopNetwork/BBSFirewall
 */

const ssh2 = require('ssh2');
const net = require('net');
const fs = require('fs');
const logger = require('./logger');
const metrics = require('./metrics');
const { getIPFilter } = require('./ipfilter');
const { getGeoIP } = require('./geoip');
const { detectFromSSHEnvironment, detectFromTerminalType, getBackendPortForEncoding } = require('./encoding-detector');
const { buildHeader: buildProxyHeader } = require('./proxy-protocol');

const log = logger.getLogger('ssh');

// Mirrors ProxyConnection.shouldBlockConnection in proxy.js — the telnet path's
// GeoIP country block was never ported over here, which let a caller from a
// blocked country simply connect via SSH_MODE=terminate instead of telnet to
// bypass BLOCKED_COUNTRIES entirely.
function shouldBlockByCountry(config, ipAddress) {
  const geoip = getGeoIP();
  if (!geoip || !geoip.isEnabled) return false;

  const geoInfo = geoip.getCountryInfo(ipAddress);
  if (!geoInfo || !geoInfo.countryCode) {
    if (config.blockUnknownCountries) {
      log.info(`Blocked unknown country for IP: ${ipAddress}`);
      return true;
    }
    return false;
  }

  log.debug(`SSH connection from ${geoInfo.countryName} (${geoInfo.countryCode})`);

  if (config.blockedCountries.length > 0) {
    const isBlocked = config.blockedCountries.includes(geoInfo.countryCode.toUpperCase());
    if (isBlocked) {
      log.info(`Blocked ${geoInfo.countryName} (${geoInfo.countryCode})`);
    }
    return isBlocked;
  }

  return false;
}

function createSSHServer(config) {
  if (config.sshMode !== 'terminate') {
    return null;
  }

  let hostKey;
  try {
    hostKey = fs.readFileSync(config.sshHostKey, 'utf8');
  } catch (err) {
    log.error(`Failed to read SSH host key from ${config.sshHostKey}: ${err.message}`);
    log.error('Generate a host key with: ssh-keygen -t rsa -b 4096 -f ssh_host_key -N "" -m PEM');
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
      const clientIP   = client._sock?.remoteAddress;
      const clientPort = client._sock?.remotePort || 0;

      client.on('error', (err) => {
        log.debug(`SSH client error: ${err.message}`);
      });

      if (!clientIP) {
        log.blocked('SSH connection rejected: unable to determine client IP');
        client.end();
        return;
      }

      log.connection(`SSH client connected from ${clientIP}`);

      const ipFilter = getIPFilter();
      let sshConnectionTracked = false;
      let sshWhitelisted = false;

      if (ipFilter) {
        const accessCheck = ipFilter.shouldAllowConnection(clientIP);
        if (!accessCheck.allowed) {
          log.blocked(`SSH connection blocked from ${clientIP}: ${accessCheck.reason}`);
          client.end();
          return;
        }
        sshWhitelisted = accessCheck.whitelisted || false;

        // Check per-IP concurrent connection limit (whitelisted IPs are exempt)
        if (!accessCheck.whitelisted && ipFilter.isConnectionLimitExceeded(clientIP)) {
          log.blocked(`SSH connection rejected: per-IP limit reached for ${clientIP}`);
          client.end();
          return;
        }

        // Check country blocking (whitelisted IPs are exempt)
        if (!accessCheck.whitelisted && shouldBlockByCountry(config, clientIP)) {
          log.blocked(`SSH connection blocked by country filter: ${clientIP}`);
          client.end();
          return;
        }

        // Register this connection in the per-IP tracker
        ipFilter.trackConnectionOpen(clientIP);
        sshConnectionTracked = true;
      }

      client.on('authentication', (ctx) => {
        log.info(`SSH auth from ${clientIP} (user: ${ctx.username})`);

        if (ctx.method === 'password' || ctx.method === 'none') {
          ctx.accept();
        } else {
          ctx.reject(['password', 'none']);
        }
      });

      client.on('ready', () => {
        log.info(`SSH client ${clientIP} authenticated`);

        client.on('session', (accept, reject) => {
          log.debug(`Session requested for ${clientIP}`);

          if (typeof accept !== 'function') {
            log.error(`Session accept is not a function for ${clientIP}`);
            return;
          }

          const session = accept();

          let detectedEncoding = 'cp437';
          let sshEnv = {};
          let termType = null;

          session.on('env', (accept, reject, info) => {
            log.debug(`SSH env from ${clientIP}: ${info.key}=${info.value}`);
            sshEnv[info.key] = info.value;

            if (config.encodingDetection) {
              const envDetected = detectFromSSHEnvironment(sshEnv);
              if (envDetected === 'utf8') {
                detectedEncoding = 'utf8';
                log.info(`Detected UTF-8 encoding from SSH environment for ${clientIP}`);
              }
            }

            accept && accept();
          });

          session.on('pty', (accept, reject, info) => {
            log.debug(`PTY requested for ${clientIP}, term: ${info.term}`);

            if (info && info.term) {
              termType = info.term;

              if (config.encodingDetection && detectedEncoding === 'cp437') {
                const termDetected = detectFromTerminalType(termType);
                if (termDetected === 'utf8') {
                  detectedEncoding = 'utf8';
                  log.info(`Detected UTF-8 from terminal type '${termType}' for ${clientIP}`);
                }
              }
            }

            if (typeof accept === 'function') {
              accept();
            } else {
              log.warn(`PTY accept is not a function for ${clientIP}`);
            }
          });

          session.on('window-change', (info) => {
            log.debug(`Window change for ${clientIP}: ${info.cols}x${info.rows}`);
          });

          session.on('shell', (accept, reject) => {
            log.debug(`Shell requested for ${clientIP}`);

            if (typeof accept !== 'function') {
              log.error(`Shell accept is not a function for ${clientIP}`);
              return;
            }

            const stream = accept();
            log.connection(`SSH shell session started for ${clientIP}`);

            stream.allowHalfOpen = true;

            const actualBackendPort = config.encodingDetection
              ? getBackendPortForEncoding(detectedEncoding, config)
              : config.backendPort;

            if (config.encodingDetection) {
              log.info(`SSH client ${clientIP} using backend port ${actualBackendPort} for encoding: ${detectedEncoding}`);
            }

            const backendSocket = new net.Socket();
            backendSocket.setNoDelay(true);
            backendSocket.setKeepAlive(true, 30000);

            // Pause the SSH stream until the backend is connected and the
            // PROXY header has been written, so it is always first in the
            // backend stream.
            stream.pause();

            // Give up if the backend TCP connection does not establish in time.
            let connectTimer = config.backendConnectTimeout > 0 ? setTimeout(() => {
              log.blocked(`SSH client ${clientIP}: backend connect timed out after ` +
                `${config.backendConnectTimeout}ms (${config.backendHost}:${actualBackendPort})`);
              stream.end();
              if (!backendSocket.destroyed) backendSocket.destroy();
            }, config.backendConnectTimeout) : null;
            const clearConnectTimer = () => {
              if (connectTimer) { clearTimeout(connectTimer); connectTimer = null; }
            };
            backendSocket.once('close', clearConnectTimer);

            backendSocket.connect(actualBackendPort, config.backendHost, () => {
              clearConnectTimer();
              log.connection(`SSH client ${clientIP} connected to backend ${config.backendHost}:${actualBackendPort}`);
              backendSocket.setNoDelay(true);

              // Send PROXY Protocol v1 header before any BBS data flows.
              // The backend must support it — see PROXY_PROTOCOL_ENABLED in .env.
              if (config.proxyProtocolEnabled) {
                const header = buildProxyHeader(
                  clientIP,
                  backendSocket.localAddress,
                  clientPort,
                  backendSocket.localPort
                );
                backendSocket.write(header);
                log.info(`SSH PROXY Protocol header sent for ${clientIP}: ${header.trim()}`);
              }

              stream.resume();
            });

            let bytesFromClient = 0;
            let bytesFromBackend = 0;

            let triggerScan = !!(config.triggerBlock && config.triggerBlock.enabled) && !sshWhitelisted;
            let triggerBuf = null;

            stream.on('data', (data) => {
              if (triggerScan) {
                const cap = config.triggerBlock.scanBytes;
                triggerBuf = triggerBuf ? Buffer.concat([triggerBuf, data]) : Buffer.from(data);
                if (triggerBuf.length > cap) triggerBuf = triggerBuf.subarray(0, cap);

                const ipf = getIPFilter();
                const hit = ipf && ipf.matchTrigger(triggerBuf.toString('latin1'));
                if (hit) {
                  log.blocked(`Auto-block ${clientIP}: shell input matched trigger ${JSON.stringify(hit)}`);
                  if (ipf) ipf.autoBlockIP(clientIP, hit);
                  metrics.incTriggerBlock();
                  stream.end();
                  if (!backendSocket.destroyed) backendSocket.destroy();
                  return;
                }
                if (triggerBuf.length >= cap) { triggerScan = false; triggerBuf = null; }
              }

              bytesFromClient += data.length;
              metrics.incBytes('fromClient', data.length);

              if (!backendSocket.writable || backendSocket.destroyed) {
                log.debug(`Backend not writable, dropping ${data.length} bytes`);
                return;
              }

              if (!backendSocket.write(data)) {
                log.debug('Backend buffer full, pausing SSH stream');
                stream.pause();
                backendSocket.once('drain', () => {
                  log.debug('Backend drained, resuming SSH stream');
                  if (!stream.destroyed) stream.resume();
                });
              }
            });

            backendSocket.on('data', (data) => {
              bytesFromBackend += data.length;
              metrics.incBytes('fromBackend', data.length);

              if (!stream.writable || stream.destroyed) {
                log.debug(`SSH stream not writable, dropping ${data.length} bytes`);
                return;
              }

              if (!stream.write(data)) {
                log.debug('SSH stream buffer full, pausing backend');
                backendSocket.pause();
                stream.once('drain', () => {
                  log.debug('SSH stream drained, resuming backend');
                  if (!backendSocket.destroyed) backendSocket.resume();
                });
              }
            });

            backendSocket.on('error', (err) => {
              log.error(`Backend error for SSH client ${clientIP}: ${err.message}`);
              stream.end();
            });

            backendSocket.on('close', () => {
              log.connection(`Backend connection closed for SSH client ${clientIP}`);
              stream.end();
            });

            stream.on('close', () => {
              log.connection(`SSH stream closed for ${clientIP}. Bytes: client→backend=${bytesFromClient}, backend→client=${bytesFromBackend}`);
              if (!backendSocket.destroyed) backendSocket.destroy();
            });

            stream.on('error', (err) => {
              log.error(`SSH stream error for ${clientIP}: ${err.message}`);
              if (!backendSocket.destroyed) backendSocket.destroy();
            });
          });

          session.on('exec', (accept, reject, info) => {
            log.debug(`Exec request from ${clientIP}: ${info.command}`);
            // A remote command against a BBS gateway is always a bot. If it
            // matches a trigger, blacklist the source.
            if (config.triggerBlock && config.triggerBlock.enabled && !sshWhitelisted) {
              const ipf = getIPFilter();
              const hit = ipf && ipf.matchTrigger(String(info.command || ''));
              if (hit) {
                log.blocked(`Auto-block ${clientIP}: exec command matched trigger ${JSON.stringify(hit)}`);
                if (ipf) ipf.autoBlockIP(clientIP, hit);
                metrics.incTriggerBlock();
                client.end();
                return;
              }
            }
            reject();
          });
        });
      });

      client.on('close', () => {
        log.connection(`SSH client ${clientIP} disconnected`);
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
    return null;
  }

  server.on('error', (err) => {
    log.error(`SSH server error: ${err.message}`);
    if (err.code === 'EADDRINUSE') {
      log.error(`SSH port ${config.sshListenPort} is already in use`);
      process.exit(1);
    }
  });

  server.listen(config.sshListenPort, () => {
    log.info(`SSH server (terminate) listening on port ${config.sshListenPort}`);
    log.info(`SSH connections forwarded to ${config.backendHost}:${config.backendPort}`);
  });

  return server;
}

module.exports = { createSSHServer, startSSHServer };
