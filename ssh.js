/**
 * BBSFirewall - SSH server (terminate mode)
 * Accepts any credentials and proxies the session to the backend telnet server.
 * Acts as the telnet client toward the BBS (telnet-filter.js), so binary
 * transfers such as Zmodem pass through intact.
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
const { createTelnetClient } = require('./telnet-filter');

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

// How long a caller has to finish the SSH handshake and log in (OpenSSH's
// LoginGraceTime default). Applies even with CONNECTION_TIMEOUT=0, which only
// governs idle BBS sessions.
const LOGIN_GRACE_MS = 120000;
// SSH "env" requests accepted per session; a normal client sends a handful.
const MAX_ENV_VARS = 64;
// Session channels open at once per connection. A BBS client uses one; each
// accepted channel holds memory, and ssh2 itself allows billions.
const MAX_SESSIONS = 4;

// Drop a caller outright (blocked, timed out, or tripped a trigger).
function dropSocket(socket) {
  socket.on('error', () => {});
  socket.destroy();
}

// `tracker` is the BBSFirewall instance (server.js): SSH connections count
// against the same activeConnections / MAX_CONNECTIONS as telnet and SSH
// passthrough, which go through its handleNewConnection(). Terminate mode used
// to bypass that entirely - no global cap, no idle timeout.
//
// Every check runs when the TCP connection is accepted, before ssh2 sees the
// socket. ssh2's own connection callback only fires once the caller has sent
// its SSH banner, so checks placed there never ran for a caller that connects
// and stays silent: blocked IPs, rate limits, the per-IP and global caps and
// the idle timeout were all skipped, and such sockets stayed open forever.
// The returned net.Server owns the port; accepted sockets are handed to ssh2
// with injectSocket().
function createSSHServer(config, tracker) {
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

  // Per-socket state set at accept time, read back in the ssh2 callback.
  const accepted = new WeakMap();

  const sshd = new ssh2.Server(
    {
      hostKeys: [hostKey],
      // Banner "SSH-2.0-BBSFirewall" instead of the default, which names the
      // SSH library and its exact version.
      ident: 'BBSFirewall',
      algorithms: {
        cipher: config.sshCiphers,
      },
    },
    (client) => {
      const socket = client._sock;
      const conn = socket && accepted.get(socket);

      client.on('error', (err) => {
        log.debug(`SSH client error: ${err.message}`);
      });

      if (!conn) {
        // Only sockets from the accept handler below are ever injected.
        client.end();
        return;
      }

      const { clientIP, clientPort, whitelisted: sshWhitelisted, noteActivity } = conn;

      // One BBS shell at a time per SSH connection. Each shell opens its own
      // backend connection, so unlimited shell channels on one connection let a
      // single caller (any credentials, one per-IP slot) open unlimited BBS
      // sessions.
      let shellOpen = false;
      let sessionsOpen = 0;

      client.on('authentication', (ctx) => {
        log.info(`SSH auth from ${clientIP} (user: ${ctx.username})`);

        if (ctx.method === 'password' || ctx.method === 'none') {
          ctx.accept();
        } else {
          ctx.reject(['password', 'none']);
        }
      });

      client.on('ready', () => {
        conn.loggedIn();
        log.info(`SSH client ${clientIP} authenticated`);

        client.on('session', (accept, reject) => {
          log.debug(`Session requested for ${clientIP}`);

          if (typeof accept !== 'function') {
            log.error(`Session accept is not a function for ${clientIP}`);
            return;
          }

          if (sessionsOpen >= MAX_SESSIONS) {
            log.blocked(`SSH client ${clientIP}: refused session channel (${MAX_SESSIONS} already open)`);
            if (typeof reject === 'function') reject();
            return;
          }
          sessionsOpen++;
          const session = accept();
          session.once('close', () => { sessionsOpen--; });

          let detectedEncoding = 'cp437';
          let sshEnv = {};
          let termType = null;
          let envCount = 0;

          session.on('env', (accept, reject, info) => {
            if (++envCount > MAX_ENV_VARS) {
              if (typeof reject === 'function') reject();
              return;
            }
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

            if (shellOpen) {
              log.blocked(`SSH client ${clientIP}: refused a second concurrent shell on one connection`);
              if (typeof reject === 'function') reject();
              return;
            }
            shellOpen = true;
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

            // The backend speaks telnet and the caller speaks SSH - answer its
            // negotiation here and keep telnet commands off the caller's screen.
            const telnet = createTelnetClient((reply) => {
              if (backendSocket.writable && !backendSocket.destroyed) backendSocket.write(reply);
            });

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
            let triggerScanner = null; // see ipfilter.createTriggerScanner

            stream.on('data', (data) => {
              noteActivity();
              if (triggerScan) {
                const ipf = getIPFilter();
                if (!triggerScanner && ipf) triggerScanner = ipf.createTriggerScanner(config.triggerBlock.scanBytes);
                const hit = triggerScanner && triggerScanner.feed(data);
                if (hit) {
                  log.blocked(`Auto-block ${clientIP}: shell input matched trigger ${JSON.stringify(hit)}`);
                  ipf.autoBlockIP(clientIP, hit);
                  metrics.incTriggerBlock();
                  // Drop the whole SSH connection, not just this shell: the
                  // blocklist is only checked at connect, so a still-open
                  // connection could open a fresh shell straight to the BBS.
                  if (!backendSocket.destroyed) backendSocket.destroy();
                  dropSocket(socket);
                  return;
                }
                if (!triggerScanner || triggerScanner.full) { triggerScan = false; triggerScanner = null; }
              }

              bytesFromClient += data.length;
              metrics.incBytes('fromClient', data.length);

              if (!backendSocket.writable || backendSocket.destroyed) {
                log.debug(`Backend not writable, dropping ${data.length} bytes`);
                return;
              }

              if (!backendSocket.write(telnet.toBackend(data))) {
                log.debug('Backend buffer full, pausing SSH stream');
                stream.pause();
                backendSocket.once('drain', () => {
                  log.debug('Backend drained, resuming SSH stream');
                  if (!stream.destroyed) stream.resume();
                });
              }
            });

            backendSocket.on('data', (raw) => {
              bytesFromBackend += raw.length;
              metrics.incBytes('fromBackend', raw.length);
              const data = telnet.fromBackend(raw);
              if (data.length === 0) return; // negotiation only
              noteActivity();

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
              shellOpen = false;
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
                dropSocket(socket);
                return;
              }
            }
            reject();
          });
        });
      });

      client.on('close', () => {
        log.connection(`SSH client ${clientIP} disconnected`);
      });
    }
  );

  const server = net.createServer((socket) => {
    const clientIP   = socket.remoteAddress;
    const clientPort = socket.remotePort || 0;

    if (!clientIP) {
      log.blocked('SSH connection rejected: unable to determine client IP');
      dropSocket(socket);
      return;
    }

    if (tracker && tracker.activeConnections >= config.maxConnections) {
      log.blocked(`SSH connection rejected: max connections (${config.maxConnections}) reached`);
      metrics.incRejected();
      dropSocket(socket);
      return;
    }

    const ipFilter = getIPFilter();
    let whitelisted = false;
    let ipTracked = false;

    if (ipFilter) {
      const accessCheck = ipFilter.shouldAllowConnection(clientIP);
      if (!accessCheck.allowed) {
        log.blocked(`SSH connection blocked from ${clientIP}: ${accessCheck.reason}`);
        dropSocket(socket);
        return;
      }
      whitelisted = accessCheck.whitelisted || false;

      // Check per-IP concurrent connection limit (whitelisted IPs are exempt)
      if (!whitelisted && ipFilter.isConnectionLimitExceeded(clientIP)) {
        log.blocked(`SSH connection rejected: per-IP limit reached for ${clientIP}`);
        dropSocket(socket);
        return;
      }

      // Check country blocking (whitelisted IPs are exempt)
      if (!whitelisted && shouldBlockByCountry(config, clientIP)) {
        log.blocked(`SSH connection blocked by country filter: ${clientIP}`);
        dropSocket(socket);
        return;
      }

      // Register this connection in the per-IP tracker
      ipFilter.trackConnectionOpen(clientIP);
      ipTracked = true;
    }

    log.connection(`SSH client connected from ${clientIP}`);

    // All checks passed - take a global connection slot.
    if (tracker) {
      tracker.activeConnections++;
      metrics.incActive('ssh');
    }

    // Must finish the handshake and log in within LOGIN_GRACE_MS.
    let loginTimer = setTimeout(() => {
      log.info(`SSH login timeout for ${clientIP}`);
      socket.destroy();
    }, LOGIN_GRACE_MS);

    // Same idle timeout the telnet side applies (server.js handleNewConnection).
    // Not socket.setTimeout(): ssh2 pings the client every 15s on its own
    // (keepalive@openssh.com) and each ping write resets a socket timer, so it
    // never fires. Only session data in either direction counts as activity -
    // noteActivity() is called from the shell stream/backend data handlers.
    let idleTimer = null;
    if (config.connectionTimeout > 0) {
      idleTimer = setTimeout(() => {
        log.info(`SSH connection timeout for ${clientIP}`);
        socket.destroy();
      }, config.connectionTimeout);
    }

    socket.once('close', () => {
      clearTimeout(loginTimer);
      clearTimeout(idleTimer);
      if (tracker) {
        tracker.activeConnections--;
        metrics.decActive('ssh');
      }
      if (ipTracked) {
        const ipf = getIPFilter();
        if (ipf) ipf.trackConnectionClose(clientIP);
      }
    });

    accepted.set(socket, {
      clientIP,
      clientPort,
      whitelisted,
      noteActivity: () => { if (idleTimer) idleTimer.refresh(); },
      loggedIn: () => { clearTimeout(loginTimer); loginTimer = null; },
    });
    sshd.injectSocket(socket);
  });

  return server;
}

function startSSHServer(config, activeConnectionsTracker) {
  const server = createSSHServer(config, activeConnectionsTracker);

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
