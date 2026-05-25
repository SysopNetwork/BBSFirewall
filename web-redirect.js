/**
 * BBSFirewall - Web redirect server
 * Handles HTTP (port 80) and HTTPS (port 443) redirects to a configured URL.
 * Also serves Let's Encrypt ACME challenge files on the HTTP listener so you
 * can issue/renew certs without stopping the server. Run setup-certs.sh to
 * get that set up — it handles the whole certbot dance for you.
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const http  = require('http');
const https = require('https');
const fs    = require('fs');
const path  = require('path');
const logger = require('./logger');
const { config } = require('./config');

let httpServer  = null;
let httpsServer = null;

// ---------------------------------------------------------------------------
// ACME challenge handler
// Certbot writes a token file to <acmeWebroot>/.well-known/acme-challenge/
// and expects the HTTP server to serve it at that URL path. Without this,
// webroot mode fails and you have to stop the server to renew certs. No fun.
// ---------------------------------------------------------------------------
function serveAcmeChallenge(req, res) {
  const token = path.basename(req.url); // strip any path trickery
  const challengeFile = path.join(
    path.resolve(config.acmeWebroot),
    '.well-known',
    'acme-challenge',
    token
  );

  try {
    const content = fs.readFileSync(challengeFile, 'utf8');
    logger.info(`ACME challenge served: ${token}`);
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(content);
    return true;
  } catch (_) {
    // File not found — not an active challenge, fall through to redirect
    return false;
  }
}

// ---------------------------------------------------------------------------
// Shared request handler — used by both HTTP and HTTPS listeners
// ---------------------------------------------------------------------------
function makeRequestHandler(label) {
  return (req, res) => {
    const clientIp = req.socket.remoteAddress || 'unknown';

    // Let's Encrypt verification — serve the challenge file, don't redirect it
    if (req.url.startsWith('/.well-known/acme-challenge/')) {
      if (!serveAcmeChallenge(req, res)) {
        res.writeHead(404);
        res.end('Not found');
      }
      return;
    }

    const host = req.headers.host || '';
    logger.info(`${label} redirect: ${clientIp} [${host}${req.url}] -> ${config.webRedirectUrl}`);
    res.writeHead(301, { Location: config.webRedirectUrl });
    res.end();
  };
}

// ---------------------------------------------------------------------------
// Ensure the ACME webroot directory exists so certbot can write to it.
// Certbot will error out if the directory isn't there already.
// ---------------------------------------------------------------------------
function ensureAcmeWebroot() {
  const dir = path.join(path.resolve(config.acmeWebroot), '.well-known', 'acme-challenge');
  if (!fs.existsSync(dir)) {
    try {
      fs.mkdirSync(dir, { recursive: true });
      logger.info(`Created ACME webroot: ${dir}`);
    } catch (err) {
      logger.warn(`Could not create ACME webroot directory: ${err.message}`);
    }
  }
}

// ---------------------------------------------------------------------------
// HTTP listener (port 80)
// ---------------------------------------------------------------------------
function startHttpServer() {
  if (!config.webRedirectEnabled) {
    logger.info('HTTP redirect server is disabled');
    return;
  }

  ensureAcmeWebroot();

  httpServer = http.createServer(makeRequestHandler('HTTP'));

  httpServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      logger.error('Port 80 is already in use — HTTP redirect server failed to start');
    } else {
      logger.error(`HTTP redirect server error: ${err.message}`);
    }
  });

  httpServer.listen(80, () => {
    logger.info(`HTTP redirect server listening on port 80 -> ${config.webRedirectUrl}`);
  });
}

// ---------------------------------------------------------------------------
// HTTPS listener (port 443 by default)
// Requires a TLS certificate — run setup-certs.sh to get one from Let's Encrypt.
// A missing or unreadable cert file logs an error but does NOT crash the rest
// of the server. Telnet and HTTP redirect keep running just fine.
// ---------------------------------------------------------------------------
function startHttpsServer() {
  if (!config.httpsRedirectEnabled) {
    logger.info('HTTPS redirect server is disabled');
    return;
  }

  let tlsKey, tlsCert;

  try {
    tlsKey  = fs.readFileSync(path.resolve(config.httpsKeyPath));
    tlsCert = fs.readFileSync(path.resolve(config.httpsCertPath));
  } catch (err) {
    logger.error(`HTTPS redirect: failed to load TLS certificate — ${err.message}`);
    logger.error('Run setup-certs.sh to generate a Let\'s Encrypt certificate, then restart.');
    return; // don't crash — everything else still works
  }

  httpsServer = https.createServer({ key: tlsKey, cert: tlsCert }, makeRequestHandler('HTTPS'));

  httpsServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      logger.error(`Port ${config.httpsRedirectPort} is already in use — HTTPS redirect server failed to start`);
    } else {
      logger.error(`HTTPS redirect server error: ${err.message}`);
    }
  });

  httpsServer.listen(config.httpsRedirectPort, () => {
    logger.info(`HTTPS redirect server listening on port ${config.httpsRedirectPort} -> ${config.webRedirectUrl}`);
  });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
function startWebRedirectServer() {
  if (!config.webRedirectEnabled && !config.httpsRedirectEnabled) {
    logger.info('Web redirect is disabled');
    return;
  }

  if (!config.webRedirectUrl) {
    logger.warn('Web redirect is enabled but WEB_REDIRECT_URL is not set — skipping');
    return;
  }

  startHttpServer();
  startHttpsServer();
}

function stopWebRedirectServer() {
  return new Promise((resolve) => {
    let pending = 0;
    const done = () => { if (--pending <= 0) resolve(); };

    if (httpServer) {
      pending++;
      httpServer.close(() => { logger.info('HTTP redirect server closed'); done(); });
      httpServer = null;
    }

    if (httpsServer) {
      pending++;
      httpsServer.close(() => { logger.info('HTTPS redirect server closed'); done(); });
      httpsServer = null;
    }

    if (pending === 0) resolve();
  });
}

module.exports = { startWebRedirectServer, stopWebRedirectServer };
