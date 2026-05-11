/**
 * BBS Firewall - Web redirect server
 * Listens on port 80 and sends HTTP 301 redirects to a configured destination URL.
 * Useful for redirecting web browsers that connect to the firewall's IP address.
 *
 * Note: HTTPS (port 443) redirect is not supported without a TLS certificate.
 * Only plain HTTP (port 80) traffic is handled by this module.
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const http = require('http');
const logger = require('./logger');
const { config } = require('./config');

let redirectServer = null;

function startWebRedirectServer() {
  if (!config.webRedirectEnabled) {
    logger.info('Web redirect server is disabled');
    return null;
  }

  if (!config.webRedirectUrl) {
    logger.warn('Web redirect server is enabled but WEB_REDIRECT_URL is not set — skipping');
    return null;
  }

  redirectServer = http.createServer((req, res) => {
    const clientIp = req.socket.remoteAddress || 'unknown';
    const host = req.headers.host || '';
    logger.info(`Web redirect: ${clientIp} [${host}${req.url}] -> ${config.webRedirectUrl}`);
    res.writeHead(301, { Location: config.webRedirectUrl });
    res.end();
  });

  redirectServer.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      logger.error('Port 80 is already in use — web redirect server failed to start');
    } else {
      logger.error(`Web redirect server error: ${err.message}`);
    }
  });

  redirectServer.listen(80, () => {
    logger.info(`Web redirect server listening on port 80 -> ${config.webRedirectUrl}`);
  });

  return redirectServer;
}

function stopWebRedirectServer() {
  return new Promise((resolve) => {
    if (!redirectServer) {
      resolve();
      return;
    }
    redirectServer.close(() => {
      logger.info('Web redirect server closed');
      resolve();
    });
  });
}

module.exports = { startWebRedirectServer, stopWebRedirectServer };
