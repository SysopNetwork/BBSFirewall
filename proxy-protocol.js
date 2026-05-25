/**
 * BBSFirewall - PROXY Protocol v1 header builder
 * https://github.com/SysopNetwork/BBSFirewall
 *
 * Builds the one-line header that gets prepended to every backend TCP connection
 * when PROXY_PROTOCOL_ENABLED=true. The backend BBS (or a module sitting in front
 * of it) reads this line and uses it to get the real client IP instead of the
 * proxy's IP.
 *
 * Header format (PROXY Protocol v1 spec):
 *   PROXY TCP4 <client-ip> <proxy-ip> <client-port> <proxy-port>\r\n
 *   PROXY TCP6 <client-ip> <proxy-ip> <client-port> <proxy-port>\r\n
 *
 * Full spec: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
 *
 * Important: the downstream BBS software must support PROXY Protocol or have a
 * module/plugin that handles it. Without that, it will see this line as garbage
 * data and the connection will break. Don't enable this without a compatible backend.
 */

/**
 * Strips the IPv4-mapped IPv6 prefix from an address if present.
 * Node.js reports IPv4 clients as ::ffff:x.x.x.x on dual-stack sockets.
 * The PROXY Protocol spec wants the plain IPv4 address in that case.
 */
function cleanIP(ip) {
  if (!ip) return 'unknown';
  return ip.replace(/^::ffff:/i, '');
}

/**
 * Builds a PROXY Protocol v1 header string.
 *
 * @param {string} clientIp   - Real client IP (from the inbound socket)
 * @param {string} proxyIp    - Proxy's outbound IP (local address of the backend socket)
 * @param {number} clientPort - Real client source port
 * @param {number} proxyPort  - Proxy's outbound port (local port of the backend socket)
 * @returns {string} The complete header line including \r\n
 */
function buildHeader(clientIp, proxyIp, clientPort, proxyPort) {
  const src = cleanIP(clientIp);
  const dst = cleanIP(proxyIp);

  // Detect address family — if either address still contains a colon it's IPv6
  const proto = src.includes(':') ? 'TCP6' : 'TCP4';

  return `PROXY ${proto} ${src} ${dst} ${clientPort || 0} ${proxyPort || 0}\r\n`;
}

module.exports = { buildHeader };
