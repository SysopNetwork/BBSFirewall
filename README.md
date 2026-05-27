<div align="center">

```
  ██████╗ ██████╗ ███████╗    ███████╗██╗██████╗ ███████╗██╗    ██╗ █████╗ ██╗     ██╗
  ██╔══██╗██╔══██╗██╔════╝    ██╔════╝██║██╔══██╗██╔════╝██║    ██║██╔══██╗██║     ██║
  ██████╔╝██████╔╝███████╗    █████╗  ██║██████╔╝█████╗  ██║ █╗ ██║███████║██║     ██║
  ██╔══██╗██╔══██╗╚════██║    ██╔══╝  ██║██╔══██╗██╔══╝  ██║███╗██║██╔══██║██║     ██║
       ██████╔╝██████╔╝███████║    ██║     ██║██║  ██║███████╗╚███╔███╔╝██║  ██║███████╗███████╗
       ╚═════╝ ╚═════╝ ╚══════╝    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚══════╝
```

**A lightweight TCP proxy firewall for BBS telnet connections, built with Node.js.**

By **[Sysop Network](https://github.com/SysopNetwork)** — https://github.com/SysopNetwork/BBSFirewall

[![Node.js](https://img.shields.io/badge/Node.js-14%2B-brightgreen?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-MIT-blue?logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?logo=linux&logoColor=white)]()
[![PM2](https://img.shields.io/badge/PM2-ready-2B037A?logo=pm2&logoColor=white)](https://pm2.keymetrics.io/)

</div>

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🔀 | **TCP Proxy** | Forwards telnet connections to a backend BBS server |
| 🔒 | **SSH Server** | Encrypted SSH access on any port, proxied to the telnet backend |
| 🌐 | **HTTPS Redirect** | Redirects both HTTP (port 80) and HTTPS (port 443) to a configured URL |
| 🔑 | **Let's Encrypt** | Built-in cert setup script with auto-renewal, no downtime required |
| 📡 | **PROXY Protocol v1** | Passes the real client IP to the backend BBS (requires compatible backend) |
| 🌍 | **Country Blocking** | Block connections by country using a local GeoIP database |
| ✅ | **IP Whitelist** | Trusted IPs that bypass all firewall rules |
| 🚫 | **IP Blocklist** | Permanently block specific IPs or CIDR ranges |
| ⚡ | **Rate Limiting** | Automatic flood protection with configurable temporary blocks |
| 🔗 | **Per-IP Connection Limit** | Cap simultaneous connections from a single IP |
| 🖥️ | **Encoding Detection** | Automatic UTF-8/CP437 detection with separate backend routing |
| 🛑 | **Graceful Shutdown** | Clean shutdown on SIGTERM/SIGINT, active sessions drain properly |
| ⚙️ | **PM2 Ready** | Includes `ecosystem.config.js` for process management |

---

## 🚀 Installation

### Requirements

- Node.js 14 or higher
- Root or `CAP_NET_BIND_SERVICE` to bind ports below 1024 (23, 80, 443)
- Linux recommended for production; runs anywhere Node.js runs

### Quick start

```bash
# 1. Clone the repo
git clone https://github.com/SysopNetwork/BBSFirewall.git
cd BBSFirewall

# 2. Install dependencies
npm install

# 3. Create your config
cp .env.example .env
nano .env   # set BACKEND_HOST, BACKEND_PORT at minimum

# 4. Start it
npm start
```

### Production (PM2)

```bash
npm install -g pm2

pm2 start ecosystem.config.js
pm2 save
pm2 startup   # follow the printed command to enable auto-start on boot
```

PM2 commands:

```bash
pm2 start ecosystem.config.js   # start
pm2 stop bbsfirewall            # stop
pm2 restart bbsfirewall         # restart
pm2 logs bbsfirewall            # tail logs
pm2 list                        # status
```

---

## ⚙️ Configuration

All settings live in `.env`. Copy `.env.example` to get started — every option is documented there.

### 🌐 Network

<table>
<tr>
<th width="270">Variable</th>
<th>Description</th>
<th width="170">Default</th>
</tr>
<tr><td><code>LISTEN_PORT</code></td><td>Port to listen on for incoming telnet connections</td><td><code>23</code></td></tr>
<tr><td><code>BACKEND_HOST</code></td><td>Backend BBS server hostname or IP</td><td><code>127.0.0.1</code></td></tr>
<tr><td><code>BACKEND_PORT</code></td><td>Backend BBS server port</td><td><code>23</code></td></tr>
<tr><td><code>ENCODING_DETECTION</code></td><td>Enable automatic UTF-8/CP437 encoding detection</td><td><code>false</code></td></tr>
<tr><td><code>BACKEND_PORT_CP437</code></td><td>Backend port for CP437 (DOS/ANSI) clients</td><td><code>2323</code></td></tr>
<tr><td><code>BACKEND_PORT_UTF8</code></td><td>Backend port for UTF-8 (Unicode) clients</td><td><code>2423</code></td></tr>
</table>

### 🔗 Connection Limits

<table>
<tr>
<th width="270">Variable</th>
<th>Description</th>
<th width="170">Default</th>
</tr>
<tr><td><code>MAX_CONNECTIONS</code></td><td>Maximum total simultaneous connections</td><td><code>100</code></td></tr>
<tr><td><code>MAX_CONNECTIONS_PER_IP</code></td><td>Max simultaneous connections from a single IP (<code>0</code> = unlimited)</td><td><code>0</code></td></tr>
<tr><td><code>CONNECTION_TIMEOUT</code></td><td>Connection timeout in milliseconds (<code>0</code> to disable)</td><td><code>300000</code></td></tr>
</table>

### 🌍 Country Blocking

<table>
<tr>
<th width="270">Variable</th>
<th>Description</th>
<th width="170">Default</th>
</tr>
<tr><td><code>BLOCKED_COUNTRIES</code></td><td>Comma-separated ISO country codes to block (e.g. <code>CN,RU,KP</code>)</td><td><em>(empty)</em></td></tr>
<tr><td><code>BLOCK_UNKNOWN_COUNTRIES</code></td><td>Block connections with undetermined country</td><td><code>false</code></td></tr>
</table>

### 🛡️ IP Lists

<table>
<tr>
<th width="270">Variable</th>
<th>Description</th>
<th width="170">Default</th>
</tr>
<tr><td><code>WHITELIST_PATH</code></td><td>Path to IP whitelist file (bypasses all firewall rules)</td><td><em>(empty)</em></td></tr>
<tr><td><code>BLOCKLIST_PATH</code></td><td>Path to IP blocklist file (permanent blocks)</td><td><em>(empty)</em></td></tr>
</table>

### ⚡ Rate Limiting

<table>
<tr>
<th width="270">Variable</th>
<th>Description</th>
<th width="170">Default</th>
</tr>
<tr><td><code>RATE_LIMIT_ENABLED</code></td><td>Enable connection flood protection</td><td><code>true</code></td></tr>
<tr><td><code>MAX_CONNECTIONS_PER_WINDOW</code></td><td>Max connection attempts per IP per time window</td><td><code>10</code></td></tr>
<tr><td><code>RATE_LIMIT_WINDOW_MS</code></td><td>Time window in milliseconds</td><td><code>60000</code></td></tr>
<tr><td><code>RATE_LIMIT_BLOCK_DURATION_MS</code></td><td>Temporary block duration in milliseconds</td><td><code>300000</code></td></tr>
</table>

### 📡 PROXY Protocol

<table>
<tr>
<th width="270">Variable</th>
<th>Description</th>
<th width="170">Default</th>
</tr>
<tr><td><code>PROXY_PROTOCOL_ENABLED</code></td><td>Prepend real client IP to backend TCP stream</td><td><code>false</code></td></tr>
</table>

### 🌐 Web Redirect

<table>
<tr>
<th width="270">Variable</th>
<th>Description</th>
<th width="170">Default</th>
</tr>
<tr><td><code>WEB_REDIRECT_ENABLED</code></td><td>Redirect HTTP traffic on port 80</td><td><code>false</code></td></tr>
<tr><td><code>WEB_REDIRECT_URL</code></td><td>Destination URL for redirects (used by both HTTP and HTTPS)</td><td><em>(empty)</em></td></tr>
</table>

### 🔒 HTTPS Redirect

<table>
<tr>
<th width="270">Variable</th>
<th>Description</th>
<th width="170">Default</th>
</tr>
<tr><td><code>HTTPS_REDIRECT_ENABLED</code></td><td>Redirect HTTPS traffic on port 443</td><td><code>false</code></td></tr>
<tr><td><code>HTTPS_REDIRECT_PORT</code></td><td>Port to listen on for HTTPS</td><td><code>443</code></td></tr>
<tr><td><code>HTTPS_CERT_PATH</code></td><td>Path to TLS certificate (fullchain)</td><td><code>./certs/fullchain.pem</code></td></tr>
<tr><td><code>HTTPS_KEY_PATH</code></td><td>Path to TLS private key</td><td><code>./certs/privkey.pem</code></td></tr>
<tr><td><code>ACME_WEBROOT</code></td><td>Directory for Let's Encrypt challenge files</td><td><code>./certs/webroot</code></td></tr>
</table>

### 📋 Logging

<table>
<tr>
<th width="270">Variable</th>
<th>Description</th>
<th width="170">Default</th>
</tr>
<tr><td><code>LOG_LEVEL</code></td><td>Log level: <code>debug</code>, <code>info</code>, <code>warn</code>, <code>error</code></td><td><code>info</code></td></tr>
</table>

### 🔒 SSH Server

<table>
<tr>
<th width="270">Variable</th>
<th>Description</th>
<th width="170">Default</th>
</tr>
<tr><td><code>SSH_ENABLED</code></td><td>Enable the SSH server</td><td><code>false</code></td></tr>
<tr><td><code>SSH_LISTEN_PORT</code></td><td>Port to listen on for SSH connections</td><td><code>2222</code></td></tr>
<tr><td><code>SSH_HOST_KEY</code></td><td>Path to SSH host private key file</td><td><code>./ssh_host_key</code></td></tr>
<tr><td><code>SSH_CIPHERS</code></td><td>Comma-separated list of allowed SSH ciphers</td><td><em>(see below)</em></td></tr>
</table>

---

## 🔒 SSH Server

BBSFirewall includes an optional SSH server that accepts any username and password and proxies the session to the backend BBS via telnet. This lets users connect with a modern SSH client instead of a raw telnet client.

### Setup

Generate an SSH host key (only needed once):

```bash
ssh-keygen -t rsa -b 4096 -f ssh_host_key -N "" -m PEM
```

Enable in `.env`:

```env
SSH_ENABLED=true
SSH_LISTEN_PORT=22
SSH_HOST_KEY=./ssh_host_key
```

Connect from any SSH client — any username and password works:

```bash
ssh yourserver.example.com
```

### Default SSH Ciphers

Includes both modern and legacy ciphers for old terminal clients:

- `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`
- `aes128-ctr`, `aes192-ctr`, `aes256-ctr`
- `aes128-cbc`, `aes192-cbc`, `aes256-cbc`
- `3des-cbc` (for very old clients)

> **Note:** Binary file transfers (Zmodem, Ymodem, etc.) do not work reliably over SSH due to PTY character processing. Use the telnet connection for file transfers and SSH for interactive browsing.

---

## 🌐 Web & HTTPS Redirect

BBSFirewall can redirect web browsers that hit your firewall's IP address to your BBS website.

### HTTP redirect (port 80)

```env
WEB_REDIRECT_ENABLED=true
WEB_REDIRECT_URL=https://yourbbs.example.com
```

### HTTPS redirect (port 443)

Requires a TLS certificate. Run `setup-certs.sh` to get a free one from Let's Encrypt (see below).

```env
HTTPS_REDIRECT_ENABLED=true
HTTPS_REDIRECT_PORT=443
HTTPS_CERT_PATH=./certs/fullchain.pem
HTTPS_KEY_PATH=./certs/privkey.pem
```

`WEB_REDIRECT_URL` is used as the destination for both HTTP and HTTPS redirects.

> **Note:** On Linux, binding ports 80 and 443 requires root or the `CAP_NET_BIND_SERVICE` capability.

---

## 🔑 Let's Encrypt Certificates

BBSFirewall includes `setup-certs.sh` to get a free TLS certificate from Let's Encrypt using certbot's webroot method. The HTTP server stays running the whole time — no downtime.

### Requirements

- Port 80 must be reachable from the internet
- `WEB_REDIRECT_ENABLED=true` in your `.env`
- BBSFirewall must be running before you run the script
- DNS must already point your domain to this server

### Get a certificate

```bash
bash setup-certs.sh yourdomain.com --email you@example.com
```

The script will:
1. Install certbot if it's not already there
2. Verify port 80 is listening
3. Run certbot in webroot mode (no service interruption)
4. Copy the certificates to `./certs/`
5. Install a renewal hook that auto-copies new certs and restarts BBSFirewall
6. Print the `.env` lines to add

### Manual renewal

```bash
bash setup-certs.sh yourdomain.com --renew
```

Renewal is also automatic via certbot's built-in systemd timer — you don't have to think about it.

---

## 📡 PROXY Protocol v1

BBSFirewall can prepend a PROXY Protocol v1 header to every backend connection so the destination BBS can see the real client IP instead of the firewall's IP.

```env
PROXY_PROTOCOL_ENABLED=true
```

When enabled, every connection to the backend starts with:

```
PROXY TCP4 203.0.113.45 192.0.2.1 56324 23
```

Fields: `protocol`, `real client IP`, `proxy IP`, `client port`, `proxy port`.

This works for both telnet and SSH connections.

> ⚠️ **Important:** The backend BBS software must support PROXY Protocol, or have a module/plugin that reads and strips the header before the BBS sees it. **Enabling this against an incompatible backend will break all connections** — the BBS will receive the header line as garbage data at the start of every session.

Compatible backends include HAProxy, Nginx, Synchronet, WWIV, Mystic, and any software with a PROXY Protocol module. Standard MajorBBS/Worldgroup requires a companion MBBS module to handle the header.

Full spec: https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

---

## 🌍 Country Blocking

Block connections from specific countries using a local MaxMind GeoLite2 database. No external API calls — the lookup happens entirely on your server.

### Setup

```bash
npm run setup-geoip
```

Follow the on-screen instructions. A free MaxMind account is required at [maxmind.com](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data).

### Configuration

```env
BLOCKED_COUNTRIES=CN,RU,KP,IR
BLOCK_UNKNOWN_COUNTRIES=false
```

Use [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) two-letter country codes.

---

## 🛡️ IP Filtering & Rate Limiting

### Whitelist

IPs in the whitelist bypass **all** firewall rules — country blocking, rate limiting, blocklist, per-IP limits. Use this for trusted admin IPs.

```bash
cp whitelist.txt.example whitelist.txt
# Add your trusted IPs — one per line, CIDR ranges supported
```

```env
WHITELIST_PATH=./whitelist.txt
```

### Blocklist

Permanently blocked IPs. Rejected immediately on connect regardless of any other setting.

```bash
cp blocklist.txt.example blocklist.txt
# Add IPs to block — one per line, CIDR ranges supported
```

```env
BLOCKLIST_PATH=./blocklist.txt
```

### Rate Limiting

Automatically blocks IPs that hammer the connection too frequently. Temporary blocks expire after `RATE_LIMIT_BLOCK_DURATION_MS`.

```env
RATE_LIMIT_ENABLED=true
MAX_CONNECTIONS_PER_WINDOW=10
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_BLOCK_DURATION_MS=300000
```

### Connection Decision Order

Every incoming connection goes through these checks in order:

| Step | Check | Action |
|:---:|---|---|
| 1 | ✅ Whitelist | Matched IPs are allowed immediately — all other checks skipped |
| 2 | 🚫 Blocklist | Permanent block |
| 3 | ⚡ Rate limit | Temporary block if threshold exceeded |
| 4 | 🔗 Per-IP connection limit | Reject if over `MAX_CONNECTIONS_PER_IP` |
| 5 | 🌍 GeoIP country check | Block if country is in `BLOCKED_COUNTRIES` |
| 6 | 🔀 Forward | Connect to backend BBS |

---

## 🖥️ Encoding Detection

BBSFirewall can detect whether a connecting SSH client prefers UTF-8 or CP437 and route them to separate backend ports. Useful if your BBS software runs separate instances for each encoding.

```env
ENCODING_DETECTION=true
BACKEND_PORT_CP437=2323
BACKEND_PORT_UTF8=2423
```

Detection for SSH clients is based on the client's `LANG`/`LC_ALL` environment variables and terminal type. Telnet connections always default to CP437 — there's no reliable way to detect encoding before the connection is established.

---

## 📁 Architecture

```
BBSFirewall/
├── server.js              # Main entry point, connection manager, graceful shutdown
├── proxy.js               # Bidirectional TCP proxy handler
├── ssh.js                 # SSH server — accepts any credentials, proxies to telnet
├── web-redirect.js        # HTTP + HTTPS redirect server with ACME challenge support
├── proxy-protocol.js      # PROXY Protocol v1 header builder
├── config.js              # Configuration loading and validation
├── logger.js              # Log level filtering
├── geoip.js               # MaxMind GeoLite2 country lookup
├── ipfilter.js            # IP lists, rate limiting, per-IP connection tracking
├── encoding-detector.js   # UTF-8/CP437 detection logic
├── download-geoip.js      # GeoIP database setup helper
├── setup-certs.sh         # Let's Encrypt certificate setup script
├── ecosystem.config.js    # PM2 process config
├── package.json
├── .env.example           # Documented example configuration
├── whitelist.txt.example
├── blocklist.txt.example
└── data/                  # GeoIP database (not included, run setup-geoip)
```

---

## 🏆 Credits

BBSFirewall is developed and maintained by [Mark Laudenbach](https://github.com/laudenbachm) at [Sysop Network](https://github.com/SysopNetwork).

Built on the foundation of [bbsfw](https://github.com/ryanfantus/bbsfw) by [Ryan Fantus](https://github.com/ryanfantus). Solid starting point — thanks for putting that together.

---

## 📄 License

MIT — Copyright (c) 2026 Sysop Network
