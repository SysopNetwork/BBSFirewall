# BBS Firewall

A lightweight TCP proxy firewall for BBS telnet connections, built with Node.js.

## Features

- **TCP Proxy** — Forwards telnet connections to a backend BBS server
- **Per-IP Connection Limit** — Configurable cap on simultaneous connections per client IP
- **Web Redirect** — Redirects HTTP traffic on port 80 to a configured URL
- **Country Blocking** — Block connections by country using a local GeoIP database
- **IP Whitelist** — Trusted IPs that bypass all firewall rules
- **IP Blocklist** — Permanently block specific IPs or CIDR ranges
- **Rate Limiting** — Automatic flood protection with temporary blocks
- **SSH Server** — Optional encrypted SSH access that proxies to the telnet backend
- **Encoding Detection** — Automatic UTF-8/CP437 detection for smart backend routing
- **Graceful Shutdown** — Clean shutdown on SIGTERM/SIGINT
- **Minimal Dependencies** — Only Node.js built-ins plus `ssh2` and `maxmind`

## Installation

1. Ensure Node.js 14+ is installed

2. Install dependencies:
   ```bash
   npm install
   ```

3. Copy the example configuration and edit it:
   ```bash
   cp .env.example .env
   ```

4. (Optional) Set up the GeoIP database for country blocking:
   ```bash
   npm run setup-geoip
   ```

5. Start the firewall:
   ```bash
   npm start
   ```

## Configuration

All settings are configured through environment variables or the `.env` file.

### Network

| Variable | Description | Default |
|---|---|---|
| `LISTEN_PORT` | Port to listen on for incoming telnet connections | `23` |
| `BACKEND_HOST` | Backend BBS server hostname or IP | `127.0.0.1` |
| `BACKEND_PORT` | Backend BBS server port | `23` |
| `ENCODING_DETECTION` | Enable automatic UTF-8/CP437 encoding detection | `false` |
| `BACKEND_PORT_CP437` | Backend port for CP437 (DOS/ANSI) clients | `2323` |
| `BACKEND_PORT_UTF8` | Backend port for UTF-8 (Unicode) clients | `2423` |

### Connection Limits

| Variable | Description | Default |
|---|---|---|
| `MAX_CONNECTIONS` | Maximum total simultaneous connections | `100` |
| `MAX_CONNECTIONS_PER_IP` | Max simultaneous connections from a single IP (`0` = unlimited) | `0` |
| `CONNECTION_TIMEOUT` | Connection timeout in milliseconds (`0` to disable) | `300000` |

### Country Blocking

| Variable | Description | Default |
|---|---|---|
| `BLOCKED_COUNTRIES` | Comma-separated ISO country codes to block (e.g. `CN,RU,KP`) | _(empty)_ |
| `BLOCK_UNKNOWN_COUNTRIES` | Block connections with undetermined country | `false` |

### IP Lists

| Variable | Description | Default |
|---|---|---|
| `WHITELIST_PATH` | Path to IP whitelist file (bypasses all firewall rules) | _(empty)_ |
| `BLOCKLIST_PATH` | Path to IP blocklist file (permanent blocks) | _(empty)_ |

### Rate Limiting

| Variable | Description | Default |
|---|---|---|
| `RATE_LIMIT_ENABLED` | Enable connection flood protection | `true` |
| `MAX_CONNECTIONS_PER_WINDOW` | Max connection attempts per IP per time window | `10` |
| `RATE_LIMIT_WINDOW_MS` | Time window in milliseconds | `60000` |
| `RATE_LIMIT_BLOCK_DURATION_MS` | Temporary block duration in milliseconds | `300000` |

### Web Redirect

| Variable | Description | Default |
|---|---|---|
| `WEB_REDIRECT_ENABLED` | Redirect HTTP traffic on port 80 | `false` |
| `WEB_REDIRECT_URL` | Destination URL for the HTTP redirect | _(empty)_ |

### Logging

| Variable | Description | Default |
|---|---|---|
| `LOG_LEVEL` | Log level: `debug`, `info`, `warn`, `error` | `info` |

### SSH Server

| Variable | Description | Default |
|---|---|---|
| `SSH_ENABLED` | Enable the SSH server | `false` |
| `SSH_LISTEN_PORT` | Port to listen on for SSH connections | `2222` |
| `SSH_HOST_KEY` | Path to SSH host private key file | `./ssh_host_key` |
| `SSH_CIPHERS` | Comma-separated list of allowed SSH ciphers | _(see below)_ |

---

## Per-IP Connection Limit

The `MAX_CONNECTIONS_PER_IP` setting controls how many simultaneous active connections a single IP address can hold at one time. This is distinct from rate limiting, which tracks connection attempts over a time window.

**Examples:**
- `MAX_CONNECTIONS_PER_IP=0` — Unlimited (disabled)
- `MAX_CONNECTIONS_PER_IP=3` — Maximum 3 active connections per IP

When a new connection would exceed the limit, it is immediately rejected. Existing active connections from that IP are not affected. Whitelisted IPs are exempt from this limit.

---

## Web Redirect

When `WEB_REDIRECT_ENABLED=true`, BBS Firewall starts a lightweight HTTP server on port 80 that sends a `301 Moved Permanently` redirect to `WEB_REDIRECT_URL`. This redirects any web browser that navigates to your firewall's IP address.

```env
WEB_REDIRECT_ENABLED=true
WEB_REDIRECT_URL=https://yourbbs.example.com
```

**Note:** HTTPS (port 443) redirect requires a TLS certificate and is not handled by this module. Only plain HTTP (port 80) traffic is redirected.

**Note:** On Linux, listening on port 80 requires root privileges or the `CAP_NET_BIND_SERVICE` capability.

---

## Country Blocking

Block connections from specific countries using a local MaxMind GeoLite2 database.

### Setup

```bash
npm run setup-geoip
```

Follow the on-screen instructions to obtain and install the MaxMind GeoLite2 Country database. A free account at [maxmind.com](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) is required.

### Configuration

```env
BLOCKED_COUNTRIES=CN,RU,KP,IR
BLOCK_UNKNOWN_COUNTRIES=false
```

Use [ISO 3166-1 alpha-2](https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) two-letter country codes. The GeoIP database is queried locally with no external API calls.

---

## IP Filtering & Rate Limiting

### Whitelist

IPs in the whitelist bypass **all** firewall rules including country blocking, rate limiting, and the blocklist.

```bash
cp whitelist.txt.example whitelist.txt
# Edit whitelist.txt — one IP or CIDR range per line
```

```env
WHITELIST_PATH=./whitelist.txt
```

### Blocklist

IPs in the blocklist are permanently rejected regardless of other settings.

```bash
cp blocklist.txt.example blocklist.txt
# Edit blocklist.txt — one IP or CIDR range per line
```

```env
BLOCKLIST_PATH=./blocklist.txt
```

Both files support single IPs and CIDR ranges (e.g. `10.0.0.0/8`). Comments start with `#`.

### Rate Limiting

Automatically blocks IPs that connect too frequently within a sliding time window.

```env
RATE_LIMIT_ENABLED=true
MAX_CONNECTIONS_PER_WINDOW=10
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_BLOCK_DURATION_MS=300000
```

### Connection Decision Order

1. **Whitelist** — if matched, allow immediately (all other checks skipped)
2. Blocklist check — permanent block
3. Rate limit check — temporary block
4. Per-IP concurrent connection limit
5. GeoIP country check
6. Forward connection to backend

---

## SSH Server

BBS Firewall includes an optional SSH server that accepts any username and password and proxies the session to the backend BBS via telnet.

### Setup

Generate an SSH host key:

```bash
ssh-keygen -t rsa -b 4096 -f ssh_host_key -N "" -m PEM
```

Enable in `.env`:

```env
SSH_ENABLED=true
SSH_LISTEN_PORT=2222
SSH_HOST_KEY=./ssh_host_key
```

Connect from any SSH client:

```bash
ssh -p 2222 anyusername@yourserver.example.com
```

Any password will be accepted.

### Default SSH Ciphers

- `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`
- `aes128-ctr`, `aes192-ctr`, `aes256-ctr`
- `aes128-cbc`, `aes192-cbc`, `aes256-cbc`
- `3des-cbc` (for very old terminal clients)

### Known Limitation

Binary file transfers (Zmodem, Ymodem, etc.) do not work reliably over SSH due to PTY character processing. Use the telnet connection for file transfers and SSH for browsing.

---

## Encoding Detection

BBS Firewall can automatically detect whether a connecting client prefers UTF-8 or CP437 and route them to separate backend ports.

```env
ENCODING_DETECTION=true
BACKEND_PORT_CP437=2323
BACKEND_PORT_UTF8=2423
```

For SSH connections, detection is based on the client's `LANG`/`LC_ALL` environment variables and terminal type. Telnet connections default to CP437.

---

## Architecture

```
bbsfirewall/
├── server.js            # Main entry point and connection manager
├── proxy.js             # Bidirectional TCP proxy handler
├── ssh.js               # SSH server module
├── web-redirect.js      # HTTP redirect server (port 80)
├── config.js            # Configuration loading and validation
├── logger.js            # Log level filtering and output
├── geoip.js             # MaxMind GeoLite2 country lookup
├── ipfilter.js          # IP lists, rate limiting, per-IP connection tracking
├── encoding-detector.js # UTF-8/CP437 detection logic
├── download-geoip.js    # GeoIP database setup helper
├── package.json
├── .env.example         # Example configuration
├── whitelist.txt.example
├── blocklist.txt.example
└── data/                # GeoIP database directory
```

## License

MIT
