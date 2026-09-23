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

📋 **[See what's new in v1.4.0 →](CHANGELOG.md)**

</div>

---

## ✨ Features

| | Feature | Description |
|---|---|---|
| 🔀 | **TCP Proxy** | Forwards telnet connections to a backend BBS server |
| 🔒 | **SSH Server** | Encrypted SSH access on any port, proxied to the telnet backend |
| 🌐 | **HTTPS Redirect** | Redirects both HTTP (port 80) and HTTPS (port 443) to a configured URL |
| 🔑 | **Let's Encrypt** | Built-in cert setup script with auto-renewal, no downtime required |
| 🛠️ | **Web Config Editor** | HTTPS admin UI (port 8443) to edit `.env` and IP lists; trusted-host + login gated |
| 🔐 | **Two-Factor Auth** | TOTP authenticator app + one-time backup codes protect the admin UI, on top of scrypt-hashed passwords |
| 📜 | **Log Viewer** | Browse, view, and delete per-proxy log files from the browser — automatically grouped by type, with anything older than 30 days folded into per-month sections |
| 📊 | **System Stats** | Live CPU, memory, disk, and bandwidth metrics for the running firewall process |
| 🔌 | **Management API** | Key-authenticated REST API to automate firewall configuration from your own tooling |
| 📡 | **PROXY Protocol v1** | Passes the real client IP to the backend BBS (requires compatible backend) |
| 🌍 | **Country Blocking** | Block connections by country using a local GeoIP database |
| ✅ | **IP Whitelist** | Trusted IPs that bypass all firewall rules |
| 🚫 | **IP Blocklist** | Permanently block specific IPs or CIDR ranges |
| ⚡ | **Rate Limiting** | Automatic flood protection with configurable temporary blocks |
| 🎯 | **Auto-Block Triggers** | Blacklist an IP that sends a known bot/scanner/exploit string in its first bytes |
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

## 🔄 Updating

```bash
node update.js --check     # see if a newer release exists — changes nothing
node update.js             # check, confirm, download, apply, then offer to restart
node update.js --yes       # skip the "apply this update?" confirmation (still asks about restart)
node update.js --rollback  # list backups made by previous updates
node update.js --rollback pre-update-1.3.7-2026-09-22T12-00-00-000Z   # restore one
```

Every update backs up the current install first, downloads the tagged GitHub release,
overlays it, reinstalls dependencies, and re-validates your `.env` before restarting —
if anything in that chain fails, it automatically restores the pre-update backup so the
old version keeps running instead of a broken one. Your `.env` and list files (whitelist,
blocklist, trusted hosts, triggers) are never touched by an update.

The same thing is available from the web editor's **Tools** tab (an "Update now" button
next to GeoIP/SSH key/certs), and over the [Management API](API.md)
(`GET /api/update/check`, `POST /api/update/apply`, `POST /api/update/rollback`).

Self-update is **Linux-only** (it shells out to `tar` and `pm2`) — on another OS, or a
host missing `tar`, the check still works so you can see whether an update exists, but
applying one is refused; update that install manually (`git pull` or re-download +
`npm install`) instead. It also never runs on a schedule — always an explicit command or
button click.

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
<tr><td><code>CONNECTION_TIMEOUT</code></td><td>Idle connection timeout in milliseconds (<code>0</code> to disable)</td><td><code>300000</code></td></tr>
<tr><td><code>BACKEND_CONNECT_TIMEOUT_MS</code></td><td>Max wait for the backend TCP connection to establish (<code>0</code> to disable)</td><td><code>10000</code></td></tr>
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

### 🎯 Auto-Block Triggers

Scan the first bytes a telnet/SSH caller sends for known bot / scanner / exploit strings and blacklist the source IP on a match. Patterns are read from a list file — plain text is a case-insensitive substring, `/regex/flags` is a JS regex, and `\xNN \r \n \t \0` escapes work in plain patterns (for TLS/binary probes). Also applies to SSH shell input and remote commands in terminate mode. Whitelisted IPs are exempt. Copy `triggers.txt.example` to `triggers.txt` to start.

<table>
<tr>
<th width="270">Variable</th>
<th>Description</th>
<th width="170">Default</th>
</tr>
<tr><td><code>TRIGGER_BLOCK_ENABLED</code></td><td>Enable auto-block on a trigger match</td><td><code>false</code></td></tr>
<tr><td><code>TRIGGER_LIST_PATH</code></td><td>Path to the trigger pattern file</td><td><code>./triggers.txt</code></td></tr>
<tr><td><code>TRIGGER_SCAN_BYTES</code></td><td>Bytes of the caller's first data to scan (16–65536)</td><td><code>1024</code></td></tr>
<tr><td><code>TRIGGER_BLOCK_MODE</code></td><td><code>blocklist</code> = append to <code>blocklist.txt</code> (permanent); <code>temp</code> = in-memory block</td><td><code>blocklist</code></td></tr>
<tr><td><code>TRIGGER_BLOCK_DURATION_MS</code></td><td>Block length for <code>temp</code> mode</td><td><code>86400000</code></td></tr>
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

### 🛠️ Web Config Editor

<table>
<tr>
<th width="270">Variable</th>
<th>Description</th>
<th width="170">Default</th>
</tr>
<tr><td><code>CONFIG_EDITOR_ENABLED</code></td><td>Enable the HTTPS web config editor</td><td><code>false</code></td></tr>
<tr><td><code>CONFIG_EDITOR_PORT</code></td><td>Port the editor listens on (must differ from LISTEN_PORT / SSH port)</td><td><code>8443</code></td></tr>
<tr><td><code>CONFIG_EDITOR_BIND</code></td><td>Address to bind the editor listener to</td><td><code>0.0.0.0</code></td></tr>
<tr><td><code>CONFIG_EDITOR_CERT_PATH</code></td><td>Path to the editor's TLS certificate (fullchain)</td><td><code>./certs/config-editor/fullchain.pem</code></td></tr>
<tr><td><code>CONFIG_EDITOR_KEY_PATH</code></td><td>Path to the editor's TLS private key</td><td><code>./certs/config-editor/privkey.pem</code></td></tr>
<tr><td><code>CONFIG_EDITOR_TRUSTEDHOSTS_PATH</code></td><td>IPv4/IPv6 CIDR allowlist file — empty/missing denies all</td><td><code>./trustedhosts.txt</code></td></tr>
<tr><td><code>CONFIG_EDITOR_SESSION_TIMEOUT_MS</code></td><td>Idle session timeout (min 60000)</td><td><code>1800000</code></td></tr>
<tr><td><code>CONFIG_EDITOR_PM2_APP</code></td><td>pm2 process name the Restart button acts on</td><td><code>bbsfirewall</code></td></tr>
<tr><td><code>CONFIG_EDITOR_HTTP_REDIRECT_ENABLED</code></td><td>Answer plain-HTTP requests on the editor's own port with a 301 to <code>https://</code> (same port, no extra listener)</td><td><code>true</code></td></tr>
</table>

### 🔌 Management API

<table>
<tr>
<th width="270">Variable</th>
<th>Description</th>
<th width="170">Default</th>
</tr>
<tr><td><code>API_ENABLED</code></td><td>Enable the management API (requires <code>CONFIG_EDITOR_ENABLED=true</code>)</td><td><code>false</code></td></tr>
<tr><td><code>API_KEY</code></td><td>Bearer key clients send; minimum 24 characters</td><td><em>(required when enabled)</em></td></tr>
<tr><td><code>API_TRUSTEDHOSTS_PATH</code></td><td>Optional source-IP allowlist file; empty/missing = any IP (key still required)</td><td><code>./api-trustedhosts.txt</code></td></tr>
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

## 🛠️ Web Config Editor

An HTTPS admin UI (default port **8443**) for editing `.env` and the whitelist / blocklist / trustedhosts files from a browser instead of SSH. It runs in-process with the firewall on its own port and its own TLS certificate.

### Two gates

1. **Trusted-host allowlist** — `trustedhosts.txt`, one IPv4/IPv6 address or CIDR per line. Any address **not** matched is refused before the login page is even shown. An empty or missing file locks everyone out (fail-closed).
2. **Login** — a scrypt-hashed password (`node setup-admin.js` creates it in `.admin-security.json`, kept out of `.env`), checked with a constant-time compare and exchanged for a short-lived, IP-bound session cookie (`HttpOnly`, `Secure`, `SameSite=Strict`). Optional MFA (TOTP + one-time backup codes) can be turned on from Security Settings in the header. Failed logins/MFA codes lock the source IP for 15 minutes after 5 tries. Mutating requests also require a per-session CSRF token.

### Setup

```bash
# 1. Certificate — Let's Encrypt for a public hostname...
bash setup-config-cert.sh admin.example.com --email you@example.com

# ...or self-signed for a bare IP / internal hostname
bash setup-config-cert.sh 95.182.86.146 --self-signed

# 2. Allowlist the IP(s) you will administer from
cp trustedhosts.txt.example trustedhosts.txt
$EDITOR trustedhosts.txt

# 3. Enable it in .env
CONFIG_EDITOR_ENABLED=true
CONFIG_EDITOR_PORT=8443
CONFIG_EDITOR_CERT_PATH=./certs/config-editor/fullchain.pem
CONFIG_EDITOR_KEY_PATH=./certs/config-editor/privkey.pem
CONFIG_EDITOR_TRUSTEDHOSTS_PATH=./trustedhosts.txt

# 4. Create the admin account (username/password no longer live in .env)
node setup-admin.js

# 5. Restart
pm2 restart bbsfirewall
```

Then browse to `https://your-host:8443/`. Enable MFA (TOTP + backup codes) afterward
from Security Settings, under your username in the top-right of the header.

> **Expose the editor port directly.** The trusted-host gate matches the real TCP peer address — it deliberately ignores `X-Forwarded-For`. Behind a reverse proxy every request would appear to come from the proxy, breaking the gate; the editor logs a warning if it sees a forwarding header. For defence in depth, also restrict the port at the host firewall (`ufw allow from <admin-ip> to any port 8443`) or bind it to a private interface / `127.0.0.1` (SSH tunnel) with `CONFIG_EDITOR_BIND`.

### Tabs

- **Settings** — the whole `.env`, grouped into collapsible sections with per-field help and a *more* toggle for longer explanations (e.g. SSH terminate vs passthrough).
- **Lists** — the **Whitelist / Blocklist / Trusted Hosts / Triggers / API Trusted Hosts** editors, labeled by name, not filename, with "Add my IP" / "/24" / "/29" quick-add buttons on Whitelist and Blocklist.
- **Tools** — one-click **download / update** of the MaxMind GeoIP database (needs `MAXMIND_LICENSE_KEY` saved), **generate an SSH host key** for terminate mode, **issue a Let's Encrypt certificate** for the editor or the port-443 redirect (installs certbot if missing; console output shown on success or failure), and **check for / apply updates** (see [Updating](#-updating) — Linux-only, restarts on success, automatic rollback on failure).
- **System Stats** — live CPU %, load average, memory, process RSS, disk, bandwidth (current/avg/peak), BBSFirewall folder and log-file disk usage, per-interface network throughput, and firewall counters (active connections, accepted/rejected, blocklist size, temp-blocked IPs). Auto-refreshes every 4s.
- **Logs** — browse the per-proxy rotated log files written by `file-logger.js` (`LOG_FILE_ENABLED`, on by default — see Retention below). Files are grouped by proxy type, with anything older than 30 days automatically folded into per-month sections so a long-running board's log list stays readable instead of scrolling forever. View a file's content (large files are tailed to the last 512 KB) or permanently delete one.
- **Security Settings** — under your username in the header: change your password, enable/disable MFA (TOTP QR code + one-time backup codes), regenerate backup codes, and whitelist your own IP.

### Behavior

- **Save** writes `.env` after a timestamped backup into an `ENVBACKUPS/` folder next to `.env` (`.env.bak.<ISO>`, newest 15 kept), then validates the result in a fresh process. If validation fails the previous `.env` is restored and the errors are returned — the running config is never left broken.
- `.env` comments and layout are preserved; disabling an optional field comments its line out; new keys are appended under a marked block.
- Editing `trustedhosts.txt` in the UI takes effect immediately (no restart). `.env` changes need a restart — the **Restart firewall** button runs `pm2 restart`, with a **Stay signed in after restart** checkbox: leave it checked and the page carries your session over and reconnects on its own; uncheck it to be logged out on restart.
- Downloading/updating the GeoIP database and issuing the editor's own certificate both take effect live (no restart). Issuing the port-443 redirect certificate needs a restart.
- The `setup-config-cert.sh` Let's Encrypt mode installs its own renewal hook; renew manually with `bash setup-config-cert.sh --renew`.

### Plain-HTTP redirect

A browser that visits `http://your-host:8443` (plain HTTP on the editor's HTTPS port) would otherwise fail the TLS handshake with `ERR_EMPTY_RESPONSE`. With `CONFIG_EDITOR_HTTP_REDIRECT_ENABLED=true` (the default) the editor peeks the first byte of each connection: a TLS handshake is served normally, and a plain-HTTP request gets a `301` to `https://<CONFIG_EDITOR_CERT_DOMAIN or the request's Host>:<port><path>`. Same port, no extra listener. Set it to `false` to just drop such requests.

### Certificate renewal

```bash
bash setup-config-cert.sh --renew
```

### Management API

Enable `API_ENABLED=true` and set `API_KEY` (min 24 chars) to expose the same operations as the editor UI over REST, on the **same HTTPS port** under `/api/*`. Meant for a remote dashboard. The config editor must be enabled — the API has no listener of its own.

> **Full reference, response shapes, and sample code (curl / Node / Python): [API.md](API.md).** A ready-to-run check is bundled as `api-smoke.sh`.

**Auth** — every request carries the key, not a cookie:

```
Authorization: Bearer <API_KEY>          # or:   X-API-Key: <API_KEY>
```

The key is compared in constant time and never logged; 5 bad keys from one IP lock that IP out of the API for 15 minutes (its own counter — separate from the browser login). The API lane is **independent of `trustedhosts.txt`** — a caller does not need to be a trusted editor host — but you can narrow it by source IP with `api-trustedhosts.txt` (same file format; **empty or missing = any IP**, the key still applies). Edit it live from the `api-trustedhosts.txt` tab.

| Method + path | Does |
|---|---|
| `GET /api/config` | Full `.env` (grouped, with the current list-file contents and `status.version`) |
| `GET /api/health` | Cert/GeoIP/SSH host key health (Tools tab) |
| `GET /api/stats` | Live host + firewall metrics (CPU, memory, disk, network, connection counters) |
| `POST /api/save` | Write `.env` and/or the list files — same body the UI sends: `{"env":{"KEY":{"value":"...","enabled":true}},"files":{"blocklist":"..."}}`. Same backup → validate-in-child → restore-on-failure guard. |
| `POST /api/restart` | `pm2 restart` the firewall |
| `POST /api/geoip` | Download/update the MaxMind database (`{"action":"download"\|"update"}`) |
| `POST /api/sshkey` | Generate the SSH host key (`{"type":"rsa"\|"ed25519","overwrite":false}`) |
| `POST /api/cert` | Issue a Let's Encrypt certificate (`{"target":"editor"\|"redirect"}`) |
| `GET /api/update/check` | Check GitHub for a newer release |
| `POST /api/update/apply` | Download and apply an update, then restart (`{}` or `{"tag":"v1.4.0"}`) |
| `POST /api/update/rollback` | Restore a previous update backup, then restart (`{"backup":"pre-update-…"}`) |

```bash
curl -s https://your-host:8443/api/stats -H "Authorization: Bearer $API_KEY"

curl -s https://your-host:8443/api/save -H "Authorization: Bearer $API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"env":{"BLOCKED_COUNTRIES":{"value":"CN,RU,KP","enabled":true}},"files":{}}'
```

> The API has the **same power as the admin UI** — including rewriting `.env` (its own `API_KEY`, the editor password, everything). A changed `API_KEY` or any `.env` mode change applies on the next restart, not immediately.

---

## 📈 Status Endpoint (uptime monitoring)

A lightweight `GET /status` on the config editor's HTTPS port, for monitoring tools like [Uptime Kuma](https://github.com/louislam/uptime-kuma) that just need a quick liveness check — no API key, no login. Requires `CONFIG_EDITOR_ENABLED=true` (it shares that listener; no port of its own).

```bash
curl -s https://your-host:8443/status
```

```json
{
  "ok": true,
  "version": "1.4.0",
  "uptimeSec": 86412,
  "listeners": { "telnet": true, "ssh": true, "webRedirect": true, "configEditor": true }
}
```

`ok` reflects the telnet listener specifically (the app's core job); `listeners` gives a per-service breakdown if your monitor supports a JSON-path check (Uptime Kuma's "HTTP(s) - Json Query" monitor type, checking `$.ok == true`, for example). Values are read from the actual running servers, not just from `.env` flags, so a bind failure shows up as down.

Since there's **no key or session to fall back on**, `status-trustedhosts.txt` is **fail-closed** like `trustedhosts.txt` — an empty or missing file blocks *everyone*, including you. Add your monitoring host's IP before relying on this:

```
# status-trustedhosts.txt
203.0.113.10        # your Uptime Kuma server
```

Edit it live from the **Lists** tab ("Status Endpoint Trusted Hosts") or `STATUS_TRUSTEDHOSTS_PATH` in `.env`.

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
| 7 | 🎯 Trigger scan | While forwarding, scan the caller's first `TRIGGER_SCAN_BYTES`; blacklist + drop on a match |

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
├── config-editor.js       # HTTPS web config editor (server, sessions, .env writer, tools, stats)
├── config-editor-ui.js    # Config editor HTML views (login, MFA challenge, app shell)
├── security.js            # Admin password (scrypt) + MFA (TOTP/backup codes) store
├── wordlist.js            # Word list backing 4-word MFA backup codes
├── setup-admin.js         # One-time admin account creation (node setup-admin.js)
├── disable-mfa.js         # Emergency MFA disable (node disable-mfa.js --yes)
├── trustedhosts.js        # IPv4/IPv6 CIDR allowlist matching for the config editor
├── metrics.js             # Shared live counters read by the config editor's System Stats tab
├── proxy-protocol.js      # PROXY Protocol v1 header builder
├── config.js              # Configuration loading and validation
├── logger.js              # Log level filtering
├── geoip.js               # MaxMind GeoLite2 country lookup
├── ipfilter.js            # IP lists, rate limiting, per-IP connection tracking
├── encoding-detector.js   # UTF-8/CP437 detection logic
├── download-geoip.js      # GeoIP database setup helper
├── setup-certs.sh         # Let's Encrypt certificate setup script (web redirect)
├── setup-config-cert.sh   # TLS cert setup for the config editor (LE or self-signed)
├── api-smoke.sh           # Management API smoke test
├── ecosystem.config.js    # PM2 process config
├── package.json
├── API.md                 # Management API reference + sample code
├── .env.example           # Documented example configuration
├── whitelist.txt.example
├── blocklist.txt.example
├── trustedhosts.txt.example
├── triggers.txt.example
├── api-trustedhosts.txt.example
└── data/                  # GeoIP database (not included, run setup-geoip)
```

---

## 🏆 Credits

BBSFirewall is developed and maintained by [Mark Laudenbach](https://github.com/laudenbachm) at [Sysop Network](https://github.com/SysopNetwork).

Built on the foundation of [bbsfw](https://github.com/ryanfantus/bbsfw) by [Ryan Fantus](https://github.com/ryanfantus). Solid starting point — thanks for putting that together.

---

## 📄 License

MIT — Copyright (c) 2026 Sysop Network
