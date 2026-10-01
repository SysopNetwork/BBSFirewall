# 🔒 BBSFirewall Security Guide

BBSFirewall sits in front of your BBS on the open internet, and its admin tools can
rewrite its own configuration and run commands on the host. This guide covers how
to set it up so the firewall protects your board without becoming the weak point
itself.

It is written for **v1.5.0 and later**. A few protections described here are new
in 1.5.0 and are marked as such.

- [Reporting a vulnerability](#-reporting-a-vulnerability)
- [Quick checklist](#-quick-checklist)
- [1. The web config editor](#1-the-web-config-editor)
- [2. Admin accounts, passwords and MFA](#2-admin-accounts-passwords-and-mfa)
- [3. The Management API](#3-the-management-api)
- [4. The status endpoint](#4-the-status-endpoint)
- [5. SSH: choosing a mode](#5-ssh-choosing-a-mode)
- [6. PROXY Protocol and your backend](#6-proxy-protocol-and-your-backend)
- [7. Filtering callers](#7-filtering-callers)
- [8. The host firewall (ufw)](#8-the-host-firewall-ufw)
- [9. The server itself](#9-the-server-itself)
- [10. Updates](#10-updates)
- [11. Logs and monitoring](#11-logs-and-monitoring)
- [12. If you think something is wrong](#12-if-you-think-something-is-wrong)

---

## 🐞 Reporting a vulnerability

Please **do not** open a public issue for a security problem. Use GitHub's private
reporting instead: on the [BBSFirewall repository](https://github.com/SysopNetwork/BBSFirewall),
open the **Security** tab and choose **Report a vulnerability**. Only the
maintainers can see the report.

Include what you found, how to reproduce it, and which version you ran
(`"version"` in `package.json`, or the header of the web editor). You will get a
reply, and a fix will go out in a release with a note in [CHANGELOG.md](CHANGELOG.md).

**Supported versions:** only the latest release gets security fixes. If you are on
an older one, update first (see [Updates](#10-updates)) and check whether the
problem is still there.

---

## ✅ Quick checklist

If you only do ten things:

1. Keep **`trustedhosts.txt`** down to the addresses you actually administer from.
   Never put `0.0.0.0/0` or `::/0` in it.
2. Turn on **MFA** for every admin account, and store the backup codes offline.
3. Use **long passwords** — 12 characters is the minimum; a 4–5 word passphrase is
   better.
4. Give helpers a **Firewall Admin** account, not a Global Admin one.
5. Leave the **Management API** off unless something uses it. If it is on, use a
   random key and fill in `api-trustedhosts.txt`.
6. Make sure **nobody can reach your BBS directly** — only through the firewall.
7. Only enable **PROXY Protocol** when your backend understands it, and only accept
   it from the firewall.
8. Keep the **Whitelist** tiny. Whitelisted addresses skip every check.
9. Turn on **ufw**, and let BBSFirewall manage its rules from the Tools tab.
10. **Keep BBSFirewall and the OS updated**, and read the release notes.

---

## 1. The web config editor

The editor (default port **8443**) can change every setting, edit every list, restart
the firewall and run the Tools actions. Treat it like root access to the box.

### Who can reach it: `trustedhosts.txt`

The editor checks the caller's address against `trustedhosts.txt` **before** it shows
the login page. Anyone not listed gets `403 Forbidden`. An empty or missing file
locks *everyone* out — this is deliberate (fail-closed).

- List only the addresses you administer from: your home IP, your office, a VPN exit.
- Prefer single addresses (`/32`, `/128`) or small ranges. A mobile carrier's whole
  range lets in everyone else on that carrier too — they still need your password and
  MFA, but they can now try.
- **Never** add `0.0.0.0/0` or `::/0`. That turns the gate off.
- Locked yourself out? Edit `trustedhosts.txt` over SSH. The editor re-reads it when
  it is saved from the UI; after a hand edit, restart (`pm2 restart bbsfirewall`).

### Expose it directly, not behind a reverse proxy

The trusted-host check uses the real TCP connection's address and **ignores**
`X-Forwarded-For` and similar headers on purpose — those are trivial to fake. Behind
a reverse proxy, every request would appear to come from the proxy, and the gate
would let everyone in. The editor logs a warning if it sees a forwarding header.

If you would rather not expose the port at all, bind it to localhost and use an SSH
tunnel:

```env
CONFIG_EDITOR_BIND=127.0.0.1
```

```bash
ssh -L 8443:127.0.0.1:8443 you@your-firewall   # then browse to https://localhost:8443
```

(Put `127.0.0.1` in `trustedhosts.txt` for this.)

### Certificate

Use a real Let's Encrypt certificate if the box has a hostname (Tools tab, or
`bash setup-config-cert.sh admin.example.com --email you@example.com`). A self-signed
certificate (`--self-signed`) still encrypts the connection, but your browser can't
tell you're talking to the right server. Check the fingerprint the first time you
accept it.

### What already protects a logged-in session

You do not need to configure these, but it helps to know they are there:

- Session cookies are `HttpOnly`, `Secure`, `SameSite=Strict`, and tied to the IP you
  logged in from.
- Sessions end after 30 minutes idle (`CONFIG_EDITOR_SESSION_TIMEOUT_MS`) and after
  12 hours regardless.
- Every change needs a per-session CSRF token. Pages are served with a strict
  Content-Security-Policy.
- 5 wrong passwords or 5 wrong MFA codes lock that IP out for 15 minutes.

**Log out** when you are done on a shared or public computer (your username, top
right → Log out).

---

## 2. Admin accounts, passwords and MFA

### Creating the first account

The first admin account is created on the server, never over the web:

```bash
node setup-admin.js
```

It stores a scrypt hash of the password (never the password itself) in
`.admin-security.json`, readable by root only. Further accounts are added from
**Security Settings → Admin Accounts** in the editor.

### Two roles

| | Global Admin | Firewall Admin |
|---|:---:|:---:|
| Change ordinary settings (ports, limits, country blocking, triggers, …) | ✅ | ✅ |
| Edit Whitelist, Blocklist and Triggers | ✅ | ✅ |
| Restart the firewall, GeoIP and certificate tools | ✅ | ✅ |
| View and download logs | ✅ | ✅ |
| Change own password and MFA, "Whitelist my IP" | ✅ | ✅ |
| Config Editor, Management API and Host Firewall (UFW) settings | ✅ | ❌ |
| Trusted Hosts, API Trusted Hosts and Status allowlists; list-file paths | ✅ | ❌ |
| Install updates or roll back *(1.5.0)* | ✅ | ❌ |
| Delete log files *(1.5.0)* | ✅ | ❌ |
| Replace the SSH host key *(1.5.0)* | ✅ | ❌ |
| Manage admin accounts, UFW rules, reboot the server | ✅ | ❌ |

The rule of thumb: a Firewall Admin can run the firewall day to day, but cannot
change **who can reach the admin tools**, cannot change **what code runs**, and
cannot **erase the record** of what they did. Give co-sysops and helpers a Firewall
Admin account.

- One account per person. Shared logins make the logs useless.
- Delete an account the moment someone no longer needs it. Their open sessions end
  immediately.
- Keep more than one Global Admin, or keep SSH access to the box, so losing one
  account doesn't lock you out.

### Passwords

The minimum is **12 characters**. There are no "must contain a symbol" rules —
length matters far more. Four or five random words make a good passphrase. Use a
password manager, and don't reuse a password from anywhere else.

### MFA (two-factor)

Turn it on under **Security Settings → Enable MFA** and scan the QR code with any
authenticator app (Google Authenticator, Authy, 1Password, Bitwarden, …).

- You get **one-time backup codes** when you enable MFA. Print them or store them in
  your password manager — **not** on the same phone as the authenticator.
- A Global Admin can mark an account **"Require MFA"**. That account must set up MFA
  at its next login before it can do anything else.
- Turning MFA on asks for your current password *(1.5.0)*, so a stolen session can't
  swap in its own authenticator.

**Lost your phone and your backup codes?** Anyone with root on the server can clear
MFA for an account:

```bash
node disable-mfa.js --yes --user <username>
```

That is intentional: shell access to the box is the real trust boundary, so protect
it accordingly (see [The server itself](#9-the-server-itself)).

---

## 3. The Management API

The API (`API_ENABLED=true`) gives a program **the same power as a Global Admin**:
it can rewrite `.env`, edit every list, restart, update and roll back. It exists for
dashboards and hosting tools.

- **Leave it off** unless something actually uses it.
- **Use a long random key**, not a password you made up. The minimum is 24 characters:

  ```bash
  openssl rand -hex 32
  ```

- **Fill in `api-trustedhosts.txt`** with the addresses of the systems that call the
  API. Unlike `trustedhosts.txt`, an **empty file here allows any address**
  (fail-open), so the key is the only protection until you add entries.
- The key goes in a header (`Authorization: Bearer …` or `X-API-Key: …`), never in a
  URL, so it doesn't end up in logs or browser history.
- 5 wrong keys lock that IP out of the API for 15 minutes.
- **Rotating the key** needs a restart to take effect. Change it if it may have leaked
  — for example if it was pasted into a chat or committed to a repository.

---

## 4. The status endpoint

`GET /status` lets an uptime monitor (Uptime Kuma, etc.) check the firewall without
a login or key. It reports whether each listener is up, the uptime, and the
BBSFirewall version.

Because there is no key, it is guarded only by `status-trustedhosts.txt` — and that
file is **fail-closed**: empty or missing blocks everyone. List only your monitoring
server(s).

---

## 5. SSH: choosing a mode

`SSH_MODE` decides what listens on the BBS's SSH port (`SSH_LISTEN_PORT`). This is
the port **callers** use. Your own admin SSH login to the server is a different
port and a different program (`sshd`).

| Mode | What it does | Who checks the login |
|---|---|---|
| `off` | No SSH port. | — |
| `terminate` | BBSFirewall is the SSH server. It accepts **any** username and password and connects the caller to the BBS over telnet. | Your BBS's own login screen |
| `passthrough` | BBSFirewall only filters by IP and passes the encrypted SSH stream to a backend that runs its own SSH server. | The backend SSH server |

- Use `off` if your board has no SSH callers.
- **`terminate` is not an authentication layer.** It exists so callers can use an SSH
  client; the BBS's own login is what protects accounts. All the firewall's checks
  (blocklist, rate limit, caps, country, triggers) still apply. As of 1.5.0 they
  apply **the moment a caller connects** — a caller that connects and stays silent is
  checked and dropped too — and every caller must finish logging in within
  2 minutes.
- `terminate` needs a **host key** (Tools tab, or `ssh-keygen`). Keep it: replacing it
  makes every caller's SSH client warn that the server's identity changed, which
  trains people to click through real warnings.
- Use `passthrough` when your backend has its own SSH server, so public-key logins and
  SFTP keep working end to end.

---

## 6. PROXY Protocol and your backend

With `PROXY_PROTOCOL_ENABLED=true` (and `SSH_PROXY_PROTOCOL=true` for passthrough),
the firewall tells the backend the caller's real IP in a header at the start of each
connection. Two things matter:

1. **Only enable it if the backend understands it.** Otherwise the BBS sees the header
   as garbage and every connection breaks. Stock OpenSSH does **not** understand it,
   and neither does the Major BBS SSH daemon without an add-on module that reads the
   header — leave `SSH_PROXY_PROTOCOL=false` unless yours does.
2. **The backend must only accept PROXY headers from the firewall.** The header is
   just text. If anyone else can reach the backend directly, they can send their own
   header and claim to be any IP — including an address your BBS trusts.

That second point applies even without PROXY Protocol: **if callers can reach your
BBS directly, the firewall is optional for them.** Make sure the BBS's telnet and SSH
ports only accept connections from the firewall — run them on the same host bound to
`127.0.0.1`, put them on a private network, or restrict them with the backend host's
own firewall.

---

## 7. Filtering callers

These settings protect your board from scanners, floods and bots.

- **Whitelist** — addresses here skip **every** check: blocklist, rate limit, caps,
  country blocking and auto-block triggers. Keep it to a handful of addresses you
  truly trust, and avoid large ranges. Admin access to the editor is controlled by
  `trustedhosts.txt`, not the whitelist — you don't need to whitelist yourself to
  administer the box.
- **Blocklist** — permanent blocks, single IPs or CIDR ranges, IPv4 and IPv6.
- **Rate limiting** (on by default) — more than `MAX_CONNECTIONS_PER_WINDOW`
  connections in `RATE_LIMIT_WINDOW_MS` blocks that IP for
  `RATE_LIMIT_BLOCK_DURATION_MS`.
- **`MAX_CONNECTIONS_PER_IP`** — the default `0` means unlimited. A small number
  (say 3–10) stops one address from taking every line.
- **`CONNECTION_TIMEOUT`** — drops idle sessions. `0` turns it off, which lets idle or
  abandoned connections hold a slot indefinitely; only do that if your callers really
  need it.
- **Country blocking** — needs the free MaxMind database (Tools tab).
  `BLOCK_UNKNOWN_COUNTRIES=true` is stricter but also blocks some legitimate callers.
- **Auto-block triggers** (`TRIGGER_BLOCK_ENABLED`) — if a caller's first bytes match a
  pattern in `triggers.txt` (known exploit strings, HTTP requests on the telnet port,
  …), its IP is blocked. Start from `triggers.txt.example`.
  - `TRIGGER_BLOCK_MODE=blocklist` adds the IP to `blocklist.txt` for good; `temp`
    blocks it for `TRIGGER_BLOCK_DURATION_MS`.
  - Prefer plain-text patterns. Regex patterns that could take exponential time
    (`(a+)+`, `(a|aa)+`, …) are refused, but simple patterns are still faster and
    easier to get right.
  - Test a new pattern on a quiet day and watch the logs: a pattern that is too broad
    will block real callers.

---

## 8. The host firewall (ufw)

BBSFirewall filters callers in the application. A host firewall adds a second layer
in the kernel that keeps working even while BBSFirewall restarts.

1. Install ufw and **turn it on yourself**. BBSFirewall never turns ufw on or off.
   Allow your admin SSH port *before* enabling it:

   ```bash
   ufw allow 22/tcp     # or whatever port YOU log in on
   ufw enable
   ```

2. Set `UFW_ENABLED=true` and `HOST_ADMIN_SSH_PORT` (your admin SSH port, not the
   BBS's), then use **Tools → Host firewall (UFW) → Preview / Apply**. BBSFirewall
   opens the BBS ports to everyone and limits the editor and your admin SSH port to
   Trusted Hosts. Apply refuses to remove access to your admin SSH port.
   `UFW_AUTO_APPLY=true` makes the same changes automatically at startup and after
   each Save — removing someone from Trusted Hosts then closes their ufw access
   straight away. When a change looks risky, it is left for you to Apply.
3. Optionally set `UFW_PUSH_BLOCKS=true` to copy blocklist entries and trigger
   auto-blocks into ufw, so blocked addresses are dropped by the kernel. It never
   pushes anything that overlaps Trusted Hosts, the Whitelist or localhost, and it
   refuses to run with an empty Trusted Hosts list.

Before changing firewall rules on a remote box, make sure you know how to reach your
hosting provider's **web console**. It is the way back in if a rule ever locks you
out.

---

## 9. The server itself

BBSFirewall is only as safe as the machine it runs on.

- **Keep the OS patched.** On Ubuntu/Debian, turn on automatic security updates:
  `apt install unattended-upgrades`.
- **Lock down your own SSH login**: SSH keys instead of passwords
  (`PasswordAuthentication no`), and limit it to Trusted Hosts with ufw (above).
- **It usually runs as root**, because it binds ports below 1024 and manages ufw and
  certificates. That makes the admin editor root-equivalent — another reason to keep
  `trustedhosts.txt` tight and MFA on.
- **Secrets stay on the box.** These files hold credentials and are created
  readable by root only. They are already in `.gitignore` — never copy them into a
  repository, a support ticket or a chat:
  - `.env` (API key, MaxMind license key)
  - `.admin-security.json` (password hashes, MFA secrets, backup-code hashes)
  - `ssh_host_key`
  - `certs/` (TLS private keys)
  - `ENVBACKUPS/`, `ADMINBACKUPS/`, `.config-editor-sessions.json`
- **Back them up** somewhere safe and private. Restoring `.env`, the list files and
  `.admin-security.json` brings a rebuilt server back exactly as it was.
- **`REBOOT_ENABLED`** adds a full server reboot button for Global Admins. Leave it
  off unless you need it.

---

## 10. Updates

- **Update from the Tools tab** (Global Admin only) or on the server with
  `node update.js`. Each update backs up the current version first and restores it
  automatically if anything fails. Your `.env` and list files are never touched.
- Updates come from **tagged releases** of the official repository,
  [SysopNetwork/BBSFirewall](https://github.com/SysopNetwork/BBSFirewall). Be wary of
  copies from anywhere else.
- **Read the release notes** ([CHANGELOG.md](CHANGELOG.md)) before updating. Security
  fixes are listed under **🔒 Security**.
- **Roll back** from Tools → Updates → Backups, or `node update.js --rollback`, if a
  release misbehaves. Rolling back to a version older than a security fix brings the
  problem back, so go forward again once the issue is fixed.
- If you installed with `git clone`, `git pull && npm install` also works; check
  `git log` to see what changed.

---

## 11. Logs and monitoring

- **File logs** are on by default, one file per day per service, kept for
  `LOG_RETENTION_DAYS` (30). At the default level (`connections`) the
  `config-editor` log records every admin login (and failed attempt), saved
  settings, restarts, updates, and password, MFA and account changes, with the
  account name and IP. Don't lower `CONFIG_EDITOR_LOG_LEVEL` below `connections`,
  or you lose that record.
- **Only a Global Admin can delete log files** *(1.5.0)*, so a Firewall Admin can't
  remove the record of their own actions.
- **Look at the logs now and then**: repeated failed logins to the editor, a blocklist
  that suddenly grows fast, or a lot of rejected connections from one range are all
  worth a closer look. The **Logs** tab has a search.
- **Watch uptime** with the [status endpoint](#4-the-status-endpoint), so you hear
  about an outage before your callers do.

---

## 12. If you think something is wrong

If you suspect someone else got into the admin editor or the server:

1. **Restrict access first.** Over SSH, cut `trustedhosts.txt` down to your current
   address only and restart.
2. **Check the admin accounts** (Security Settings → Admin Accounts). Delete any you
   don't recognise. Their sessions end immediately.
3. **Change every admin password**, re-enroll MFA, and regenerate backup codes.
4. **Rotate the `API_KEY`** and restart, if the API is on.
5. **Review `.env` and the lists** for changes you didn't make — look especially at
   Trusted Hosts, the Whitelist, the API settings and `BACKEND_HOST`. `ENVBACKUPS/`
   holds earlier copies of `.env` to compare against.
6. **Read the `config-editor` logs** around the time things changed.
7. **Check the server itself**: unknown SSH keys in `~/.ssh/authorized_keys`, new
   users, cron jobs. If root itself may be compromised, rebuild the server and restore
   your backed-up configuration rather than trying to clean it.
8. If you believe BBSFirewall has a flaw that let this happen, please
   [report it](#-reporting-a-vulnerability).
