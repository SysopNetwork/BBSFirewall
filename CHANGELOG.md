# Changelog

All notable changes to BBSFirewall are documented here. This is the first tracked
entry — see the git history for changes before v1.3.5.

## v1.4.0 — 2026-09-23

### ✨ Added

- **Self-update from the Tools tab**: check for and apply tagged GitHub releases
  directly from the config editor (or the Management API), with automatic backup
  and rollback if anything fails. Linux only.
- **Multiple admin accounts**, each with its own password and MFA, and a role:
  Global Admin (can also manage other admin accounts) or Firewall Admin. A
  Global Admin can require MFA on a specific account, forcing setup at next
  login.
- **Full server reboot** (Tools tab, Global Admin only, off by default —
  enable it in Settings first). A meaningfully bigger action than the existing
  "Restart firewall" button: it reboots the whole host, not just the app. Requires
  typing "REBOOT" to confirm, and is refused unless BBSFirewall can confirm pm2
  has a working boot-time service on the host, with a live pre-flight check shown
  before you ever get to the confirmation box.
- **Unauthenticated `GET /status`** endpoint for uptime monitors (e.g. Uptime
  Kuma), gated by its own trusted-host list.
- **Random username / password generators** in "Add admin account" and the
  password-change form — the password generator uses the browser's crypto API
  and fills/reveals/copies a policy-compliant password in one click.
- **Light theme**, alongside the existing dark theme. A toggle in the header
  switches instantly and remembers your choice; the login and MFA screens pick
  up the saved (or OS-preferred) theme automatically.
- **Reset another admin's password** (Global Admin, Manage Admin Accounts):
  sets a new password on another account without needing its old one. Any
  active session on that account is signed out immediately.

### 🔐 Security

- **The Management API key and MaxMind license key are no longer sent to the
  browser in plaintext.** `GET /api/config` used to include their real values
  for every authenticated session regardless of role — a Firewall Admin
  account (or anyone who saw their screen or captured their traffic) could
  read a credential that grants full, MFA-free control over the firewall.
  These fields are now write-only, the same way the admin password itself
  already worked: leave the field blank on Save to keep the current key,
  type a new one to replace it.
- The Management API lane's read-only endpoints (`/api/config`, `/api/health`,
  `/api/stats`, `/api/update/check`, `/api/logs`, `/api/logs/view`) are no
  longer silent on success — each now logs who read what, so a valid key
  being used to pull config/health/stats/logs leaves an audit trail (visible
  once file-log verbosity is raised to `info`).
- Password change, admin account creation, MFA enable, backup-code
  regeneration, MFA-required policy changes, and log-file deletion are now
  captured under the *default* file-log verbosity — previously only
  password-reset, account-delete, and MFA-disable were, so half of the
  account/credential lifecycle went unlogged unless verbosity was raised.

### 🐛 Fixes

- GeoIP database download no longer hangs when a host's IPv6 route is
  configured but not actually reachable.
- GeoIP "Update database" no longer deletes the existing database before
  confirming a replacement can be downloaded.
- The web-redirect TLS certificate button no longer silently reuses the config
  editor's certificate when both cover the same hostname.

## v1.3.7 — 2026-09-17

### 🐛 Fixes

- Fixed the "Restart" button incorrectly reporting "pm2 was not found on this host"
  after certain restart sequences, even though pm2 was installed and working normally.

## v1.3.6 — 2026-09-17

Security hardening and stability fixes for SSH filtering, MFA, and the config editor.

### 🔐 Security

- SSH connections (`SSH_MODE=terminate`) now enforce country blocking consistently with
  telnet connections.
- IPv6 ranges in the whitelist and blocklist are now matched correctly.
- Enabling MFA, disabling MFA, and regenerating backup codes now sign out any other
  active admin sessions, matching existing password-change behavior.
- Authenticator codes can no longer be reused once accepted.

### 🐛 Fixes

- Fixed a config editor restart issue where, with "stay signed in" left unchecked, the
  previous session could briefly appear active before redirecting to the login page.

### ⬆️ Upgrading

- No action required — all changes apply automatically on update.

## v1.3.5 — 2026-09-16

A major update to the web config editor, focused on admin security and day-to-day
operability.

### 🔐 Security

- **Two-factor authentication** for the web config editor — TOTP authenticator app
  support with one-time backup codes, managed from a new self-service Security Settings
  page under your username in the header.
- Admin passwords are now **scrypt-hashed** and stored outside `.env`
  (`node setup-admin.js`), replacing the old plaintext `CONFIG_EDITOR_USERNAME` /
  `CONFIG_EDITOR_PASSWORD` fields.

### 🎨 Admin UI refresh

- Section icons throughout Settings and Tools.
- A dedicated **Lists** tab for the Whitelist / Blocklist / Trusted Hosts / Triggers /
  API Trusted Hosts editors, split out from Settings.
- Official Sysop Network branding — logo and favicon.
- "Performance" renamed **System Stats**, now also showing bandwidth (current / average
  / peak) and disk usage alongside CPU, memory, and network stats.

### 📜 Logging

- File logging is now **on by default**, with configurable retention (1–3650 days,
  default 30) and automatic daily pruning.
- The **Logs** tab automatically groups files by proxy type, with anything older than
  30 days folded into per-month sections — a long-running board's log list stays
  readable instead of turning into one giant table.

### 🔌 Management API

- Key-authenticated REST API for automating firewall configuration from your own
  tooling, alongside the browser UI.

### ⬆️ Upgrading

- Existing installs: run `node setup-admin.js` once to migrate your `.env` username and
  password into the new hashed store, then remove the old `CONFIG_EDITOR_USERNAME` /
  `CONFIG_EDITOR_PASSWORD` lines from `.env`.
- Two-factor auth is opt-in — enable it from Security Settings whenever you're ready.
