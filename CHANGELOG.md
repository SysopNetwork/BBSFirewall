# Changelog

All notable changes to BBSFirewall are documented here. This is the first tracked
entry — see the git history for changes before v1.3.5.

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
