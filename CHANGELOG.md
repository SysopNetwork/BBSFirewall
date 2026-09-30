# Changelog

All notable changes to BBSFirewall are documented here. This is the first tracked
entry — see the git history for changes before v1.3.5.

## v1.5.0 — Unreleased

### ✨ Added

- **Host firewall (UFW) rule management** (Tools tab, Global Admin only, off by
  default). Preview and then manually apply tagged ufw rules built from your own
  settings — public listeners open to anyone, the config editor and admin SSH port
  limited to Trusted Hosts. Apply is refused if it would leave the admin SSH port
  without an allow rule. BBSFirewall never turns ufw itself on or off. Also shows
  the host's own ufw drop log.
- **Kernel-level block push** (`UFW_PUSH_BLOCKS`, off by default). Blocklist
  entries and trigger auto-blocks are mirrored into ufw as `deny from` rules, so
  blocked callers are dropped by the kernel even while BBSFirewall restarts.
  Syncs automatically; temporary trigger blocks are removed when they expire.
  Never pushes anything overlapping Trusted Hosts, the Whitelist, or loopback, and
  refuses to push at all with an empty Trusted Hosts list. Capped by
  `UFW_BLOCK_MAX_RULES` (default 1000). Status, "Sync now" and "Remove pushed
  rules" live in the Tools tab.
- **Log search** (Logs tab and `GET /api/logs/search`). Search every log file at
  once by text, type, level and date range — every word must match, `"quotes"`
  for a phrase, `-word` to exclude. Newest matches first, terms highlighted;
  click a result to open that file at that exact line, with the lines around it.
  Download all results as a text file.
- **Better log viewer**: line numbers, colour-coded levels with on/off chips per
  level, a live filter box, "Load older / newer lines" to page through files of
  any size (it used to stop at the last 512 KB), and **Follow (live)** on today's
  file to watch new lines arrive like `tail -f`.
- **Download log files** from the file list or the viewer — the whole file, no
  size limit (`GET /api/logs/download`) — or **every log file at once** as one
  `.zip` with "Download all (.zip)" (`GET /api/logs/download-all`). Streamed, so
  a big log folder doesn't use extra memory.

### 🔒 Security

- **Firewall Admin accounts can no longer change who can reach the editor.** The
  Config Editor, Management API and Host Firewall (UFW) settings, every list-file
  path, and the Trusted Hosts / API / Status allowlists are now Global Admin only —
  shown read-only to a Firewall Admin and refused by the server. A Firewall Admin
  could previously set their own API key (which outlives their account) or lock
  the Global Admin out.
- **List-file paths and `LOG_DIR` must stay inside the BBSFirewall folder**, and
  list files must be `.txt`. A changed path outside it is refused — it previously
  let one Save write any file on the host as root.
- **Turning MFA on asks for your current password**, and MFA setup is refused
  while MFA is already on (disable it first to replace an authenticator). A stolen
  session cookie could previously swap in its own authenticator.
- Login and MFA lockouts now count attempts that arrive at the same moment; the
  password and backup-code checks no longer pause every connected caller.
- Caller-supplied text (e.g. an SSH username) can no longer forge lines in the log
  files or console output.
- A role name that isn't recognised now gets the least access, not the most.
- Trigger regexes with repeated alternation `(a|aa)+` or nested groups `((a+))+`
  are now refused as catastrophic-backtracking risks, like `(a+)+` already was.

### 🐛 Fixed

- **Saving no longer drops auto-blocks.** Save used to rewrite every list file
  from what the page loaded, silently deleting trigger auto-blocks (and "Whitelist
  my IP") added since. Only lists you actually edited are written now, keeping any
  lines added on disk meanwhile; if a list changed on disk any other way, nothing
  is saved and you're asked to reload.
- Settings containing `\` or `"` (e.g. an API key) were saved in a form the
  firewall read back differently from what was typed. Values now load exactly as
  entered.
- A blocked caller that never hung up kept a connection slot until
  `CONNECTION_TIMEOUT` (forever at 0); refused connections are now dropped at once.
- SSH (terminate mode) now counts against `MAX_CONNECTIONS`, honours
  `CONNECTION_TIMEOUT` (idle = no session data; SSH keepalives don't count), and allows one BBS shell per SSH connection — one caller
  could previously open unlimited BBS sessions over a single connection.
- SSH (terminate mode) now acts as a proper telnet client toward the BBS: the
  backend's option negotiation no longer shows up as stray characters (e.g.
  `√♥ √☺ √ ²` before the first screen), and 0xFF bytes are escaped/unescaped
  correctly in both directions instead of being corrupted.
- Self-update and rollback no longer freeze every telnet/SSH session while
  `npm install` runs. A rollback no longer restores an old `status-trustedhosts.txt`
  or copies admin-account backups around, and a pre-release tag (`v1.5.0-beta.9`)
  can be pinned.
- An interrupted "Download all (.zip)" no longer leaves the download stuck — two of
  them used to block all further zip downloads until a restart.
- IPv6 whitelist/blocklist entries now match however they're written
  (`2001:DB8:0::1` = `2001:db8::1`).
- Trigger scanning no longer re-scans everything received so far on every
  packet (about 2 s of CPU per caller at a 64 KB `TRIGGER_SCAN_BYTES`).
- Kernel block push never denies an address in the Status or API allowlists.
- UFW Apply refuses to remove the only rule for a port sshd is listening on (e.g.
  after changing Admin SSH port before moving sshd).
- Changing a list's path now starts the new file with the current list, and
  editing that list in the same Save is refused (it went to the old file).
- System Stats, log Follow and UFW sync polling no longer keep an idle session
  signed in forever.
- The plain-HTTP redirect only echoes a well-formed `Host` header; a log file
  deleted mid-download returns 404 instead of an error.
- After "Restart firewall" (and self-update / reboot), the editor could reload
  while the old process was still shutting down and come up empty — no settings,
  no version — until a manual refresh. It now waits for the new process before
  reloading, and retries loading its settings instead of giving up on the first
  failed request. The exiting process also tells browsers to drop their
  connection, so on a host running ufw the page no longer stalls for up to a
  minute on a connection to the old process.
- Host firewall (UFW) Preview/Apply compared Trusted Hosts entries as typed
  (`1.2.3.4/32`, `0.0.0.0/0`) against ufw's own spelling (`1.2.3.4`, `Anywhere`),
  so such entries showed a change that never went away — and Apply would have
  deleted the matching rules. Rules are now always compared in ufw's form, and
  "Anywhere" rules are added/removed one address family at a time (removing the
  IPv4 one no longer silently removes the IPv6 one too).
- The startup banner now shows the version at every LOG_LEVEL.
- Host firewall (UFW) rules for the config editor port only admitted Trusted
  Hosts, silently blocking uptime monitors listed only in Status Trusted Hosts and
  Management API callers. The rule now admits all three lists (and any IP when the
  API is on with an empty API allowlist, matching the app itself).
- Logs tab: the search form and the per-category file tables now lay out
  identically on every box — they used to shift depending on which log types
  existed and how long their names were.
- The self-updater compared versions by splitting on dots only, so a pre-release
  like `1.5.0-beta.1` counted as *newer* than `1.5.0` and would never have been
  offered the final release. Pre-release tags now sort before their release.

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
