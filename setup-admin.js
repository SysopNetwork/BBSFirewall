#!/usr/bin/env node

/**
 * BBSFirewall - config editor admin account setup
 *
 * Creates .admin-security.json (the scrypt-hashed password + MFA store used
 * by config-editor.js). This is deliberately a shell-run script rather than
 * a web form: bootstrapping the very first admin credential over an
 * unauthenticated HTTP endpoint would be a new, trusted-host-gate-only
 * attack surface, which is exactly the kind of thing this project's whole
 * design avoids. Run this once, over SSH, as whoever owns the BBSFirewall
 * files.
 *
 *   node setup-admin.js            interactive prompts for username/password
 *   node setup-admin.js --reset    overwrite an existing admin account
 *
 * If .env still has CONFIG_EDITOR_USERNAME/CONFIG_EDITOR_PASSWORD set (the
 * pre-MFA login method), this offers to import them so upgraders keep their
 * existing password instead of being forced to pick a new one. It never
 * writes to .env itself — remove the old lines there afterward.
 *
 * The password prompt is NOT masked: the SSH session itself is already
 * encrypted, this runs once during setup, and readline's masking trick needs
 * real keypress/raw-mode handling that gets unreliable over anything other
 * than a live TTY (it silently breaks under piped input, for example). Not
 * worth the fragility for a one-time bootstrap script — mind your terminal
 * scrollback/screen-sharing while typing.
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const readline = require('readline');
const security = require('./security');

// override: true so a stale CONFIG_EDITOR_USERNAME/PASSWORD in the inherited
// shell environment doesn't shadow what .env actually says right now.
require('dotenv').config({ quiet: true, override: true });

const RESET = process.argv.slice(2).includes('--reset');

console.log('=== BBSFirewall - Admin Account Setup ===\n');

if (security.secretsExist() && !RESET) {
  console.log(`An admin account already exists (${security.STORE_PATH}).`);
  console.log('Re-run with --reset to replace it, or use the "Security Settings"');
  console.log('page in the web editor to change the password normally.');
  process.exit(1);
}

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

// Sequential rl.question() calls over piped (non-TTY) input can silently
// drop lines: readline flushes every buffered line into 'line' events as
// soon as a data chunk arrives, but question() only listens for the next
// one, so any question issued after an `await` has already missed lines
// that arrived earlier in the same chunk. The async-iterator protocol
// queues every emitted line instead, so pulling from it one at a time here
// is correct for both piped input (this is also how the smoke test that
// drives this script works) and a real interactive TTY.
const lines = rl[Symbol.asyncIterator]();

async function ask(question) {
  process.stdout.write(question);
  const { value, done } = await lines.next();
  if (done) {
    console.log('\nNo more input (stdin closed) - aborting.');
    process.exit(1);
  }
  return value;
}

async function main() {
  let username = '';
  let password = null;

  const existingUser = (process.env.CONFIG_EDITOR_USERNAME || '').trim();
  const existingPass = process.env.CONFIG_EDITOR_PASSWORD || '';

  if (existingUser && existingPass) {
    console.log(`Found an existing .env login: username "${existingUser}".`);
    const importIt = (await ask('Import it as the new admin account? [Y/n] ')).trim().toLowerCase();
    if (importIt === '' || importIt === 'y' || importIt === 'yes') {
      username = existingUser;
      password = existingPass;
      console.log('Imported. Remove CONFIG_EDITOR_USERNAME/CONFIG_EDITOR_PASSWORD from .env');
      console.log('once you have confirmed you can log in with it.\n');
    }
  }

  if (!username) {
    while (!username) {
      username = (await ask('Admin username: ')).trim();
      if (!username) console.log('Username cannot be empty.');
    }
  }

  if (!password) {
    for (;;) {
      const p1 = await ask(`Admin password (min ${security.MIN_PASSWORD_LENGTH} characters): `);
      const pwErr = security.passwordError(p1);
      if (pwErr) {
        console.log(pwErr);
        continue;
      }
      const p2 = await ask('Confirm password: ');
      if (p1 !== p2) {
        console.log('Passwords did not match, try again.\n');
        continue;
      }
      password = p1;
      break;
    }
  } else {
    const pwErr = security.passwordError(password);
    if (pwErr) {
      console.log(`The imported .env password does not meet the current password policy: ${pwErr}`);
      process.exit(1);
    }
  }

  // Wipes any existing store and starts over with exactly one 'master_admin'
  // account - additional admins (role 'firewall_admin') are added afterward
  // from Security Settings > Admin Accounts in the web editor, not here.
  security.resetToSingleAccount(username, password);

  rl.close();
  console.log(`\nAdmin account "${username}" (Provider / Master Admin) saved to ${security.STORE_PATH} (mode 600).`);
  console.log('Restart BBSFirewall (or pm2 restart) so the config editor picks it up.');
  console.log('You can enable MFA, and add more admin accounts, afterward from Security');
  console.log('Settings in the web editor.');
}

main().catch((err) => {
  console.error(`Setup failed: ${err.message}`);
  process.exit(1);
});
