#!/usr/bin/env node

/**
 * BBSFirewall - emergency MFA disable
 *
 * Clears MFA (TOTP secret + backup codes) from .admin-security.json without
 * going through the web editor - for when an admin has lost their
 * authenticator device and every backup code, and is locked out of their
 * own firewall. Leaves the username/password untouched.
 *
 * Requires --yes; a bare `node disable-mfa.js` refuses and changes nothing.
 * There is deliberately no password re-prompt here: filesystem access to
 * this app's own files (as root, or whatever account runs it) is already
 * the trust boundary this script relies on - the same boundary that already
 * lets that account read/rewrite .env, every IP list, and the SSH host key.
 *
 * With more than one admin account configured, pass --user to say which one
 * (a bare run just lists the usernames rather than guessing).
 *
 *   node disable-mfa.js --yes [--user <username>]
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const security = require('./security');

const args = process.argv.slice(2);
const YES = args.includes('--yes');
const userFlagIdx = args.indexOf('--user');
const requestedUser = userFlagIdx !== -1 ? args[userFlagIdx + 1] : null;

console.log('=== BBSFirewall - Emergency MFA Disable ===\n');

const accounts = security.listAccounts();
if (!accounts.length) {
  console.log(`No admin account found (${security.STORE_PATH} is missing or unreadable).`);
  console.log('Nothing to disable. Run setup-admin.js first if you need to create one.');
  process.exit(1);
}

let secrets;
if (requestedUser) {
  secrets = accounts.find((a) => a.username === requestedUser);
  if (!secrets) {
    console.log(`No admin account named "${requestedUser}". Configured accounts: ` +
      accounts.map((a) => a.username).join(', '));
    process.exit(1);
  }
} else if (accounts.length === 1) {
  secrets = accounts[0];
} else {
  console.log('More than one admin account is configured - re-run with --user to say which one:');
  for (const a of accounts) console.log(`  ${a.username} (${a.role}, MFA ${a.mfa.enabled ? 'enabled' : 'off'})`);
  process.exit(1);
}

if (!secrets.mfa || !secrets.mfa.enabled) {
  console.log('MFA is not currently enabled on this account. Nothing to do.');
  process.exit(0);
}

if (!YES) {
  console.log(`MFA is enabled for admin "${secrets.username}".`);
  console.log('This will turn it off and permanently invalidate every backup code.');
  console.log('Re-run with --yes to confirm:\n');
  console.log('  node disable-mfa.js --yes\n');
  process.exit(1);
}

secrets.mfa = { enabled: false, secret: null, pendingSecret: null, confirmedAt: null };
secrets.backupCodes = [];
security.writeSecrets(secrets);

console.log(`MFA disabled for admin "${secrets.username}".`);
console.log('A plain password login will work again immediately - no restart needed.');
console.log('Re-enable MFA (and get a fresh set of backup codes) from Security Settings');
console.log('in the web editor whenever you are ready.');
