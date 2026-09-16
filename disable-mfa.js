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
 *   node disable-mfa.js --yes
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const security = require('./security');

const YES = process.argv.slice(2).includes('--yes');

console.log('=== BBSFirewall - Emergency MFA Disable ===\n');

const secrets = security.readSecrets();
if (!secrets) {
  console.log(`No admin account found (${security.STORE_PATH} is missing or unreadable).`);
  console.log('Nothing to disable. Run setup-admin.js first if you need to create one.');
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
