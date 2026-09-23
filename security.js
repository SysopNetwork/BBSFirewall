/**
 * BBSFirewall - admin password + MFA secrets store
 *
 * Owns .admin-security.json (chmod 600, next to .config-editor-sessions.json):
 * a scrypt password hash, an optional TOTP secret, and hashed single-use
 * backup codes. Deliberately self-contained (does not require
 * ./config-editor.js) so config.js can call secretsExist() without a
 * circular require. No new npm dependency - TOTP (RFC 6238) and base32 are
 * both implemented on Node's built-in crypto.
 *
 * The store holds an ARRAY of admin accounts (`{accounts:[...]}`), each with
 * its own password hash, MFA secret/backup codes, a coarse `role`
 * ('master_admin' or 'firewall_admin'), and an `mfaRequired` policy flag -
 * see [[roadmap-hosted-platform]] item 4 / v1.4. A pre-multi-admin store is a
 * single account object (`{username,password,...}` with no `accounts`
 * array); `loadStore()` migrates it to `{accounts:[that account,
 * role:'master_admin']}` on first read and persists the migration, so an
 * upgrader's existing login keeps working with no manual step. Most call
 * sites are unaffected by the migration: `readSecrets(username)` still
 * returns one account-shaped object and `writeSecrets(account)` still writes
 * one back - only the on-disk envelope around it changed.
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WORDS } = require('./wordlist');

const STORE_PATH = path.join(__dirname, '.admin-security.json');
const FILE_MODE = 0o600;
const BACKUPS_KEPT = 15;

const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = 64;
const BACKUP_CODE_KEYLEN = 32;

const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;
const TOTP_WINDOW = 1; // accept the step before/after this one, for clock drift

function chmodQuiet(p, mode) {
  try { fs.chmodSync(p, mode); } catch (_) { /* best effort (e.g. Windows) */ }
}

function timingSafeEqualStr(a, b) {
  const ab = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ab.length !== bb.length) {
    crypto.timingSafeEqual(ab, ab);
    return false;
  }
  return crypto.timingSafeEqual(ab, bb);
}

// Uniform random index in [0, maxExclusive) via rejection sampling over
// crypto.randomBytes - avoids modulo bias without depending on
// crypto.randomInt (added in Node 14.10; package.json only guarantees 14.0).
function randomIndex(maxExclusive) {
  const limit = 0x100000000 - (0x100000000 % maxExclusive);
  let x;
  do {
    x = crypto.randomBytes(4).readUInt32BE(0);
  } while (x >= limit);
  return x % maxExclusive;
}

// ---------------------------------------------------------------------------
// store read/write
// ---------------------------------------------------------------------------
// 'master_admin' = full access, incl. managing other admin accounts ("Provider
// / Master Admin" in the UI). 'firewall_admin' = day-to-day access to this
// one firewall only ("Firewall Admin" in the UI). Renamed from the original
// 'owner'/'provider' pair (v1.4) - LEGACY_ROLES below maps an already-stored
// old value forward so existing accounts don't need a manual fix-up.
const ROLES = ['master_admin', 'firewall_admin'];
const LEGACY_ROLES = { owner: 'master_admin', provider: 'firewall_admin' };

function secretsExist() {
  return fs.existsSync(STORE_PATH);
}

// Fills in defaults for fields that may be missing on an older/hand-edited
// account record. `role` defaults to 'master_admin' for any account
// predating roles entirely (v1 single-account stores, and the v2 migration
// below) - the safe choice, since that account previously had full,
// unrestricted access.
function normalizeAccount(a) {
  if (!a || !a.username || !a.password) return null;
  if (!a.mfa) a.mfa = { enabled: false, secret: null, pendingSecret: null, confirmedAt: null };
  if (!Array.isArray(a.backupCodes)) a.backupCodes = [];
  if (LEGACY_ROLES[a.role]) a.role = LEGACY_ROLES[a.role];
  if (!ROLES.includes(a.role)) a.role = 'master_admin';
  // Per-account MFA policy (v1.4): defaults to false (optional, the original
  // behavior) for any account predating this field.
  if (typeof a.mfaRequired !== 'boolean') a.mfaRequired = false;
  if (!Number.isFinite(a.createdAt)) a.createdAt = Date.now();
  return a;
}

// Reads the raw store and migrates a pre-v2 (single-account) file in place.
// Returns null only when the file is missing/unreadable/empty - never for a
// store with zero accounts (deleteAccount refuses to ever produce one).
function loadStore() {
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(STORE_PATH, 'utf8'));
  } catch (_) {
    return null;
  }
  if (!raw || typeof raw !== 'object') return null;

  if (Array.isArray(raw.accounts)) {
    const before = raw.accounts.map((a) => a && a.role);
    const normalized = raw.accounts.map(normalizeAccount);
    // Persist a legacy role rename (or any other normalizeAccount fix-up)
    // immediately, same reasoning as the v1-to-v2 store migration below -
    // otherwise every read keeps remapping 'owner'/'provider' in memory
    // without the on-disk file ever catching up. Compared before filtering
    // out any malformed (null) entries, so indices still line up.
    const changed = normalized.some((a, i) => a && a.role !== before[i]);
    raw.accounts = normalized.filter(Boolean);
    if (changed) writeStore(raw);
    return raw;
  }

  // v1 shape: the store WAS a single account. Wrap it and persist the
  // migration immediately so every later read/write already sees v2 - this
  // function's return value must stay accurate for the deleteAccount
  // "never leave zero accounts" guarantee to hold.
  if (raw.password) {
    const migrated = { accounts: [normalizeAccount({
      username: raw.username,
      password: raw.password,
      mfa: raw.mfa,
      backupCodes: raw.backupCodes,
      role: 'master_admin',
      createdAt: raw.updatedAt || Date.now(),
    })] };
    writeStore(migrated);
    return migrated;
  }

  return null;
}

// Timestamped backups live in their own ADMINBACKUPS/ folder next to
// .admin-security.json, same pattern as config-editor.js's ENVBACKUPS/ for
// .env - keeps the app directory from accumulating dozens of loose
// `.admin-security.json.bak.*` files alongside the real store.
const BACKUP_DIRNAME = 'ADMINBACKUPS';
const BACKUP_DIR = path.join(path.dirname(STORE_PATH), BACKUP_DIRNAME);

function pruneBackups() {
  try {
    const base = path.basename(STORE_PATH);
    const backups = fs.readdirSync(BACKUP_DIR)
      .filter((n) => n.startsWith(base + '.bak.'))
      .sort();
    while (backups.length > BACKUPS_KEPT) {
      fs.unlinkSync(path.join(BACKUP_DIR, backups.shift()));
    }
  } catch (_) { /* best effort */ }
}

// One-time cleanup: an older version of this file wrote `.bak.*` siblings
// directly next to .admin-security.json - move any still there into
// ADMINBACKUPS/ so everything ends up in one place. Cheap to call on every
// write since it's a no-op once nothing matches.
function migrateLegacyBackups() {
  try {
    const dir = path.dirname(STORE_PATH);
    const base = path.basename(STORE_PATH);
    for (const n of fs.readdirSync(dir)) {
      if (!n.startsWith(base + '.bak.')) continue;
      try { fs.renameSync(path.join(dir, n), path.join(BACKUP_DIR, n)); } catch (_) {}
    }
  } catch (_) { /* best effort */ }
}

// Backs up the existing store (if any) before overwriting, mirrors the
// backup-then-write-then-chmod pattern config-editor.js uses for .env.
function writeStore(store) {
  store.updatedAt = Date.now();
  const text = JSON.stringify(store, null, 2);
  if (fs.existsSync(STORE_PATH)) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = path.join(BACKUP_DIR, `${path.basename(STORE_PATH)}.bak.${stamp}`);
    try {
      fs.mkdirSync(BACKUP_DIR, { recursive: true, mode: 0o700 });
      migrateLegacyBackups();
      fs.copyFileSync(STORE_PATH, backupPath);
      chmodQuiet(backupPath, FILE_MODE);
    } catch (_) { /* best effort */ }
  }
  fs.writeFileSync(STORE_PATH, text, { mode: FILE_MODE });
  chmodQuiet(STORE_PATH, FILE_MODE); // mode: only applies on create; enforce on overwrite too
  pruneBackups();
}

// ---------------------------------------------------------------------------
// account access - most of config-editor.js's call sites only ever deal with
// ONE account at a time (whichever is in the caller's session), so
// readSecrets()/writeSecrets() keep their pre-multi-admin, single-account
// shape; only the account-management endpoints need the full list.
// ---------------------------------------------------------------------------
function listAccounts() {
  const store = loadStore();
  return store ? store.accounts : [];
}

function readSecrets(username) {
  const store = loadStore();
  if (!store) return null;
  return store.accounts.find((a) => a.username === username) || null;
}

// `account` must carry its own (unchanged) `.username` - looks up the
// matching entry in the CURRENT on-disk store (not a stale copy) and
// replaces it, so a concurrent write to a different account is never lost.
function writeSecrets(account) {
  const store = loadStore() || { accounts: [] };
  const idx = store.accounts.findIndex((a) => a.username === account.username);
  if (idx === -1) store.accounts.push(account);
  else store.accounts[idx] = account;
  writeStore(store);
}

// setup-admin.js only: wipes the ENTIRE store and replaces it with one fresh
// 'master_admin' account. Deliberately separate from writeSecrets (which
// only ever touches one account within the existing store) - --reset means
// "start over", not "add another account".
function resetToSingleAccount(username, password) {
  writeStore({ accounts: [normalizeAccount({
    username, password: hashPassword(password), role: 'master_admin', createdAt: Date.now(),
  })] });
}

// Both throw a plain Error with a user-facing message on failure - callers
// (the master_admin-only /api/security/accounts/* handlers) catch and relay it.
function createAccount(username, password, role, mfaRequired) {
  username = String(username || '').trim();
  if (!username) throw new Error('Username cannot be empty.');
  const pwErr = passwordError(password);
  if (pwErr) throw new Error(pwErr);
  if (!ROLES.includes(role)) throw new Error('Role must be "master_admin" or "firewall_admin".');

  const store = loadStore() || { accounts: [] };
  if (store.accounts.some((a) => a.username.toLowerCase() === username.toLowerCase())) {
    throw new Error('An account with that username already exists.');
  }
  const account = normalizeAccount({
    username, password: hashPassword(password), role, mfaRequired: !!mfaRequired, createdAt: Date.now(),
  });
  store.accounts.push(account);
  writeStore(store);
  return account;
}

// master_admin-only, via config-editor.js. Toggles whether this account MUST
// set up MFA before it can use anything else (enforced at login - see
// handleLoginPost's mfaSetupRequired). Does not itself enable/disable MFA -
// an account that already has MFA on is unaffected either way.
function setMfaRequired(username, required) {
  const store = loadStore();
  if (!store) throw new Error('No admin accounts configured.');
  const account = store.accounts.find((a) => a.username === username);
  if (!account) throw new Error('No such account.');
  account.mfaRequired = !!required;
  writeStore(store);
  return account;
}

// Refuses to ever leave the store with zero accounts - callers layer their
// own rules on top (config-editor.js additionally refuses to delete the
// caller's own account, or the last remaining 'owner').
function deleteAccount(username) {
  const store = loadStore();
  if (!store) throw new Error('No admin accounts configured.');
  const idx = store.accounts.findIndex((a) => a.username === username);
  if (idx === -1) throw new Error('No such account.');
  if (store.accounts.length <= 1) throw new Error('Cannot delete the only remaining admin account.');
  store.accounts.splice(idx, 1);
  writeStore(store);
}

// ---------------------------------------------------------------------------
// password policy - length-focused (NIST 800-63B: length matters more than
// forced character-class complexity, and arbitrary symbol rules mainly
// annoy password-manager users without stopping real attacks). The single
// source of truth for every place a new/changed admin password is accepted
// (setup-admin.js, createAccount, change-password) - keep it there rather
// than re-checking `.length` ad hoc so the rule can never drift between them.
// ---------------------------------------------------------------------------
const MIN_PASSWORD_LENGTH = 12;

function passwordError(plain) {
  if (String(plain || '').length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`;
  }
  return null;
}

// ---------------------------------------------------------------------------
// password hashing (scrypt)
// ---------------------------------------------------------------------------
function hashPassword(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(plain), salt, SCRYPT_KEYLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P }).toString('hex');
  return { algo: 'scrypt', hash, salt, N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, keylen: SCRYPT_KEYLEN };
}

function verifyPassword(plain, record) {
  if (!record || record.algo !== 'scrypt') return false;
  try {
    const candidate = crypto.scryptSync(String(plain), record.salt, record.keylen,
      { N: record.N, r: record.r, p: record.p }).toString('hex');
    return timingSafeEqualStr(candidate, record.hash);
  } catch (_) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// TOTP (RFC 6238) on top of HOTP (RFC 4226) - HMAC-SHA1, 30s step, 6 digits
// ---------------------------------------------------------------------------
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = '';
  for (const b of buf) bits += b.toString(2).padStart(8, '0');
  let out = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, '0');
    out += BASE32_ALPHABET[parseInt(chunk, 2)];
  }
  return out;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const c of clean) {
    const idx = BASE32_ALPHABET.indexOf(c);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20)); // 160 bits, the RFC 6238 recommendation
}

function hotp(secretBase32, counter) {
  const key = base32Decode(secretBase32);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return (bin % (10 ** TOTP_DIGITS)).toString().padStart(TOTP_DIGITS, '0');
}

// `field` is 'secret' (the confirmed, live MFA secret) or 'pendingSecret'
// (mid-setup, before "Enable MFA" is confirmed) — secrets.mfa[field].
//
// Unlike backup codes (each hash marked usedAt and never matched again), a
// bare TOTP check has no memory of what it already accepted: the same
// correct code stays valid for the whole ~60-90s window (current step ± 1),
// so it could be submitted more than once — e.g. by whatever briefly saw it
// (a compromised authenticator app/extension, a shoulder-surfed phone
// screen) racing a second, attacker-initiated verification. Track the last
// time-step that verified successfully and refuse to accept that step (or
// an earlier one) again, the same single-use guarantee backup codes already
// have. Persisted immediately (writeSecrets), like verifyAndConsumeBackupCode.
function verifyTotp(secrets, field, code, window = TOTP_WINDOW) {
  const mfa = secrets && secrets.mfa;
  const secretBase32 = mfa ? mfa[field] : null;
  const cleaned = String(code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(cleaned) || !secretBase32) return false;

  const now = Math.floor(Date.now() / 1000);
  const currentStep = Math.floor(now / TOTP_STEP_SECONDS);
  const lastUsedStep = Number.isFinite(mfa.lastUsedStep) ? mfa.lastUsedStep : -1;

  let matchedStep = null;
  // Check every step in the window unconditionally (no early return) so
  // response time doesn't reveal which offset, if any, matched — the
  // replay check below is a cheap integer compare alongside the constant-
  // time string compare, so it doesn't change that timing shape.
  for (let w = -window; w <= window; w++) {
    const step = currentStep + w;
    const candidate = hotp(secretBase32, step);
    if (timingSafeEqualStr(candidate, cleaned) && step > lastUsedStep) matchedStep = step;
  }
  if (matchedStep === null) return false;

  mfa.lastUsedStep = matchedStep;
  writeSecrets(secrets);
  return true;
}

function otpauthUrl(username, secretBase32) {
  const label = encodeURIComponent(`BBSFirewall:${username}`);
  const issuer = encodeURIComponent('BBSFirewall');
  return `otpauth://totp/${label}?secret=${secretBase32}&issuer=${issuer}&digits=${TOTP_DIGITS}&period=${TOTP_STEP_SECONDS}`;
}

// ---------------------------------------------------------------------------
// backup codes - 8 codes, 4 random words each (~44 bits of entropy per code)
// ---------------------------------------------------------------------------
function randomWord() {
  return WORDS[randomIndex(WORDS.length)];
}

function generateBackupCodes(n = 8) {
  const codes = [];
  for (let i = 0; i < n; i++) {
    codes.push([randomWord(), randomWord(), randomWord(), randomWord()].join('-'));
  }
  return codes;
}

function normalizeCode(code) {
  return String(code || '').toLowerCase().trim();
}

function hashBackupCode(code) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(normalizeCode(code), salt, BACKUP_CODE_KEYLEN, { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P }).toString('hex');
  return { hash, salt, usedAt: null };
}

function matchesBackupCodeHash(code, record) {
  if (!record || record.usedAt) return false;
  try {
    const candidate = crypto.scryptSync(normalizeCode(code), record.salt, BACKUP_CODE_KEYLEN,
      { N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P }).toString('hex');
    return timingSafeEqualStr(candidate, record.hash);
  } catch (_) {
    return false;
  }
}

// Verifies `code` against secrets.backupCodes; on a match, marks that entry
// used and persists the change (single-use, survives a restart). Checks
// every code unconditionally before deciding, so response time doesn't leak
// which (if any) code position matched.
function verifyAndConsumeBackupCode(secrets, code) {
  if (!secrets || !Array.isArray(secrets.backupCodes)) return false;
  let matchedIndex = -1;
  for (let i = 0; i < secrets.backupCodes.length; i++) {
    if (matchesBackupCodeHash(code, secrets.backupCodes[i]) && matchedIndex === -1) {
      matchedIndex = i;
    }
  }
  if (matchedIndex === -1) return false;
  secrets.backupCodes[matchedIndex].usedAt = Date.now();
  writeSecrets(secrets);
  return true;
}

module.exports = {
  STORE_PATH,
  ROLES,
  MIN_PASSWORD_LENGTH,
  passwordError,
  secretsExist,
  listAccounts,
  readSecrets,
  writeSecrets,
  resetToSingleAccount,
  createAccount,
  deleteAccount,
  setMfaRequired,
  hashPassword,
  verifyPassword,
  generateTotpSecret,
  verifyTotp,
  otpauthUrl,
  generateBackupCodes,
  hashBackupCode,
  verifyAndConsumeBackupCode,
};
