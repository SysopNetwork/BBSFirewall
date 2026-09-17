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
function secretsExist() {
  return fs.existsSync(STORE_PATH);
}

function readSecrets() {
  try {
    const data = JSON.parse(fs.readFileSync(STORE_PATH, 'utf8'));
    if (!data || typeof data !== 'object' || !data.password) return null;
    if (!data.mfa) data.mfa = { enabled: false, secret: null, pendingSecret: null, confirmedAt: null };
    if (!Array.isArray(data.backupCodes)) data.backupCodes = [];
    return data;
  } catch (_) {
    return null;
  }
}

function pruneBackups() {
  try {
    const dir = __dirname;
    const base = path.basename(STORE_PATH);
    const backups = fs.readdirSync(dir)
      .filter((n) => n.startsWith(base + '.bak.'))
      .sort();
    while (backups.length > BACKUPS_KEPT) {
      fs.unlinkSync(path.join(dir, backups.shift()));
    }
  } catch (_) { /* best effort */ }
}

// Backs up the existing store (if any) before overwriting, mirrors the
// backup-then-write-then-chmod pattern config-editor.js uses for .env.
function writeSecrets(data) {
  data.updatedAt = Date.now();
  const text = JSON.stringify(data, null, 2);
  if (fs.existsSync(STORE_PATH)) {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const backupPath = `${STORE_PATH}.bak.${stamp}`;
    try {
      fs.copyFileSync(STORE_PATH, backupPath);
      chmodQuiet(backupPath, FILE_MODE);
    } catch (_) { /* best effort */ }
  }
  fs.writeFileSync(STORE_PATH, text, { mode: FILE_MODE });
  chmodQuiet(STORE_PATH, FILE_MODE); // mode: only applies on create; enforce on overwrite too
  pruneBackups();
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
  secretsExist,
  readSecrets,
  writeSecrets,
  hashPassword,
  verifyPassword,
  generateTotpSecret,
  verifyTotp,
  otpauthUrl,
  generateBackupCodes,
  hashBackupCode,
  verifyAndConsumeBackupCode,
};
