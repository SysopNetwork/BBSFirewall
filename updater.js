/**
 * BBSFirewall - self-update engine
 *
 * Shared by update.js (CLI) and config-editor.js's /api/update/* handlers.
 * Downloads a tagged GitHub Release tarball, overlays it onto the running
 * install, and gates the result behind the same config.validateConfig()
 * check config-editor.js's /api/save uses — restoring an automatic backup on
 * any failure so a bad update never leaves the firewall broken or down.
 *
 * Linux-only by design: process.platform is checked before anything mutates
 * disk (see checkPlatform() below). tar.exe exists on modern Windows too, so
 * its presence alone is not treated as "safe to proceed" — file mode bits,
 * pm2's process model and other assumptions here are POSIX-specific.
 */

const fs = require('fs');
const path = require('path');
const { execFile, execFileSync } = require('child_process');
const { https } = require('follow-redirects');

const REPO = 'SysopNetwork/BBSFirewall';
const NPM_INSTALL_TIMEOUT_MS = 5 * 60 * 1000;
const EXTRACT_TIMEOUT_MS = 60 * 1000;
const VALIDATE_TIMEOUT_MS = 8000;
const GITHUB_TIMEOUT_MS = 10000;
const BACKUPS_KEPT = 5;

// Never restored from backup and never overlaid from a release — these are
// either secrets, machine-local runtime state, or the backup store itself.
// A GitHub release tarball is a `git archive` of the tag, so none of these
// (all gitignored) are ever present in it anyway; this exclude list only
// matters for what we back up FROM the live app directory.
const APP_BACKUP_EXCLUDE = new Set([
  'node_modules', '.git', 'data', 'certs', 'logs', 'ENVBACKUPS', 'update-backups',
  '.env', '.admin-security.json', '.config-editor-sessions.json',
  'ssh_host_key', 'ssh_host_key.pub',
  'whitelist.txt', 'blocklist.txt', 'trustedhosts.txt', 'triggers.txt', 'api-trustedhosts.txt',
]);

function execFileAsync(file, args, opts) {
  return new Promise((resolve, reject) => {
    execFile(file, args, opts || {}, (err, stdout, stderr) => {
      if (err) return reject(Object.assign(err, { stdout, stderr }));
      resolve({ stdout, stderr });
    });
  });
}

// ---------------------------------------------------------------------------
// platform / tool detection
// ---------------------------------------------------------------------------

function checkPlatform() {
  if (process.platform !== 'linux') {
    return `Self-update is only supported on Linux hosts (this host reports "${process.platform}"). ` +
      'Update this install manually, or from a Linux management box, instead.';
  }
  return null;
}

// Cache a SUCCESSFUL detection forever (never a failure) — mirrors
// config-editor.js's hasPm2()/hasCertbot(), whose comment explains why: a
// slow/busy box can make a transient check fail right after a restart, and
// caching that "not found" permanently wedges the feature for the process's
// whole life (this bit BBSFirewall for real in v1.3.6, fixed in v1.3.7).
let tarAvailable = false;
async function hasTar() {
  if (tarAvailable) return true;
  try {
    await execFileAsync('tar', ['--version'], { timeout: 4000 });
    tarAvailable = true;
    return true;
  } catch (_) {
    return false;
  }
}

let pm2Available = false;
async function hasPm2() {
  if (pm2Available) return true;
  try {
    await execFileAsync('pm2', ['-v'], { timeout: 4000 });
    pm2Available = true;
    return true;
  } catch (_) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// version
// ---------------------------------------------------------------------------

// Deliberately NOT require('./package.json') — Node caches a module by its
// resolved path, and this is called again after applyUpdate()/rollback have
// just overwritten package.json on disk (to report the version now running).
// A require() would keep returning whatever was cached from before the
// overlay. Read + parse fresh every time instead.
function getCurrentVersion(appDir) {
  try {
    const raw = fs.readFileSync(path.join(appDir || __dirname, 'package.json'), 'utf-8');
    return String(JSON.parse(raw).version || '');
  } catch (_) {
    return '';
  }
}

function normalizeVersion(v) {
  return String(v || '').replace(/^v/i, '').split('.').map((n) => parseInt(n, 10) || 0);
}

function compareVersions(a, b) {
  const pa = normalizeVersion(a);
  const pb = normalizeVersion(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na !== nb) return na < nb ? -1 : 1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// GitHub API
// ---------------------------------------------------------------------------

function githubApiGet(pathName) {
  return new Promise((resolve, reject) => {
    const req = https.get({
      hostname: 'api.github.com',
      path: pathName,
      headers: {
        'User-Agent': 'BBSFirewall-Updater',
        Accept: 'application/vnd.github+json',
      },
      timeout: GITHUB_TIMEOUT_MS,
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        if (res.statusCode === 404) return resolve(null);
        if (res.statusCode !== 200) {
          return reject(new Error(`GitHub API returned HTTP ${res.statusCode} for ${pathName}`));
        }
        try {
          resolve(JSON.parse(data));
        } catch (err) {
          reject(new Error('Could not parse GitHub API response: ' + err.message));
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('GitHub API request timed out')));
    req.on('error', reject);
  });
}

function releaseFromApi(json) {
  if (!json) return null;
  return {
    tagName: json.tag_name,
    name: json.name || json.tag_name,
    body: json.body || '',
    tarballUrl: json.tarball_url,
    publishedAt: json.published_at,
  };
}

async function fetchLatestRelease() {
  return releaseFromApi(await githubApiGet(`/repos/${REPO}/releases/latest`));
}

// Used to verify a caller-supplied tag is an actual published release BEFORE
// it is used in any path or exec argument — never trust a tag string from a
// request body (or CLI arg) without confirming it against GitHub first.
async function fetchReleaseByTag(tag) {
  return releaseFromApi(await githubApiGet(`/repos/${REPO}/releases/tags/${encodeURIComponent(tag)}`));
}

async function checkForUpdate(appDir) {
  const currentVersion = getCurrentVersion(appDir);
  let release = null;
  let error = null;
  try {
    release = await fetchLatestRelease();
  } catch (err) {
    error = err.message;
  }
  const latestVersion = release ? String(release.tagName || '').replace(/^v/i, '') : currentVersion;
  return {
    currentVersion,
    latestVersion,
    updateAvailable: !!release && compareVersions(currentVersion, latestVersion) < 0,
    tagName: release ? release.tagName : null,
    releaseNotes: release ? release.body : '',
    publishedAt: release ? release.publishedAt : null,
    error,
  };
}

function downloadFile(url, destPath) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(destPath, { mode: 0o600 });
    https.get(url, { headers: { 'User-Agent': 'BBSFirewall-Updater' }, timeout: GITHUB_TIMEOUT_MS }, (response) => {
      if (response.statusCode !== 200) {
        file.close();
        fs.unlink(destPath, () => {});
        return reject(new Error(`Download failed: HTTP ${response.statusCode}`));
      }
      response.pipe(file);
      file.on('finish', () => file.close(() => resolve()));
      file.on('error', (err) => { fs.unlink(destPath, () => {}); reject(err); });
    }).on('error', (err) => {
      fs.unlink(destPath, () => {});
      reject(err);
    }).on('timeout', function onTimeout() { this.destroy(new Error('Download timed out')); });
  });
}

// ---------------------------------------------------------------------------
// file tree copy (no shell-out — this part alone is not Linux-specific)
// ---------------------------------------------------------------------------

function copyTree(src, dest, excludeTopLevel) {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (excludeTopLevel && excludeTopLevel.has(entry.name)) continue;
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    if (entry.isSymbolicLink()) continue; // skip defensively; nothing in this repo relies on symlinks
    if (entry.isDirectory()) {
      copyTree(s, d, null); // exclusions only apply at the top level
    } else if (entry.isFile()) {
      fs.copyFileSync(s, d);
    }
  }
}

function extractValidateError(err) {
  const stderr = (err && err.stderr && err.stderr.toString()) || err.message || '';
  const m = stderr.match(/\bError:\s*Configuration validation failed:\r?\n/);
  if (m) {
    const after = stderr.slice(m.index + m[0].length);
    const lines = [];
    for (const raw of after.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      if (/^at\s/.test(line) || line.startsWith('Node.js v') || line === '^') break;
      lines.push(line);
    }
    if (lines.length) return lines.join('\n');
  }
  return stderr.split(/\r?\n/).slice(0, 5).join('\n') || err.message;
}

function pruneUpdateBackups(backupsRoot) {
  try {
    const entries = fs.readdirSync(backupsRoot, { withFileTypes: true })
      .filter((e) => e.isDirectory() && e.name.startsWith('pre-update-'))
      .map((e) => e.name)
      .sort();
    while (entries.length > BACKUPS_KEPT) {
      fs.rmSync(path.join(backupsRoot, entries.shift()), { recursive: true, force: true });
    }
  } catch (_) { /* best effort */ }
}

function listBackups(appDir) {
  const backupsRoot = path.join(appDir, 'update-backups');
  try {
    return fs.readdirSync(backupsRoot, { withFileTypes: true })
      .filter((e) => e.isDirectory() && e.name.startsWith('pre-update-'))
      .map((e) => e.name)
      .sort()
      .reverse();
  } catch (_) {
    return [];
  }
}

// ---------------------------------------------------------------------------
// apply / rollback
// ---------------------------------------------------------------------------

// Thin wrapper: doApplyUpdate() below returns {ok:false, error} for every
// failure it anticipates, but a GitHub/network call can still reject outside
// those guards (e.g. a DNS failure before the backup step even runs). Callers
// (config-editor.js's /api/update/apply, update.js) rely on this NEVER
// rejecting — an uncaught rejection there would skip the busy-lock release
// and wedge the update feature until the process restarts.
async function applyUpdate(opts) {
  try {
    return await doApplyUpdate(opts);
  } catch (err) {
    return { ok: false, error: `Unexpected error during update: ${err.message}` };
  }
}

async function doApplyUpdate({ tag, appDir } = {}) {
  appDir = appDir || process.cwd();

  const platformError = checkPlatform();
  if (platformError) return { ok: false, error: platformError };

  if (!(await hasTar())) {
    return { ok: false, error: 'The "tar" command is not available on this host — self-update requires it.' };
  }

  let release;
  if (tag) {
    if (!/^v\d+\.\d+\.\d+$/.test(tag)) {
      return { ok: false, error: `Invalid version tag "${tag}".` };
    }
    release = await fetchReleaseByTag(tag);
    if (!release) return { ok: false, error: `No published release found for tag "${tag}".` };
  } else {
    release = await fetchLatestRelease();
    if (!release) return { ok: false, error: 'Could not reach GitHub to find the latest release.' };
  }

  const currentVersion = getCurrentVersion(appDir);
  const newVersion = String(release.tagName || '').replace(/^v/i, '');
  if (currentVersion && newVersion && compareVersions(currentVersion, newVersion) >= 0 && !tag) {
    return { ok: false, error: `Already on v${currentVersion}, which is at or ahead of the latest release (v${newVersion}).` };
  }

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupsRoot = path.join(appDir, 'update-backups');
  const backupDir = path.join(backupsRoot, `pre-update-${currentVersion || 'unknown'}-${stamp}`);
  const tmpDir = path.join(backupsRoot, '.tmp');
  const stagingDir = path.join(tmpDir, `staging-${stamp}`);
  const tarPath = path.join(tmpDir, `release-${stamp}.tar.gz`);

  const cleanupTmp = () => {
    try { fs.rmSync(tarPath, { force: true }); } catch (_) {}
    try { fs.rmSync(stagingDir, { recursive: true, force: true }); } catch (_) {}
  };

  try {
    fs.mkdirSync(backupsRoot, { recursive: true, mode: 0o700 });
    fs.mkdirSync(tmpDir, { recursive: true, mode: 0o700 });
  } catch (err) {
    return { ok: false, error: `Could not create the backup directory: ${err.message}` };
  }

  // Back up BEFORE touching any live file — if this fails, nothing has changed yet.
  try {
    copyTree(appDir, backupDir, APP_BACKUP_EXCLUDE);
  } catch (err) {
    try { fs.rmSync(backupDir, { recursive: true, force: true }); } catch (_) {}
    return { ok: false, error: `Backup failed — nothing was changed: ${err.message}` };
  }

  const rollback = (reason) => {
    try {
      copyTree(backupDir, appDir, null);
      execFileSync('npm', ['install', '--omit=dev'], { cwd: appDir, stdio: 'pipe', timeout: NPM_INSTALL_TIMEOUT_MS });
    } catch (restoreErr) {
      cleanupTmp();
      return {
        ok: false,
        error: `${reason}\n\nThe automatic rollback ALSO failed (${restoreErr.message}). ` +
          `The app directory may be inconsistent — restore manually from update-backups/${path.basename(backupDir)}.`,
        backup: path.basename(backupDir),
      };
    }
    cleanupTmp();
    return {
      ok: false,
      error: `${reason}\n\nRestored the previous version (v${currentVersion || 'unknown'}) automatically.`,
      backup: path.basename(backupDir),
      restored: true,
    };
  };

  try {
    await downloadFile(release.tarballUrl, tarPath);
  } catch (err) {
    return rollback(`Download failed: ${err.message}`);
  }

  try {
    fs.mkdirSync(stagingDir, { recursive: true });
    execFileSync('tar', ['-xzf', tarPath, '-C', stagingDir, '--strip-components=1'], { timeout: EXTRACT_TIMEOUT_MS, stdio: 'pipe' });
  } catch (err) {
    return rollback(`Extracting the release failed: ${err.message}`);
  }

  if (!fs.existsSync(path.join(stagingDir, 'package.json')) || !fs.existsSync(path.join(stagingDir, 'server.js'))) {
    return rollback('The downloaded release looks incomplete (missing package.json or server.js).');
  }

  try {
    copyTree(stagingDir, appDir, null);
  } catch (err) {
    return rollback(`Applying the new files failed: ${err.message}`);
  }

  try {
    execFileSync('npm', ['install', '--omit=dev'], { cwd: appDir, stdio: 'pipe', timeout: NPM_INSTALL_TIMEOUT_MS });
  } catch (err) {
    return rollback(`"npm install" failed on the new version: ${(err.stderr || err.message).toString().slice(0, 2000)}`);
  }

  try {
    execFileSync(process.execPath, ['-e', 'require("./config").validateConfig()'], {
      cwd: appDir, stdio: 'pipe', timeout: VALIDATE_TIMEOUT_MS,
      env: { ...process.env, DOTENV_CONFIG_QUIET: 'true' },
    });
  } catch (err) {
    return rollback(`The updated code rejected the current configuration:\n${extractValidateError(err)}`);
  }

  cleanupTmp();
  pruneUpdateBackups(backupsRoot);

  return {
    ok: true,
    previousVersion: currentVersion,
    newVersion,
    tagName: release.tagName,
    backup: path.basename(backupDir),
  };
}

// Same never-reject contract as applyUpdate() above, for the same reason.
async function rollbackToBackup(backupName, appDir) {
  try {
    return await doRollbackToBackup(backupName, appDir);
  } catch (err) {
    return { ok: false, error: `Unexpected error during rollback: ${err.message}` };
  }
}

async function doRollbackToBackup(backupName, appDir) {
  appDir = appDir || process.cwd();

  const platformError = checkPlatform();
  if (platformError) return { ok: false, error: platformError };

  if (!backupName || /[\\/]|\.\./.test(backupName) || !backupName.startsWith('pre-update-')) {
    return { ok: false, error: 'Invalid backup name.' };
  }
  const backupsRoot = path.join(appDir, 'update-backups');
  const backupDir = path.join(backupsRoot, backupName);
  if (!fs.existsSync(path.join(backupDir, 'package.json'))) {
    return { ok: false, error: `Backup "${backupName}" was not found.` };
  }

  try {
    copyTree(backupDir, appDir, null);
    execFileSync('npm', ['install', '--omit=dev'], { cwd: appDir, stdio: 'pipe', timeout: NPM_INSTALL_TIMEOUT_MS });
    execFileSync(process.execPath, ['-e', 'require("./config").validateConfig()'], {
      cwd: appDir, stdio: 'pipe', timeout: VALIDATE_TIMEOUT_MS,
      env: { ...process.env, DOTENV_CONFIG_QUIET: 'true' },
    });
  } catch (err) {
    return { ok: false, error: `Rollback to "${backupName}" failed: ${(err.stderr || err.message).toString().slice(0, 2000)}` };
  }

  return { ok: true, restoredFrom: backupName, newVersion: getCurrentVersion(appDir) };
}

module.exports = {
  REPO,
  checkPlatform,
  hasTar,
  hasPm2,
  getCurrentVersion,
  compareVersions,
  checkForUpdate,
  fetchLatestRelease,
  fetchReleaseByTag,
  applyUpdate,
  rollbackToBackup,
  listBackups,
};
