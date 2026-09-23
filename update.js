#!/usr/bin/env node

/**
 * BBSFirewall - self-update CLI
 *
 * Checks GitHub for a newer release and, on confirmation, downloads and
 * applies it via updater.js (backup -> overlay -> npm install ->
 * validateConfig() gate -> automatic rollback on any failure). Never
 * restarts pm2 on its own without an explicit answer/flag.
 *
 *   node update.js               interactive: check, confirm, apply, ask about restart
 *   node update.js --check       check only, changes nothing (exit 1 if an update exists)
 *   node update.js --yes         skip the "apply this update?" confirmation
 *   node update.js --restart     also skip the "restart now?" confirmation
 *   node update.js --rollback           list available backups
 *   node update.js --rollback <name>    restore that backup
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const readline = require('readline');
const { execFile } = require('child_process');
const updater = require('./updater');

require('dotenv').config({ quiet: true, override: true });

const APP_DIR = __dirname;
const args = process.argv.slice(2);
const CHECK_ONLY = args.includes('--check');
const SKIP_CONFIRM = args.includes('--yes');
const SKIP_RESTART_CONFIRM = args.includes('--restart');
const ROLLBACK_IDX = args.indexOf('--rollback');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
// See setup-admin.js for why this uses the async-iterator protocol instead of
// sequential rl.question() calls: piped/non-TTY input can silently drop lines
// with the latter.
const lines = rl[Symbol.asyncIterator]();
async function confirm(question) {
  process.stdout.write(question + ' [y/N] ');
  const { value, done } = await lines.next();
  if (done) return false;
  return /^y(es)?$/i.test(String(value).trim());
}

function execFileAsync(file, cmdArgs, opts) {
  return new Promise((resolve, reject) => {
    execFile(file, cmdArgs, opts || {}, (err, stdout, stderr) => {
      if (err) return reject(Object.assign(err, { stdout, stderr }));
      resolve({ stdout, stderr });
    });
  });
}

async function maybeRestart() {
  if (!(await updater.hasPm2())) {
    console.log('\npm2 was not found on this host - restart BBSFirewall manually to apply the update.');
    return;
  }
  const appName = (process.env.CONFIG_EDITOR_PM2_APP || 'bbsfirewall').trim();
  const doRestart = SKIP_RESTART_CONFIRM || await confirm(`\nRestart "${appName}" now to apply the update?`);
  if (!doRestart) {
    console.log(`Not restarting. Run "pm2 restart ${appName}" whenever you're ready.`);
    return;
  }
  console.log(`Restarting "${appName}"...`);
  try {
    await execFileAsync('pm2', ['restart', appName, '--update-env'], { timeout: 20000, cwd: APP_DIR });
    console.log('Restarted.');
  } catch (err) {
    console.error(`pm2 restart failed: ${err.message}`);
    console.error(`Run "pm2 restart ${appName}" manually.`);
  }
}

async function runRollback() {
  const name = args[ROLLBACK_IDX + 1];
  if (!name || name.startsWith('--')) {
    const backups = updater.listBackups(APP_DIR);
    if (!backups.length) {
      console.log('No update backups found.');
      return;
    }
    console.log('Available backups (newest first):\n');
    backups.forEach((b) => console.log('  ' + b));
    console.log('\nRestore one with: node update.js --rollback <name>');
    return;
  }

  const platformError = updater.checkPlatform();
  if (platformError) {
    console.error(platformError);
    process.exit(1);
  }

  const ok = SKIP_CONFIRM || await confirm(`Roll back to "${name}"? This restores that version's code and re-runs npm install.`);
  if (!ok) {
    console.log('Cancelled.');
    return;
  }
  console.log('Rolling back...');
  const result = await updater.rollbackToBackup(name, APP_DIR);
  if (!result.ok) {
    console.error('Rollback failed: ' + result.error);
    process.exit(1);
  }
  console.log(`Restored. Now running v${result.newVersion}.`);
  await maybeRestart();
}

async function main() {
  console.log('=== BBSFirewall - Self-Update ===\n');

  if (ROLLBACK_IDX !== -1) {
    await runRollback();
    return;
  }

  const current = updater.getCurrentVersion(APP_DIR);
  console.log(`Current version: v${current}`);
  console.log('Checking GitHub for the latest release...\n');

  const info = await updater.checkForUpdate(APP_DIR);
  if (info.error) {
    console.error('Could not check for updates: ' + info.error);
    process.exit(1);
  }

  if (!info.updateAvailable) {
    console.log(`Already up to date (v${info.currentVersion}).`);
    process.exit(0);
  }

  console.log(`Update available: v${info.currentVersion} -> v${info.latestVersion}\n`);
  if (info.releaseNotes) {
    console.log('--- Release notes ---');
    console.log(info.releaseNotes.trim());
    console.log('---------------------\n');
  }

  if (CHECK_ONLY) {
    process.exit(1); // signal "update available" to scripts, without changing anything
  }

  const platformError = updater.checkPlatform();
  if (platformError) {
    console.error(platformError);
    process.exit(1);
  }
  if (!(await updater.hasTar())) {
    console.error('The "tar" command is not available on this host - self-update requires it.');
    process.exit(1);
  }

  const proceed = SKIP_CONFIRM || await confirm(`Update to v${info.latestVersion} now?`);
  if (!proceed) {
    console.log('Cancelled.');
    process.exit(0);
  }

  console.log('\nBacking up, downloading, and applying the update - this can take a minute...');
  const result = await updater.applyUpdate({ appDir: APP_DIR });
  if (!result.ok) {
    console.error('\nUpdate failed: ' + result.error);
    process.exit(1);
  }

  console.log(`\nUpdated: v${result.previousVersion} -> v${result.newVersion}`);
  console.log(`Backup kept at update-backups/${result.backup} (roll back with: node update.js --rollback ${result.backup})`);

  await maybeRestart();
}

main().finally(() => rl.close()).catch((err) => {
  console.error('Unexpected error: ' + err.message);
  process.exit(1);
});
