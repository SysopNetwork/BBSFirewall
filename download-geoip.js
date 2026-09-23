#!/usr/bin/env node

/**
 * BBSFirewall - MaxMind GeoLite2 database setup helper
 * https://github.com/SysopNetwork/BBSFirewall
 */

const fs = require('fs');
const path = require('path');
const { https } = require('follow-redirects');
const { execFileSync } = require('child_process');

// Load .env so MAXMIND_LICENSE_KEY can be set there instead of on the command line.
// override: true so the file wins over a stale value in the inherited environment.
require('dotenv').config({ quiet: true, override: true });

const DATA_DIR = path.join(__dirname, 'data');
const DB_PATH = path.join(DATA_DIR, 'GeoLite2-Country.mmdb');

// --force / --update: replace an existing database instead of stopping.
const FORCE = process.argv.slice(2).some((a) => a === '--force' || a === '--update');

console.log('=== BBSFirewall - GeoIP Database Setup ===\n');

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  console.log('Created data directory');
}

if (fs.existsSync(DB_PATH) && FORCE) {
  const stats = fs.statSync(DB_PATH);
  const age = Math.floor((Date.now() - stats.mtime.getTime()) / (1000 * 60 * 60 * 24));
  console.log(`Replacing existing database (${age} days old)...`);
  // Deliberately NOT deleted here. The old file stays in place and serving
  // until a new one has been fully downloaded and extracted below, where
  // fs.renameSync() atomically swaps it in. Deleting it up front used to mean
  // ANY download failure (bad key, MaxMind outage, a network hiccup) left the
  // box with no database at all — including a manually-uploaded one, which is
  // never re-downloadable by definition.
}

if (fs.existsSync(DB_PATH) && !FORCE) {
  const stats = fs.statSync(DB_PATH);
  const age = Math.floor((Date.now() - stats.mtime.getTime()) / (1000 * 60 * 60 * 24));
  console.log(`Database already exists (${age} days old)`);
  console.log(`Location: ${DB_PATH}`);

  if (age > 30) {
    console.log('\nWarning: Database is older than 30 days. Consider updating it.');
  }

  console.log('\nTo update, re-run with --force (or delete the file and run again).');
  process.exit(0);
}

console.log('GeoLite2 databases are free but require a MaxMind account.\n');
console.log('Option 1: Download manually (Recommended)');
console.log('  1. Sign up at: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data');
console.log('  2. Download the GeoLite2 Country database (MMDB format)');
console.log('  3. Extract GeoLite2-Country.mmdb to:');
console.log(`     ${DB_PATH}\n`);

console.log('Option 2: Use a license key (if you have one)');
console.log('  Add MAXMIND_LICENSE_KEY=your_key to your .env file, then run:');
console.log('  npm run setup-geoip\n');
console.log('  (or pass it inline: MAXMIND_LICENSE_KEY=your_key node download-geoip.js)\n');

const licenseKey = (process.env.MAXMIND_LICENSE_KEY || '').trim();

if (licenseKey) {
  console.log('License key detected, attempting download...\n');

  const url = `https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${encodeURIComponent(licenseKey)}&suffix=tar.gz`;
  const tarPath = path.join(DATA_DIR, 'GeoLite2-Country.tar.gz');

  console.log('Downloading...');

  // family: 4 — some hosts advertise a global IPv6 address (and a default
  // route for it) that is not actually routable to the internet. Node's
  // https.get has no Happy-Eyeballs fallback (unlike curl), so if DNS returns
  // an AAAA record it connects to that dead end and hangs for Linux's own TCP
  // SYN-retry timeout (~70-90s) before failing with ETIMEDOUT. MaxMind/
  // Cloudflare serve identically over IPv4, so forcing it sidesteps the whole
  // class of problem. The explicit `timeout` below is a second, independent
  // safety net for any other kind of network hang.
  const DOWNLOAD_TIMEOUT_MS = 20000;

  try {
    const file = fs.createWriteStream(tarPath);

    const cleanupPartial = () => { if (fs.existsSync(tarPath)) fs.unlinkSync(tarPath); };

    const req = https.get(url, { family: 4, timeout: DOWNLOAD_TIMEOUT_MS }, (response) => {
      if (response.statusCode !== 200) {
        console.error(`Download failed: HTTP ${response.statusCode}`);
        console.error('Check your license key or download manually.');
        cleanupPartial();
        process.exit(1);
      }

      response.pipe(file);

      file.on('finish', () => {
        file.close();
        console.log('Downloaded successfully');

        try {
          console.log('Extracting...');
          execFileSync('tar', ['-xzf', tarPath, '-C', DATA_DIR], { stdio: 'pipe' });

          const files = fs.readdirSync(DATA_DIR);
          const extractedDir = files.find(f => f.startsWith('GeoLite2-Country_'));

          if (extractedDir) {
            const mmdbSource = path.join(DATA_DIR, extractedDir, 'GeoLite2-Country.mmdb');
            if (fs.existsSync(mmdbSource)) {
              // Atomic on POSIX: replaces DB_PATH (if it exists) in one step,
              // so there is never a moment with no database on disk.
              fs.renameSync(mmdbSource, DB_PATH);
              fs.unlinkSync(tarPath);
              fs.rmSync(path.join(DATA_DIR, extractedDir), { recursive: true });
              console.log('Installation complete!');
              console.log(`Database location: ${DB_PATH}`);
              process.exit(0);
            }
          }

          console.error('Could not find .mmdb file in extracted archive');
          console.error('The previous database (if any) was left untouched.');
          cleanupPartial();
          process.exit(1);
        } catch (err) {
          console.error(`Extraction failed: ${err.message}`);
          console.error('The previous database (if any) was left untouched.');
          cleanupPartial();
          process.exit(1);
        }
      });
    }).on('error', (err) => {
      cleanupPartial();
      console.error(`Download error: ${err.message}`);
      console.error('The previous database (if any) was left untouched.');
      process.exit(1);
    });

    req.on('timeout', () => {
      req.destroy(new Error(`connection timed out after ${DOWNLOAD_TIMEOUT_MS / 1000}s ` +
        '(check network/firewall connectivity to download.maxmind.com)'));
    });
  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
} else {
  console.log('No license key provided. Download manually or set MAXMIND_LICENSE_KEY.');
  process.exit(0);
}
