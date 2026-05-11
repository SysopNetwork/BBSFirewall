/**
 * BBS Firewall - GeoIP country lookup using MaxMind GeoLite2
 * https://github.com/SysopNetwork/BBSFirewall
 */

const fs = require('fs');
const path = require('path');
const maxmind = require('maxmind');
const logger = require('./logger');

class GeoIPLookup {
  constructor() {
    this.reader = null;
    this.dbPath = path.join(__dirname, 'data', 'GeoLite2-Country.mmdb');
    this.isEnabled = false;
  }

  async initialize() {
    try {
      if (!fs.existsSync(this.dbPath)) {
        logger.warn('GeoIP database not found. Country blocking disabled.');
        logger.warn('Run "npm run setup-geoip" to download the database.');
        this.isEnabled = false;
        return false;
      }

      this.reader = await maxmind.open(this.dbPath);
      this.isEnabled = true;
      logger.info('GeoIP database loaded successfully');
      return true;
    } catch (err) {
      logger.error(`Failed to load GeoIP database: ${err.message}`);
      this.isEnabled = false;
      return false;
    }
  }

  lookup(ipAddress) {
    if (!this.isEnabled || !this.reader) return null;

    try {
      const cleanIp = ipAddress.replace(/^::ffff:/i, '');
      const result = this.reader.get(cleanIp);

      if (result && result.country) {
        return {
          ip: ipAddress,
          countryCode: result.country.iso_code || null,
          countryName: result.country.names ? result.country.names.en : null,
        };
      }

      return null;
    } catch (err) {
      logger.debug(`GeoIP lookup failed for ${ipAddress}: ${err.message}`);
      return null;
    }
  }

  isCountryBlocked(ipAddress, blockedCountries) {
    if (!this.isEnabled || !blockedCountries || blockedCountries.length === 0) return false;

    const geoInfo = this.lookup(ipAddress);

    if (!geoInfo || !geoInfo.countryCode) return false;

    const isBlocked = blockedCountries.includes(geoInfo.countryCode.toUpperCase());

    if (isBlocked) {
      logger.info(`Blocked connection from ${geoInfo.countryName} (${geoInfo.countryCode}): ${ipAddress}`);
    }

    return isBlocked;
  }

  getCountryInfo(ipAddress) {
    return this.lookup(ipAddress);
  }
}

let geoipInstance = null;

async function initializeGeoIP() {
  if (!geoipInstance) {
    geoipInstance = new GeoIPLookup();
    await geoipInstance.initialize();
  }
  return geoipInstance;
}

function getGeoIP() {
  return geoipInstance;
}

module.exports = { initializeGeoIP, getGeoIP };
