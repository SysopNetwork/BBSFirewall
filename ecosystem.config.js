/**
 * BBSFirewall - PM2 ecosystem config
 * https://github.com/SysopNetwork/BBSFirewall
 *
 * Start:   pm2 start ecosystem.config.js
 * Stop:    pm2 stop bbsfirewall
 * Restart: pm2 restart bbsfirewall
 * Logs:    pm2 logs bbsfirewall
 * Status:  pm2 list
 */

module.exports = {
  apps: [
    {
      name: 'bbsfirewall',
      script: 'server.js',
      // Restart automatically if it crashes, but not if it exits cleanly
      autorestart: true,
      // Don't watch files — restart manually after updates
      watch: false,
      // Give it 10 seconds to come up before PM2 considers it crashed
      min_uptime: '10s',
      // PM2 will stop trying to restart after 10 consecutive crashes
      max_restarts: 10,
    },
  ],
};
