/**
 * BBSFirewall - Shared runtime counters
 *
 * A tiny in-process bag of live numbers the proxy layer updates and the config
 * editor's Performance tab reads. Keeping it in its own module avoids a
 * circular require between server.js and config-editor.js.
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const metrics = {
  startedAt: Date.now(),
  // Active client connections, broken down by proxy service.
  active: { telnet: 0, ssh: 0, 'ssh-passthrough': 0 },
  // Monotonic totals since process start.
  totals: { accepted: 0, rejected: 0, backendErrors: 0, triggerBlocks: 0 },
};

function incActive(proxy) {
  if (metrics.active[proxy] === undefined) metrics.active[proxy] = 0;
  metrics.active[proxy]++;
  metrics.totals.accepted++;
}

function decActive(proxy) {
  if (metrics.active[proxy] === undefined) metrics.active[proxy] = 0;
  if (metrics.active[proxy] > 0) metrics.active[proxy]--;
}

function incRejected() { metrics.totals.rejected++; }
function incBackendError() { metrics.totals.backendErrors++; }
function incTriggerBlock() { metrics.totals.triggerBlocks++; }

function snapshot() {
  const totalActive = Object.values(metrics.active).reduce((a, b) => a + b, 0);
  return {
    startedAt: metrics.startedAt,
    activeTotal: totalActive,
    active: { ...metrics.active },
    totals: { ...metrics.totals },
  };
}

module.exports = { incActive, decActive, incRejected, incBackendError, incTriggerBlock, snapshot };
