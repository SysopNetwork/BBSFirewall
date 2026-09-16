/**
 * BBSFirewall - Shared runtime counters
 *
 * A tiny in-process bag of live numbers the proxy layer updates and the config
 * editor's System Stats tab reads. Keeping it in its own module avoids a
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
  // Lifetime bytes transferred, both directions, across every proxy.
  bytes: { fromClient: 0, fromBackend: 0 },
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

// direction is 'fromClient' or 'fromBackend' — called from proxy.js/ssh.js at
// the same spots that already track per-connection byte counts locally.
function incBytes(direction, n) {
  if (!n || (direction !== 'fromClient' && direction !== 'fromBackend')) return;
  metrics.bytes[direction] += n;
}

// ---------------------------------------------------------------------------
// Bandwidth rate sampling — current (since last sample) and peak (monotonic
// high-water mark) bytes/sec, in both directions. Sampled on a server-side
// timer (started once from server.js) so avg/max stay meaningful even when
// no admin has the System Stats tab open, independent of the tab's own 4s
// client-side poll.
// ---------------------------------------------------------------------------
let lastSample = null; // { at, fromClient, fromBackend }
let currentRate = { fromClient: 0, fromBackend: 0 };
let maxRate = { fromClient: 0, fromBackend: 0 };
let bwTimer = null;

function sampleBandwidth() {
  const now = Date.now();
  if (lastSample) {
    const dtSec = (now - lastSample.at) / 1000;
    if (dtSec > 0) {
      const dClient = metrics.bytes.fromClient - lastSample.fromClient;
      const dBackend = metrics.bytes.fromBackend - lastSample.fromBackend;
      currentRate = { fromClient: dClient / dtSec, fromBackend: dBackend / dtSec };
      maxRate.fromClient = Math.max(maxRate.fromClient, currentRate.fromClient);
      maxRate.fromBackend = Math.max(maxRate.fromBackend, currentRate.fromBackend);
    }
  }
  lastSample = { at: now, fromClient: metrics.bytes.fromClient, fromBackend: metrics.bytes.fromBackend };
}

function startBandwidthSampler(intervalMs) {
  if (bwTimer) clearInterval(bwTimer);
  sampleBandwidth(); // seed lastSample immediately, before the first interval tick
  bwTimer = setInterval(sampleBandwidth, intervalMs);
  if (bwTimer.unref) bwTimer.unref();
}

function snapshot() {
  const totalActive = Object.values(metrics.active).reduce((a, b) => a + b, 0);
  const elapsedSec = (Date.now() - metrics.startedAt) / 1000;
  const totalBytes = metrics.bytes.fromClient + metrics.bytes.fromBackend;
  return {
    startedAt: metrics.startedAt,
    activeTotal: totalActive,
    active: { ...metrics.active },
    totals: { ...metrics.totals },
    bytes: { ...metrics.bytes },
    rate: { current: { ...currentRate }, max: { ...maxRate } },
    // Derived on read from totals/elapsed-time — no separate tracking needed.
    avgMbit: elapsedSec > 0 ? (totalBytes * 8) / elapsedSec / 1e6 : 0,
  };
}

module.exports = {
  incActive, decActive, incRejected, incBackendError, incTriggerBlock, incBytes,
  startBandwidthSampler, snapshot,
};
