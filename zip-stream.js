/**
 * BBSFirewall - minimal streaming ZIP writer
 *
 * Just enough of the ZIP format (PKWARE APPNOTE 6.3) to stream a set of files
 * straight to an HTTP response without buffering any of them: DEFLATE
 * compression via Node's own zlib, sizes and CRC-32 written AFTER each file's
 * data in a data descriptor (general-purpose flag bit 3), so nothing has to be
 * known up front. No npm dependency.
 *
 * Deliberately NOT implemented: ZIP64. Callers must keep the archive under
 * MAX_ZIP_BYTES and MAX_ZIP_ENTRIES (checked before streaming starts, since
 * a response can't be un-sent halfway through).
 *
 * https://github.com/SysopNetwork/BBSFirewall
 */

const fs = require('fs');
const zlib = require('zlib');
const { once } = require('events');

const MAX_ZIP_BYTES = 3.5 * 1024 * 1024 * 1024; // headroom under the 4 GiB non-ZIP64 limit
const MAX_ZIP_ENTRIES = 65000;                   // under the 65535 non-ZIP64 limit

// CRC-32 (IEEE 802.3, reflected 0xEDB88320) — zlib.crc32 only exists from Node 22.
const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32Update(crc, buf) {
  let c = crc ^ 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// MS-DOS date/time, local time, 2-second resolution (what every unzip tool shows).
function dosDateTime(d) {
  const year = Math.max(1980, d.getFullYear());
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2),
    date: ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

const FLAGS = 0x0008 | 0x0800; // bit 3: sizes/CRC in data descriptor; bit 11: UTF-8 names
const METHOD_DEFLATE = 8;
const VERSION = 20; // 2.0: deflate + data descriptors

// Waits for 'drain' only while the client is still there. A response whose
// client hung up never drains and never emits 'error' - it just closes - so
// waiting on 'drain' alone left the whole download (and its caller's
// concurrency slot and open file) pending forever.
async function writeOut(out, buf) {
  if (out.destroyed || out.writableEnded) throw new Error('client disconnected');
  if (out.write(buf)) return;
  await new Promise((resolve, reject) => {
    const cleanup = () => {
      out.off('drain', onDrain);
      out.off('close', onGone);
      out.off('error', onGone);
    };
    const onDrain = () => { cleanup(); resolve(); };
    const onGone = () => { cleanup(); reject(new Error('client disconnected')); };
    out.on('drain', onDrain);
    out.on('close', onGone);
    out.on('error', onGone);
  });
}

/**
 * Stream a ZIP of `entries` ([{ name, path, mtime }]) to `out` (a writable,
 * e.g. an http.ServerResponse). Resolves with { files, bytesIn, bytesOut }.
 * A file that disappears mid-run (log pruning) is skipped, not fatal.
 */
async function streamZip(out, entries) {
  if (entries.length > MAX_ZIP_ENTRIES) throw new Error(`too many files for one zip (${entries.length})`);
  const central = [];
  let offset = 0;
  let bytesIn = 0;

  for (const e of entries) {
    let src;
    try {
      src = fs.createReadStream(e.path);
      await once(src, 'open');
    } catch (_) {
      continue; // gone since it was listed
    }
    const name = Buffer.from(e.name, 'utf8');
    const { time, date } = dosDateTime(e.mtime || new Date());

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(VERSION, 4);
    local.writeUInt16LE(FLAGS, 6);
    local.writeUInt16LE(METHOD_DEFLATE, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    // crc / sizes (14..25) stay 0 — they follow in the data descriptor
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    const headerOffset = offset;
    await writeOut(out, local);
    await writeOut(out, name);
    offset += local.length + name.length;

    let crc = 0;
    let usize = 0;
    let csize = 0;
    const deflate = zlib.createDeflateRaw({ level: 6 });
    src.on('data', (chunk) => { crc = crc32Update(crc, chunk); usize += chunk.length; });
    src.on('error', (err) => deflate.destroy(err));
    src.pipe(deflate);
    try {
      for await (const chunk of deflate) {
        csize += chunk.length;
        await writeOut(out, chunk);
      }
    } finally {
      // Leaving the loop early (client gone, read error) must not leave the
      // log file open.
      src.destroy();
      deflate.destroy();
    }
    offset += csize;
    bytesIn += usize;
    if (offset > MAX_ZIP_BYTES) throw new Error('zip grew past the non-ZIP64 size limit');

    const desc = Buffer.alloc(16);
    desc.writeUInt32LE(0x08074b50, 0);
    desc.writeUInt32LE(crc, 4);
    desc.writeUInt32LE(csize, 8);
    desc.writeUInt32LE(usize, 12);
    await writeOut(out, desc);
    offset += desc.length;

    central.push({ name, time, date, crc, csize, usize, headerOffset });
  }

  const cdStart = offset;
  for (const c of central) {
    const h = Buffer.alloc(46);
    h.writeUInt32LE(0x02014b50, 0);
    h.writeUInt16LE((3 << 8) | VERSION, 4); // made by: Unix, 2.0
    h.writeUInt16LE(VERSION, 6);
    h.writeUInt16LE(FLAGS, 8);
    h.writeUInt16LE(METHOD_DEFLATE, 10);
    h.writeUInt16LE(c.time, 12);
    h.writeUInt16LE(c.date, 14);
    h.writeUInt32LE(c.crc, 16);
    h.writeUInt32LE(c.csize, 20);
    h.writeUInt32LE(c.usize, 24);
    h.writeUInt16LE(c.name.length, 28);
    // extra len, comment len, disk no., internal attrs = 0
    h.writeUInt32LE(((0o100644) << 16) >>> 0, 38); // external attrs: regular file, rw-r--r--
    h.writeUInt32LE(c.headerOffset, 42);
    await writeOut(out, h);
    await writeOut(out, c.name);
    offset += h.length + c.name.length;
  }

  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(central.length, 8);
  end.writeUInt16LE(central.length, 10);
  end.writeUInt32LE(offset - cdStart, 12);
  end.writeUInt32LE(cdStart, 16);
  await writeOut(out, end);

  return { files: central.length, bytesIn, bytesOut: offset + end.length };
}

module.exports = { streamZip, crc32Update, MAX_ZIP_BYTES, MAX_ZIP_ENTRIES };
