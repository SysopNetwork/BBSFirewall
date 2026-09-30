/**
 * BBSFirewall - minimal telnet client for SSH terminate mode
 *
 * In terminate mode the firewall is the SSH server and the backend is a telnet
 * server, so the firewall has to be the telnet client in between. Without this
 * the backend's option negotiation (IAC WILL/DO ...) reached the SSH caller's
 * screen as stray characters, and any 0xFF data byte was corrupted both ways:
 * telnet sends it doubled (IAC IAC), which breaks binary transfers like Zmodem.
 *
 * Policy: agree to BINARY, ECHO and SUPPRESS-GO-AHEAD (what a normal BBS
 * client runs with), refuse every other option, ignore subnegotiations. State
 * is tracked per option so we only answer a change, never loop on repeats.
 * https://github.com/SysopNetwork/BBSFirewall
 */

const IAC = 255, DONT = 254, DO = 253, WONT = 252, WILL = 251, SB = 250, SE = 240;
const BINARY = 0, ECHO = 1, SGA = 3;

const SERVER_MAY = new Set([BINARY, ECHO, SGA]); // server WILL x -> we DO x
const WE_WILL = new Set([BINARY, SGA]);          // server DO x   -> we WILL x

const S_DATA = 0, S_IAC = 1, S_OPT = 2, S_SB = 3, S_SB_IAC = 4;

/**
 * @param {(reply: Buffer) => void} sendToBackend  writes negotiation replies
 * @returns {{fromBackend: (buf: Buffer) => Buffer, toBackend: (buf: Buffer) => Buffer}}
 */
function createTelnetClient(sendToBackend) {
  let state = S_DATA;
  let verb = 0;
  const remoteOn = new Set(); // options the server has enabled on its side
  const localOn = new Set();  // options we have enabled on our side

  function negotiate(cmd, opt) {
    let reply = null;
    if (cmd === WILL) {
      if (SERVER_MAY.has(opt)) {
        if (!remoteOn.has(opt)) { remoteOn.add(opt); reply = DO; }
      } else {
        reply = DONT;
      }
    } else if (cmd === WONT) {
      if (remoteOn.has(opt)) { remoteOn.delete(opt); reply = DONT; }
    } else if (cmd === DO) {
      if (WE_WILL.has(opt)) {
        if (!localOn.has(opt)) { localOn.add(opt); reply = WILL; }
      } else {
        reply = WONT;
      }
    } else if (cmd === DONT) {
      if (localOn.has(opt)) { localOn.delete(opt); reply = WONT; }
    }
    if (reply !== null) sendToBackend(Buffer.from([IAC, reply, opt]));
  }

  // Strips telnet commands out of the backend stream, keeping only data.
  // Sequences split across chunks are carried over in `state`.
  function fromBackend(buf) {
    if (state === S_DATA && buf.indexOf(IAC) === -1) return buf;
    const out = Buffer.allocUnsafe(buf.length);
    let n = 0;
    for (let i = 0; i < buf.length; i++) {
      const b = buf[i];
      switch (state) {
        case S_DATA:
          if (b === IAC) state = S_IAC; else out[n++] = b;
          break;
        case S_IAC:
          if (b === IAC) { out[n++] = IAC; state = S_DATA; }       // escaped 0xFF
          else if (b >= WILL && b <= DONT) { verb = b; state = S_OPT; }
          else if (b === SB) state = S_SB;
          else state = S_DATA;                                      // NOP, GA, etc.
          break;
        case S_OPT:
          negotiate(verb, b);
          state = S_DATA;
          break;
        case S_SB:
          if (b === IAC) state = S_SB_IAC;
          break;
        case S_SB_IAC:
          state = b === SE ? S_DATA : S_SB;
          break;
      }
    }
    return out.subarray(0, n);
  }

  // Doubles any 0xFF the caller sends so the backend reads it as data.
  function toBackend(buf) {
    let count = 0;
    for (let i = buf.indexOf(IAC); i !== -1; i = buf.indexOf(IAC, i + 1)) count++;
    if (count === 0) return buf;
    const out = Buffer.allocUnsafe(buf.length + count);
    let n = 0;
    for (let i = 0; i < buf.length; i++) {
      out[n++] = buf[i];
      if (buf[i] === IAC) out[n++] = IAC;
    }
    return out;
  }

  return { fromBackend, toBackend };
}

module.exports = { createTelnetClient };
