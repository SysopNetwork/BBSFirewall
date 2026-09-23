# BBSFirewall Management API

Key-authenticated REST access to everything the web config editor can do — read and
write `.env`, edit the IP / trigger list files, restart the firewall, run the GeoIP /
SSH-key / certificate tools, and read live system + firewall metrics. Intended for a
remote dashboard.

The API is **not** a separate service. It rides on the config editor's HTTPS listener
(`CONFIG_EDITOR_PORT`, default `8443`) under the `/api/*` paths. The config editor must
be enabled for the API to work.

> **Not the same thing as `GET /status`.** `/status` is a separate, unauthenticated
> endpoint on the same port for uptime monitors (Uptime Kuma etc.) — no API key, no
> session, gated only by `status-trustedhosts.txt`. See the "Status Endpoint" section
> in the README.

- [Enabling the API](#enabling-the-api)
- [Authentication](#authentication)
- [Base URL and TLS](#base-url-and-tls)
- [Endpoints](#endpoints)
- [Error responses](#error-responses)
- [Data shapes](#data-shapes)
- [Security notes](#security-notes)
- [Sample code](#sample-code)
- [Verifying it works](#verifying-it-works)

---

## Enabling the API

In `.env`:

```env
CONFIG_EDITOR_ENABLED=true          # required — the API has no listener of its own
CONFIG_EDITOR_PORT=8443

API_ENABLED=true
API_KEY=<a long random string, minimum 24 characters>
API_TRUSTEDHOSTS_PATH=./api-trustedhosts.txt   # optional source-IP allowlist
```

Generate a key:

```bash
openssl rand -hex 32          # or: head -c 32 /dev/urandom | base64
```

Then restart the firewall (`pm2 restart bbsfirewall`, or the editor's **Restart** button).
A changed `API_KEY` only takes effect after a restart.

### `api-trustedhosts.txt` — optional IP allowlist

One IPv4/IPv6 address or CIDR per line (`#` comments allowed). If the file is **missing
or empty, any source IP may call the API** — the key is still required. Add entries to
restrict the API to known dashboard hosts. This list is independent of
`trustedhosts.txt` (the browser editor's gate); an API caller does **not** need to be a
trusted editor host. Edits made through the editor UI or `POST /api/save` apply live, no
restart.

```
# api-trustedhosts.txt
203.0.113.10          # the dashboard server
2001:db8:1234::/48
```

---

## Authentication

Every request carries the key in a header — **never** in the URL or query string.

```
Authorization: Bearer <API_KEY>
```

or

```
X-API-Key: <API_KEY>
```

- The key is compared in constant time and is never written to any log.
- Five bad keys from one source IP lock that IP out of the API for 15 minutes
  (`429`). This counter is **separate** from the browser login's lockout — a
  misconfigured dashboard cannot lock a human admin out of the web UI.
- There is no session, cookie, or CSRF token. Each request authenticates on its own.

---

## Base URL and TLS

```
https://<host>:<CONFIG_EDITOR_PORT>/api/...
```

The listener is HTTPS only. If the editor uses a real (Let's Encrypt) certificate,
normal TLS verification works. If it uses a self-signed certificate, the client must
skip verification (`curl -k`, `rejectUnauthorized: false`, `verify=False`).

Plain HTTP sent to this port is answered with a `301` to the `https://` URL (unless
`CONFIG_EDITOR_HTTP_REDIRECT_ENABLED=false`), so an accidental `http://` call redirects
rather than failing — but API clients should call `https://` directly.

---

## Endpoints

| Method + path | Purpose | Body |
|---|---|---|
| `GET /api/config` | Full `.env` (grouped, with current values), the list-file contents, and process status | — |
| `GET /api/health` | Cert / SSH host key / GeoIP / certbot health (the Tools tab) | — |
| `GET /api/stats` | Live host + firewall metrics | — |
| `POST /api/save` | Write `.env` and/or the list files | JSON, see below |
| `POST /api/restart` | `pm2 restart` the firewall | `{}` or `{"keepSession": false}` |
| `POST /api/geoip` | Download / update the MaxMind GeoLite2 database | `{"action": "download"}` \| `{"action": "update"}` |
| `POST /api/sshkey` | Generate the SSH host key (terminate mode) | `{"type": "rsa"\|"ed25519", "overwrite": false}` |
| `POST /api/cert` | Issue a Let's Encrypt certificate | `{"target": "editor"\|"redirect"}` |
| `GET /api/update/check` | Check GitHub for a newer release | — |
| `POST /api/update/apply` | Download and apply an update, then restart | `{}` or `{"tag": "v1.4.0", "keepSession": false}` |
| `POST /api/update/rollback` | Restore a previous update backup, then restart | `{"backup": "pre-update-1.3.7-…"}` |
| `GET /api/logs` | List rotated log files (`file-logger.js`'s per-proxy `logs/<proxy>/` folders) | — |
| `GET /api/logs/view` | Read one log file's content (tailed if large) | — (`?proxy=` and `?file=` query params) |
| `POST /api/logs/delete` | Permanently delete one log file | `{"proxy": "telnet", "file": "telnet-2026-09-11.log"}` |

All responses are `application/json`.

### `GET /api/config`

```jsonc
{
  "csrf": null,                 // always null on the API (browser-only field)
  "username": "api",
  "sections": [
    {
      "name": "Network",
      "help": "…",
      "fields": [
        {
          "key": "LISTEN_PORT",
          "type": "port",        // port | int | bool | enum | csv | string | secret
          "label": "Telnet listen port",
          "help": "…",
          "helpLong": null,
          "required": true,
          "options": null,       // array of allowed values when type === "enum"
          "enabled": true,       // false = the key is commented out / unset in .env
          "value": "23",
          "placeholder": ""      // default/commented value shown when not set
        }
        // …
      ]
    }
    // … one section per .env group
  ],
  "files": {
    "whitelist":    { "path": "./whitelist.txt",    "content": "…", "exists": true },
    "blocklist":    { "path": "./blocklist.txt",    "content": "…", "exists": true },
    "trustedhosts": { "path": "./trustedhosts.txt", "content": "…", "exists": true },
    "triggers":     { "path": "./triggers.txt",     "content": "…", "exists": true },
    "apihosts":     { "path": "./api-trustedhosts.txt", "content": "…", "exists": true }
  },
  "status": {
    "pid": 1908,
    "version": "1.3.0",
    "uptimeHuman": "2m 15s",
    "pm2": true,
    "envPath": "/BBSFirewall/.env"
  }
}
```

> `value` for `type: "secret"` fields (`API_KEY`, `MAXMIND_LICENSE_KEY`) contains the **real
> secret**. See [Security notes](#security-notes). The admin password/MFA are not part of
> `.env`/this schema at all — they live in `.admin-security.json` (`node setup-admin.js`),
> managed via the browser-only `/api/security/*` endpoints (not exposed to the key-authenticated
> Management API).

### `GET /api/health`

Split out of `/api/config` in v1.3.5 — this is the only endpoint that shells out to
`ssh-keygen`/`openssl`/`certbot` to probe the SSH host key and TLS certs, so it's the one
worth polling on its own schedule (or not at all) instead of on every config read. Probes
are cached 4s and run concurrently.

```jsonc
{
  "geoip":  { "dbPath": "…", "exists": true, "sizeBytes": 8590103, "ageDays": 8, "licenseKeySet": true },
  "sshHostKey": { "path": "…", "exists": true, "fingerprint": "SHA256:…", "type": "RSA" },
  "certs": {
    "editor":   { "path": "…", "exists": true, "subject": "CN = admin.example.com",
                  "notAfter": "Dec  2 08:08:31 2026 GMT", "daysLeft": 83, "selfSigned": false },
    "redirect": { "…": "…" }
  },
  "certbotInstalled": true,
  "domains": { "editor": "admin.example.com", "redirect": "bbs.example.com" },
  "sshMode": "passthrough"
}
```

### `GET /api/stats`

```jsonc
{
  "now": 1788996848430,
  "host": {
    "hostname": "bfd1", "version": "1.3.0", "platform": "linux",
    "osUptimeSec": 3681, "procUptimeSec": 135,
    "loadavg": [0.04, 0.04, 0.01],
    "cpu": { "percent": 2, "cores": 1, "model": "Intel Xeon …" },
    "memTotalBytes": 2063577088, "memFreeBytes": 1705578496,
    "nodeVersion": "v18.19.1"
  },
  "process": { "pid": 1908, "rssBytes": 76513280, "heapUsedBytes": 8952240, "heapTotalBytes": 10162176 },
  "network": { "eth0": { "rxBytesPerSec": 1500, "txBytesPerSec": 2072 } },   // Linux only, may be null
  "disk": { "totalBytes": 20109631488, "freeBytes": 15980851200, "usedBytes": 4128780288, "path": "/BBSFirewall" },
  "firewall": {
    "startedAt": 1788996714040,
    "activeTotal": 0,
    "active": { "telnet": 0, "ssh": 0, "ssh-passthrough": 0 },
    "totals": { "accepted": 0, "rejected": 0, "backendErrors": 0, "triggerBlocks": 0 },
    "ipfilter": {
      "whitelistSize": 2, "blocklistSize": 2, "temporarilyBlockedIPs": 0,
      "trackedIPs": 0, "activeIPConnections": 0, "triggerCount": 30, "autoBlocked": 0
    }
  },
  "geoip": { "dbPath": "…", "exists": true, "sizeBytes": 8590103, "ageDays": 8, "licenseKeySet": true }
}
```

### `POST /api/save`

Send only the keys you want to change. This is the exact body the editor UI sends.

```jsonc
{
  "env": {
    "BLOCKED_COUNTRIES": { "value": "CN,RU,KP", "enabled": true },
    "SSH_PROXY_PROTOCOL": { "value": "false", "enabled": false }   // enabled:false comments the line out
  },
  "files": {
    "blocklist": "203.0.113.5\n198.51.100.0/24\n"                  // full replacement text for the file
  }
}
```

- `env` — object of `KEY: { value: string, enabled: boolean }`. Only keys the editor
  schema knows are applied; unknown keys are ignored. `enabled: false` comments the
  line out (its value is kept). Newlines in a value are rejected.
- `files` — any of `whitelist`, `blocklist`, `trustedhosts`, `triggers`, `apihosts`.
  The string is the **entire new file content**.
- Both `env` and `files` are optional; `{"env":{},"files":{}}` is a valid no-op (it
  still makes a timestamped `.env` backup).

**Safety:** `.env` is backed up (to `ENVBACKUPS/`), written, then validated by a fresh
`node` process. If validation fails the previous `.env` is restored and the response is
`400` with the errors — the running config is never left broken. `trustedhosts` /
`apihosts` / `triggers` text is checked before it is written (unparseable lines and
catastrophic-backtracking regexes are rejected). List-file edits reload live; `.env`
changes need a restart.

Success:

```json
{ "ok": true, "backup": "ENVBACKUPS/.env.bak.2026-09-09T23-34-26-973Z",
  "files": { "blocklist": "saved" }, "trustedHostCount": 4 }
```

### `POST /api/restart`

```json
{ "ok": true, "restarting": true, "keepSession": true,
  "message": "Restarting \"bbsfirewall\". …" }
```

The HTTPS listener goes down for a second or two while `pm2` restarts the process. If
`pm2` is not installed the response is `{ "ok": true, "restarting": false, "message": "…" }`
and you must restart manually.

### `POST /api/geoip`, `POST /api/sshkey`, `POST /api/cert`

These run a shell command on the server and return its output. They can take up to a few
minutes (`/api/cert` runs certbot). Only one mutating operation runs at a time — a second
one gets `429` (see below).

```jsonc
// POST /api/geoip {"action":"update"}
{ "ok": true, "action": "update", "exitCode": 0, "output": "…console output…",
  "geoip": { "exists": true, "sizeBytes": 8590103, "ageDays": 0, "licenseKeySet": true } }

// POST /api/sshkey {"type":"ed25519","overwrite":true}
{ "ok": true, "output": "…", "sshHostKey": { "exists": true, "fingerprint": "SHA256:…", "type": "ED25519" },
  "note": "Set SSH_MODE=terminate (if not already) and restart to use it." }

// POST /api/cert {"target":"editor"}   (needs CONFIG_EDITOR_CERT_DOMAIN set + saved)
{ "ok": true, "target": "editor", "domain": "admin.example.com", "exitCode": 0,
  "certbotInstalled": true, "output": "…", "health": { /* buildHealth() */ } }
```

### `GET /api/update/check`, `POST /api/update/apply`, `POST /api/update/rollback`

Self-update, Linux-only (see `updater.js` and the "Updating" section of the README) — a
Windows host or one without `tar` gets `platformSupported: false` / `tarAvailable: false`
from the check and any apply/rollback attempt refuses immediately, before touching any
file. `/api/update/apply` and `/api/update/rollback` both restart the process on success,
the same way `/api/restart` does — the HTTP response arrives first, then the process
restarts a moment later. Only one mutating update/restart/save/geoip/sshkey/cert operation
runs at a time.

```jsonc
// GET /api/update/check
{ "currentVersion": "1.3.7", "latestVersion": "1.4.0", "updateAvailable": true,
  "tagName": "v1.4.0", "releaseNotes": "…markdown…", "publishedAt": "2026-…",
  "platformSupported": true, "tarAvailable": true,
  "backups": ["pre-update-1.3.6-2026-…"] }

// POST /api/update/apply {}
{ "ok": true, "previousVersion": "1.3.7", "newVersion": "1.4.0", "tagName": "v1.4.0",
  "backup": "pre-update-1.3.7-2026-…", "restarting": true, "keepSession": true,
  "message": "Updated to v1.4.0. Restarting — …" }

// A failed apply automatically restores the pre-update backup and does NOT restart:
{ "ok": false, "error": "npm install failed on the new version: …\n\nRestored the previous version (v1.3.7) automatically.",
  "backup": "pre-update-1.3.7-2026-…", "restored": true }

// POST /api/update/rollback {"backup":"pre-update-1.3.6-2026-…"}
{ "ok": true, "restoredFrom": "pre-update-1.3.6-2026-…", "newVersion": "1.3.6",
  "restarting": true, "keepSession": true, "message": "Restored v1.3.6. Restarting — …" }
```

### `GET /api/logs`, `GET /api/logs/view`, `POST /api/logs/delete`

Per-proxy rotated log files written by `file-logger.js` (`LOG_FILE_ENABLED=true`), one
folder per proxy (`telnet`, `ssh`, `ssh-passthrough`, `web`, `config-editor`) under
`LOG_DIR` (default `./logs`), one file per UTC day.

```jsonc
// GET /api/logs
{
  "dir": "/BBSFirewall/logs",
  "enabled": true,
  "files": [
    { "proxy": "telnet", "file": "telnet-2026-09-11.log", "date": "2026-09-11",
      "size": 48213, "mtime": "2026-09-11T21:48:59.833Z" },
    { "proxy": "ssh",    "file": "ssh-2026-09-10.log",    "date": "2026-09-10",
      "size": 91027, "mtime": "2026-09-10T23:59:58.001Z" }
  ]
}
```

`GET /api/logs/view?proxy=telnet&file=telnet-2026-09-11.log`:

```json
{ "proxy": "telnet", "file": "telnet-2026-09-11.log",
  "content": "[2026-09-11T00:00:01.000Z] [BLOCKED] …\n…",
  "truncated": false, "size": 48213 }
```

Files over 512 KB are **tailed**, not rejected — `truncated: true` and `content` holds
just the last 512 KB (rounded down to a whole line), never the whole file. `proxy` and
`file` are validated against the exact `<proxy>-<YYYY-MM-DD>.log` shape `file-logger.js`
itself writes — anything else (a path-traversal attempt, a mismatched proxy/file pair, a
name that never existed) is `400`; a well-formed name that isn't on disk is `404`.

`POST /api/logs/delete {"proxy":"telnet","file":"telnet-2026-09-11.log"}`:

```json
{ "ok": true, "proxy": "telnet", "file": "telnet-2026-09-11.log" }
```

Deletion is **permanent** — there is no backup or trash. Deleting a proxy's
currently-open (today's) file closes its write stream first; the next log line for that
proxy just opens a fresh file, same as after a normal midnight rotation. Goes through the
same one-at-a-time busy lock as save/restart/geoip/sshkey/cert (`429` if another mutating
op is in flight).

---

## Error responses

| Status | Body | Meaning |
|---|---|---|
| `401` | `{"error":"Invalid API key"}` | Key missing or wrong |
| `401` | `{"error":"Not authenticated"}` | No `Authorization` / `X-API-Key` header at all (request fell through to the browser lane) |
| `403` | `{"error":"Forbidden"}` | Source IP not in `api-trustedhosts.txt` (when that list is non-empty) |
| `429` | `{"error":"Too many failed attempts. Try again later."}` | 5 bad keys from this IP in 15 min |
| `429` | `{"error":"A \"save\" operation is already running — wait for it to finish."}` | Another mutating op (save/restart/geoip/sshkey/cert/logs delete) is in flight |
| `400` | `{"errors":["…","…"]}` or `{"error":"…"}` | `POST /api/save` validation failed; `.env` was not changed (or was restored) |
| `400` | `{"error":"invalid log file name"}` or `{"error":"proxy and file are required"}` | `/api/logs/view` or `/api/logs/delete` got a `proxy`/`file` pair that isn't a well-formed, matching log filename |
| `404` | `{"error":"Log file not found"}` | `/api/logs/view` or `/api/logs/delete` got a well-formed name that isn't on disk |
| `404` | `{"error":"Not found"}` | Unknown `/api/*` path or wrong method |

---

## Data shapes

### Round-tripping a setting

`GET /api/config` gives you `sections[].fields[]`, each with `key`, `value`, `enabled`.
To change one, `POST /api/save` with just that key:

```json
{ "env": { "MAX_CONNECTIONS": { "value": "512", "enabled": true } }, "files": {} }
```

To **unset** an optional key (comment it out), send `"enabled": false`.

### Editing a list file

```json
{ "env": {}, "files": { "triggers": "GET / HTTP\n/\\x16\\x03/\nCONNECT \n" } }
```

The whole file is replaced with the string you send.

---

## Security notes

- **The API key is equivalent to root on the box.** `GET /api/config` returns every
  secret in `.env` (the editor password, the MaxMind key, and `API_KEY` itself);
  `POST /api/save` can rewrite `.env`; `/api/restart`, `/api/sshkey`, `/api/cert` run
  commands; `/api/update/apply` replaces the running code entirely (with an automatic
  rollback if it fails validation). Treat `API_KEY` with the same care as the server's
  SSH password. Rotate it (edit `.env`, restart) if the dashboard is ever compromised.
- **Restrict by IP.** Put the dashboard's address in `api-trustedhosts.txt`.
- **Log files can contain caller IPs and raw connection data** (depending on the
  configured file-log level), and `POST /api/logs/delete` removes them with no
  undo. Treat `/api/logs*` with the same care as any other data-handling endpoint.
- **Expose the editor port directly**, not behind a reverse proxy — the IP allowlist
  matches the real TCP peer and ignores `X-Forwarded-For`.
- Changing `API_KEY` (or any `.env` mode selector) via `/api/save` applies on the next
  restart, not immediately.
- There are **no CORS headers**. A browser page on a different origin cannot read
  `/api/*` responses; call the API from your dashboard's backend.

---

## Sample code

### curl

```bash
API=https://admin.example.com:8443
KEY='paste-your-API_KEY-here'
# add -k if the editor uses a self-signed certificate

# read metrics
curl -s "$API/api/stats" -H "Authorization: Bearer $KEY"

# read the whole config
curl -s "$API/api/config" -H "Authorization: Bearer $KEY"

# change one setting
curl -s "$API/api/save" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  --data-raw '{"env":{"BLOCKED_COUNTRIES":{"value":"CN,RU,KP","enabled":true}},"files":{}}'

# replace the blocklist file
curl -s "$API/api/save" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  --data-raw '{"env":{},"files":{"blocklist":"203.0.113.5\n198.51.100.0/24\n"}}'

# restart to apply .env changes
curl -s "$API/api/save" >/dev/null ; curl -s -X POST "$API/api/restart" -H "Authorization: Bearer $KEY"

# check for and apply an update, or roll one back
curl -s "$API/api/update/check" -H "Authorization: Bearer $KEY"
curl -s -X POST "$API/api/update/apply" -H "Authorization: Bearer $KEY"
curl -s -X POST "$API/api/update/rollback" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  --data-raw '{"backup":"pre-update-1.3.7-2026-09-22T12-00-00-000Z"}'

# list log files, view one, delete one
curl -s "$API/api/logs" -H "Authorization: Bearer $KEY"
curl -s "$API/api/logs/view?proxy=telnet&file=telnet-2026-09-11.log" -H "Authorization: Bearer $KEY"
curl -s -X POST "$API/api/logs/delete" -H "Authorization: Bearer $KEY" \
  -H 'Content-Type: application/json' \
  --data-raw '{"proxy":"telnet","file":"telnet-2026-09-11.log"}'
```

### Node.js (18+, built-in fetch)

```js
const BASE = 'https://admin.example.com:8443';
const KEY  = process.env.BBSFW_API_KEY;

// For a self-signed editor cert only:
// const { Agent, setGlobalDispatcher } = require('undici');
// setGlobalDispatcher(new Agent({ connect: { rejectUnauthorized: false } }));

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(BASE + path, {
    method,
    headers: {
      'Authorization': `Bearer ${KEY}`,
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => null);
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status} ${JSON.stringify(data)}`);
  return data;
}

(async () => {
  const stats = await api('/api/stats');
  console.log(`v${stats.host.version}  active=${stats.firewall.activeTotal}  ` +
              `rejected=${stats.firewall.totals.rejected}  blocklist=${stats.firewall.ipfilter.blocklistSize}`);

  // add a country to the block list
  await api('/api/save', { method: 'POST', body: {
    env: { BLOCKED_COUNTRIES: { value: 'CN,RU,KP,IR', enabled: true } }, files: {},
  }});

  // await api('/api/restart', { method: 'POST' });   // apply it
})().catch(e => { console.error(e); process.exit(1); });
```

### Python (requests)

```python
import os, requests

BASE = "https://admin.example.com:8443"
KEY  = os.environ["BBSFW_API_KEY"]
S = requests.Session()
S.headers["Authorization"] = f"Bearer {KEY}"
# S.verify = False   # self-signed editor cert only

def api(path, method="GET", json=None):
    r = S.request(method, BASE + path, json=json, timeout=30)
    r.raise_for_status()
    return r.json()

stats = api("/api/stats")
print(f"v{stats['host']['version']}  active={stats['firewall']['activeTotal']}  "
      f"blocklist={stats['firewall']['ipfilter']['blocklistSize']}")

api("/api/save", "POST", json={
    "env": {"MAX_CONNECTIONS_PER_IP": {"value": "5", "enabled": True}},
    "files": {},
})
# api("/api/restart", "POST")
```

---

## Verifying it works

`api-smoke.sh` ships in the repo. It exercises auth (good key, bad key, `X-API-Key`),
the read endpoints (`/api/config`, `/api/logs`), a no-op save (safe — it only writes a
`.env` backup), and the plain-HTTP redirect, and fails loudly if anything is off:

```bash
API=https://admin.example.com:8443 KEY='your-API_KEY' bash api-smoke.sh
```

Expected output:

```
auth: good key /api/stats ......... OK
auth: bad key rejected ............ OK
auth: X-API-Key header ............ OK
read: /api/config ................. OK
read: /api/logs .................... OK
read: firewall reports version .... 1.3.0
write: no-op /api/save ............ OK
redirect: plain HTTP on the port .. OK -> https://admin.example.com:8443/anything?x=1
ALL CHECKS PASSED
```

The script in full:

```bash
#!/usr/bin/env bash
set -euo pipefail
API=${API:-https://admin.example.com:8443}
KEY=${KEY:?set KEY to your API_KEY}
CURL=(curl -sS --max-time 20)         # add -k here if the editor cert is self-signed

code() { "${CURL[@]}" -o /dev/null -w '%{http_code}' "$@"; }

echo -n "auth: good key /api/stats ......... "; [ "$(code -H "Authorization: Bearer $KEY" "$API/api/stats")" = 200 ] && echo OK || { echo FAIL; exit 1; }
echo -n "auth: bad key rejected ............ "; [ "$(code -H "Authorization: Bearer nope" "$API/api/stats")" = 401 ] && echo OK || { echo FAIL; exit 1; }
echo -n "auth: X-API-Key header ............ "; [ "$(code -H "X-API-Key: $KEY" "$API/api/stats")" = 200 ] && echo OK || { echo FAIL; exit 1; }
echo -n "read: /api/config ................. "; [ "$(code -H "Authorization: Bearer $KEY" "$API/api/config")" = 200 ] && echo OK || { echo FAIL; exit 1; }
echo -n "read: /api/logs .................... "; [ "$(code -H "Authorization: Bearer $KEY" "$API/api/logs")" = 200 ] && echo OK || { echo FAIL; exit 1; }

ver=$("${CURL[@]}" -H "Authorization: Bearer $KEY" "$API/api/stats" \
      | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).host.version))')
echo    "read: firewall reports version .... $ver"

echo -n "write: no-op /api/save ............ "
"${CURL[@]}" -X POST -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  --data-raw '{"env":{},"files":{}}' "$API/api/save" | grep -q '"ok":true' && echo OK || { echo FAIL; exit 1; }

http=${API/https:/http:}
echo -n "redirect: plain HTTP on the port .. "
loc=$(curl -sS --max-time 10 -o /dev/null -w '%{redirect_url}' "$http/anything?x=1")
[ "$loc" = "${API}/anything?x=1" ] && echo "OK -> $loc" || echo "note: got '$loc' (redirect may be disabled)"

echo "ALL CHECKS PASSED"
```
