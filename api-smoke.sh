#!/usr/bin/env bash
#
# BBSFirewall Management API smoke test.
# Exercises auth, the read endpoints (config, logs), a no-op save (safe — only
# writes a .env backup), and the plain-HTTP->HTTPS redirect. Fails loudly if
# anything is off.
#
#   API=https://admin.example.com:8443 KEY='your-API_KEY' bash api-smoke.sh
#
# See API.md for the full reference.

set -euo pipefail
API=${API:-https://admin.example.com:8443}
KEY=${KEY:?set KEY to your API_KEY}
CURL=(curl -sS --max-time 20)         # add -k here if the editor cert is self-signed

code() { "${CURL[@]}" -o /dev/null -w '%{http_code}' "$@"; }

echo -n "auth: good key /api/stats ......... "; [ "$(code -H "Authorization: Bearer $KEY" "$API/api/stats")" = 200 ] && echo OK || { echo FAIL; exit 1; }
echo -n "auth: bad key rejected ............ "; [ "$(code -H "Authorization: Bearer nope" "$API/api/stats")" = 401 ] && echo OK || { echo FAIL; exit 1; }
echo -n "auth: X-API-Key header ............ "; [ "$(code -H "X-API-Key: $KEY" "$API/api/stats")" = 200 ] && echo OK || { echo FAIL; exit 1; }
echo -n "read: /api/config ................. "; [ "$(code -H "Authorization: Bearer $KEY" "$API/api/config")" = 200 ] && echo OK || { echo FAIL; exit 1; }
echo -n "read: /api/health .................. "; [ "$(code -H "Authorization: Bearer $KEY" "$API/api/health")" = 200 ] && echo OK || { echo FAIL; exit 1; }
echo -n "read: /api/logs .................... "; [ "$(code -H "Authorization: Bearer $KEY" "$API/api/logs")" = 200 ] && echo OK || { echo FAIL; exit 1; }

ver=$("${CURL[@]}" -H "Authorization: Bearer $KEY" "$API/api/stats" \
      | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>console.log(JSON.parse(s).host.version))')
echo    "read: firewall reports version .... $ver"

echo -n "write: no-op /api/save ............ "
"${CURL[@]}" -X POST -H "Authorization: Bearer $KEY" -H 'Content-Type: application/json' \
  --data-raw '{"env":{},"files":{}}' "$API/api/save" | grep -q '"ok":true' && echo OK || { echo FAIL; exit 1; }

http=${API/https:/http:}
echo -n "redirect: plain HTTP on the port .. "
loc=$(curl -sS --max-time 10 -o /dev/null -w '%{redirect_url}' "$http/anything?x=1" || true)
[ "$loc" = "${API}/anything?x=1" ] && echo "OK -> $loc" || echo "note: got '$loc' (redirect may be disabled)"

echo "ALL CHECKS PASSED"
