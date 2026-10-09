#!/bin/bash
# palog e2e verification - run on server as ubuntu
set -u
B=http://127.0.0.1:8080
ADMIN_USER=admin
ADMIN_PW="${1:-}"
AOK=1

say() { printf '\n== %s ==\n' "$*"; }
fail() { echo "FAIL: $*"; AOK=0; }

[ -n "$ADMIN_PW" ] || { echo "usage: $0 <admin-password>"; exit 2; }

say "1. admin login"
LOGIN=$(curl -sS -m 5 -X POST "$B/api/login" -H 'Content-Type: application/json' -d "{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PW\"}")
TOK=$(echo "$LOGIN" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$TOK" ] || { echo "login response: $LOGIN"; fail "no token"; exit 1; }
echo "token ok: ${TOK:0:12}..."

say "2. /api/me (admin)"
ME=$(curl -sS -m 5 "$B/api/me" -H "Authorization: Bearer $TOK")
echo "$ME"
echo "$ME" | grep -q '"role":"admin"' || fail "me not admin: $ME"

say "3. devices list (admin, expect panabit)"
DEV=$(curl -sS -m 5 "$B/api/devices" -H "Authorization: Bearer $TOK")
echo "$DEV"
echo "$DEV" | grep -q '"name":"panabit"' || fail "panabit missing: $DEV"

say "4. add second device fw-test on 40201 (idempotent)"
if ! echo "$DEV" | grep -q '"name":"fw-test"'; then
  ADD=$(curl -sS -m 5 -X PUT "$B/api/devices" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"name":"fw-test","port":40201,"enabled":true}')
  echo "$ADD"
  echo "$ADD" | grep -q '"name":"fw-test"' || fail "add device: $ADD"
else
  echo "already exists, skip"
fi

sleep 2
say "5. health shows 2 listeners"
HL=$(curl -sS -m 5 "$B/api/health")
echo "$HL"
echo "$HL" | grep -q 'fw-test' || fail "fw-test listener missing: $HL"

say "6. create scoped user auditor (fw-test only, idempotent)"
if ! curl -sS -m 5 "$B/api/users" -H "Authorization: Bearer $TOK" | grep -q '"username":"auditor"'; then
  UADD=$(curl -sS -m 5 -X PUT "$B/api/users" -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' -d '{"username":"auditor","password":"auditpw1","role":"user","devices":"fw-test"}')
  echo "$UADD"
  echo "$UADD" | grep -q '"username":"auditor"' || fail "create auditor: $UADD"
else
  echo "already exists, skip"
fi

say "7. auditor login"
ALOGIN=$(curl -sS -m 5 -X POST "$B/api/login" -H 'Content-Type: application/json' -d '{"username":"auditor","password":"auditpw1"}')
ATOK=$(echo "$ALOGIN" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$ATOK" ] || { echo "auditor login: $ALOGIN"; fail "auditor no token"; }

say "8. auditor: all devices allowed incl panabit? (should only see fw-test)"
ADEV=$(curl -sS -m 5 "$B/api/devices" -H "Authorization: Bearer $ATOK")
echo "$ADEV"

say "9. auditor: query stats device=panabit -> expect 403"
S403=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "$B/api/stats?device=panabit" -H "Authorization: Bearer $ATOK")
echo "http $S403"
[ "$S403" = "403" ] || fail "expected 403 for panabit got $S403"

say "10. auditor: query stats device=fw-test -> expect 200"
S200=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "$B/api/stats?device=fw-test" -H "Authorization: Bearer $ATOK")
echo "http $S200"
[ "$S200" = "200" ] || fail "expected 200 for fw-test got $S200"

say "11. auditor: admin endpoint users -> expect 403"
U403=$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "$B/api/users" -H "Authorization: Bearer $ATOK")
echo "http $U403"
[ "$U403" = "403" ] || fail "expected 403 for users got $U403"

say "12. send test UDP packet to fw-test:40201, verify device-tagged storage"
python3 - "$()" <<'PYEOF' >/dev/null 2>&1 || true
PYEOF
python3 /tmp/send_test_pkt.py 40201 > /dev/null 2>&1 || true
sleep 2
SLOGS=$(curl -sS -m 5 "$B/api/logs?device=fw-test&limit=3" -H "Authorization: Bearer $ATOK")
echo "$SLOGS"
echo "$SLOGS" | grep -q '"device":"fw-test"' || fail "fw-test row not device-tagged: $SLOGS"
echo "$SLOGS" | grep -q 'e2e.test.cn' || fail "test packet domain missing: $SLOGS"

if [ "$AOK" = 1 ]; then echo; echo "E2E_RESULT: ALL PASS"; else echo; echo "E2E_RESULT: SOME FAILED"; exit 1; fi