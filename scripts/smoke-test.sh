#!/usr/bin/env bash
# End-to-end smoke gate (spec §12). Run from a fully-seeded stack:
#     ./scripts/smoke-test.sh
# Covers: container health, sign_networks/subnet drift guard, no-plaintext-mech
# audit, live API loop with real TOTP logins, DKIM on stored mail (header
# section only), token-tagged inbound spam + same-run external relay copy,
# DNS doc freshness, secret hygiene (all-objects history scan, fail-closed),
# and the identity subsystem (signup/tiers/admin queue/family/recovery).
set -euo pipefail
cd "$(dirname "$0")/.."
source .env
DOMAIN="${MAIL_DOMAIN}"

echo "== 1. containers healthy =="
# All 9 long-running services must be present and free of bad states; the 5
# services that define healthchecks (openldap postgres keycloak rspamd mailpit)
# must additionally report (healthy). Fail-on-bad semantics: exit nonzero only
# when something is actually wrong.
docker compose ps --format '{{.Service}} {{.Status}}' | tee /dev/stderr | \
  awk '
    tolower($0) ~ /unhealthy|restarting|exited|exiting|dead|paused|created|removing/ { bad=1; print "BAD STATE: " $0 }
    tolower($0) ~ /\(healthy\)/ { ok++ }
    { n++ }
    END {
      if (n < 9) { print "only " n "/9 services up"; bad=1 }
      if (ok < 5) { print "only " ok "/5 healthchecked services healthy"; bad=1 }
      exit bad
    }' || { echo "unhealthy containers"; exit 1; }

echo "== 1b. rspamd sign_networks == COMPOSE_SUBNET (drift guard) =="
# sign_networks is RENDERED at container start from $COMPOSE_SUBNET
# (render-dkim-signing.sh -> override.d), so drift should be structurally
# impossible — this guard proves the live RUNNING config really carries the
# .env subnet on every gate run, catching rendering/wiring regressions rather
# than comparing a static file that no longer exists.
DUMP=$(docker compose exec -T rspamd rspamadm configdump dkim_signing 2>/dev/null)
ENV_SUBNET=$(grep '^COMPOSE_SUBNET=' .env | cut -d= -f2)
if [ -z "$ENV_SUBNET" ] || ! printf '%s' "$DUMP" | grep -qF "\"${ENV_SUBNET}\""; then
  echo "DRIFT: live sign_networks does not contain COMPOSE_SUBNET='${ENV_SUBNET:-unset}'"
  echo "       check render-dkim-signing.sh / compose env wiring, then up -d --force-recreate rspamd"
  exit 1
fi
echo "sign_networks ok (${ENV_SUBNET})"

echo "== 2. no plaintext auth mechs on dovecot =="
docker compose exec -T dovecot doveconf -n | tee /dev/stderr | \
  grep -E "^auth_mechanisms = xoauth2 oauthbearer$" > /dev/null \
  || { echo "BAD MECHS"; exit 1; }
if docker compose exec -T dovecot doveconf -n | grep -q "mechanisms.*plain"; then
  echo "PLAIN LEAKED"; exit 1
fi

echo "== 3. live api loop =="
python3 scripts/live_check.py

echo "== 4. DKIM signature stored (header section only) =="
# Every message stored in bob's mailbox arrives through the postfix milter path
# (API submission), so all of them must be signed once sign_networks covers the
# compose subnet. IMAP moves delivered mail new/ -> cur/ on first SELECT, so
# both dirs are audited. The signature must sit in the message HEADER SECTION
# (line 1 up to the first blank line): grepping the whole file would also match
# body text that merely quotes a DKIM-Signature line and count it as signed.
# (Alice's Sent copy is IMAP-appended before signing and is deliberately out of
# scope here; see README security notes.)
docker compose exec -T dovecot sh -c '
  cd /var/mail/vhosts/'"${DOMAIN}"'/bob/Maildir || exit 9
  total=0; signed=0
  for f in $(find new cur -type f 2>/dev/null); do
    total=$((total+1))
    sed -n "1,/^$/p" "$f" | grep -q "^DKIM-Signature:" && signed=$((signed+1))
  done
  echo "bob stored messages: $total, DKIM-signed in header section: $signed"
  [ "$total" -ge 1 ] && [ "$signed" -eq "$total" ]' \
  || { echo "unsigned or missing stored mail for bob"; exit 1; }

echo "== 5. inbound spam headers =="
# swaks ships in the postfix image; inject from inside it so the mail takes the
# real :25 -> milter -> LMTP path like any external inbound message. The Subject
# carries a per-run token (same pattern as live_check's live-check-<epoch>) so
# stale copies from earlier runs can never satisfy this step. A second,
# non-local recipient puts the SAME message on the external relay leg audited
# in step 6 — one probe, both delivery paths.
TOKEN="smoke-spam-$(date +%s)"
docker compose exec -T postfix sh -c "swaks --to alice@${DOMAIN},ext-copy-${TOKEN}@example.org \
  --from scanner@example.net --server localhost:25 --header 'Subject: ${TOKEN}' \
  --body 'XJS*C4JDBQADN1'" >/dev/null
spam_file=""
for _ in $(seq 1 10); do
  spam_file=$(docker compose exec -T dovecot sh -c \
    'grep -rl "'"$TOKEN"'" /var/mail/vhosts/'"${DOMAIN}"'/alice/Maildir/new/ /var/mail/vhosts/'"${DOMAIN}"'/alice/Maildir/cur/ 2>/dev/null | head -1')
  [ -n "$spam_file" ] && break
  sleep 1
done
[ -n "$spam_file" ] || { echo "${TOKEN} never delivered to alice"; exit 1; }
echo "delivered as: $spam_file"
docker compose exec -T dovecot sh -c \
  'grep -h "^Authentication-Results:" '"$spam_file"'' | tee /dev/stderr | grep -q . \
  || { echo "no Authentication-Results header"; exit 1; }

echo "== 6. same-run external relay copy in mailpit =="
# The example.org recipient is non-local, so that leg leaves via
# relayhost [mailpit]:1025. Assert THIS run's token (not just any stored
# message) so leftovers from earlier runs cannot mask a broken relay.
mp_hit=""
for _ in $(seq 1 10); do
  mp_hit=$(curl -sf "http://localhost:8025/api/v1/messages" | \
    python3 -c "
import sys, json
ms = json.load(sys.stdin)['messages']
print('yes' if any('${TOKEN}' in (m.get('Subject') or '') for m in ms) else '')" || true)
  [ -n "$mp_hit" ] && break
  sleep 1
done
[ -n "$mp_hit" ] || { echo "${TOKEN} never reached mailpit"; exit 1; }
echo "external relay copy ok (${TOKEN})"

echo "== 7. dns records doc has dkim pubkey =="
grep -q "v=DKIM1\|public" docs/dns-records.txt || { echo "dns-records incomplete"; exit 1; }

echo "== 8. secret hygiene (spec §8 #8) =="
git check-ignore -q .env || { echo "FAIL: .env not gitignored"; exit 1; }
if git ls-files --error-unmatch .env >/dev/null 2>&1; then
  echo "FAIL: .env tracked despite gitignore"; exit 1
fi
SECRET=$(grep '^KC_INTROSPECTION_SECRET=' .env | cut -d= -f2)
# Fail CLOSED: an empty/missing secret means the scan below would prove nothing.
# A seeded stack always carries it, so absence is itself a seeding failure.
if [ -z "$SECRET" ]; then
  echo "FAIL: KC_INTROSPECTION_SECRET missing/empty in .env — cannot run history scan"
  exit 1
fi
# Scan EVERY object in the object database — including unreachable ones
# (orphaned commits, amended-away blobs) that `git log --all -p` never visits.
# Blob contents stream one at a time through grep, so memory stays bounded no
# matter the history size. Only object SHAs are ever printed, never the secret.
scan_history_for_secret() {
  git cat-file --batch-all-objects --batch-check='%(objectname) %(objecttype)' |
  awk '$2 == "blob" { print $1 }' |
  while read -r sha; do
    if git cat-file blob "$sha" 2>/dev/null | grep -qF -- "$SECRET"; then
      echo "$sha"
      break
    fi
  done
  return 0
}
leak=$(scan_history_for_secret)
if [ -n "$leak" ]; then
  echo "FAIL: introspection secret found in git object: $leak"
  exit 1
fi
grep -rqE "INTROSPECTION" api/Dockerfile mail/*/Dockerfile \
  && { echo "FAIL: secret referenced in an image build"; exit 1; }
echo "secret hygiene ok"

echo "== 9. identity subsystem: signup + tiers + admin queue + family + recovery =="
# Phase-5 gate (identity-auth-flow spec §12). Needs the stack booted with the
# smoke overrides exported BEFORE `docker compose up -d --build`:
#     IDVERIFY_MODE=manual FAMILY_LINK_COOLDOWN_HOURS=0 RECOVERY_MIN_DWELL_SECONDS=5
#
# OTP extraction idiom: OTP_PROVIDER=console MASKS phone numbers in its log
# lines ("OTP for +91****6670 via sms: 801037") — and distinct E.164 numbers
# can mask identically (+918000000001 and +910000000001 both become
# "+91****0001"). Codes are therefore located by ORDER, never by phone text:
# snapshot the api log length, trigger exactly ONE send, then require exactly
# one new console-OTP line past the snapshot.
api_log_lines() { docker compose logs api 2>/dev/null | wc -l; }
one_otp_after() {   # $1 = api_log_lines snapshot taken BEFORE the triggering send
  local codes n
  codes=$(docker compose logs api 2>/dev/null | tail -n +"$(( $1 + 1 ))" \
          | sed -nE 's/^.*OTP for .* via sms: ([0-9]{6})$/\1/p')
  n=$(printf '%s\n' "$codes" | grep -c . || true)
  [ "$n" = "1" ] || { echo "expected exactly 1 new console OTP after mark $1, got $n"; exit 1; }
  printf '%s\n' "$codes"
}
kc_token() {        # $1=username $2=password $3=totp-secret -> prints access token
  python3 scripts/kc_browserless_login.py \
    --base-url "http://localhost:${KEYCLOAK_PORT}" --realm "$KC_REALM" \
    --client-id "$KC_APP_CLIENT" \
    --redirect-uri "http://localhost:${API_PORT}/auth/callback" \
    --username "$1" --password "$2" --totp-secret "$3" \
    | python3 -c 'import json,sys;print(json.load(sys.stdin)["access_token"])'
}
SMOKE_PW="smoke-password-123"

# --- 9-pre. idempotency: scrub smoke identities from earlier runs -------------
# signup/start answers 409 for an existing email, so re-runs against a dirty
# database must first remove carol/dave everywhere (children before the
# accounts row; LDAP entries and Maildirs too — dovecot recreates on demand).
docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$SOVEREIGN_APP_DB" -q <<SQL
DELETE FROM recovery_requests WHERE email IN ('carol@sovereign.mail','dave@sovereign.mail');
DELETE FROM family_links WHERE requester_email IN ('carol@sovereign.mail','dave@sovereign.mail')
                          OR target_email    IN ('carol@sovereign.mail','dave@sovereign.mail');
DELETE FROM devices WHERE email IN ('carol@sovereign.mail','dave@sovereign.mail');
DELETE FROM verification_reviews WHERE email IN ('carol@sovereign.mail','dave@sovereign.mail');
DELETE FROM notifications WHERE email IN ('carol@sovereign.mail','dave@sovereign.mail');
DELETE FROM signup_sessions WHERE payload_json->>'email' IN ('carol@sovereign.mail','dave@sovereign.mail');
DELETE FROM otp_challenges WHERE phone_e164 IN ('+918000000001','+918000000002');
DELETE FROM accounts WHERE email IN ('carol@sovereign.mail','dave@sovereign.mail');
SQL
docker compose exec -T openldap sh -c \
  'for u in carol dave; do ldapdelete -x -D "cn=admin,dc='"${DOMAIN//./,dc=}"'" \
     -w "'"$LDAP_ROOT_PASSWORD"'" "mail=$u@'"$DOMAIN"',ou=people,dc='"${DOMAIN//./,dc=}"'" 2>/dev/null; done; true'
docker compose exec -T dovecot sh -c \
  'rm -rf /var/mail/vhosts/'"${DOMAIN}"'/carol /var/mail/vhosts/'"${DOMAIN}"'/dave 2>/dev/null; true'

# --- 9a. signup, tier1 skip path (carol) --------------------------------------
MARK=$(api_log_lines)
curl -s -o /tmp/smoke-signup.json -w '%{http_code}' \
  -X POST localhost:8000/signup/start -H 'content-type: application/json' \
  -d '{"email":"carol@sovereign.mail","display_name":"Carol","phone_e164":"+918000000001","account_type":"independent"}' \
  | grep -q '^202$' || { echo "signup/start carol"; exit 1; }
TOK=$(python3 -c 'import json;print(json.load(open("/tmp/smoke-signup.json"))["session_token"])')
OTP_CODE=$(one_otp_after "$MARK")
curl -sf -X POST localhost:8000/signup/verify-otp -H 'content-type: application/json' \
  -d "{\"token\":\"$TOK\",\"code\":\"$OTP_CODE\"}" >/dev/null || { echo "carol verify-otp"; exit 1; }
curl -sf -X POST localhost:8000/signup/complete -H 'content-type: application/json' \
  -d "{\"token\":\"$TOK\",\"choice\":{\"kind\":\"skip\"},\"password\":\"$SMOKE_PW\"}" \
  | grep -q '"tier1_phone"' || { echo "carol tier1 complete"; exit 1; }
# provisioned directory row carries an SSHA password hash (same admin bind DN
# as seed-ldap.sh uses). LDIF prints raw-digest values BASE64 ("userPassword::"
# + encoded body), so decode before matching; plain form kept as fallback.
if ! docker compose exec -T openldap ldapsearch -x \
     -b "ou=people,dc=${DOMAIN//./,dc=}" "(mail=carol@sovereign.mail)" userPassword \
     -D "cn=admin,dc=${DOMAIN//./,dc=}" -w "$LDAP_ROOT_PASSWORD" > /tmp/carol-ldap.ldif 2>&1; then
  :; fi
B64PW=$(sed -n 's/^userPassword:: \([A-Za-z0-9+/=]*\)$/\1/p' /tmp/carol-ldap.ldif)
{ [ -n "$B64PW" ] && printf '%s' "$B64PW" | base64 -d | grep -q "{SSHA}"; } \
  || grep -q "^userPassword: {SSHA}" /tmp/carol-ldap.ldif \
  || { echo "carol LDAP row lacks SSHA hash — ldapsearch output:"; head -20 /tmp/carol-ldap.ldif; exit 1; }

# --- 9b. signup, MANUAL idverify round-trip (dave) ----------------------------
# IDVERIFY_MODE=manual routes every submission to the operator queue; signup
# itself still completes at tier1 with identity_status=queued_manual_review.
MARK=$(api_log_lines)
curl -s -o /tmp/smoke-signup.json -w '%{http_code}' \
  -X POST localhost:8000/signup/start -H 'content-type: application/json' \
  -d '{"email":"dave@sovereign.mail","display_name":"Dave","phone_e164":"+918000000002","account_type":"independent"}' \
  | grep -q '^202$' || { echo "signup/start dave"; exit 1; }
TOK2=$(python3 -c 'import json;print(json.load(open("/tmp/smoke-signup.json"))["session_token"])')
CODE2=$(one_otp_after "$MARK")
curl -sf -X POST localhost:8000/signup/verify-otp -H 'content-type: application/json' \
  -d "{\"token\":\"$TOK2\",\"code\":\"$CODE2\"}" >/dev/null || { echo "dave verify-otp"; exit 1; }
curl -sf -X POST localhost:8000/signup/complete -H 'content-type: application/json' \
  -d "{\"token\":\"$TOK2\",\"choice\":{\"kind\":\"submit_id\",\"full_name\":\"Dave\",\"document_type\":\"national_id\",\"id_number\":\"XX999999\",\"consent_selfie\":true},\"password\":\"$SMOKE_PW\"}" \
  | grep -q 'queued_manual_review' || { echo "dave manual queue body"; exit 1; }

# --- 9c. admin dashboard over the bearer JSON route ---------------------------
ADMIN_TOKEN=$(kc_token "$SOVEREIGN_ADMIN_USER" "$TEST_USER_PASSWORD" "$TEST_TOTP_SECRET_ADMIN") \
  || { echo "admin KC login"; exit 1; }
REV=$(curl -sf localhost:8000/admin/api/reviews -H "Authorization: Bearer $ADMIN_TOKEN") \
  || { echo "admin reviews fetch"; exit 1; }
printf '%s' "$REV" | grep -q dave@sovereign.mail || { echo "admin queue missing dave"; exit 1; }
RID=$(printf '%s' "$REV" | python3 -c '
import json,sys
rs=[r for r in json.load(sys.stdin)["reviews"] if r["email"]=="dave@sovereign.mail"]
assert rs, "no pending review for dave"
print(rs[0]["review_id"])') || { echo "review id extraction"; exit 1; }
curl -s -o /dev/null -w '%{http_code}' -X POST "localhost:8000/admin/api/reviews/$RID/approve" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | grep -q '^200$' || { echo "review approve"; exit 1; }
docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$SOVEREIGN_APP_DB" -tAc \
  "SELECT tier||'/'||verification FROM accounts WHERE email='dave@sovereign.mail'" \
  | grep -q "tier2_identity/manual_verified" || { echo "tier2 promotion"; exit 1; }

# --- 9d. family links ----------------------------------------------------------
CAROL_TOKEN=$(kc_token carol@sovereign.mail "$SMOKE_PW" "MFZWQ3DFOZQWS4ZA") \
  || { echo "carol KC login"; exit 1; }
DAVE_TOKEN=$(kc_token dave@sovereign.mail "$SMOKE_PW" "NBSWY3DPEHPK3PXP") \
  || { echo "dave KC login"; exit 1; }
ALICE_TOKEN=$(kc_token "$TEST_USER_ALICE" "$TEST_USER_PASSWORD" "$TEST_TOTP_SECRET_ALICE") \
  || { echo "alice KC login"; exit 1; }
# tier1 requester must be refused (family requests require tier2_identity)
C=$(curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8000/family/requests \
      -H "Authorization: Bearer $CAROL_TOKEN" -H 'content-type: application/json' \
      -d '{"target_email":"alice@sovereign.mail"}')
[ "$C" = "422" ] || { echo "tier1 family request expected 422, got $C"; exit 1; }
# dave (freshly promoted tier2) requests; CAROL approves her OWN incoming request
LID=$(curl -sf -X POST localhost:8000/family/requests \
        -H "Authorization: Bearer $DAVE_TOKEN" -H 'content-type: application/json' \
        -d '{"target_email":"carol@sovereign.mail"}' \
        | python3 -c 'import json,sys;print(json.load(sys.stdin)["link_id"])') \
  || { echo "family request dave->carol"; exit 1; }
curl -s -o /dev/null -w '%{http_code}' -X POST "localhost:8000/family/requests/$LID/approve" \
  -H "Authorization: Bearer $CAROL_TOKEN" | grep -q '^200$' || { echo "family approve carol"; exit 1; }
# a second link dave<->alice so alice's recovery below branches pending_family;
# alice approves from her own incoming queue like any member would
LID2=$(curl -sf -X POST localhost:8000/family/requests \
         -H "Authorization: Bearer $DAVE_TOKEN" -H 'content-type: application/json' \
         -d "{\"target_email\":\"${TEST_USER_ALICE}\"}" \
         | python3 -c 'import json,sys;print(json.load(sys.stdin)["link_id"])') \
  || { echo "family request dave->alice"; exit 1; }
APID=$(curl -sf localhost:8000/family/requests -H "Authorization: Bearer $ALICE_TOKEN" \
       | python3 -c '
import json,sys
rs=[r for r in json.load(sys.stdin)["requests"] if r.get("requester_email")=="dave@sovereign.mail"]
assert rs, "alice incoming family queue empty"
print(rs[0]["link_id"])') || { echo "alice incoming queue read"; exit 1; }
curl -s -o /dev/null -w '%{http_code}' -X POST "localhost:8000/family/requests/$APID/approve" \
  -H "Authorization: Bearer $ALICE_TOKEN" | grep -q '^200$' || { echo "family approve alice"; exit 1; }
# instant revoke probe: requester kills the dave<->carol link outright
curl -s -o /dev/null -w '%{http_code}' -X POST "localhost:8000/family/requests/$LID/revoke" \
  -H "Authorization: Bearer $DAVE_TOKEN" | grep -q '^200$' || { echo "family revoke"; exit 1; }

# pointer-only guarantee (spec §12/§15.3): the notification reaches the LOCAL
# recipient through our own postfix->dovecot path (mailpit only sees non-local
# relay copies), names the event in its subject, and carries NO URL.
FAM_FILE=""
for _ in $(seq 1 10); do
  FAM_FILE=$(docker compose exec -T dovecot sh -c \
    'grep -rl "^Subject: Sovereign Mail: family link request" \
       /var/mail/vhosts/'"${DOMAIN}"'/carol/Maildir/new/ /var/mail/vhosts/'"${DOMAIN}"'/carol/Maildir/cur/ 2>/dev/null | head -1')
  [ -n "$FAM_FILE" ] && break
  sleep 1
done
[ -n "$FAM_FILE" ] || { echo "family notification email never landed"; exit 1; }
# Negative control is structural: no URL -> sh prints nothing -> gate passes.
# The conditional MUST live inside sh -c (an if-less then/fi is a syntax error
# whose empty output would silently pass); "$1" keeps the path out of the
# quoted script text entirely.
if docker compose exec -T dovecot sh -c \
     'if grep -qiE "https?://" "$1"; then echo URL; fi' sh "$FAM_FILE" | grep -q URL; then
  echo "POINTER-ONLY VIOLATION: URL in family email ($FAM_FILE)"; exit 1
fi

# --- 9e. recovery pass 1: family branch (alice) --------------------------------
APHONE=$(docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$SOVEREIGN_APP_DB" -tAc \
  "SELECT phone_e164 FROM accounts WHERE email='${TEST_USER_ALICE}'")
[ -n "$APHONE" ] || { echo "alice accounts row/phone missing (db-migrate backfill ran?)"; exit 1; }
# anti-enumeration pin: ghost vs real start bodies must be BYTE-identical.
# The real call doubles as the live request whose OTP is extracted next.
A=$(curl -s -X POST localhost:8000/recovery/start -H 'content-type: application/json' \
      -d '{"email":"ghost@sovereign.mail"}'; echo)
MARK=$(api_log_lines)
B=$(curl -s -X POST localhost:8000/recovery/start -H 'content-type: application/json' \
      -d "{\"email\":\"${TEST_USER_ALICE}\"}"; echo)
[ "$A" = "$B" ] || { echo "anti-enumeration bodies differ"; exit 1; }
RCODE=$(one_otp_after "$MARK")
STAGE=$(curl -sf -X POST localhost:8000/recovery/verify-otp -H 'content-type: application/json' \
  -d "{\"email\":\"${TEST_USER_ALICE}\",\"code\":\"$RCODE\"}" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["stage"])') \
  || { echo "alice verify-otp call"; exit 1; }
case "$STAGE" in
  pending_family)
    # smoke links are cooldown-free (FAMILY_LINK_COOLDOWN_HOURS=0), so the
    # linked member authorizes immediately; R7 wire silence means this endpoint
    # answers the constant body whatever it actually decided
    curl -sf -X POST localhost:8000/recovery/family-approve \
      -H "Authorization: Bearer $DAVE_TOKEN" -H 'content-type: application/json' \
      -d "{\"requester_email\":\"${TEST_USER_ALICE}\"}" >/dev/null \
      || { echo "recovery family-approve call"; exit 1; } ;;
  *) echo "unexpected recovery stage for alice: $STAGE"; exit 1 ;;
esac
curl -sf -X POST localhost:8000/recovery/complete -H 'content-type: application/json' \
  -d "{\"email\":\"${TEST_USER_ALICE}\",\"new_password\":\"recovered-pass-123\"}" \
  | grep -q '"reset":true' || { echo "alice recovery complete"; exit 1; }
# NOTE: alice's seeded TEST_USER_PASSWORD no longer authenticates after this —
# the reset rewrote her LDAP password. Later phases must not re-login as alice.

# --- 9f. recovery pass 2: device dwell branch (bob) ----------------------------
BOB_TOKEN=$(kc_token "$TEST_USER_BOB" "$TEST_USER_PASSWORD" "$TEST_TOTP_SECRET_BOB") \
  || { echo "bob KC login"; exit 1; }
DEV=$(curl -sf -X POST localhost:8000/account/devices -H "Authorization: Bearer $BOB_TOKEN" \
  -H 'content-type: application/json' -d '{"label":"smoke-dwell-device"}' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["device_id"])') \
  || { echo "device registration"; exit 1; }
MARK=$(api_log_lines)
curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8000/recovery/start \
  -H 'content-type: application/json' -H "X-Device-ID: $DEV" \
  -d "{\"email\":\"${TEST_USER_BOB}\"}" | grep -q '^202$' || { echo "bob recovery start"; exit 1; }
RCODE=$(one_otp_after "$MARK")
STAGE=$(curl -sf -X POST localhost:8000/recovery/verify-otp -H 'content-type: application/json' \
  -d "{\"email\":\"${TEST_USER_BOB}\",\"code\":\"$RCODE\"}" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["stage"])') \
  || { echo "bob verify-otp call"; exit 1; }
case "$STAGE" in
  pending_dwell) sleep 6 ;;   # RECOVERY_MIN_DWELL_SECONDS=5 override + margin
  *) echo "unexpected recovery stage for bob: $STAGE"; exit 1 ;;
esac
# the SAME recognizing device must finish the wait (§13.6)
curl -sf -X POST localhost:8000/recovery/complete -H 'content-type: application/json' \
  -H "X-Device-ID: $DEV" \
  -d "{\"email\":\"${TEST_USER_BOB}\",\"new_password\":\"bob-recovered-pass-123\"}" \
  | grep -q '"reset":true' || { echo "bob recovery complete"; exit 1; }

# --- 9g. recovery pass 3: pending_admin branch + assisted grant (carol) --------
# No active link (hers was revoked above) and no registered device -> assisted
# queue; the operator path is the bearer grant route from Task 14.
MARK=$(api_log_lines)
curl -s -o /dev/null -w '%{http_code}' -X POST localhost:8000/recovery/start \
  -H 'content-type: application/json' \
  -d '{"email":"carol@sovereign.mail"}' | grep -q '^202$' || { echo "carol recovery start"; exit 1; }
RCODE=$(one_otp_after "$MARK")
STAGE=$(curl -sf -X POST localhost:8000/recovery/verify-otp -H 'content-type: application/json' \
  -d '{"email":"carol@sovereign.mail","code":"'"$RCODE"'"}' \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["stage"])') \
  || { echo "carol verify-otp call"; exit 1; }
case "$STAGE" in
  pending_admin)
    REQ_ID=$(docker compose exec -T postgres psql -U "$POSTGRES_USER" -d "$SOVEREIGN_APP_DB" -tAc \
      "SELECT req_id FROM recovery_requests WHERE email='carol@sovereign.mail'
       AND status='pending_admin' ORDER BY created_at DESC LIMIT 1" | tr -d '[:space:]')
    [ -n "$REQ_ID" ] || { echo "no pending_admin recovery row for carol"; exit 1; }
    curl -s -o /dev/null -w '%{http_code}' -X POST "localhost:8000/admin/api/recovery/$REQ_ID/grant" \
      -H "Authorization: Bearer $ADMIN_TOKEN" | grep -q '^200$' || { echo "admin grant"; exit 1; } ;;
  *) echo "unexpected recovery stage for carol: $STAGE"; exit 1 ;;
esac
curl -sf -X POST localhost:8000/recovery/complete -H 'content-type: application/json' \
  -d '{"email":"carol@sovereign.mail","new_password":"carol-recovered-pass"}' \
  | grep -q '"reset":true' || { echo "carol recovery complete"; exit 1; }

echo "identity subsystem ok"
echo "SMOKE TEST PASSED"
