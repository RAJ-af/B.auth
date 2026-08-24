#!/usr/bin/env bash
# End-to-end smoke gate (spec §12). Run from a fully-seeded stack:
#     ./scripts/smoke-test.sh
# Covers: container health, sign_networks/subnet drift guard, no-plaintext-mech
# audit, live API loop with real TOTP logins, DKIM on stored mail (header
# section only), token-tagged inbound spam + same-run external relay copy,
# DNS doc freshness, secret hygiene (all-objects history scan, fail-closed).
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
# dkim_signing.conf carries a STATIC copy of the compose subnet (rspamd reads no
# compose env). If .env ever changes the subnet without the conf following,
# submissions silently stop being signed — so compare both parses and fail
# loudly on drift instead of discovering it via unsigned mail later.
CONF_SUBNET=$(sed -n 's/^sign_networks[[:space:]]*=//p' \
  config/rspamd/local.d/dkim_signing.conf | head -1 | tr -d ' ;[]"')
ENV_SUBNET=$(grep '^COMPOSE_SUBNET=' .env | cut -d= -f2)
if [ -z "$CONF_SUBNET" ] || [ -z "$ENV_SUBNET" ] || [ "$CONF_SUBNET" != "$ENV_SUBNET" ]; then
  echo "DRIFT: sign_networks='${CONF_SUBNET:-unset}' != COMPOSE_SUBNET='${ENV_SUBNET:-unset}'"
  echo "       align config/rspamd/local.d/dkim_signing.conf with .env, then up -d rspamd"
  exit 1
fi
echo "sign_networks ok (${CONF_SUBNET})"

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

echo "SMOKE TEST PASSED"
