#!/usr/bin/env bash
# End-to-end smoke gate (spec §12). Run from a fully-seeded stack:
#     ./scripts/smoke-test.sh
# Covers: container health, no-plaintext-mech audit, live API loop with real
# TOTP logins, DKIM on stored mail, inbound spam headers, external relay copy,
# DNS doc freshness, secret hygiene.
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

echo "== 2. no plaintext auth mechs on dovecot =="
docker compose exec -T dovecot doveconf -n | tee /dev/stderr | \
  grep -E "^auth_mechanisms = xoauth2 oauthbearer$" > /dev/null \
  || { echo "BAD MECHS"; exit 1; }
if docker compose exec -T dovecot doveconf -n | grep -q "mechanisms.*plain"; then
  echo "PLAIN LEAKED"; exit 1
fi

echo "== 3. live api loop =="
python3 scripts/live_check.py

echo "== 4. DKIM signature stored =="
# Every message stored in bob's mailbox arrives through the postfix milter path
# (API submission), so all of them must be signed once sign_networks covers the
# compose subnet. IMAP moves delivered mail new/ -> cur/ on first SELECT, so
# both dirs are audited. (Alice's Sent copy is IMAP-appended before signing and
# is deliberately out of scope here; see README security notes.)
docker compose exec -T dovecot sh -c '
  cd /var/mail/vhosts/'"${DOMAIN}"'/bob/Maildir || exit 9
  total=$(find new cur -type f 2>/dev/null | wc -l)
  signed=$(grep -rl "DKIM-Signature" new cur 2>/dev/null | wc -l)
  echo "bob stored messages: $total, DKIM-signed: $signed"
  [ "$total" -ge 1 ] && [ "$signed" -eq "$total" ]' \
  || { echo "unsigned or missing stored mail for bob"; exit 1; }

echo "== 5. inbound spam headers =="
# swaks ships in the postfix image; inject from inside it so the mail takes the
# real :25 -> milter -> LMTP path like any external inbound message.
docker compose exec -T postfix sh -c "swaks --to alice@${DOMAIN} --from scanner@example.net \
  --server localhost:25 --header 'Subject: smoke-spam' --body 'XJS*C4JDBQADN1'" >/dev/null
spam_file=""
for _ in $(seq 1 10); do
  spam_file=$(docker compose exec -T dovecot sh -c \
    'grep -rl "Subject: smoke-spam" /var/mail/vhosts/'"${DOMAIN}"'/alice/Maildir/new/ /var/mail/vhosts/'"${DOMAIN}"'/alice/Maildir/cur/ 2>/dev/null | head -1')
  [ -n "$spam_file" ] && break
  sleep 1
done
[ -n "$spam_file" ] || { echo "smoke-spam never delivered to alice"; exit 1; }
echo "delivered as: $spam_file"
docker compose exec -T dovecot sh -c \
  'grep -h "^Authentication-Results:" '"$spam_file"'' | tee /dev/stderr | grep -q . \
  || { echo "no Authentication-Results header"; exit 1; }

echo "== 6. external copy in mailpit =="
curl -sf "http://localhost:8025/api/v1/messages" | \
  python3 -c "import sys,json;ms=json.load(sys.stdin)['messages'];assert any('example.org' in json.dumps(m) for m in ms);print('mailpit ok')"

echo "== 7. dns records doc has dkim pubkey =="
grep -q "v=DKIM1\|public" docs/dns-records.txt || { echo "dns-records incomplete"; exit 1; }

echo "== 8. secret hygiene (spec §8 #8) =="
git check-ignore -q .env || { echo "FAIL: .env not gitignored"; exit 1; }
if git ls-files --error-unmatch .env >/dev/null 2>&1; then
  echo "FAIL: .env tracked despite gitignore"; exit 1
fi
SECRET=$(grep '^KC_INTROSPECTION_SECRET=' .env | cut -d= -f2)
if [ -n "$SECRET" ] && git log --all -p | grep -qF "$SECRET"; then
  echo "FAIL: introspection secret found in git history"; exit 1
fi
grep -rqE "INTROSPECTION" api/Dockerfile mail/*/Dockerfile \
  && { echo "FAIL: secret referenced in an image build"; exit 1; }
echo "secret hygiene ok"

echo "SMOKE TEST PASSED"
