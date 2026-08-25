#!/usr/bin/env bash
# Apply db/migrations/*.sql in order to the sovereign_app database, then run the
# idempotent seeded-user backfill (spec §6). Safe to re-run any time.
set -euo pipefail
cd "$(dirname "$0")/.."
source .env
: "${SOVEREIGN_APP_DB:=sovereign_app}"
PSQL="docker compose exec -T postgres psql -U ${POSTGRES_USER} -v ON_ERROR_STOP=1"

$PSQL -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname='${SOVEREIGN_APP_DB}'" \
  | grep -q 1 || $PSQL -d postgres -c "CREATE DATABASE ${SOVEREIGN_APP_DB}"

$PSQL -d "${SOVEREIGN_APP_DB}" <<'SQL'
CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now());
SQL
for f in db/migrations/*.sql; do
  v="$(basename "$f")"
  if [ "$($PSQL -d "${SOVEREIGN_APP_DB}" -tAc \
        "SELECT count(*) FROM schema_migrations WHERE version='${v}'")" = "0" ]; then
    echo "applying ${v}"
    $PSQL -d "${SOVEREIGN_APP_DB}" -f - < "$f"
    $PSQL -d "${SOVEREIGN_APP_DB}" -c "INSERT INTO schema_migrations(version) VALUES ('${v}')"
  fi
done

# Backfill: accounts rows for users that seed-ldap.sh already created, so existing
# users exercise every flow. Values come from operator-controlled .env seed vars.
$PSQL -d "${SOVEREIGN_APP_DB}" <<SQL
INSERT INTO accounts (email,display_name,phone_e164,account_type,tier,verification,status)
VALUES ('${TEST_USER_ALICE}','Alice','${TEST_PHONE_ALICE}','independent','tier1_phone','phone_only','active'),
       ('${TEST_USER_BOB}','Bob','${TEST_PHONE_BOB}','independent','tier1_phone','phone_only','active'),
       ('${SOVEREIGN_ADMIN_USER}','Sovereign Admin','${TEST_PHONE_ADMIN}','independent','tier1_phone','phone_only','active')
ON CONFLICT (email) DO NOTHING;
SQL
echo "db migrate + backfill OK (${SOVEREIGN_APP_DB})"