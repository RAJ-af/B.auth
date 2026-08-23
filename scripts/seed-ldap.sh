#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .env
RDN="${MAIL_DOMAIN//./,dc=}"
sed -e "s/__DOMAIN_RDN__/${RDN}/g" \
    -e "s/__ALICE__/${TEST_USER_ALICE}/g" \
    -e "s/__BOB__/${TEST_USER_BOB}/g" \
    -e "s|__PASSWORD__|${TEST_USER_PASSWORD}|g" \
    config/openldap/test-users.ldif.template > /tmp/users.ldif
docker compose exec -T openldap ldapadd -x \
  -D "cn=admin,dc=${RDN}" -w "${LDAP_ROOT_PASSWORD}" -c -f - < /tmp/users.ldif
rm -f /tmp/users.ldif