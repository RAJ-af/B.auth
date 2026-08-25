#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .env
RDN="${MAIL_DOMAIN//./,dc=}"

# Grant anonymous READ access (osixia default ACL denies it with `by * none`).
# Keycloak LDAP federation is seeded in Task 3 with authType=none (anonymous
# search), so this is required. userPassword/shadowLastChange stay protected:
# anonymous may bind (auth) but never read them. Idempotent: full replace.
docker compose exec -T openldap ldapmodify -Y EXTERNAL -H ldapi:/// -Q <<EOF
dn: olcDatabase={1}mdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.exact="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" manage by * break
olcAccess: {1}to attrs=userPassword,shadowLastChange by self write by dn="cn=admin,dc=${RDN}" write by anonymous auth by * none
olcAccess: {2}to * by self read by dn="cn=admin,dc=${RDN}" write by anonymous read by * none
EOF

sed -e "s/__DOMAIN_RDN__/${RDN}/g" \
    -e "s/__ALICE__/${TEST_USER_ALICE}/g" \
    -e "s/__BOB__/${TEST_USER_BOB}/g" \
    -e "s/__ADMIN__/${SOVEREIGN_ADMIN_USER}/g" \
    -e "s|__PASSWORD__|${TEST_USER_PASSWORD}|g" \
    config/openldap/test-users.ldif.template > /tmp/users.ldif
# NOTE: ldapadd reads LDIF from stdin by default; "-f -" is not supported by
# OpenLDAP (it would try to open a literal file named "-").
docker compose exec -T openldap ldapadd -x \
  -D "cn=admin,dc=${RDN}" -w "${LDAP_ROOT_PASSWORD}" -c < /tmp/users.ldif
rm -f /tmp/users.ldif