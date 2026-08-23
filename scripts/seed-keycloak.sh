#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
source .env
KC="http://127.0.0.1:${KEYCLOAK_PORT}"
KCADM="docker compose exec -T keycloak /opt/keycloak/bin/kcadm.sh"

$KCADM config credentials --server "$KC" --realm master --user "$KC_ADMIN" --password "$KC_ADMIN_PASSWORD" >/dev/null
$KCADM create realms -s realm="$KC_REALM" -s enabled=true -s sslRequired=NONE \
  -s bruteForceProtected=true -s failureFactor=10 -s waitIncrementSeconds=900 \
  -s accessTokenLifespan=300 2>/dev/null || echo "realm exists"

# OTP policy + required default action
# KC 26.x: no /authentication/otp-policy sub-resource; policy fields live on the realm.
# Required-action alias is uppercase (CONFIGURE_TOTP).
$KCADM update realms/"$KC_REALM" -r "$KC_REALM" \
  -s otpPolicyType=totp -s otpPolicyAlgorithm=HmacSHA1 -s otpPolicyDigits=6 \
  -s otpPolicyPeriod=30 -s otpPolicyLookAheadWindow=1
$KCADM update authentication/required-actions/CONFIGURE_TOTP -r "$KC_REALM" \
  -s enabled=true -s defaultAction=true

# Public PKCE client
$KCADM create clients -r "$KC_REALM" -f - <<JSON || $KCADM get "clients?clientId=${KC_APP_CLIENT}" -r "$KC_REALM" --fields id >/dev/null
{"clientId":"${KC_APP_CLIENT}","publicClient":true,"standardFlowEnabled":true,
 "directAccessGrantsEnabled":false,"serviceAccountsEnabled":false,
 "redirectUris":["http://localhost:8000/auth/callback","http://localhost:*/*","sovereign://callback"],
 "webOrigins":["*"],"attributes":{"pkce.code.challenge.method":"S256"},
 "protocolMappers":[{"name":"api-audience","protocol":"openid-connect",
   "protocolMapper":"oidc-audience-mapper",
   "config":{"included.client.audience":"${API_AUDIENCE}","access.token.claim":"true"}}]}
JSON

# Confidential introspection client: generate secret, persist to .env (gitignored)
SECRET=$(openssl rand -hex 24)
CID=$($KCADM create clients -r "$KC_REALM" -f - -i <<JSON
{"clientId":"${KC_INTROSPECTION_CLIENT}","publicClient":false,"standardFlowEnabled":false,
 "directAccessGrantsEnabled":false,"secret":"${SECRET}"}
JSON
)
$KCADM set-password 2>/dev/null || true
grep -q '^KC_INTROSPECTION_SECRET=' .env && \
  sed -i.bak "s|^KC_INTROSPECTION_SECRET=.*|KC_INTROSPECTION_SECRET=${SECRET}|" .env && rm -f .env.bak || \
  echo "KC_INTROSPECTION_SECRET=${SECRET}" >> .env

# LDAP user federation
$KCADM create components -r "$KC_REALM" -f - <<JSON || echo "federation exists"
{"name":"sovereign-ldap","providerId":"ldap","providerType":"org.keycloak.storage.UserStorageProvider",
 "parentId":"${KC_REALM}",
 "config":{"vendor":["other"],"enabled":["true"],"priority":["1"],
  "connectionUrl":["ldap://openldap:389"],"usersDn":["ou=people,dc=${MAIL_DOMAIN//./,dc=}"],
  "usernameLdapAttribute":["mail"],"rdnLdapAttribute":["mail"],"uuidLdapAttribute":["entryUUID"],
  "userObjectClasses":["inetOrgPerson"],"editMode":["READ_ONLY"],
  "searchScope":["1"],"authType":["none"],"pagination":["true"],"importUsers":["true"]}}
JSON

seeded_otp() { # $1=username $2=base32-secret
  UID_=$($KCADM get "users?username=$1&exact=true" -r "$KC_REALM" --fields id --format csv --noquotes | tail -1)
  $KCADM create "users/$UID_/credentials" -r "$KC_REALM" -f - >/dev/null <<JSON || echo "otp already set for $1"
{"type":"otp","userLabel":"seeded","value":"unused",
 "secretData":"{\"value\":\"$2\"}","credentialData":"{\"digits\":6,\"period\":30,\"algorithm\":\"HmacSHA1\"}"}
JSON
}
seeded_otp "$TEST_USER_ALICE" "$TEST_TOTP_SECRET_ALICE"
seeded_otp "$TEST_USER_BOB" "$TEST_TOTP_SECRET_BOB"

echo "Keycloak seeded. Realm: $KC_REALM"
