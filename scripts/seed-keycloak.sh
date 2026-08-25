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

# OTP policy + required default action.
# KC 26.x: no /authentication/otp-policy sub-resource — the policy fields live on the
# realm representation; the required-action alias is uppercase (CONFIGURE_TOTP).
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
# Wave B gate: Keycloak 26 does NOT honor port wildcards in valid redirect
# URIs ("Invalid parameter: redirect_uri" for http://localhost:<otherport>/...),
# so the dashboard callback must be pinned literally. Converge on every run
# (create-only would skip this on re-runs).
CID_APP=$($KCADM get "clients?clientId=${KC_APP_CLIENT}" -r "$KC_REALM" \
  --fields id --format csv --noquotes | tail -1)
$KCADM update "clients/${CID_APP}" -r "$KC_REALM" \
  -s "redirectUris=[\"http://localhost:8000/auth/callback\",\"http://localhost:*/*\",\"sovereign://callback\",\"http://localhost:${KEYCLOAK_PORT}/admin/callback\"]" >/dev/null

# Confidential introspection client: generate secret, persist to .env (gitignored).
# Re-runs must UPDATE the existing client's secret (not skip) so .env stays in
# sync with Keycloak — Wave B gate found the bare create aborted the whole seed
# under set -e once the client existed.
SECRET=$(openssl rand -hex 24)
CID=$($KCADM create clients -r "$KC_REALM" -f - -i <<JSON
{"clientId":"${KC_INTROSPECTION_CLIENT}","publicClient":false,"standardFlowEnabled":false,
 "directAccessGrantsEnabled":false,"secret":"${SECRET}"}
JSON
) || {
  CID=$($KCADM get "clients?clientId=${KC_INTROSPECTION_CLIENT}" -r "$KC_REALM" \
    --fields id --format csv --noquotes | tail -1)
  $KCADM update "clients/${CID}" -r "$KC_REALM" -s "secret=${SECRET}"
}
grep -q '^KC_INTROSPECTION_SECRET=' .env && \
  sed -i "s|^KC_INTROSPECTION_SECRET=.*|KC_INTROSPECTION_SECRET=${SECRET}|" .env || \
  echo "KC_INTROSPECTION_SECRET=${SECRET}" >> .env

# LDAP user federation.
# KC 26.x specifics vs upstream docs: config keys are usernameLDAPAttribute /
# rdnLDAPAttribute / uuidLDAPAttribute (uppercase LDAP) and importEnabled;
# parentId must be the REALM ID, not its name; and a child user-attribute-ldap-mapper
# is required for lookups to resolve into users.
RID=$($KCADM get realms/"$KC_REALM" -r master --fields id --format csv --noquotes | tail -1)
CID_LDAP=$($KCADM create components -r "$KC_REALM" -f - -i <<JSON || $KCADM get "components?parent=${RID}&type=org.keycloak.storage.UserStorageProvider" -r "$KC_REALM" --format csv --noquotes | grep sovereign-ldap | cut -d, -f1 | tail -1
{"name":"sovereign-ldap","providerId":"ldap","providerType":"org.keycloak.storage.UserStorageProvider",
 "parentId":"${RID}",
 "config":{"vendor":["other"],"enabled":["true"],"priority":["1"],
  "connectionUrl":["ldap://openldap:389"],"usersDn":["ou=people,dc=${MAIL_DOMAIN//./,dc=}"],
  "usernameLDAPAttribute":["mail"],"rdnLDAPAttribute":["mail"],"uuidLDAPAttribute":["entryUUID"],
  "userObjectClasses":["inetOrgPerson"],"editMode":["READ_ONLY"],
  "searchScope":["1"],"authType":["none"],"pagination":["true"],"importEnabled":["true"]}}
JSON
)
# Username + email mappers (email keeps the JWT email claim == LDAP mail).
$KCADM create components -r "$KC_REALM" -f - >/dev/null <<JSON || echo "mapper exists"
{"name":"username","providerId":"user-attribute-ldap-mapper",
 "providerType":"org.keycloak.storage.ldap.mappers.LDAPStorageMapper","parentId":"${CID_LDAP}",
 "config":{"ldap.attribute":["mail"],"user.model.attribute":["username"],
  "read.only":["true"],"is.mandatory.in.ldap":["true"]}}
JSON
$KCADM create components -r "$KC_REALM" -f - >/dev/null <<JSON || echo "mapper exists"
{"name":"email","providerId":"user-attribute-ldap-mapper",
 "providerType":"org.keycloak.storage.ldap.mappers.LDAPStorageMapper","parentId":"${CID_LDAP}",
 "config":{"ldap.attribute":["mail"],"user.model.attribute":["email"],
  "read.only":["true"],"is.mandatory.in.ldap":["true"]}}
JSON
# Import the directory now so admin tooling sees alice/bob immediately.
$KCADM create "user-storage/${CID_LDAP}/sync?action=triggerFullSync&parent=${RID}" \
  -r "$KC_REALM" >/dev/null 2>&1 || echo "ldap sync failed"

# NOTE: OTP credentials are NOT attached here — KC 26.x has no admin endpoint that
# creates credentials for an existing user (POST /users/<id>/credentials is gone).
# Instead CONFIGURE_TOTP is a default required action above, and
# scripts/kc_browserless_login.py completes the enrollment form with the known
# TEST_TOTP_SECRET_* from .env on first login per user (form-driven, no ROPC).

# --- sovereign-admin dashboard role (identity-auth-flow spec §11) -------------
$KCADM create roles -r "$KC_REALM" -s name=sovereign-admin \
  -s 'description=Admin dashboard access' >/dev/null || echo "role exists"
ADMIN_UID=$($KCADM get users -r "$KC_REALM" -q username="$SOVEREIGN_ADMIN_USER" \
  --fields id --format csv --noquotes | tail -1)
if [ -n "${ADMIN_UID}" ] && [ "${ADMIN_UID}" != "id" ]; then
  $KCADM add-roles -r "$KC_REALM" --uid "${ADMIN_UID}" --rolename sovereign-admin >/dev/null \
    || echo "WARN: role assignment failed"
else
  echo "NOTE: ${SOVEREIGN_ADMIN_USER} not yet imported from LDAP; run this seed again after their first login"
fi

echo "Keycloak seeded. Realm: $KC_REALM"
