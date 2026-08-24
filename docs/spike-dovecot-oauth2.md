# Spike: Dovecot OAuth2 passdb vs Keycloak introspection (Task 4, spec §11)

**Outcome: SPIKE SUCCEEDED — no fallback needed.** SASL XOAUTH2 login against
Dovecot 2.3.19 with alice's real Keycloak token (browserless PKCE via
`scripts/kc_browserless_login.py`, no ROPC) returns:

```
RESULT: OK [b'Logged in']
```

Negative control (garbage bearer token): `[AUTHENTICATIONFAILED]`. Post-STARTTLS
capability advertises exactly `AUTH=XOAUTH2 AUTH=OAUTHBEARER` — no plain/login.

## Winning configuration

Dovecot 2.3.x reads the oauth2 parameters from an **args file**, not from
dovecot.conf settings. The passdb block lives in `config/dovecot/dovecot.conf`;
the args file is rendered by the container entrypoint from
`config/dovecot/90-oauth2.conf.template` (holds the introspection secret,
`chmod 600`).

`config/dovecot/dovecot.conf` (auth-relevant extract):

```
auth_mechanisms = xoauth2 oauthbearer

passdb {
  driver = oauth2
  mechanisms = xoauth2 oauthbearer
  args = /etc/dovecot/dovecot-oauth2.conf.ext
}

userdb static {
  driver = static
  args = uid=vmail gid=vmail home=/var/mail/vhosts/%d/%n allow_all_users=yes
}

service lmtp {
  inet_listener lmtp {
    port = 24
  }
}
```

`config/dovecot/90-oauth2.conf.template` — verbatim:

```
# Dovecot 2.3.x OAuth2 passdb args file. Rendered by the container entrypoint into
# /etc/dovecot/dovecot-oauth2.conf.ext (referenced by passdb { args = ... } in
# dovecot.conf). These keys are NOT dovecot.conf settings — putting them there dies
# with "Unknown setting".
#
# Variant B (explicit introspection): 2.3.x REQUIRES a concrete introspection_url at
# auth-process init — openid_configuration_url alone dies with "Password grant,
# tokeninfo, introspection URL or validation key dictionary must be given" even though
# the discovery document is fetchable. Internal KC hop is plain HTTP under start-dev —
# recorded trade-off #2.
introspection_url = http://keycloak:8080/realms/sovereign/protocol/openid-connect/token/introspect
# Default mode is "auth": a GET with the token as Authorization: Bearer — Keycloak's
# RFC 7662 endpoint does not accept that (it wants form POST). "post" sends
# token + client_id + client_secret as urlencoded form fields, which KC accepts.
introspection_mode = post
# Explicit active-field check: KC returns JSON boolean true, which dovecot compares
# as the string "true". Kept explicit after debugging ("Processing field active"
# -> "Provided token is not valid" when the value did not match).
active_attribute = active
active_value = true
client_id = mail-introspection
client_secret = __KC_INTROSPECTION_SECRET__
username_attribute = preferred_username
```

## Error signatures observed on losing paths

1. **Official `dovecot/dovecot:2.3.21` image has NO oauth2 support.** Every
   placement of the settings dies with `doveconf: Fatal: Unknown setting:
   oauth2_client_id`. Verified via binary grep (`grep -ac oauth2
   /usr/lib/dovecot/auth` → 2 incidental hits) vs Debian's package (full symbol
   set: `oauth2_lookup`, `oauth2_introspection_start`, …). Resolution: build on
   `debian:bookworm-*` + `dovecot-core dovecot-imapd dovecot-lmtpd`
   (1:2.3.19.1+dfsg1-2.1+deb12u6 at time of writing).
2. **Old-style block header mangles inner settings:** `passdb oauth2 { ... }`
   → `Unknown setting: passdb { <setting>`. Use the new-style block
   `passdb { driver = oauth2 ... }`.
3. **Missing args-file keys kill the whole auth process at startup:**
   `auth: Fatal: oauth2: Password grant, tokeninfo, introspection URL or
   validation key dictionary must be given`; clients see `* BYE Auth process
   broken`. A bare `openid_configuration_url` does NOT satisfy init even though
   the discovery document is fetchable — an explicit `introspection_url`
   (variant B) is required.
4. **Default introspection_mode ("auth") is GET + Bearer header,** which
   Keycloak's RFC 7662 endpoint rejects → `Introspection failed: No username
   returned`. Fix: `introspection_mode = post` (sends
   `token=…&client_id=…&client_secret=…` as urlencoded form fields; no Basic
   auth header).
5. **active-field comparison:** KC answers JSON boolean `true`; dovecot compares
   the string form. Mismatch logs `Processing field active` followed by
   `Introspection failed: Provided token is not valid`. Fix: explicit
   `active_value = true`.
6. **Issuer/Host binding (the deep one):** KC validates an introspected token
   against the realm URL derived from the request Host header. Tokens obtained
   through the published port carry `iss=http://localhost:8080/realms/sovereign`;
   container-side requests arrive with `Host: keycloak:8080` → KC judges the
   token foreign → `{"active":false}` → same "Provided token is not valid"
   signature as #5. Proven with one identical body sent four ways:

   | Vantage | Host header       | Response            |
   |---------|-------------------|---------------------|
   | host    | localhost:8080    | full introspection  |
   | in-net  | keycloak:8080     | `{"active":false}`  |
   | in-net  | localhost:8080    | full introspection  |
   | host    | keycloak:8080     | `{"active":false}`  |

   Resolution: pin the canonical frontend URL on Keycloak — compose command
   `start-dev --import-realm --hostname http://localhost:${KEYCLOAK_PORT}`.

## Consequences for later tasks

- Tasks 7+ (API): Keycloak's discovery/JWKS URLs now advertise
  `http://localhost:${KEYCLOAK_PORT}/...`. Any *container-side* caller must use
  explicitly configured service URLs (`http://keycloak:8080/...`) and must not
  follow the discovery document's advertised endpoints blindly — from inside the
  compose network, `localhost` resolves to the caller itself.
- Dovecot logs to stderr (`log_path = /dev/stderr`) so `docker compose logs
  dovecot` shows auth failures. `auth_verbose = yes` stays on; `auth_debug` is
  deliberately off (can leak sensitive material into logs).
- LMTP listener proven live: `220 <host> Dovecot (Debian) ready.` on TCP 24.
- Maildir materializes per spec §5 on first login:
  `/var/mail/vhosts/<domain>/<user>/Maildir`, owned `vmail:vmail` (uid/gid
  5000), mode 700.
