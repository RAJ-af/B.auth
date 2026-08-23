# Sovereign Email System — MVP #1 Design

- **Date:** 2026-08-23
- **Status:** Approved design; implementation plan pending
- **Scope:** Single-deployment MVP. No cross-country federation, no PGP/E2E encryption, no JMAP.

## 1. Purpose & Constraints

Self-hosted "sovereign" email system: Postfix + Dovecot + Rspamd under Docker Compose,
Keycloak for identity, FastAPI middle layer exposing REST to client apps.

Hard constraints that shaped every decision below:

1. **Handover audience:** government IT teams who are *not* highly specialized.
   Architecture must be standard and well-documented over clever. Boring wins.
2. **Client ecosystem:** end users connect via our own Web/iOS/Android apps through the
   backend API (AppAuth-iOS / AppAuth-Android / oidc-client-ts). Raw third-party IMAP
   clients are explicitly **not** a primary use case.
3. **Environment:** local Docker Compose only for this MVP. Outbound external mail lands
   in a Mailpit catch-all, never the internet. Placeholder domain, parameterized.

### Goals

- One `docker compose up` brings up the full stack locally.
- Login is OIDC Authorization Code + PKCE + mandatory TOTP against Keycloak.
- All email access flows through per-user JWTs — no password path to the mail store.
- SPF/DKIM/DMARC configured end-to-end (checks inbound, DKIM signing outbound).
- A scripted smoke test proves the whole loop without manual browser steps.

### Non-goals (this MVP)

Authenticated submission on exposed ports, Let's Encrypt, Keycloak production profile,
mailbox quotas, attachment binary download, JMAP adapter, spam *rejection* tuning,
high availability / horizontal scaling.

## 2. Decision Log

| Decision | Choice | Rationale | Rejected |
|---|---|---|---|
| User database | **OpenLDAP shared directory** — Keycloak federates to it; it holds all passwords | Industry-standard self-hosted mail pattern (iRedMail/Mailcow lineage); safe for non-specialist maintainers; avoids coupling Dovecot logins to Keycloak's token endpoint | Keycloak-only w/ checkpassword→ROPC plumbing (ROPC deprecated, brittle across KC upgrades); Postgres user table synced to KC (two sources of truth) |
| Login flow | **OIDC Authorization Code + PKCE only**, public client, S256 | Same flow Google/Microsoft native apps use; ROPC password grant rejected as deprecated/risky | Password-grant proxy at `/login`; deferring TOTP |
| Mail access | **OAuth2 end-to-end** — Dovecot `passdb oauth2` validates the same Keycloak JWTs; API replays caller's token over SASL XOAUTH2 | Per-user isolation preserved into the mail layer; one credential type; zero password handling post-login | Backend master-user account (API bug = total exposure); direct Maildir reads (reimplements flags/concurrency badly) |
| Domain | Placeholder `sovereign.mail`, everything via `.env` | Local-only now; real-domain cutover later is config, not code | Real domain from day one |
| Protocol surface | REST for MVP #1 | JMAP needs session objects, change-tracking state, push semantics — a protocol implementation, not an endpoint rename. Future adapter over the same mail core | JMAP now |
| Spam policy | Rspamd checks + adds headers only, never rejects | Nothing silently dropped while testing thresholds | reject/greylist active |

## 3. Architecture

```
            ┌────────────────────────── docker compose network (mailnet) ──────────────────────────┐
 Browser/   │                                                                                       │
 your apps  │  FastAPI :8000 ──IMAP+SASL XOAUTH2──► Dovecot :143 ──► Maildir volume                 │
    │       │    │  │                                  │                                               │
 HTTPS      │    │  └─ token exchange ──► Keycloak :8080 ◄── introspection ──┘ (passdb oauth2)       │
 (PKCE+TOTP)│    │        sig check via JWKS     │                                                   │
    │       │    │                               │ LDAP user federation                              │
    └──────┼────┼──────────────────────────►    ▼                                                   │
           │    │                          OpenLDAP :389  (users live HERE)                          │
           │    └─send─► Postfix :2587 (compose-net only) ──milter──► Rspamd ◄──► Redis             │
           │                                                                                       │
 Inbound:  │  :25 (127.0.0.1 only) Postfix ──► Rspamd milter (SPF/DKIM/DMARC + DKIM sign)          │
           │                ──LMTP :24──► Dovecot ──► Maildir                                      │
 Dev aid:  │  Postfix relayhost ► Mailpit :1025 (external-bound mail), UI :8025                     │
           │  cert-init (one-shot): internal CA + server certs → shared certs volume               │
           └───────────────────────────────────────────────────────────────────────────────────────┘
```

**10 containers total:**

| Group | Service | Image | Role |
|---|---|---|---|
| Core | `postfix` | custom build (Debian slim) | Virtual mailbox domain → LMTP; Rspamd milter; trusted-relay listener :2587 (compose-net only) |
| Core | `dovecot` | `dovecot/dovecot` official | IMAP + LMTP; `passdb oauth2`; static userdb `vmail`; Maildir storage |
| Core | `rspamd` | official | Milter: inbound SPF/DKIM/DMARC checks; outbound DKIM signing; headers-only actions |
| Core | `keycloak` | `quay.io/keycloak/keycloak:26` | Realm `sovereign`; LDAP federation; PKCE public client; TOTP enforced; `start-dev` profile |
| Core | `api` | custom build (python slim) | FastAPI middle layer; JWKS validation; XOAUTH2 IMAP client; MIME/SMTP submit |
| Supporting | `openldap` | `osixia/openldap` | The user database (`ou=people`). Fallback image if stale: `ltb-project/openldap` or Debian+slapd |
| Supporting | `postgres` | `postgres:16` | Keycloak datastore only |
| Supporting | `redis` | official | Rspamd stats/cache backend |
| Supporting | `mailpit` | official | Outbound catch-all SMTP :1025; inspection UI :8025 (published on 127.0.0.1) |
| Supporting | `cert-init` | alpine + openssl | One-shot internal CA + server certs (SANs: localhost, mail.sovereign.mail, service DNS names) → shared volume |

Volumes: `pg_data`, `ldap_data`, `maildir_vmail`, `rspamd_data`, `dkim_keys`, `certs`.
Healthchecks + `depends_on: condition: service_healthy` ordering throughout (KC startup
is slow; nothing may race it).

## 4. Identity & Auth Design

### OpenLDAP

- Suffix `dc=sovereign,dc=mail`; OU `ou=people`.
- User entry = `inetOrgPerson` + `mail` attribute; **the `mail` attribute IS the username**
  (email-as-username). `userPassword` seeded salted-SHA by `seed-ldap.sh`.
- Test users: `alice@sovereign.mail`, `bob@sovereign.mail`.

### Keycloak realm `sovereign`

- **LDAP federation:** vendor Other, edit mode READ_ONLY, users import on demand;
  password validation happens by binding against OpenLDAP — Keycloak stores no passwords.
- **Clients:**
  - `sovereign-app` — **public**, Standard flow only, PKCE required (S256),
    redirect URIs allow-listed to dev origins (localhost ports + app URL schemes).
  - `mail-introspection` — **confidential**; used exclusively by Dovecot for RFC 7662
    token introspection (introspection requires authenticated clients).
    **Secret lifecycle:** generated by `seed-keycloak.sh` (`openssl rand -hex 24`) at
    client creation; written to `.env` as `KC_INTROSPECTION_SECRET` — `.env` is
    gitignored — and injected into the Dovecot container as an environment variable,
    from which the oauth2 config template is rendered at container start. It is never
    committed, never baked into an image layer. Rotation process: deferred to Phase 2
    (trade-offs register #8).
  - Audience mapper on `sovereign-app` adding audience `sovereign-mail-api`
    (the API middleware requires this in `aud`).
- **TOTP:** OTP policy TOTP/SHA1/6-digit/30s; Required Action *Configure OTP* enabled AND
  set as default → every login enforces second factor. Smoke-test users get **pre-seeded
  known OTP secrets** written via the credentials admin API so scripts can compute codes.
- **Brute-force detection enabled** (temporary lockout). This is the only rate-limiting in
  MVP #1 (see trade-offs register).

### Token → mailbox mapping

`preferred_username` / `email` claim == LDAP `mail` == `%d/%n` components of
`/var/mail/vhosts/%d/%n`. One identity string everywhere; no aliasing logic anywhere.

### Auth middleware (API)

PyJWT + cached JWKS from realm discovery; refetch on unknown `kid`. Validates signature,
`iss`, `exp`, and `aud ∋ sovereign-mail-api`. On failure: `401` +
`WWW-Authenticate: Bearer error="invalid_token"`.

## 5. Mail Core Design

### Postfix

- `virtual_mailbox_domains = sovereign.mail`, `virtual_transport = lmtp:dovecot:24`.
- `smtpd_milters = inet:rspamd:11332` — covers both the :25 inbound listener and the
  :2587 submission listener, so **every stored or relayed message is DKIM-signed**.
- Listener :25 → published on `127.0.0.1` only (local inbound tests via swaks).
- Listener :2587 → compose-network-only trusted relay. No AUTH. From-correctness is
  enforced upstream by the API only (trade-off #1).
- `relayhost = mailpit:1025` for non-local recipients.
- TLS from certs volume; outbound opportunistic.

### Dovecot

- Protocols: imap, lmtp. TLS required (`ssl = required`) with certs-volume material.
- `passdb oauth2`: introspection mode against Keycloak's RFC 7662 endpoint using
  `mail-introspection` client credentials (secret env-injected, config template rendered
  at startup — see §4); username attribute mapped from token claims.
- `auth_mechanisms = xoauth2 oauthbearer` — **plain/login deliberately absent**: there is
  no password authentication path into the mail store after PKCE. (Caveat noted for
  debugging: you cannot `telnet` a plaintext LOGIN; use XOAUTH2 test helper.)
- Static userdb `vmail` (uid/gid 5000), `mail_location =
  maildir:/var/mail/vhosts/%d/%n/Maildir`, first_valid_uid = 5000.

### Rspamd (+ Redis)

- DKIM signing: selector `default`, key generated by `gen-dkim.sh`
  (`rspamadm dkim_keygen`) into `dkim_keys` volume; script prints the DNS TXT record.
- Inbound symbols active: SPF, DKIM, DMARC checks stamp `X-Spam-*`/Authentication-
  Results headers.
- `actions.conf`: reject disabled (add-header only), greylisting off, Bayes off until a
  training corpus exists.

## 6. Backend API

FastAPI + uvicorn. Dependencies kept boring: `httpx`, `PyJWT[crypto]`, stdlib `imaplib`
(run in threadpool), stdlib `smtplib`, stdlib `email` for MIME.

### Endpoints

| Endpoint | Method | Behavior |
|---|---|---|
| `/login?redirect_uri=` | GET | Builds authorize URL from KC discovery (state, nonce, S256 code_challenge generated server-side; verifier held in in-memory map, TTL 10 min). Returns JSON `{authorization_url}` |
| `/auth/callback?code&state` | GET | Verifies state, exchanges code+verifier (public client, no secret), returns `{access_token, refresh_token, id_token, expires_in}` |
| `/me` | GET | Claims from validated JWT: `{sub, email, name}` |
| `/emails?folder=&limit=&offset=` | GET | IMAP list: envelope summaries `{total, messages:[{uid, subject, from, to, date, seen, size}]}` |
| `/emails/{id}?folder=` | GET | Full parsed message `{headers, text_body, html_body, attachments:[{name, type, size}]}` — attachment metadata only |
| `/send` | POST | Body `{to[], cc?, bcc?, subject, text, html?}` → From overwritten with JWT email claim → MIME → Postfix :2587 → best-effort APPEND to `Sent` via IMAP (failure logged, not fatal) → `202 {message_id}` |
| `/search?q=&folder=` | GET | Dovecot-side `SEARCH TEXT "<q>"`; same shape as list |

Rules removing ambiguity:

- `{id}` in `/emails/{id}` = **IMAP UID within the folder**; `folder` query param defaults
  to `INBOX`. Folder names restricted to an allow-list (`INBOX`, `Sent`) in MVP.
- Limits: ≤50 recipients/message, ≤10 MiB body → `422`/`413` beyond.
- `redirect_uri` validated against the same allow-list Keycloak enforces.
- Mobile/web apps may run full PKCE themselves directly against Keycloak (recommended for
  production apps); `/login` + `/auth/callback` exist so curl-based setup verification works.

### State

Login-state map is in-memory (single-replica assumption, trade-off #5). Lazy expiry on
access; no background reaper needed at MVP scale.

## 7. Error Handling

| Failure | Response |
|---|---|
| Missing/expired/bad-signature/wrong-audience token | `401` + `WWW-Authenticate: Bearer error="invalid_token"` |
| Token revoked between issue and IMAP use | Dovecot introspection rejects → mapped to `401` |
| Keycloak unreachable (discovery/exchange) | `503`; cached JWKS keeps validating already-issued tokens during brief blips |
| IMAP/SMTP downstream down | `502` — API never masks upstream failures |
| Validation/limits exceeded | `422` / `413` |
| Unknown/expired callback `state` | `400` |

## 8. Security Trade-offs Register (Phase 2 backlog)

1. **Postfix :2587 trusted relay, no AUTH.** From-address correctness lives entirely in
   FastAPI code; Postfix verifies nothing. Boundary = Docker network isolation.
   ⚠ **Before any VPS / real-domain phase: replace with authenticated submission
   (Dovecot-SASL OAuth2 or per-user credentials). Network isolation will NOT carry over
   to a VPS topology.**
2. Keycloak runs `start-dev` → production profile, reverse proxy, real TLS before handover.
3. Rspamd headers-only, never rejects → tune reject thresholds once FP-rate known.
4. Internal CA / self-signed TLS (rootCA.pem import required) → Let's Encrypt; cert paths
   already parameterized.
5. Callback state store in-memory → Redis when scaling beyond one replica.
6. No mailbox quotas; no API-layer rate limiting (Keycloak brute-force lockout mitigates
   login abuse only).
7. Attachment download endpoint missing — metadata only this round.
8. **`mail-introspection` client secret is a machine credential.** Stored in gitignored
   `.env` only, env-injected into Dovecot, never committed or baked into images; rotation
   process TBD for Phase 2. Blast radius if leaked: holder can query token
   status/metadata at the introspection endpoint — it does *not* allow minting tokens,
   reading mail, or bypassing TOTP. The §12 "no password path to the mail store"
   criterion covers *user* credentials and remains intact; this is a separate trust
   anchor, documented so its sensitivity is visible. Considered alternative: Dovecot
   local JWKS validation would eliminate the secret entirely at the cost of live
   revocation checking — rejected for MVP (revocation of short-lived ~5-min access
   tokens was judged worth the introspection round-trip), revisit at Phase 2.

## 9. Testing Strategy

**Unit (pytest):**

- JWT validation against locally-generated RSA keypair served as mock JWKS:
  sig-fail, wrong `aud`, expired, unknown-`kid` refetch.
- XOAUTH2 SASL string encoding.
- MIME builder output shape (multipart when html present, headers correct).
- From-spoof attempt is overwritten by claim enforcement.
- Recipient/body limit enforcement.

**End-to-end smoke (`scripts/smoke-test.sh`):** exercises TOTP for real, scripted —

1. Seed everything; `docker compose up -d`; wait healthy.
2. Login as alice via httpx driving `/login` → browser-less PKCE → compute TOTP from the
   pre-seeded secret (pyotp) → complete login at Keycloak → tokens land via `/auth/callback`.
3. Alice sends to `bob@sovereign.mail` + cc `ext@example.com`.
4. Bob logs in the same way; lists INBOX (message present), reads it, searches subject.
5. Assertions: message found & searchable; `DKIM-Signature` header present on stored
   messages; swaks-injected inbound message carries `X-Spam-*` headers; alice's copy in
   `Sent`; external copy visible via Mailpit API.

**Manual checklist (README):** import rootCA.pem → open Keycloak, observe TOTP enrollment/
prompt; browse Mailpit UI; Thunderbird-style raw IMAP attempt **fails** (expected —
no PLAIN mech), documented as a feature.

## 10. Deliverables Mapping

| Deliverable | Where it lands |
|---|---|
| 1. Compose wiring all **10 services** (5 core: postfix, dovecot, rspamd, keycloak, api + 5 supporting: openldap, postgres, redis, mailpit, cert-init) | `docker-compose.yml`, `.env.example` |
| 2. Backend skeleton + Keycloak JWT middleware | `api/app/{main,config,auth,keycloak}.py` |
| 3. `/login`, `/emails`, `/emails/{id}`, `/send`, `/search` (+ `/me`, `/auth/callback`) | `api/app/routers/*` |
| 4. Deploy & local-test instructions | `docs/README.md`, `scripts/smoke-test.sh`, `docs/dns-records.txt` |

```
z.auth/
├── docker-compose.yml · .env.example · .gitignore
├── scripts/{gen-certs,gen-dkim,seed-ldap,seed-keycloak,smoke-test}.sh
├── config/{postfix,dovecot,rspamd,openldap}/
├── mail/postfix/Dockerfile
├── api/{Dockerfile,requirements.txt}
│   ├── app/{main,config,auth,keycloak,imap_client,smtp_client}.py
│   ├── app/routers/{auth,emails,send,search}.py
│   └── tests/
└── docs/{README.md,dns-records.txt}
```

`docs/dns-records.txt`: SPF, DKIM pubkey (printed by gen-dkim.sh), DMARC records for
`sovereign.mail` — used on real-domain cutover day.

## 11. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| Dovecot↔Keycloak OAuth2 introspection config fiddly | First implementation task is a spike; timebox; documented fallback = temporary master-user access (Approach B), flagged as debt if used |
| `osixia/openldap` image maintenance uncertain | Layer kept thin; swap candidates named in §3 |
| Keycloak slow startup races dependents | Healthcheck-gated `depends_on` everywhere |
| Image availability/pinning | Pin versions/digests at implementation time |

## 12. Success Criteria

1. `scripts/smoke-test.sh` exits 0 executing the full loop including TOTP.
2. Config audit: Dovecot advertises no plain/login auth mechs — no password path to mail.
3. Every stored message carries a `DKIM-Signature`.
4. A newcomer following `docs/README.md` reaches a running system in ≤30 minutes.
