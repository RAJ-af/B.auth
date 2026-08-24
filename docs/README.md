# sovereign-mail MVP — operator README

Self-hosted mail for your own apps only: OpenLDAP identities, Keycloak
(PKCE + TOTP) issuing tokens, Dovecot accepting XOAUTH2 only, Postfix +
Rspamd signing/scanning everything it stores, and a small FastAPI in front of
it all. Design + rationale: `docs/superpowers/specs/2026-08-23-sovereign-email-mvp-design.md`.

## 1. Prerequisites

- Docker + Compose v2 (`docker compose version`)
- `curl`
- `python3` (host-side scripts use stdlib + `httpx`; `pip install httpx pyotp` once)

## 2. Quickstart (~15 min to a passing smoke gate)

All commands run from the repo root. `.env` holds every secret and is
gitignored — create it from the example **only if it does not exist yet**
(never overwrite a populated `.env`; values do not survive that).

```sh
test -f .env || cp .env.example .env    # then fill real values into .env

# 1. wipe state (optional; destroys all mailboxes/users/certs/keys)
docker compose down -v

# 2. core services (cert-init is one-shot; keycloak needs postgres healthy)
docker compose up -d cert-init openldap postgres keycloak

# 3. wait for Keycloak to listen (~30-60 s first boot)
until curl -so /dev/null http://localhost:8080/; do sleep 5; done

# 4. seeds + keys (order matters: keycloak seed rewrites KC_INTROSPECTION_SECRET
#    in .env, so containers that consume it are created afterwards)
./scripts/gen-certs.sh 2>/dev/null || true   # idempotent; cert-init already ran
./scripts/seed-ldap.sh                       # alice/bob from TEST_USER_*
./scripts/seed-keycloak.sh                   # realm, PKCE client, LDAP federation
./scripts/gen-dkim.sh                        # starts rspamd itself; writes docs/dns-records.txt

# 5. everything else
docker compose up -d --build
sleep 15

# 6. the gate — expect "SMOKE TEST PASSED"
./scripts/smoke-test.sh
```

`smoke-test.sh` runs two real browser-less TOTP logins end-to-end via the API,
audits Dovecot's advertised auth mechanisms, checks DKIM on stored mail,
injects an inbound spam message through Postfix :25, verifies the external
relay copy in Mailpit, and asserts secret hygiene (`.env` ignored/untracked,
introspection secret absent from git history and image builds).

## 3. Trusting the internal CA (`rootCA.pem`)

Dovecot/API/Postfix serve certificates signed by the lab CA generated inside
the `certs` volume by `cert-init`. Export it with `docker compose cp` (any
container that mounts the volume works):

```sh
docker compose cp api:/certs/rootCA.pem ./rootCA.pem
```

Import into your trust store:

```sh
# Linux (Debian/Ubuntu)
sudo cp rootCA.pem /usr/local/share/ca-certificates/sovereign-mail-ca.crt && sudo update-ca-certificates
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain rootCA.pem
```

Browsers: settings → certificates → authorities → import `rootCA.pem`
(Firefox uses its own store). Without this, IMAP/HTTPS calls must disable
verification — don't; the API keeps full verification on purpose.

## 4. What you can click

- **Keycloak console** <http://localhost:8080> — admin creds `KC_ADMIN`/
  `KC_ADMIN_PASSWORD` from `.env`. Users alice/bob will prompt for TOTP
  enrollment on first login (seeded secrets complete it automatically in the
  scripted clients; in a browser use your own authenticator instead).
- **Mailpit UI** <http://localhost:8025> — every outbound non-local message
  lands here; nothing ever leaves the machine.
- **API docs** are disabled by design (`docs_url=None`) — the API surface is
  the contract below, not Swagger.

## 5. Talking to the API

Don't hand-roll the OAuth dance. Reference clients:

- `scripts/kc_browserless_login.py` — authorization-code + PKCE against
  Keycloak's HTML forms, TOTP computed from the seeded secret (`pyotp`).
- `scripts/live_check.py` — full loop: login → `/me` → `/send` → list/read/
  search as bob.

```sh
python3 scripts/live_check.py    # expect LIVE CHECK OK
```

Endpoints: `GET /healthz`, `POST /login`, `GET /auth/callback`, `GET /me`,
`POST /send`, `GET /emails?folder=`, `GET /emails/{uid}?folder=`,
`GET /search?q=`. Mobile apps should integrate AppAuth-iOS/AppAuth-Android or
oidc-client-ts directly against Keycloak (spec §6) and call this API as a
resource server.

## 6. Troubleshooting

- **Keycloak slow first boot** — healthcheck `start_period` is 60 s; a cold
  start can sit at `(health: starting)` for a couple of minutes before the
  realm exists (the probe targets the realm discovery endpoint, which only
  answers after `seed-keycloak.sh`). Seed anyway once the log says *Listening
  on*; health flips green after seeding.
- **Port 25 blocked** — some networks/hosts block inbound :25 even locally;
  the stack publishes it on `127.0.0.1` only. If the smoke test's spam step
  times out, check `docker compose logs postfix`.
- **`telnet localhost 143` then `a LOGIN user pass` fails deliberately** —
  there is no plaintext mechanism to reach: Dovecot advertises exactly
  `xoauth2 oauthbearer` (spec §12 criterion 2). That failure is the feature.
- **Dovecot OAuth failures** — `docker compose logs dovecot`, then read
  `docs/spike-dovecot-oauth2.md` (setting-name variance and the `--hostname`
  issuer pin are covered there).
- **Changed `MAIL_DOMAIN`?** Regenerate everything scoped to it: DKIM config
  (`config/rspamd/local.d/dkim_signing.conf` domain block) + `gen-dkim.sh`,
  certs (delete the `certs` volume so cert-init recreates SANs), and both
  seeds (LDAP suffix, users).

## 7. Security posture (summary)

Full trade-offs register lives in the design spec, **§8 Security Trade-offs
Register (Phase 2 backlog)**. The load-bearing items:

- **The MSA :2587 trust boundary.** Port 2587 advertises NO AUTH and trusts
  `mynetworks` (127.0.0.0/8 + compose subnet 172.42.0.0/16) — network-position
  trust, not credential trust. Sender identity binding (From := token claim)
  lives ONLY in the API layer (`api/app/routers/send_router.py enforce_sender`).
  Anyone who can reach :2587 from inside the compose network can submit as
  anyone — acceptable at MVP; Phase-2 candidate: SMTP XOAUTH2.

  The plain :25 listener is NOT part of that boundary: `mail/postfix/
  main.cf.template` sets no `mynetworks`, so the :25 smtpd falls back to
  postfix's loopback-only default (`postconf mynetworks` on the running stack:
  `127.0.0.1/32 <postfix's own IP>/32 [::1]/128`). Other compose containers
  therefore CANNOT relay off-site via :25 — they may only hand it mail addressed
  to local virtual domains (which is all the smoke test's spam probe needs).
  The network-position trust boundary lives wholly on the :2587 master.cf
  override (`mynetworks = 127.0.0.0/8, <compose subnet>` + permit_mynetworks);
  the Phase-2 recommendation above covers retiring it in favor of authenticated
  submission.

  > ⚠ **Before any VPS / real-domain phase: replace with authenticated submission
  > (Dovecot-SASL OAuth2 or per-user credentials). Network isolation will NOT carry over
  > to a VPS topology.**

- **No password path to mail.** Dovecot speaks XOAUTH2/OAUTHBEARER only;
  audited every smoke run (step 2).
- **DKIM everywhere on the milter path.** Rspamd signs loopback AND
  compose-subnet submissions (`sign_networks` mirrors `COMPOSE_SUBNET`);
  stored INBOX mail is verified signed per run. Keys come from
  `rspamadm dkim_keygen`'s default (**1024-bit** — fine for the lab;
  regenerate ≥2048-bit before production; see note in `docs/dns-records.txt`,
  which must be refreshed after every `down -v` since the DKIM volume is wiped).
- **Secret lifecycle.** `KC_INTROSPECTION_SECRET` exists only gitignored in
  `.env`, is regenerated on each clean-room seeding, and reaches consumers via
  compose env injection — never committed, never baked into images (asserted
  by smoke step 8). All other secrets share the same .env-only lifecycle.
- **Log retention disclosure.** Uvicorn access logs retain full request lines
  including query strings (`/search?q=<terms>` reveals searched terms).
  Deliberate MVP retention for debuggability; the govt-handover register
  should list it as a Phase-2 decision (drop query strings or shorten
  retention).
- **Exception-text echo convention (documented ruling).** 502/404 error bodies
  intentionally echo downstream error text (`DownstreamError` str) for
  debuggability. Audited as carrying no credentials on all reachable paths;
  raw tracebacks and exception class names are never echoed.
- **Redirect-URI matching is fnmatch-glob today** (Phase-2 hardening): a
  wildcard pattern such as `http://localhost:*/*` admits authority-confusion
  URIs like `http://localhost:p@evil.com/` at the pattern layer. Backstopped in
  MVP by Keycloak's server-side client allow-list; Phase 2 should compare parsed
  scheme/host/port against an explicit allow-list instead of globbing.
- **Known MVP gaps** (details in §8): Keycloak `start-dev`, self-signed CA,
  no quotas/rate limiting, in-memory callback state, metadata-only attachments.

## Spec §12 success-criteria audit

| # | Criterion | Proof |
|---|-----------|-------|
| 1 | `scripts/smoke-test.sh` exits 0 executing the full loop including TOTP | Two consecutive clean-room cycles (`down -v` → seeds → build → smoke) ended `SMOKE TEST PASSED`, 2026-08-24 |
| 2 | No password path to mail — no plain/login mechs | Smoke step 2 audits `doveconf -n`: `auth_mechanisms = xoauth2 oauthbearer`, no plain; deliberate LOGIN failure documented above |
| 3 | Every stored message carries a `DKIM-Signature` | Smoke step 4: all messages in bob's Maildir signed (probe-proof: API-path submission carries signature after `sign_networks` fix). Scope: milter-path mail — the Sent copy is IMAP-appended pre-signature, and genuinely inbound external mail is correctly unsigned |
| 4 | Newcomer reaches running system in ≤30 min following this README | Quickstart is 6 numbered stages; timed clean-room runs ≈10-12 min each on warm caches (first build adds image pulls). Steps are copy-pasteable verbatim |
