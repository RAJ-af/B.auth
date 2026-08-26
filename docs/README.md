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

# 5. everything else — AFTER setting the phase-5 smoke overrides below
#    (the identity gate hard-requires manual idverify + cooldown-free family
#    links + a 5 s dwell; production defaults are off/48h/600s, see §8/§10)
for kv in IDVERIFY_MODE=manual FAMILY_LINK_COOLDOWN_HOURS=0 \
          RECOVERY_MIN_DWELL_SECONDS=5; do
  k=${kv%%=*}
  grep -q "^$k=" .env && sed -i "s|^$k=.*|$kv|" .env || printf '%s\n' "$kv" >> .env
done
docker compose up -d --build
sleep 15

# 6. the gate — expect "SMOKE TEST PASSED"
./scripts/smoke-test.sh
```

`smoke-test.sh` runs two real browser-less TOTP logins end-to-end via the API,
audits Dovecot's advertised auth mechanisms, checks DKIM on stored mail,
injects an inbound spam message through Postfix :25, verifies the external
relay copy in Mailpit, asserts secret hygiene (`.env` ignored/untracked,
introspection secret absent from git history and image builds), and drives the
identity subsystem end to end (signup → tiers → admin queue → family links →
all three recovery outcomes). The three overrides from step 5 are SMOKE-TIME
settings only; switch `IDVERIFY_MODE` back and restore the production cooldown/
dwell defaults before any non-lab use (sections 8 and 10).

**Warning:** `TEST_USER_*` identities in `.env` must stay synthetic — never
point them at real user addresses in a production deployment, since
`smoke-test.sh` resets their LDAP passwords on every run and logs into them
throughout.

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
- **Changed `MAIL_DOMAIN`?** Regenerate everything scoped to it: DKIM keys
  (`gen-dkim.sh` — the signing config itself needs no edit: its template
  `config/rspamd/dkim_signing.conf.template` is rendered at container start
  from `$MAIL_DOMAIN`/`$COMPOSE_SUBNET` into rspamd's `override.d`),
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

## 8. Self-service signup (`/signup/*`, spec §8)

Three calls make an account: `POST /signup/start {email, display_name,
phone_e164, account_type}` answers `202 {session_token}` and sends a 6-digit
phone OTP; `POST /signup/verify-otp {token, code}` moves the session to
`awaiting_identity_choice`; `POST /signup/complete {token, choice, password}`
provisions the LDAP entry (`{SSHA}` hash) plus the accounts row and activates
the mailbox. Signup sessions live 900 s; addresses are unique (409 on
duplicates) with lowercase `[a-z0-9._-]` local parts under `$MAIL_DOMAIN`.
Note the deliberate asymmetry: `/signup/start` DOES reveal address existence
via 409 (accepted UX trade-off, spec §15.3) — anti-enumeration constants are a
recovery-only rule.

**Tiers.** Everyone starts at `tier1_phone` (verified phone,
`verification=pending_identity`). A government-ID submission that verifies
promotes to `tier2_identity` (`auto_verified` or, after dashboard review,
`manual_verified`) — Tier 2 is what unlocks *initiating* family links.
Skipping the ID costs nothing: it can be submitted later from account
settings, and completion NEVER blocks on identity problems (soft-fallback
union, spec §8.4).

**Multi-document pause (`choose_identity`) and guardian accounts.** When an
AUTO verification returns MULTIPLE identities on one document, signup PAUSES
instead of deciding for you (spec §10.2): `/signup/complete` answers
HTTP 200 `{stage:"choose_identity", choices:[{id_ref, name_masked,
id_type, is_minor}]}` — names arrive pre-masked (`R*** K***`) — and the
session stays alive its normal 900 s. Pick with
`POST /signup/identity-choice {token, id_ref}` to provision from that
identity and burn the session (one-time consumption; an unoffered `id_ref`
is a 422 and retains the session). A single MINOR identity never pauses:
it provisions straight to a `guardian_managed` account whose
`guardian_phone` is the phone that just proved possession. Structural
guardianship (§8.2) is enforced at three points: guardians list their
dependents via `GET /account/dependents` (masked); managed accounts cannot
CREATE family links (422) and cannot APPROVE recoveries (refused
wire-silently, like any non-standing caller); and a managed account's own
recovery ALWAYS lands in the assisted admin queue with the phone-matched
guardians notified.

**`IDVERIFY_MODE`** lives in `.env` and is read at boot — change it, then
`docker compose up -d --force-recreate api`:

- `off` — ID submission disabled; choice descriptions say so
  (`identity_checks_off`).
- `auto` — `$IDVERIFY_SCRIPT` runs as a subprocess over the frozen versioned
  contract (spec §10.1); well-formed-but-false is a RESULT, while verifier
  trouble (timeout/bad JSON/crash) queues manual review instead of failing
  signup.
- `manual` — every submission lands in the admin queue with
  `identity_status=queued_manual_review`; signup still completes immediately
  at Tier 1.

**Console-provider DEV warning.** `OTP_PROVIDER=console` prints OTP codes in
full into `docker compose logs api` (phone masked, code visible — that is its
only delivery channel). This is strictly a lab setting: before anything that
resembles a shared machine, switch to `twilio` by filling the three `TWILIO_*`
vars. Startup logs warn while console mode is selected (spec §9 warning box).

## 9. Admin dashboard (`/admin`, spec §11)

Access is the Keycloak realm role `sovereign-admin`; `seed-keycloak.sh`
creates the role and assigns it to `$SOVEREIGN_ADMIN_USER`
(`admin@sovereign.mail`) once seeding's full sync has imported that account
from LDAP. Log in at `/admin/login`: you are redirected to Keycloak's normal
PKCE + TOTP screen and return through `/admin/callback`, which exchanges the
code, checks the role, and sets an opaque httpOnly `SameSite=Lax` session
cookie (1 h TTL). Every HTML form posts back a per-session CSRF token.

What the operator can do:

- **Review queue** (`/admin`) lists pending identity submissions grouped by
  reason; the detail page shows the payload snapshot. **Approve** promotes the
  account to `tier2_identity` / `manual_verified` (`id_source=manual`);
  **Reject** records the decision and leaves the account at Tier 1 — the
  member may reapply. Decisions are attributed (`reviewed_by`) and stamped.
- **Scripted equivalents** share the exact same guard:
  `GET /admin/api/reviews` and `POST /admin/api/reviews/{id}/approve` with
  `Authorization: Bearer <KC access token>` — how `smoke-test.sh` drives the
  queue browserlessly. The HTML POST path stays CSRF-guarded and is covered
  by pytest instead.
- **Assisted-recovery grants**: a recovery parked at `pending_admin` (see
  runbook below) is authorized by
  `POST /admin/api/recovery/{req_id}/grant` (same bearer gate). The queue
  itself is listable over the same gate:
  `GET /admin/api/recovery/pending` returns the `pending_admin` rows
  newest-first with MASKED addresses (`a***@sovereign.mail`) — pair it with
  the grant endpoint to work the queue browserlessly. Only actionable
  requests grant; anything else answers one generic 404, so scripted probes
  learn nothing about state.

## 10. Recovery runbook (`/recovery/*`, spec §13)

A recovery opens with `POST /recovery/start {email}`, which answers the
byte-identical body `{"received":true}` whether or not the address exists
(anti-enumeration; asserted every smoke run). A known address receives an OTP
on its stored phone (budget: ≤3 starts/hour/account) plus a "recovery
started" notification the owner can act on. After the OTP clears, the branch
is picked ONCE, at verification time:

| Stage | Meaning | What resolves it |
|---|---|---|
| `pending_family` | an active, cooled-down family link exists | any ONE linked member approves from their own session: `POST /recovery/family-approve {"requester_email":…}` — every member is notified at pick time (in-app + pointer-only email naming the requester masked) |
| `pending_dwell` | a recognized device vouched | the SAME device re-sends its `X-Device-ID` after `RECOVERY_MIN_DWELL_SECONDS` elapses |
| `pending_admin` | neither factor, OR the account is guardian-managed (the guardian is alerted instead) | operator grant (dashboard/API, section 9) |

All three converge on `POST /recovery/complete {email,new_password}` →
`{"reset":true}`. Requests also die: family windows expire to `expired` with
NO fallback to dwell (deliberate MVP choice, spec §13), owners or members can
cancel instantly (the owner is notified of EVERY cancellation, whoever
cancelled; `/recovery/cancel` still answers one constant body either way),
and restarting simply burns budget again.

**Why dwell exists:** the stolen-phone scenario delivers BOTH factors at once
(SIM = OTP, app storage = device token). The minimum-wait wall makes that
attack human-speed and cancellable — during dwell the owner can cancel from
any other logged-in session or delete the vouching device, which kills the
request outright.

**What `pending_admin` assist means operationally:** YOU establish identity
out-of-band first (video call, known-face pickup — whatever policy demands),
then grant. The grant is attributed to your account in `decided_by`.

**Smoke-time env overrides:** smoke runs export
`FAMILY_LINK_COOLDOWN_HOURS=0` and `RECOVERY_MIN_DWELL_SECONDS=5` before
booting the stack so the family and dwell branches resolve in seconds;
production defaults are 48 h and 600 s and everything else keeps spec values.

## 11. Secret inventory (pointer)

Every secret lives ONLY in the gitignored `.env` and reaches containers via
compose env injection — never committed, never baked into images (asserted by
smoke step 8). Full lifecycle table with accepted risks: design-spec **§15.1
"Secret lifecycle inventory (new exposures only)"**. Summary, names only:

| Secret | Lifecycle notes (spec §15.1 row) |
|---|---|
| `LDAP_ADMIN_PASSWORD` | EXISTING value, NEW exposure: global admin DN inside the api container. Interim risk accepted TEMPORARILY; successor design = dedicated least-privilege bind DN + slapd ACL (spec §21 #9), same milestone as retiring the :2587 trust boundary. NOT permanent design. |
| `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` / `TWILIO_FROM_NUMBER` | stay EMPTY until `OTP_PROVIDER=twilio`; provider module redacts credentials from logs; rotate via Twilio console |
| OTP codes | 6-digit crypto-random; stored SHA-256-only, single-use, ≤5 attempts, 300 s TTL; console provider PRINTS them by design — dev labs only |
| Device IDs | raw shown once at registration; server stores SHA-256 only |
| Passwords | `{SSHA}` salted-SHA-1 in LDAP (the scheme binds require); TLS-only transit; min length enforced; stronger schemes tracked as register #10 |

The MVP-era inventory (`KC_INTROSPECTION_SECRET` et al.) is described in
section 7 above. No secret VALUES belong in this README.

## 12. Family links (`/family/*`, spec §12)

A Tier-2 member initiates: `POST /family/requests {"target_email":…}`, capped
at ≤2 requests per unordered pair per rolling 24 h. The target sees an
approve affordance IN APP ONLY — approving is an authenticated API call by
the target account itself (`POST /family/requests/{id}/approve`), so there is
structurally nothing speakable over a phone or pasteable into a chat.
Unapproved requests expire after 10 minutes.

**Cooldown semantics.** Approval sets
`usable_at = now + FAMILY_LINK_COOLDOWN_HOURS` (default 48 h). A fresh link
authorizes NO recovery until the cooldown elapses — an attacker who sneaks a
link onto a briefly-compromised account hands the owner 48 hours to notice
and revoke. Smoke overrides the knob to 0 so the flow completes instantly;
production keeps 48.

**Revoke.** Instant, EITHER party, from any live state, no confirmation
theater: `POST /family/requests/{id}/revoke` kills usability immediately.
Revoked links can never approve recoveries; a fresh cooldown applies if they
are ever re-established.

**Who gets told.** Every LIVE transition notifies all linked members of BOTH
accounts' link neighborhoods: requested / approved / revoked each produce an
in-app row plus an email copy into every member's sovereign mailbox, and a
pending_family recovery window opening fans out the same way (section 10).
Expiry is the one SILENT transition — it flips lazily inside read paths and
sends nothing; that notification is deferred to Phase 2 (spec §21 register
#15).

**Pointer-only guarantee.** Those notifications NAME the event ("open the app
to review") and identify people MASKED (`r***@sovereign.mail`) but NEVER carry
an action URL — the smoke gate greps the delivered message for URLs and fails
hard on any hit. This is load-bearing for the nothing-relayable property
(spec §15.3): forwarding or phishing the email grants nothing.

## Spec §12 success-criteria audit

| # | Criterion | Proof |
|---|-----------|-------|
| 1 | `scripts/smoke-test.sh` exits 0 executing the full loop including TOTP | Two consecutive clean-room cycles (`down -v` → seeds → build → smoke) ended `SMOKE TEST PASSED`, 2026-08-24 |
| 2 | No password path to mail — no plain/login mechs | Smoke step 2 audits `doveconf -n`: `auth_mechanisms = xoauth2 oauthbearer`, no plain; deliberate LOGIN failure documented above |
| 3 | Every stored message carries a `DKIM-Signature` | Smoke step 4: all messages in bob's Maildir signed (probe-proof: API-path submission carries signature after `sign_networks` fix). Scope: milter-path mail — the Sent copy is IMAP-appended pre-signature, and genuinely inbound external mail is correctly unsigned |
| 4 | Newcomer reaches running system in ≤30 min following this README | Quickstart is 6 numbered stages; timed clean-room runs ≈10-12 min each on warm caches (first build adds image pulls). Steps are copy-pasteable verbatim |
