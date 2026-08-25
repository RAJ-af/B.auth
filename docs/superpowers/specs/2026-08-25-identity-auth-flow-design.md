# Sovereign Email — User Identity & Auth Flow Subsystem Design

- **Date:** 2026-08-25
- **Status:** Approved design; implementation plan pending
- **Parent:** builds on `2026-08-23-sovereign-email-mvp-design.md` (referenced as "MVP spec §N")
- **Scope:** self-service signup, verification tiers, manual review queue + admin
  dashboard, forgot-password recovery, family-link recovery, device tracking,
  notifications. Login itself is UNCHANGED (MVP spec §4: OIDC auth-code + PKCE +
  enforced TOTP).

## 1. Purpose & Constraints

The MVP shipped admin-scripted users only (`seed-ldap.sh`). This subsystem adds the
account lifecycle a citizen-facing deployment needs, for the same handover audience
as MVP spec §1: government IT teams who are not highly specialized — boring,
standard, documented over clever.

Hard constraints inherited and extended:

1. **No ROPC anywhere**, including tests; passwords reach Keycloak only through its
   HTML forms. This subsystem never adds a password *grant*; it does add password
   *storage* writes (Decision Log #1).
2. **LDAP→Keycloak remains the sole authentication path.** Federation stays
   READ_ONLY. No application state introduced here can authenticate anyone.
3. **Everything per-deployment configurable via `.env`**, following the
   MAIL_DOMAIN/COMPOSE_SUBNET pattern. Zero new containers.
4. **Client apps are separate teams' deliverables** (own-apps-only). This repo ships
   REST endpoints plus ONE operator web page (the admin dashboard). Every flow below
   is designed to be driven by a mobile/web client against these endpoints.
5. **Nothing assumes Twilio.** Twilio is one pluggable sender; swapping a domestic
   SMSC is the government operator's responsibility (sender-ID registration, e.g.
   India DLT, likewise theirs — out of scope by agreement).

### Goals

- A citizen signs up with name + phone, proves phone possession via OTP, chooses a
  password, and gets a mailbox — self-service, no admin step.
- Per-deployment verification tiers: Tier 1 (phone-verified) always; Tier 2
  (identity-verified) when enabled, via pluggable AUTO script or MANUAL review.
- Family-link recovery with human-in-the-loop friction on EVERY path.
- Device tracking as an additional recovery factor, never a sole factor.

### Non-goals (this subsystem)

WebAuthn/passkeys (Phase 2 — would obsolete the recovery dwell trade-off),
refresh-token revocation after reset, mailbox quotas, custom LDAP schema,
full parental-control suites beyond the structural guardian support in §8.2,
cross-deployment federation.

## 2. Requirements Mapping

| Req | Requirement | Where |
|---|---|---|
| #1 | Verification tiers, per-deployment OFF/ON | §7 (tiers), §10 (AUTO/MANUAL), `IDVERIFY_MODE` |
| #2 | Signup collects name+phone, OTP-verified; bootstrap account has no family link | §8.1 |
| #3 | Pluggable OTP sender `send_otp(phone, code, channel)`; Twilio dev impl; rate limits vs cost abuse | §9 |
| #4 | AUTO contract `{verified, govt_id_ref, linked_identities[{id_ref,name,id_type,is_minor}]}`; mock reference impl; multi-identity disambiguation; guardian-managed minors; NO hardcoded age cutoff | §10.1, §8.2, §10.2 |
| #5 | MANUAL mode admin queue; approve/reject semantics | §11 |
| #6 | Family-link recovery: Tier-2 gate, in-app approve only, expiry, 48h cooldown, instant revoke, notify all, owner notified of attempts, concrete reset mechanism | §12, §13 |
| #7 | Device tracking: random opaque IDs never derived from identity data; labels separate; list/remove; additional factor only | §14, §13 |
| #8 | Integrate EXISTING identity store; per-deployment config | Decision Log #2, §5 |
| #4b | AUTO verified:false disposition | §10.3 |
| #4c | Script timeout/error must not hang signup; safe fallback | §10.3, §8.4 invariant |

## 3. Decision Log

| Decision | Choice | Rationale | Rejected |
|---|---|---|---|
| Password lifecycle home | **API-owned**: signup/reset write `{SSHA}` userPassword straight to OpenLDAP | Matches seed-ldap.sh precedent; phone-centric resets fit this phone-first system; federation stays READ_ONLY; zero change to proven KC config | KC WRITABLE federation + its email-based reset flows (email-centric while this system is deliberately phone-centric; KC gains LDAP write access; reset mail lands in the mailbox of a user who cannot log in) |
| New-state store | **Postgres DB `sovereign_app`** beside Keycloak's database (same engine, new logical DB) | NOT a second *user* database: credentials/login identity remain solely LDAP→KC; this DB holds OTP challenges, links, queues — none of it authenticates anyone. Relational integrity fits links/queues; avoids custom LDAP schema (handover burden); TTL'd data doesn't belong in a directory | Custom LDAP objectClasses; storing app state in KC's internal DB (anti-pattern) |
| Identity-verification failure disposition | **Tri-state** (§10.3): verified→T2; explicit false→T1 final; infra failure→T1 + auto-enqueue MANUAL review | Fail-visible: every script outage appears as queue growth with reason `auto_script_error`; citizens never blocked by backend config mistakes | Hard 503 on misconfig (blocks signups for an ops problem); fail-open to T2 (security hole) |
| Signup completion invariant | **Once phone OTP is verified, `/signup/complete` always succeeds** — downstream verification may degrade the tier, never block the signup; availability failures live ONLY at the OTP-send step (`503`, budget unconsumed) | One rule everywhere; client contract self-describing (§8.4); no bare-503 guessing post-OTP | Mixed hard/soft fallback depending on failure class |
| Reject semantics (MANUAL queue) | Account **stays Tier 1, reason recorded, reapply allowed** (bounded by OTP budgets) | A rejection judges THIS submission, not the person; permanent blocking needs due-process tooling outside MVP scope; schema keeps a `blocked` status operators may set manually | First-class permanent-block flow |
| Recovery friction | **Mandatory dwell on every self-service path**: family approval OR 600s dwell before reset authorization claimable; cancellation paths; ≤3 starts/hour/account | Stolen phone delivers BOTH factors at once (SIM = OTP, app storage = device token); notice-and-neutralize needs delivery(<30s)+notice(min)+act(2–3min) ≈ 10 min; one mental model: "a recovery notification is actionable for ten minutes" | Instant device-path reset (silent-takeover path); hardware-bound keys deferred to Phase 2 |
| Family approval threshold | Any ONE linked member approves | Links are individually approved pairs; quorum logic multiplies UI+state complexity for rare multi-adult households | Majority/quorum gating |
| Admin surface | Server-rendered HTML dashboard in the API (`sovereign-admin` realm role, PKCE login, CSRF) | Requirement asks for a dashboard; boring stack (Jinja2 + one stylesheet); usable at handover with zero extra deployments | JSON-only endpoints (no operator screen); CLI tool (not a dashboard) |
| Deliverable shape | One spec + one plan (~16 tasks), phased into 3 SDD waves | Shared infrastructure (schema, OTP, notifications, admin auth) specified once; waves give splitting's isolation benefit inside one artifact | Two specs/plans (boundary forces a shared-infra spec anyway) |

## 4. Architecture (delta on the MVP stack)

**Zero new containers.** The subsystem lives in the existing `api` service and uses
the existing `postgres` container with a NEW logical database:

```
api gains:                              postgres gains:
  routers/{signup,recovery,family,        new DB sovereign_app
   account,admin}_router.py               (Keycloak keeps its own DB;
  services/{otp_service,ldap_admin,        separate logical database)
   idverify,family,recovery,devices,
   notifications}
  db.py            (psycopg helpers)
  ssha_util.py     ({SSHA} hash generation)
  templates/ + static css (dashboard)
```

New internal edges: `api → openldap` (WRITE, admin bind — see Secret Lifecycle §15),
`api → postgres/sovereign_app`. New external edge: `api → twilio` ONLY when
`OTP_PROVIDER=twilio` (offline behavior: send fails → budget unconsumed → `503` at
send step only).

Module isolation rules:

- ALL LDAP writes live in `ldap_admin.py`, exposing exactly `create_user()` and
  `set_password()`. The Phase-2 swap to a least-privilege bind DN touches ONE file.
- ALL provider calls live behind the interface in §9. Nothing else knows Twilio.
- The idverify runner is the ONLY code allowed to spawn the verification subprocess.

## 5. Data Model (`sovereign_app`)

Plain numbered migrations `db/migrations/NNN_slug.sql` applied by
`scripts/db-migrate.sh` (idempotent `createdb` first-run + `schema_migrations`
table; runs via `docker compose exec postgres psql`). No ORM.

```sql
accounts(email PK,                       -- canonical lowercase, == LDAP mail == token claim
         display_name, phone_e164,       -- E.164 normalized
         account_type,                   -- independent | guardian_managed
         guardian_phone,                 -- set iff guardian_managed; control channel
         tier,                           -- tier1_phone | tier2_identity
         verification,                   -- last outcome enum (§8.4)
         id_source,                      -- auto | manual | null (how Tier 2 was granted)
         govt_id_ref,                    -- opaque ref from ID system, if any
         status,                         -- active | blocked
         created_at, updated_at)

otp_challenges(id PK, purpose,           -- signup | recovery
         phone_e164, code_sha256, channel,   -- sms | voice ; code stored ONLY hashed
         expires_at, attempts_left, created_at, consumed_at)

devices(device_hash PK,                  -- SHA-256 of raw device_id; RAW VALUE NEVER STORED
        email FK->accounts, label, created_at, last_seen_at)

family_links(link_id PK, requester_email, target_email,
        status,                          -- requested | approved | revoked | expired
        created_at, expires_at,          -- requested-state TTL (10 min)
        approved_at, usable_at,          -- usable_at = approved_at + FAMILY_LINK_COOLDOWN_HOURS
        revoked_at, revoked_by)

recovery_requests(req_id PK, email FK,
        status,     -- awaiting_phone | pending_family | pending_dwell | pending_admin
                    -- | authorized | completed | expired | denied | cancelled
        recognizing_device_hash, recognized_device bool,
        authorized_at, decided_by_member, cancel_reason, created_at, expires_at)

verification_reviews(review_id PK, email, payload_jsonb,
        status,                          -- pending | approved | rejected
        reason,                          -- policy_manual | auto_script_error
        error_detail, reviewed_by, decided_at, created_at)

notifications(notif_id PK, email, type, body, link_ref, created_at, read_at)

signup_sessions(token PK, payload_jsonb,
        stage,                           -- awaiting_otp | awaiting_identity_choice
        expires_at)                      -- 15 min

schema_migrations(version PK, applied_at)
```

Indexes: `otp_challenges(phone_e164, created_at)` (budget counting),
`notifications(email, created_at)`, `family_links(target_email, status)`,
`family_links(requester_email, status)`, `recovery_requests(email, status)`.
State transitions evaluate lazily on read (expired requests flip on access) —
no background reaper, matching the MVP state-store idiom.

## 6. Identity & Account Model

- **Join key everywhere = email** (canonical lowercase == LDAP `mail` == token
  `email` claim). One identity string, extending MVP spec §4's "no aliasing anywhere".
- Signup chooses a local part: `^[a-z0-9][a-z0-9._-]{1,30}$` (input lowercased);
  address = `<local>@$MAIL_DOMAIN`. Mailbox provisioning needs NO extra work —
  Dovecot static userdb + Maildir-on-first-delivery already serves any LDAP user.
- **Phone** stored E.164-normalized (`^\+[1-9]\d{7,14}$`). Phone is a contact /
  verification channel and is deliberately **NOT unique**: a guardian's phone
  legitimately verifies several managed accounts (that IS the multi-identity case).
  Abuse is bounded by rate budgets (§17), not uniqueness.
- **Tiers:** `tier1_phone` | `tier2_identity` (semantics §7).
- **Account types:** `independent` | `guardian_managed`. The mapping is structural:
  ID system says `is_minor: true` → guardian-managed, linked via `guardian_phone`.
  **No age number exists anywhere in our code** — we honor the ID system's flag only.
- **OpenLDAP stays schema-untouched.** Only delta vs MVP: the API may write user
  entries at runtime (`inetOrgPerson`, RDN `mail=<addr>` matching seed convention,
  `cn`/`sn`/`displayName` from display_name, `userPassword={SSHA}`). Verifiable:
  `ldapsearch` of the schema shows zero new classes/attrs (Success Criterion 3).
- **Seeded-user backfill:** seed gains an idempotent step inserting `accounts` rows
  for alice/bob/sovereign-admin (`tier1_phone`, `independent`, new TEST_PHONE_* env
  vars, ON CONFLICT DO NOTHING) so existing users exercise every flow in smoke.

## 7. Verification Tiers

| Capability | Tier 1 (`tier1_phone`) | Tier 2 (`tier2_identity`) |
|---|---|---|
| Login, mail, device registration | ✅ | ✅ |
| Create family link | ❌ | ✅ |
| Be TARGET of a family link | ❌ | ✅ |
| Family-approved recovery | ❌ (no links exist) | ✅ |
| Device-dwell recovery | ✅ | ✅ |
| Self-service without device or links | ❌ → assisted admin queue | ❌ → assisted admin queue |

`IDVERIFY_MODE=off` (default) → nobody ever reaches Tier 2; family features lie
dormant deployment-wide. Tier naming appears in API responses and docs exactly as
`tier1_phone` / `tier2_identity`.

## 8. Signup Flow (#2)

### 8.1 Start + complete

```
POST /signup/start {email_local, display_name, phone_e164, channel}
  validate local-part/phone → 422; duplicate address (accounts table OR LDAP
  search) → 409; phone over budget → 429
  → insert signup_sessions(token, stage=awaiting_otp, TTL 15 min)
  → provider.send_otp(...)   [ONLY step that may 503; budget consumed on success]
  → 200 {signup_token}

POST /signup/complete {signup_token, code, password}
  verify code (attempts_left--, expired/exhausted → 400) → password policy:
    length ≥ PASSWORD_MIN_LENGTH (default 12); must not contain email local part
  → ldap_admin.create_user(email, display_name, ssha(password))   [409 if raced]
  → accounts row per IDVERIFY_MODE (below); challenge consumed; session burned
```

### 8.2 Identity choice & guardian accounts

Multi-identity AUTO results pause signup (§10.2):

```
POST /signup/identity-choice {signup_token, id_ref}
  → validates id_ref was among offered choices → completes creation
```

Choosing an `is_minor:true` identity creates a `guardian_managed` account whose
`guardian_phone` = the phone that just proved possession. No chicken-and-egg: the
guardian's own account may not exist yet; control operations route by phone match.
Structural enforcement points (the whole MVP scope of guardianship):

1. `GET /account/dependents` — authenticated guardian lists managed accounts whose
   `guardian_phone` equals their account phone.
2. Managed accounts cannot CREATE family links and cannot APPROVE recovery
   requests — the guardian acts for them.
3. A managed account's own recovery goes to the ASSISTED ADMIN QUEUE only
   (no self-service branch), with the guardian notified.

One signup = one account. A parent wanting their own mailbox runs a second signup
with their own identity choice.

### 8.3 First login / TOTP

Nothing new: the realm-wide *Configure OTP* required action (MVP spec §4) enrolls
every new user at first login. The browserless helper already overrides the hidden
`totpSecret` field, so runtime-created users are scriptable in smoke tests.

### 8.4 Response contract (discriminated union — clients read FIELDS, never status codes alone)

| Case | HTTP | Body |
|---|---|---|
| Mode off | 200 | `{status:"created", tier:"tier1_phone", verification:"phone_only", email}` |
| Auto, verified | 200 | `{status:"created", tier:"tier2_identity", verification:"auto_verified", email}` |
| Auto, explicit false | 200 | `{status:"created", tier:"tier1_phone", verification:"auto_failed_tier1", email}` |
| Manual mode OR auto-infra-failure | 200 | `{status:"created", tier:"tier1_phone", verification:"manual_review_queued", reason:"policy_manual"\|"auto_script_error", email}` |
| Multi-identity pause | 200 | `{status:"choose_identity", choices:[{id_ref, name_masked, id_type, is_minor}]}` |
| Duplicate address | 409 | `{detail:"address unavailable"}` |
| Validation / bad-or-expired OTP | 400/422 | standard detail |
| Phone budget exceeded | 429 | `{detail:"too many attempts"}` |
| Provider down at SEND step | 503 | `{detail:"otp delivery unavailable"}` |

**Invariant:** once the OTP verifies, `/signup/complete` always succeeds. Downstream
verification may degrade the tier, never block the signup.

## 9. OTP Infrastructure (#3)

Provider interface (exact contract, one Python module each):

```python
send_otp(phone_number: str, code: str, channel: str) -> bool   # channel: sms | voice
send_sms(phone_number: str, text: str) -> bool                 # OTP + recovery alerts ONLY (see below)
```

- **console** (default): logs the code to container stdout BY DESIGN — dev/test/smoke
  work with zero external accounts (Mailpit-pattern dev stand-in). Startup logs a
  loud WARNING when selected; docs mark it NEVER-FOR-PRODUCTION.
- **twilio**: httpx against Twilio REST; free-tier creds in gitignored `.env`
  (empty in `.env.example`). Non-200 ⇒ logged (credentials redacted) + False.
- **Government swap:** domestic SMSC = one new module implementing the two
  functions; nothing else changes. Sender-ID/DLT registration documented as the
  operator's responsibility.
- **Channel routing:** SMS carries OTP codes and recovery-attempt alerts ONLY.
  Family-link lifecycle notifications deliberately do NOT ride SMS — they are
  delivered by this system's own mail stack into members' mailboxes (§12, §17),
  which removes the SMS cost surface from the family flow entirely.
- Codes: 6-digit crypto-random, TTL `OTP_CODE_TTL_SECONDS=300`, stored ONLY as
  SHA-256, single-use (`consumed_at`), ≤5 verify attempts per challenge.
- Budgets (PG-backed): ≤`OTP_MAX_SENDS_PER_HOUR=3` sends/hour/phone, 60s resend
  cooldown, deployment daily cap `OTP_DAILY_CAP`. **Budget consumed ONLY on
  provider success** — a Twilio outage never burns legitimate quota.

## 10. Identity Verification (#1, #4, #4b, #4c)

### 10.1 AUTO script contract (frozen, versioned)

Subprocess: JSON on **stdin** → JSON on **stdout**, `contract_version` in both
directions. Fixed timeout `IDVERIFY_TIMEOUT_SECONDS=20` (subprocess killed + reaped).

```json
IN:  {"contract_version": 1, "email": "...", "display_name": "...", "phone_e164": "..."}

OUT (exit 0 = well-formed result, even when verified:false):
    {"contract_version": 1,
     "verified": bool,
     "govt_id_ref": str|null,
     "linked_identities": [{"id_ref": str, "name": str, "id_type": str,
                            "is_minor": bool}, ...]}
```

Exit semantics: **0** = parse stdout as the result above; **nonzero exit / invalid
JSON / crash / timeout** = infrastructure failure (never a determination about the
citizen).

- Shipped reference implementation: `scripts/mock-idverify.sh` — THE one mock
  demonstrating the contract with deterministic test data
  (`MOCK_IDVERIFY_MODE` forces each outcome for tests/smoke). We do NOT fabricate
  any real country's government API.
- Operator cutover: mount the real script at `IDVERIFY_SCRIPT`; zero code changes.
  The runner is the only code that spawns it.

### 10.2 Multi-identity resolution

`verified:true` + exactly one identity → proceed. `linked_identities` length > 1 →
signup pauses (`choose_identity`, §8.2/§8.4): choices rendered MASKED
(`R*** K*** — Aadhaar-class ID` style masking is the client's rendering of
`name_masked`; API provides masked name + id_type + is_minor), user picks which
identity this account is for; minor identity ⇒ guardian-managed account (§8.2).
Zero identities returned is treated as `verified:false`.

### 10.3 Tri-state disposition (#4b, #4c)

| Outcome | Disposition |
|---|---|
| `verified:true` | Tier 2 (`id_source=auto`, govt_id_ref stored) |
| `verified:false` | **Tier 1 final** — honor the government system's actual determination; reapply allowed, bounded by OTP budgets |
| infra failure (nonzero/timeout/bad JSON/missing script) | **Tier 1 created + manual-review row auto-enqueued**, reason=`auto_script_error`, error_detail recorded |

### 10.4 Misconfig behavior

`IDVERIFY_MODE=auto` with missing/unexecutable script: api stays UP, logs a loud
ERROR at startup, and per-request behaves exactly like any infra failure (tri-state
row 3) — soft fallback uniformly, signup completes, review queued. A persistently
broken script surfaces as a growing `auto_script_error` cluster on the dashboard,
not as outage reports from citizens.

## 11. MANUAL Review Queue + Admin Dashboard (#5)

Auth: same PKCE login as everyone else; `require_admin` dependency additionally
checks `realm_access.roles ∋ sovereign-admin`. Realm role + assignment to
`$SOVEREIGN_ADMIN_USER` added to `seed-keycloak.sh` (that user also gets seeded
LDAP creds + pre-seeded TOTP like alice/bob). Session: opaque httpOnly
SameSite=Lax cookie ↔ in-memory token map (single-replica assumption, same
trade-off class as MVP spec §6 state); per-session CSRF token embedded in every
form and verified on POST.

Pages (Jinja2 + one stylesheet; system fonts, cards + tables — good-looking,
normal, no JS framework): pending-review queue grouped by reason → review detail
(payload snapshot) → Approve (tier→tier2_identity, id_source=manual) / Reject
(stays tier1_phone, reason recorded, reapply allowed) · assisted-recovery list →
Grant · recent decisions. JSON endpoints under `/admin/*` share the guard and
remain available to future tooling.

## 12. Family Links (#6)

- `POST /account/family-links {target_email}` — caller must be Tier 2; target must
  be Tier 2; no self-link; no duplicate active link. Managed accounts cannot create.
- Target receives an in-app APPROVE button ONLY. Approval is an authenticated API
  call by the target — there is structurally nothing speakable or relayable; no
  code ever exists to read out over a phone call.
- Request unapproved after 10 min → expired (lazy flip on read).
- Approve → `status=approved`, `usable_at = approved_at + FAMILY_LINK_COOLDOWN_HOURS`
  (default 48h). Fresh links authorize NO recovery for the cooldown window —
  an attacker who adds a link during temporary compromise gives the owner 48 hours
  to notice and revoke. Smoke overrides the env to 0 (documented; prod default 48).
- Revoke: instant, either party, ANY time, no cooldown.
- Delivery channels: EVERY transition (requested / approved / revoked / expired)
  notifies ALL linked members of BOTH accounts' link neighborhoods — in-app rows
  PLUS an email delivered by THIS system's own mail stack into each member's
  sovereign mailbox. Family notifications never touch the SMS provider: the mail
  infrastructure is already ours to run, so this flow carries zero marginal
  sender cost and no Twilio exposure.
- **The notification email is a POINTER ONLY** — it must NEVER contain a clickable
  approve/action link. Body shape: "You have a pending family-link request from
  R***@sovereign.mail — open the app to review." Every approve/deny/revoke step
  remains an authenticated in-app API call by the member. This is LOAD-BEARING for
  the "nothing relayable exists" security property (§15.3): a forwarded or phished
  email grants nothing.
- Rate limit: ≤2 link requests per requester→target pair per rolling 24h window
  (§17) — request-spam must not function as email harassment.
- Texts carry masked addresses (`R***@sovereign.mail`) and never codes.

## 13. Recovery (#6, #7)

```
POST /recovery/start {email}
  ALWAYS 202 {request_id} byte-identical whether or not the account exists
  (anti-enumeration; timing side-channel accepted at MVP, noted §15.3)
  if account active: create recovery_request, notify owner "recovery attempt",
  budget-check ≤ RECOVERY_MAX_ATTEMPTS_PER_HOUR=3 starts/hour/account

POST /recovery/phone/send {request_id}      → OTP to the account's phone (budgeted)
POST /recovery/phone/verify {request_id, code}
  device factor resolved server-side from X-Device-ID header vs devices table
  → branch:
     Tier 2 + approved&cooled link(s)   → pending_family (window = TTL 600s)
                                          ALL members notified (masked info);
                                          ANY ONE approval → authorized
     Recognized device (either tier)    → pending_dwell
                                          authorized_at = now + RECOVERY_MIN_DWELL_SECONDS
     Neither (or guardian-managed acct) → pending_admin (assisted queue;
                                          admin Grant → authorized)
GET /recovery/status/{request_id}           → polled by waiting client; lazy flips
POST /recovery/set-password {request_id, new_password}
  permitted iff status==authorized AND within RECOVERY_RESET_SESSION_TTL_SECONDS (600s),
  ONE-TIME consumption → SSHA → LDAP set_password → completed
POST /recovery/{request_id}/cancel          → authenticated owner session OR any
  linked member denies → cancelled (+ owner notified)
```

**Family-window expiry (explicit):** if `pending_family` elapses its full window
with no member approval, the request flips to `expired` on read and recovery
requires a fresh `/recovery/start` — consuming attempt budget like any other
restart. There is **NO automatic fallback to device-dwell**, even when the request
carried a recognized device: a deliberate MVP simplicity choice, not an oversight.
Rationale: real-time family coordination is expected (the requester tells the
member out-of-band to go approve), so the window is normally sufficient;
automatic dwell-fallback is deferred as a Phase-2 UX improvement should this prove
too rigid in practice (register #13).

Dwell rules (the stolen-phone case delivers BOTH factors at once — SIM inside =
OTP, app storage = device token):

- Reset claimable only after the dwell elapses. During dwell ANY of these voids the
  request: owner cancels from another logged-in session; owner deletes the
  recognizing device (**deleting the device that vouched kills its request**); a
  linked member denies; TTL expires; newer attempt supersedes.
- Attempt budget ≤3 starts/hour/account — restarting the clock burns budget and
  re-notifies the owner each time.
- Number choice: 600s default, its own env var so operators may diverge it from the
  family window; defaults symmetric ("a recovery notification is actionable for ten
  minutes"). Justification in Decision Log #6. Honest cost: a legitimate owner on a
  recognized device waits too — the alternative signal set is empty; Phase 2
  passkeys would remove the trade-off entirely.
- Post-reset: issued access tokens die ≤5 min naturally; refresh-token revocation
  via KC admin API = Phase 2 register item. Owner notified "password was reset".

Factor composition invariant: **OTP always mandatory; device/family is the OR-leg;
neither is ever sufficient alone** (#7 satisfied literally).

## 14. Device Tracking (#7)

- `POST /account/devices {label}` → server mints `device_id =
  secrets.token_urlsafe(16)` — pure cryptographic randomness, NEVER derived from
  username/email/family data, so collisions across one user's own devices are
  impossible by construction. Returned ONCE; client persists (app secure storage);
  sent thereafter as `X-Device-ID`.
- Server stores ONLY `SHA-256(device_id)` — a database leak alone cannot forge the
  factor. Lookup compares hashes.
- `GET /account/devices` (label, created_at, last_seen_at, id prefix) ·
  `DELETE /account/devices/{device_id}` — instant, and voids any recovery request
  that device currently vouches for (§13).
- Unknown X-Device-ID values are never auto-registered; registration requires the
  authenticated POST. Role: additional factor alongside OTP, never sole (#7).

## 15. Security Analysis

### 15.1 Secret lifecycle inventory (new exposures only)

| Secret | Lifecycle | Notes |
|---|---|---|
| `LDAP_ADMIN_PASSWORD` (EXISTING value, NEW exposure) | gitignored `.env` → compose env injection → api process memory only; never logged, never in an image layer; used solely by `ldap_admin.py` (`create_user`/`set_password`) | ⚠ **Interim risk, accepted TEMPORARILY**: global admin DN inside the api container. No new boundary crossed — the api container already holds equivalent-power secrets (`KC_INTROSPECTION_SECRET`). Successor design pinned in §21 #9: dedicated bind DN + slapd ACL allowing writes ONLY to `userPassword`/naming attrs under `ou=people`; trigger tied to the same milestone as MVP register #1 (pre-VPS). The one-file isolation (§4) makes that swap cheap. NOT permanent design. |
| `TWILIO_ACCOUNT_SID` / `TWILIO_AUTH_TOKEN` / `TWILIO_FROM_NUMBER` | gitignored `.env`, empty in `.env.example`, injected only when `OTP_PROVIDER=twilio`; provider module redacts credentials from logs; rotation via Twilio console (documented in README) | Absent entirely when console provider selected |
| OTP codes | 6-digit crypto-random; stored ONLY as SHA-256; TTL 300s; single-use; ≤5 attempts | Console provider prints codes BY DESIGN — dev only; startup WARNING when selected |
| Device IDs | raw shown once at registration; server stores SHA-256 only | DB leak alone cannot forge the factor |
| Passwords | `{SSHA}` salted-SHA-1 written to LDAP (the scheme LDAP binds require; same as seed script); transit TLS-only; min-length policy enforced | SSHA is weak by modern KDF standards — accepted because it is what LDAP federation binds against; Phase-2 register #10 investigates stronger schemes |

### 15.2 Trust boundaries & phase transitions

| Boundary | Now (local Compose MVP) | Transition to production |
|---|---|---|
| api→openldap write | admin DN, compose-net only | least-privilege bind DN + ACL (§21 #9), same milestone as :2587 AUTH replacement |
| api→postgres | trust on compose net; no TLS | VPS phase: pg TLS + network policy review alongside all services |
| api→Twilio | egress to internet, dev free tier | domestic SMSC module swap; sender-ID/DLT = operator responsibility |
| idverify subprocess | mock script | real gov ID system script behind SAME frozen contract (§10.1) |
| Admin dashboard session | in-memory map, single replica | Redis/session table when scaling (extends MVP register #5) |
| Recovery factors | SMS OTP + software device token + human dwell | WebAuthn/passkeys (§21 #11) would collapse the dwell trade-off |

### 15.3 Threat considerations

- **SIM-swap + stolen/unlocked phone** (both factors at once): mitigated by mandatory
  dwell + instant-revoke + attempt budget + notifications (§13). Residual risk
  documented honestly: a fully compromised owner ecosystem defeats any self-service
  scheme short of hardware factors.
- **Enumeration:** `/recovery/start` byte-identical responses; `/signup/start` DOES
  disclose address-existence via 409 — accepted UX trade-off for signup forms,
  noted here deliberately.
- **OTP relay/social-engineering (#6):** family approval has NO relayable artifact;
  approvals are authenticated calls by the target account. Family notification
  emails are pointers only — no action links (§12), so forwarding one grants
  nothing.
- **Guardian-phone SIM-swap cascade:** dependents resolve purely by
  `guardian_phone == account phone` matching, and phone numbers are deliberately
  non-unique — so a SIM swap against a GUARDIAN's number risks more than that
  guardian's own recovery: it grants the attacker guardian-level access
  (`GET /account/dependents` and downstream guardian actions) to EVERY dependent
  account linked to that number. **Currently UNMITIGATED at MVP** — stated
  honestly rather than patched inline; candidate directions are collected as
  register #14 as a design question, not a committed solution.
- **Cost-abuse:** per-phone/per-account budgets consumed only on provider success.

## 16. Configuration Surface (.env additions)

```
SOVEREIGN_APP_DB=sovereign_app
OTP_PROVIDER=console                # console | twilio
TWILIO_ACCOUNT_SID=                 # empty until twilio selected
TWILIO_AUTH_TOKEN=
TWILIO_FROM_NUMBER=
OTP_CODE_TTL_SECONDS=300
OTP_RESEND_COOLDOWN_SECONDS=60
OTP_MAX_SENDS_PER_HOUR=3
OTP_MAX_VERIFY_ATTEMPTS=5
OTP_DAILY_CAP=200
IDVERIFY_MODE=off                   # off | auto | manual
IDVERIFY_SCRIPT=/verify/mock-idverify.sh
IDVERIFY_TIMEOUT_SECONDS=20
FAMILY_LINK_COOLDOWN_HOURS=48
RECOVERY_REQUEST_TTL_SECONDS=600    # request lifetime == family approval window
RECOVERY_MIN_DWELL_SECONDS=600      # device-path dwell; own knob, symmetric default
RECOVERY_RESET_SESSION_TTL_SECONDS=600
RECOVERY_MAX_ATTEMPTS_PER_HOUR=3
PASSWORD_MIN_LENGTH=12
SOVEREIGN_ADMIN_USER=admin@sovereign.mail   # seeded w/ role + TOTP like alice/bob
TEST_PHONE_ALICE=+910000000001      # backfill phones for seeded users
TEST_PHONE_BOB=+910000000002
TEST_PHONE_ADMIN=+910000000003
```

api compose service additionally receives `LDAP_ADMIN_PASSWORD` (see §15.1).
`/healthz` extends with a `db` field (SELECT 1 probe).

## 17. Rate-Limit Summary

| Budget | Value | Scope |
|---|---|---|
| OTP sends/hour/phone | 3 (+60s resend cooldown, daily cap 200/deployment) | cost abuse |
| Verify attempts/challenge | 5 | code guessing |
| Signup sessions | 15-min TTL, single completion | session hygiene |
| Recovery starts/account | 3/hour | dwell-clock restart abuse |
| Family-link requests | expire unapproved at 10 min | notification spam |
| Family-link requests per requester→target pair | 2 per rolling 24h | email-harassment prevention |

## 18. Error Handling

Extends MVP spec §7 conventions:

| Failure | Response |
|---|---|
| Missing/expired/bad token | 401 + WWW-Authenticate (unchanged) |
| Non-admin on /admin/* | 403 |
| Validation (local-part, phone, password policy, bad folder-style enums) | 400/422 |
| Duplicate address / raced LDAP add | 409 |
| Any budget exceeded | 429 |
| OTP provider unreachable (SEND step only) | 503 |
| KC down (login/dashboard auth) | 503 (unchanged) |
| idverify infra failure | NEVER surfaced as error — soft fallback per §8.4 invariant |
| Unknown recovery request id | generic 202-shape status body (no oracle) |

## 19. Testing Strategy

**Unit (pytest, fakes only — no live deps):**

- SSHA generation round-trips through an LDAP-style bind check format.
- ldap_admin against a monkeypatched connection: entry shape, RDN, 409 mapping.
- otp_service: budgets/cooldown/daily-cap/TTL/attempts with a recording fake
  provider; budget-NOT-consumed-on-provider-false pinned explicitly.
- Twilio provider via httpx.MockTransport: success, non-200 → False, credential
  redaction in logs.
- idverify runner six ways via fixture scripts: single/multi/minor/false/error/
  timeout (sleeping script killed at IDVERIFY_TIMEOUT_SECONDS).
- Signup router: full response-contract union incl. choose_identity pause/resume;
  409 dup; password policy rejections.
- Recovery state machine: every branch, lazy expiry, dwell math, cancel/supersede,
  delete-device-voids-request, anti-enumeration byte-equal pins.
- Family links: Tier gating both directions, duplicate/self rejection, cooldown
  math (usable_at), instant revoke, notification fan-out to BOTH neighborhoods.
- Devices: mint randomness (never derived), hash-only storage pin, recognition,
  deletion semantics.
- Admin: require_admin role check (missing role → 403), CSRF token reject, queue
  grouping by reason, approve/reject/grant state effects.

**Smoke extension (codespace live, exit-0 gate):**

console-provider signup (code scraped from `docker compose logs api`) → runtime
user browserless-login with helper-chosen TOTP secret → mock-auto Tier-2 signup →
real family link between two runtime users → approve → dwell-gated cross-user
recovery completes → device register/list/remove → admin queue approve over HTTP
(seeded sovereign-admin user). `FAMILY_LINK_COOLDOWN_HOURS=0` +
`RECOVERY_MIN_DWELL_SECONDS=5` smoke-env overrides, loudly documented as
smoke-only. Alice/bob backfill rows exercise existing-user paths too.

## 20. Implementation Phasing (3 waves, ~16 tasks)

- **Wave A — foundations + signup (~T1–T5):** migrations infra + db.py + healthz db;
  ssha_util + ldap_admin + tests; providers + otp_service + budgets + tests;
  signup_router (start/complete, off-mode contract) + tests; seed backfill +
  compose/env wiring + wave live gate.
- **Wave B — verification tiers + admin (~T6–T10):** idverify runner + mock script +
  contract tests; auto/manual wiring + identity-choice flow; KC role seeding +
  require_admin + session/CSRF plumbing; reviews queue + HTML dashboard; wave gate.
- **Wave C — family + recovery + devices (~T11–T16):** notifications service +
  endpoints; devices service; family links lifecycle + fan-out; recovery state
  machine + assisted queue + admin grant; smoke extension; README/operator guide +
  trade-offs register updates + final gate.

Each task carries testable gates per the MVP plan discipline; SDD controller loop
with adversarial review per wave, deviations D-numbered in the ledger.

## 21. Trade-offs Register Additions (Phase 2 backlog)

1. Refresh-token revocation after password reset (KC offline-session invalidation).
2. Admin session store in-memory → shared store when scaling beyond one replica
   (extends MVP register #5).
3. `/signup/start` address-existence disclosure (409) — revisit if enumeration
   threat model tightens.
4. Recovery timing side-channel on unknown emails — constant-time hardening if
   threat model requires.
5. Family quorum policies (majority/approver roles) — deferred; single-member
   approval chosen for MVP availability.
6. Full parental-control suite beyond structural guardian support (spend limits,
   app-level locks) — product decision, not security blocker.
7. Domestic SMSC module + operator sender-ID/DLT registration — operator-side,
   interface documented (§9).
8. Notification channel depth (push, email fallback) — in-app + SMS only for MVP.
9. **Dedicated least-privilege LDAP bind DN + slapd ACL** replacing global admin DN
   in api — BLOCKER before VPS phase, same milestone as MVP register #1.
10. Password hash scheme investigation ({ARGON2}/{CRYPT} variants under OpenLDAP)
    vs required SSHA-for-bind constraint.
11. WebAuthn/passkeys as recovery/login factors — would obsolete the dwell
    trade-off and device-token fragility. Also covers optional biometric/passkey
    binding on the FAMILY-APPROVER's device: a stronger factor for the approve
    action than a bare in-app button tap.
12. Postgres TLS + per-service network policies — VPS-phase hardening sweep.
13. Auto-fallback of expired family-approval windows to device-dwell — deferred
    UX question (§13); revisit only if out-of-band coordination proves too rigid
    in practice.
14. Guardian-phone compromise cascade — DESIGN QUESTION, not a committed fix:
    candidate directions include periodic guardian identity re-verification,
    alerting dependent-account notification trails on guardian phone/context
    changes, or requiring secondary confirmation before a dependents-list query
    following a recent phone/account change. Needs threat-model work before
    anything is chosen (§15.3).

## 22. Deliverables & Repo Layout Delta

```
db/migrations/NNN_*.sql                     (new)
scripts/db-migrate.sh                       (new)
scripts/mock-idverify.sh                    (new, chmod +x)
api/app/{db,ssha_util}.py                   (new)
api/app/services/{__init__,otp_service,ldap_admin,idverify,family,recovery,
                 devices,notifications}.py  (new)
api/app/services/providers/{console,twilio}.py  (new)
api/app/routers/{signup,recovery,family,account,admin}_router.py  (new)
api/templates/+api/static/                  (dashboard)
api/tests/test_{ssha,ldap_admin,otp_service,idverify,signup_router,family,
               recovery,devices,admin_dashboard}.py  (new)
scripts/seed-ldap.sh, seed-keycloak.sh      (backfill + role additions)
docker-compose.yml, .env.example            (env surface §16)
docs/README.md                              (operator guide: flows, dashboard,
                                             provider swap, config reference)
docs/superpowers/plans/2026-08-25-identity-auth-flow.md  (next artifact)
```

## 23. Success Criteria

1. Local pytest suite green including all §19 unit pins (suite roughly doubles).
2. Extended `smoke-test.sh` exits 0 on codespace executing the FULL loop:
   signup → login(runtime user) → tier2 via mock-auto → family link approved →
   dwell-gated cross-user recovery completed → device lifecycle → admin approval.
3. Config audit: zero ROPC anywhere still true; LDAP schema unchanged
   (`ldapsearch` shows no new classes/attributes); all new behavior driven by §16
   env vars with committed defaults.
4. Anti-enumeration audit: `/recovery/start` responses byte-identical for known vs
   unknown addresses (pinned by test).
5. A newcomer following docs/README.md can explain and operate: tiers, the review
   queue, provider swap, and the recovery windows — within one reading.
