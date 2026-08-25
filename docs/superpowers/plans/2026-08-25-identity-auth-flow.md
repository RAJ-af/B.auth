# User Identity & Auth Flow — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Self-service signup with phone-OTP verification tiers, pluggable OTP senders, AUTO/MANUAL identity verification with an admin dashboard queue, family-link recovery with mandatory dwell friction, hashed device tracking, and notifications — layered onto the hardened MVP stack without touching login or the LDAP schema.

**Architecture:** Zero new containers. The existing `api` FastAPI service gains routers + a `services/` layer (otp, providers, ldap_admin, idverify, family, recovery, devices, notifications); all new state lives in a NEW Postgres logical database `sovereign_app` beside Keycloak's (credentials/login identity remain solely LDAP→Keycloak, federation stays READ_ONLY). Passwords are API-owned `{SSHA}` writes to OpenLDAP via admin bind. The admin dashboard is server-rendered Jinja2 behind PKCE + `sovereign-admin` realm role.

**Tech Stack:** Python 3.12 / FastAPI / psycopg3 / ldap3 (pure-python) / Jinja2 / httpx / PyJWT; Postgres 16 (existing container); Keycloak realm-role RBAC; pytest.

**Spec:** `docs/superpowers/specs/2026-08-25-identity-auth-flow-design.md` — read it first; section references below (§N) point there.

## Global Constraints

- Every commit message ends with a blank line then `Co-Authored-By: Claude <noreply@anthropic.com>`
- Stage EXPLICIT paths only — never `git add -A` or `git add .`
- **No ROPC anywhere**, including tests. No password grant, no direct-grant calls.
- `.env` gitignored; only empty-valued additions go into `.env.example`. Never print secret values — fingerprints only (`printf '%s' "$VAL" | sha256sum | cut -c1-16`; pin this format when comparing).
- English everywhere (code comments, commits, docs).
- No new containers. No custom LDAP schema (Success Criterion 3 audits this).
- Local machine has NO Docker: unit tests must pass locally with fakes/monkeypatches ONLY. Live Docker gates exist ONLY at wave-end tasks (5, 10, 16) on the codespace.
- Storage-touching services keep their SQL in small module-level functions so tests can swap them (repo precedent: `er.MailSession` swap pattern).
- Once phone OTP is verified, `/signup/complete` ALWAYS succeeds (§8.4 invariant); 503 exists only at the OTP-send step.
- Family notification emails are POINTER ONLY — never contain action links (§12, load-bearing).
- Recovery: OTP mandatory always; device/family is the OR-leg; NO auto dwell-fallback from expired family windows (§13); `/recovery/start` responses byte-identical known vs unknown email (§15.3), budget-exceeded starts are silently accepted-and-discarded to preserve that.

---

## File Structure

```
db/migrations/001_sovereign_app.sql       all tables + indexes (single initial migration)
scripts/db-migrate.sh                     createdb-if-missing + apply migrations + seed backfill
scripts/mock-idverify.sh                  frozen-contract mock ID verifier (spec §10.1)
api/app/db.py                             psycopg connect/dsn + tiny query helpers
api/app/ssha_util.py                      {SSHA} hash (+ verify helper for tests)
api/app/services/
  __init__.py · providers/{__init__,console,twilio}.py
  otp_service.py                          budgets + challenge lifecycle (pure cores + thin SQL)
  ldap_admin.py                           ONLY file doing LDAP writes (create_user/set_password)
  idverify.py                             subprocess runner, tri-state mapping
  notifications.py                        in-app rows + email/SMS dispatch
  devices.py                              mint/hash/resolve/list/delete (+void hook)
  family.py                               link lifecycle, cooldown, fan-out, pair rate-limit
  recovery.py                             state machine incl. dwell/cancel/supersede
api/app/routers/{signup,recovery,family,account,admin}_router.py
api/templates/admin/{base,reviews,review_detail,assists}.html · api/static/admin.css
api/tests/test_{db,ssha,ldap_admin,otp_service,idverify,signup_router,family,
               recovery,devices,notifications,admin_dashboard}.py
Modified: api/app/config.py · api/app/main.py · api/requirements.txt
          docker-compose.yml · .env.example
          scripts/seed-keycloak.sh (role) · scripts/smoke-test.sh (extension)
          docs/README.md (operator guide)
```

---

## WAVE A — foundations + signup (Tasks 1–5)

### Task 1: DB infrastructure + config surface

**Files:**
- Create: `db/migrations/001_sovereign_app.sql`, `scripts/db-migrate.sh` (chmod +x)
- Create: `api/app/db.py`, Test: `api/tests/test_db.py`
- Modify: `api/app/config.py`, `api/requirements.txt`, `docker-compose.yml` (api service env/volumes), `.env.example`

**Interfaces:**
- Produces: `Settings` fields (env names = field names uppercased): `postgres_host="postgres"`, `postgres_port:int=5432`, `postgres_user`, `postgres_password`, `sovereign_app_db="sovereign_app"`, plus ALL subsystem knobs verbatim from spec §16: `otp_provider:str="console"`, `twilio_account_sid=""`, `twilio_auth_token=""`, `twilio_from_number=""`, `otp_code_ttl_seconds:int=300`, `otp_resend_cooldown_seconds:int=60`, `otp_max_sends_per_hour:int=3`, `otp_max_verify_attempts:int=5`, `otp_daily_cap:int=200`, `idverify_mode:str="off"`, `idverify_script:str="/verify/mock-idverify.sh"`, `idverify_timeout_seconds:int=20`, `family_link_cooldown_hours:int=48`, `recovery_request_ttl_seconds:int=600`, `recovery_min_dwell_seconds:int=600`, `recovery_reset_session_ttl_seconds:int=600`, `recovery_max_attempts_per_hour:int=3`, `password_min_length:int=12`, `sovereign_admin_user:str="admin@sovereign.mail"`, `ldap_host:str="openldap"`, `ldap_admin_password:str=""`.
- Produces: `db.dsn() -> str`, `db.tx()` contextmanager (commits/rolls back), `db.one(q,params)->dict|None`, `db.many(q,params)->list[dict]`, `db.execute(q,params)`.

- [ ] **Step 1: Write db/migrations/001_sovereign_app.sql**

```sql
-- Initial schema for the sovereign_app database (spec §5).
CREATE TABLE IF NOT EXISTS accounts (
  email TEXT PRIMARY KEY,
  display_name TEXT NOT NULL,
  phone_e164 TEXT NOT NULL,
  account_type TEXT NOT NULL CHECK (account_type IN ('independent','guardian_managed')),
  guardian_phone TEXT,
  tier TEXT NOT NULL CHECK (tier IN ('tier1_phone','tier2_identity')),
  verification TEXT NOT NULL,
  id_source TEXT CHECK (id_source IN ('auto','manual')),
  govt_id_ref TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','blocked')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS otp_challenges (
  id BIGSERIAL PRIMARY KEY,
  purpose TEXT NOT NULL CHECK (purpose IN ('signup','recovery')),
  phone_e164 TEXT NOT NULL,
  code_sha256 TEXT NOT NULL,
  channel TEXT NOT NULL CHECK (channel IN ('sms','voice')),
  expires_at TIMESTAMPTZ NOT NULL,
  attempts_left INT NOT NULL DEFAULT 5,
  consumed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_otp_phone_created ON otp_challenges (phone_e164, created_at);

CREATE TABLE IF NOT EXISTS devices (
  device_hash TEXT PRIMARY KEY,              -- SHA-256 hex of raw device_id; raw NEVER stored
  email TEXT NOT NULL REFERENCES accounts(email),
  label TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS family_links (
  link_id BIGSERIAL PRIMARY KEY,
  requester_email TEXT NOT NULL REFERENCES accounts(email),
  target_email TEXT NOT NULL REFERENCES accounts(email),
  status TEXT NOT NULL CHECK (status IN ('requested','approved','revoked','expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,           -- requested-state TTL (10 min)
  approved_at TIMESTAMPTZ,
  usable_at TIMESTAMPTZ,                     -- approved_at + FAMILY_LINK_COOLDOWN_HOURS
  revoked_at TIMESTAMPTZ,
  revoked_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_fl_target ON family_links (target_email, status);
CREATE INDEX IF NOT EXISTS idx_fl_requester ON family_links (requester_email, status);

CREATE TABLE IF NOT EXISTS recovery_requests (
  req_id TEXT PRIMARY KEY,
  email TEXT NOT NULL REFERENCES accounts(email),
  status TEXT NOT NULL CHECK (status IN ('awaiting_phone','pending_family',
      'pending_dwell','pending_admin','authorized','completed','expired',
      'denied','cancelled')),
  recognizing_device_hash TEXT,
  recognized_device BOOLEAN NOT NULL DEFAULT false,
  authorized_at TIMESTAMPTZ,
  decided_by_member TEXT,
  cancel_reason TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rr_email ON recovery_requests (email, status);

CREATE TABLE IF NOT EXISTS verification_reviews (
  review_id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  payload_json JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
  reason TEXT NOT NULL CHECK (reason IN ('policy_manual','auto_script_error')),
  error_detail TEXT,
  reviewed_by TEXT,
  decided_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS notifications (
  notif_id BIGSERIAL PRIMARY KEY,
  email TEXT NOT NULL,
  type TEXT NOT NULL,
  body TEXT NOT NULL,
  link_ref TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  read_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_notif_email ON notifications (email, created_at);

CREATE TABLE IF NOT EXISTS signup_sessions (
  token TEXT PRIMARY KEY,
  payload_json JSONB NOT NULL,
  stage TEXT NOT NULL CHECK (stage IN ('awaiting_otp','awaiting_identity_choice')),
  expires_at TIMESTAMPTZ NOT NULL
);
```

- [ ] **Step 2: Write scripts/db-migrate.sh**

```bash
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
```

- [ ] **Step 3: Extend api/app/config.py Settings**

Append these fields INSIDE the existing `Settings` class (after `ca_cert_path`), keeping the guard machinery untouched:

```python
    # --- Identity & Auth Flow subsystem (spec 2026-08-25 §16) ---
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_user: str = ""
    postgres_password: str = ""
    sovereign_app_db: str = "sovereign_app"
    otp_provider: str = "console"
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_from_number: str = ""
    otp_code_ttl_seconds: int = 300
    otp_resend_cooldown_seconds: int = 60
    otp_max_sends_per_hour: int = 3
    otp_max_verify_attempts: int = 5
    otp_daily_cap: int = 200
    idverify_mode: str = "off"            # off | auto | manual
    idverify_script: str = "/verify/mock-idverify.sh"
    idverify_timeout_seconds: int = 20
    family_link_cooldown_hours: int = 48
    recovery_request_ttl_seconds: int = 600
    recovery_min_dwell_seconds: int = 600
    recovery_reset_session_ttl_seconds: int = 600
    recovery_max_attempts_per_hour: int = 3
    password_min_length: int = 12
    sovereign_admin_user: str = "admin@sovereign.mail"
    ldap_host: str = "openldap"
    ldap_admin_password: str = ""         # lifecycle: spec §15.1 row 1
```

- [ ] **Step 4: Write api/app/db.py**

```python
"""sovereign_app access: one psycopg connection per operation (MVP scale).

Deliberately boring: no pool, no ORM. A connection leak under load would show up
as wave-gate failures long before it matters at deployment scale (register #12
covers the production sweep). All SQL lives in the services that need it; this
module only owns connectivity and row shaping.
"""
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row

from .config import get_settings


def dsn() -> str:
    s = get_settings()
    return (f"host={s.postgres_host} port={s.postgres_port} "
            f"dbname={s.sovereign_app_db} user={s.postgres_user} "
            f"password={s.postgres_password}")


@contextmanager
def tx():
    conn = psycopg.connect(dsn(), row_factory=dict_row)
    try:
        with conn:                       # commits on success, rolls back on error
            yield conn
    finally:
        conn.close()


def execute(query: str, params: tuple = ()) -> None:
    with tx() as conn:
        conn.execute(query, params)


def one(query: str, params: tuple = ()) -> dict | None:
    with tx() as conn:
        return conn.execute(query, params).fetchone()


def many(query: str, params: tuple = ()) -> list[dict]:
    with tx() as conn:
        return conn.execute(query, params).fetchall()
```

- [ ] **Step 5: Failing test api/tests/test_db.py**

```python
"""DSN builder pins (live connectivity is a codespace wave gate, not local)."""
from app.db import dsn


def test_dsn_contains_all_components(monkeypatch):
    import app.config as cfg
    monkeypatch.setattr(cfg.get_settings, "cache_clear", lambda: None)
    s = cfg.get_settings.__wrapped__() if hasattr(cfg.get_settings, "__wrapped__") else cfg.get_settings()
    monkeypatch.setattr(cfg, "get_settings", lambda: type(
        "S", (), {
            "postgres_host": "pg.test", "postgres_port": 6543,
            "sovereign_app_db": "sovereign_app", "postgres_user": "u",
            "postgres_password": "p"})())
    import importlib
    from app import db
    importlib.reload(db)
    d = db.dsn()
    assert "host=pg.test" in d and "port=6543" in d and "dbname=sovereign_app" in d
    assert "user=u" in d and "password=p" in d
```

Run: `cd api && .venv/bin/python -m pytest tests/test_db.py -v`
Expected: PASS (test reloads db against a stub settings object).

- [ ] **Step 6: Wire requirements, compose, .env.example**

`api/requirements.txt` — append three lines:
```
psycopg[binary]>=3.1
ldap3>=2.9
jinja2>=3.1
```

`docker-compose.yml` — the `api` service gains environment entries and the mock-script mount:
```yaml
    environment:
      # ...existing entries stay...
      POSTGRES_HOST: postgres
      POSTGRES_PORT: "5432"
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      SOVEREIGN_APP_DB: ${SOVEREIGN_APP_DB}
      LDAP_HOST: openldap
      LDAP_ADMIN_PASSWORD: ${LDAP_ROOT_PASSWORD}
      OTP_PROVIDER: ${OTP_PROVIDER:-console}
      TWILIO_ACCOUNT_SID: ${TWILIO_ACCOUNT_SID:-}
      TWILIO_AUTH_TOKEN: ${TWILIO_AUTH_TOKEN:-}
      TWILIO_FROM_NUMBER: ${TWILIO_FROM_NUMBER:-}
      OTP_CODE_TTL_SECONDS: ${OTP_CODE_TTL_SECONDS:-300}
      OTP_RESEND_COOLDOWN_SECONDS: ${OTP_RESEND_COOLDOWN_SECONDS:-60}
      OTP_MAX_SENDS_PER_HOUR: ${OTP_MAX_SENDS_PER_HOUR:-3}
      OTP_MAX_VERIFY_ATTEMPTS: ${OTP_MAX_VERIFY_ATTEMPTS:-5}
      OTP_DAILY_CAP: ${OTP_DAILY_CAP:-200}
      IDVERIFY_MODE: ${IDVERIFY_MODE:-off}
      IDVERIFY_SCRIPT: ${IDVERIFY_SCRIPT:-/verify/mock-idverify.sh}
      IDVERIFY_TIMEOUT_SECONDS: ${IDVERIFY_TIMEOUT_SECONDS:-20}
      FAMILY_LINK_COOLDOWN_HOURS: ${FAMILY_LINK_COOLDOWN_HOURS:-48}
      RECOVERY_REQUEST_TTL_SECONDS: ${RECOVERY_REQUEST_TTL_SECONDS:-600}
      RECOVERY_MIN_DWELL_SECONDS: ${RECOVERY_MIN_DWELL_SECONDS:-600}
      RECOVERY_RESET_SESSION_TTL_SECONDS: ${RECOVERY_RESET_SESSION_TTL_SECONDS:-600}
      RECOVERY_MAX_ATTEMPTS_PER_HOUR: ${RECOVERY_MAX_ATTEMPTS_PER_HOUR:-3}
      PASSWORD_MIN_LENGTH: ${PASSWORD_MIN_LENGTH:-12}
      SOVEREIGN_ADMIN_USER: ${SOVEREIGN_ADMIN_USER}
    volumes:
      # ...existing certs mount stays...
      - ./scripts/mock-idverify.sh:/verify/mock-idverify.sh:ro
```
(The mount lands in Task 6 when the script exists — harmless placeholder until then because `IDVERIFY_MODE` defaults to `off`. Add it NOW so later tasks don't touch compose again.)

`.env.example` — append (empty secrets stay EMPTY):
```
# --- Identity & Auth Flow subsystem (docs/superpowers/specs/2026-08-25-identity-auth-flow-design.md §16) ---
SOVEREIGN_APP_DB=sovereign_app
OTP_PROVIDER=console                # console | twilio  -- console prints codes to logs, DEV ONLY
TWILIO_ACCOUNT_SID=
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
RECOVERY_REQUEST_TTL_SECONDS=600
RECOVERY_MIN_DWELL_SECONDS=600
RECOVERY_RESET_SESSION_TTL_SECONDS=600
RECOVERY_MAX_ATTEMPTS_PER_HOUR=3
PASSWORD_MIN_LENGTH=12
SOVEREIGN_ADMIN_USER=admin@sovereign.mail
TEST_PHONE_ALICE=+910000000001
TEST_PHONE_BOB=+910000000002
TEST_PHONE_ADMIN=+910000000003
```

Also append to your LOCAL gitignored `.env` the same keys with real values (phones may be the placeholders shown; nothing Twilio yet).

- [ ] **Step 7: Verify locally + commit**

```bash
bash -n scripts/db-migrate.sh && echo SYNTAX-OK
cd api && .venv/bin/pip install -q psycopg[binary] ldap3 jinja2 && .venv/bin/python -m pytest -q
cd .. 
git add db/migrations/001_sovereign_app.sql scripts/db-migrate.sh api/app/db.py api/tests/test_db.py api/app/config.py api/requirements.txt docker-compose.yml .env.example
git commit -m "feat: sovereign_app schema, migration runner, db helper, config surface"
# trailer line: Co-Authored-By: Claude <noreply@anthropic.com>
```
Expected: full suite green (existing tests plus the new one).

### Task 2: SSHA utility + LDAP admin writer

**Files:**
- Create: `api/app/ssha_util.py`, `api/app/services/__init__.py` (empty), `api/app/services/ldap_admin.py`
- Test: `api/tests/test_ssha.py`, `api/tests/test_ldap_admin.py`

**Interfaces:**
- Consumes: `Settings.ldap_host`, `Settings.ldap_admin_password`, `Settings.mail_domain`.
- Produces: `ssha(password:str)->str` ("{SSHA}b64"), `verify_ssha(password:str,stored:str)->bool`;
  `ldap_admin.base_dn()->str`, `ldap_admin.AddressTaken(Exception)`,
  `ldap_admin.LdapUnavailable(Exception)`, `ldap_admin.address_exists(email:str)->bool`,
  `ldap_admin.create_user(email:str,display_name:str,password:str)->None`,
  `ldap_admin.set_password(email:str,password:str)->None`.

- [ ] **Step 1: Failing tests**

`api/tests/test_ssha.py`:
```python
from app.ssha_util import ssha, verify_ssha


def test_format_and_roundtrip():
    stored = ssha("correct horse battery staple")
    assert stored.startswith("{SSHA}")
    assert verify_ssha("correct horse battery staple", stored)


def test_wrong_password_fails():
    stored = ssha("secret-one")
    assert not verify_ssha("secret-two", stored)


def test_salts_are_fresh():
    assert ssha("x") != ssha("x")          # same password, different salt
```

`api/tests/test_ldap_admin.py` (fake `ldap3.Connection` swapped at module boundary):
```python
import pytest
from app.services import ldap_admin


class FakeConn:
    """Records ops; emulates ldap3 result semantics."""
    last = None
    def __init__(self, *a, **k):
        self.ops = []
        self.entries = []
        self.result = {}
        self.add_ok = True
        FakeConn.last = self
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def search(self, base, filt, **k):
        self.ops.append(("search", base, filt))
        self.entries = [] if "taken@test" in filt else [{"mail": filt}]
    def add(self, dn, cls, attrs):
        self.ops.append(("add", dn, cls, attrs))
        if "taken@test" in dn:
            self.result = {"description": "entryAlreadyExists"}; return False
        self.result = {"description": "success"}; return True
    def modify(self, dn, changes):
        self.ops.append(("modify", dn, changes)); return True


@pytest.fixture
def fake_conn(monkeypatch):
    monkeypatch.setattr(ldap_admin, "_connect", FakeConn)
    return FakeConn


def test_create_user_shape(fake_conn):
    ldap_admin.create_user("new@test.mail", "Test Citizen", "pw-long-enough")
    _, dn, classes, attrs = FakeConn.last.ops[-1]
    assert dn == "mail=new@test.mail,ou=people,dc=test,dc=mail"
    assert classes == ["inetOrgPerson"]
    assert attrs["mail"] == "new@test.mail"
    assert attrs["userPassword"].startswith("{SSHA}")
    assert attrs["cn"] == attrs["sn"] == "Test Citizen"


def test_duplicate_is_address_taken(fake_conn):
    with pytest.raises(ldap_admin.AddressTaken):
        ldap_admin.create_user("taken@test.mail", "X", "pw-long-enough")


def test_set_password_modifies_userpassword(fake_conn):
    ldap_admin.set_password("a@test.mail", "brand-new-pw")
    _, dn, changes = FakeConn.last.ops[-1]
    assert dn.endswith(",ou=people,dc=test,dc=mail")
    assert changes["userPassword"][0][0] == "MODIFY_REPLACE"
    assert changes["userPassword"][0][1].startswith("{SSHA}")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd api && .venv/bin/python -m pytest tests/test_ssha.py tests/test_ldap_admin.py -v`
Expected: FAIL with ModuleNotFoundError.

- [ ] **Step 3: Implement**

`api/app/ssha_util.py`:
```python
"""{SSHA} salted-SHA-1 userPassword scheme (what OpenLDAP binds require).

Weak by modern KDF standards — accepted deliberately because the LDAP federation
binds against it; register #10 tracks stronger-scheme investigation. The API only
ever GENERATES hashes; verify_ssha exists for tests and tooling.
"""
import base64
import hashlib
import secrets


def ssha(password: str) -> str:
    salt = secrets.token_bytes(4)
    digest = hashlib.sha1(password.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(digest + salt).decode()


def verify_ssha(password: str, stored: str) -> bool:
    try:
        raw = base64.b64decode(stored.removeprefix("{SSHA}"))
        digest, salt = raw[:-4], raw[-4:]
        return secrets.compare_digest(
            hashlib.sha1(password.encode() + salt).digest(), digest)
    except Exception:
        return False
```

`api/app/services/__init__.py`: empty file.

`api/app/services/ldap_admin.py`:
```python
"""The ONLY module allowed to write to OpenLDAP (spec §4 isolation rule).

Interim posture (accepted, temporary — spec §15.1): binds as the GLOBAL admin DN.
The Phase-2 swap to a least-privilege bind DN touches exactly this file. Exposed
surface is deliberately two verbs: create_user, set_password.
"""
import logging

# T2-review correction (ledger 2026-08-25): the original block omitted `Connection`
# here — every real write died NameError->LdapUnavailable under fakes-only tests.
from ldap3 import Connection, MODIFY_REPLACE, Server

from ..config import get_settings
from ..ssha_util import ssha

log = logging.getLogger(__name__)


class LdapUnavailable(Exception):
    pass


class AddressTaken(Exception):
    pass


def base_dn() -> str:
    return "dc=" + get_settings().mail_domain.replace(".", ",dc=")


def _connect():
    s = get_settings()
    try:
        return Connection(
            Server(s.ldap_host, port=389),
            user=f"cn=admin,{base_dn()}",
            password=s.ldap_admin_password,
            auto_bind=True,
            raise_exceptions=False,
        )
    except Exception as e:                      # noqa: BLE001 — wrap everything
        raise LdapUnavailable(str(e)) from e


def address_exists(email: str) -> bool:
    with _connect() as c:
        c.search(f"ou=people,{base_dn()}", f"(mail={email})",
                 attributes=["mail"])
        return bool(c.entries)


def create_user(email: str, display_name: str, password: str) -> None:
    dn = f"mail={email},ou=people,{base_dn()}"
    with _connect() as c:
        ok = c.add(dn, ["inetOrgPerson"],
                   {"cn": display_name, "sn": display_name, "mail": email,
                    "userPassword": ssha(password)})
        desc = str(c.result.get("description", ""))
    if ok:
        log.info("ldap user created: %s", email)
        return
    if "entryAlreadyExists" in desc:
        raise AddressTaken(email)
    raise LdapUnavailable(f"ldap add failed: {desc}")


def set_password(email: str, password: str) -> None:
    dn = f"mail={email},ou=people,{base_dn()}"
    with _connect() as c:
        ok = c.modify(dn, {"userPassword": [(MODIFY_REPLACE, ssha(password))]})
        desc = str(c.result.get("description", ""))
    if not ok:
        raise LdapUnavailable(f"ldap modify failed: {desc}")
```

- [ ] **Step 4: Green**

Run: `cd api && .venv/bin/python -m pytest tests/test_ssha.py tests/test_ldap_admin.py -v`
Expected: 6 PASS.

- [ ] **Step 5: Commit**

```bash
git add api/app/ssha_util.py api/app/services/__init__.py api/app/services/ldap_admin.py api/tests/test_ssha.py api/tests/test_ldap_admin.py
git commit -m "feat: ssha hashing + single-file ldap admin writer"
```

### Task 3: OTP providers + challenge service

**Files:**
- Create: `api/app/services/providers/__init__.py` (empty), `api/app/services/providers/console.py`, `api/app/services/providers/twilio.py`, `api/app/services/otp_service.py`
- Test: `api/tests/test_otp_service.py`

**Interfaces:**
- Produces (each provider module): `send_otp(phone_number:str, code:str, channel:str)->bool`, `send_sms(phone_number:str, body:str)->bool`. `console` logs and returns True; `twilio` uses httpx against the Twilio REST API and returns False on any failure.
- Produces (`otp_service`):
  - `BudgetExceeded(Exception)`, `OtpSendError(Exception)`, `InvalidCode(Exception)`
  - `send_challenge(phone:str, purpose:str, channel:str="sms") -> None`
  - `verify_challenge(phone:str, purpose:str, code:str) -> bool`
  - pure cores: `within_budget(last_send_ts:float|None, sends_last_hour:int, sends_today:int, *, now:float, cooldown_s:int, hourly:int, daily:int)->None` (raises BudgetExceeded with reason "cooldown"|"hourly"|"daily")
  - `check_code(stored_hash:str|None, attempts_left:int|None, expires_at_ts:float|None, consumed:bool, code:str, *, now:float)->bool` (raises InvalidCode on mismatch/expiry/exhaustion; returns True only for a live unconsumed match)
  - SQL wrappers (monkeypatch targets in tests): `_last_send_ts`, `_count_since`, `_insert_challenge`, `_latest_active`.

- [ ] **Step 1: Failing tests**

```python
"""otp_service budget + verification logic; SQL is faked at module boundary."""
import time

import pytest

from app.services import otp_service as ot


class FlakyProvider:
    def __init__(self, ok=True):
        self.ok = ok
        self.calls = []
    def send_otp(self, phone, code, channel):
        self.calls.append((phone, code, channel))
        return self.ok
    def send_sms(self, phone, body):
        self.calls.append((phone, body))
        return self.ok


@pytest.fixture
def store(monkeypatch):
    """In-memory stand-in for the SQL wrappers."""
    rows = []
    monkeypatch.setattr(ot, "_insert_challenge",
                        lambda r: rows.append(r) or r)
    monkeypatch.setattr(ot, "_latest_active", lambda phone, purpose, now:
                        max((r for r in rows if r["phone"] == phone
                             and r["purpose"] == purpose), default=None,
                           key=lambda r: r["created_at"]))
    monkeypatch.setattr(ot, "_last_send_ts", lambda phone, purpose:
                        max((r["created_at"] for r in rows
                             if r["phone"] == phone), default=None))
    monkeypatch.setattr(ot, "_count_since", lambda phone, since:
                        sum(1 for r in rows if r["phone"] == phone
                            and r["created_at"] >= since))
    return {"rows": rows, "provider": None}


def _install(store, ok=True, monkeypatch=None):
    p = FlakyProvider(ok)
    store["provider"] = p
    monkeypatch.setattr(ot, "_get_provider", lambda: p)
    return p


NOW = 1_800_000_000.0


def test_budget_pure_logic():
    with pytest.raises(ot.BudgetExceeded, match="cooldown"):
        ot.within_budget(NOW - 10, 0, 0, now=NOW, cooldown_s=60, hourly=3, daily=200)
    with pytest.raises(ot.BudgetExceeded, match="hourly"):
        ot.within_budget(None, 3, 3, now=NOW, cooldown_s=60, hourly=3, daily=200)
    with pytest.raises(ot.BudgetExceeded, match="daily"):
        ot.within_budget(None, 1, 200, now=NOW, cooldown_s=60, hourly=3, daily=200)
    ot.within_budget(None, 2, 5, now=NOW, cooldown_s=60, hourly=3, daily=200)  # OK


def test_send_success_records_and_calls_provider(store, monkeypatch):
    p = _install(store, monkeypatch=monkeypatch)
    ot.send_challenge("+15550001", "signup", "sms")
    assert len(p.calls) == 1
    phone, code, channel = p.calls[0]
    assert phone == "+15550001" and channel == "sms"
    assert len(code) == 6 and code.isdigit()
    row = store["rows"][0]
    from app.ssha_util import verify_ssha
    assert row["code_sha256"].startswith("{SSHA}") or len(row["code_sha256"]) == 64


def test_provider_failure_does_not_consume_budget(store, monkeypatch):
    _install(store, ok=False, monkeypatch=monkeypatch)
    with pytest.raises(ot.OtpSendError):
        ot.send_challenge("+15550002", "signup", "sms")
    assert store["rows"] == []          # nothing recorded -> budget untouched


def test_cooldown_blocks_second_send(store, monkeypatch):
    _install(store, monkeypatch=monkeypatch)
    t = time.time()
    monkeypatch.setattr(ot.time, "time", lambda: t)
    ot.send_challenge("+15550003", "signup", "sms")
    monkeypatch.setattr(ot.time, "time", lambda: t + 5)   # inside 60s cooldown
    with pytest.raises(ot.BudgetExceeded):
        ot.send_challenge("+15550003", "signup", "sms")


def test_check_code_paths():
    import hashlib
    good = hashlib.sha256(b"123456").hexdigest()
    assert ot.check_code(good, 5, NOW + 60, False, "123456", now=NOW)
    with pytest.raises(ot.InvalidCode, match="match"):
        ot.check_code(good, 5, NOW + 60, False, "654321", now=NOW)
    with pytest.raises(ot.InvalidCode, match="expired"):
        ot.check_code(good, 5, NOW - 1, False, "123456", now=NOW)
    with pytest.raises(ot.InvalidCode, match="attempts"):
        ot.check_code(good, 0, NOW + 60, False, "654321", now=NOW)
    with pytest.raises(ot.InvalidCode, match="consumed"):
        ot.check_code(good, 5, NOW + 60, True, "123456", now=NOW)
    assert ot.check_code(None, None, None, False, "000000", now=NOW) is False
```

Run: `cd api && .venv/bin/python -m pytest tests/test_otp_service.py -v`
Expected: FAIL — ModuleNotFoundError.

- [ ] **Step 2: Implement providers**

`api/app/services/providers/console.py`:
```python
"""Dev-only OTP provider: codes go to api container logs. NEVER set OTP_PROVIDER=
console outside local/codespace labs (spec §9 warning box)."""
import logging

log = logging.getLogger("otp.console")


def send_otp(phone_number: str, code: str, channel: str) -> bool:
    log.warning("OTP for %s via %s: %s", phone_number, channel, code)
    return True


def send_sms(phone_number: str, body: str) -> bool:
    log.warning("SMS to %s: %s", phone_number, body)
    return True
```

`api/app/services/providers/twilio.py`:
```python
"""Twilio REST provider. Credentials come from Settings/env; a failed HTTP call
returns False so callers keep their budgets intact (spec §9)."""
import base64
import logging

import httpx

from ...config import get_settings

log = logging.getLogger("otp.twilio")


def send_sms(phone_number: str, body: str) -> bool:
    s = get_settings()
    url = f"https://api.twilio.com/2010-04-01/Accounts/{s.twilio_account_sid}/Messages.json"
    auth = base64.b64encode(
        f"{s.twilio_account_sid}:{s.twilio_auth_token}".encode()).decode()
    try:
        r = httpx.post(url, auth=("sid-placeholder-not-used", ""),
                       headers={"Authorization": f"Basic {auth}"},
                       data={"To": phone_number, "From": s.twilio_from_number,
                             "Body": body}, timeout=15.0)
        return r.status_code < 300
    except Exception as e:                      # noqa: BLE001
        log.warning("twilio sms failed: %s", e)
        return False


def send_otp(phone_number: str, code: str, channel: str) -> bool:
    text = (f"Sovereign Mail verification code: {code}"
            if channel == "sms" else
            f"Your Sovereign Mail code is {code}. Repeat digit by digit.")
    return send_sms(phone_number, text)
```

- [ ] **Step 3: Implement otp_service.py**

```python
"""Phone-OTP challenges: budgets, lifecycle, verification (spec §9).

Design rule under test: the provider call happens BEFORE any state is recorded;
a provider failure raises OtpSendError and consumes NOTHING.
"""
import hashlib
import logging
import secrets
import time

from ..config import get_settings
from ..db import execute, many, one
from ..ssha_util import verify_ssha
from .providers import console, twilio

log = logging.getLogger(__name__)


class BudgetExceeded(Exception):
    pass


class OtpSendError(Exception):
    pass


class InvalidCode(Exception):
    pass


def _get_provider():
    name = get_settings().otp_provider
    return {"console": console, "twilio": twilio}[name]


# --- SQL wrappers (tests swap these) ---------------------------------------

def _insert_challenge(row: dict) -> dict:
    execute("""INSERT INTO otp_challenges
               (purpose, phone_e164, code_sha256, channel, expires_at, attempts_left)
               VALUES (%(purpose)s,%(phone)s,%(code_sha256)s,%(channel)s,
                       to_timestamp(%(expires_at)s),%(attempts_left)s)""", (
        row["purpose"], row["phone"], row["code_sha256"], row["channel"],
        row["expires_at"], row["attempts_left"]))
    return row


def _latest_active(phone: str, purpose: str, now: float) -> dict | None:
    return one("""SELECT id, code_sha256, attempts_left,
                         extract(epoch from expires_at)::float AS expires_at_ts,
                         consumed_at IS NOT NULL AS consumed
                  FROM otp_challenges WHERE phone_e164=%s AND purpose=%s
                    AND created_at > to_timestamp(%s) - interval '1 hour'
                  ORDER BY created_at DESC LIMIT 1""",
              (phone, purpose, now))


def _last_send_ts(phone: str, purpose: str) -> float | None:
    r = one("""SELECT extract(epoch from created_at)::float AS ts
               FROM otp_challenges WHERE phone_e164=%s AND purpose=%s
               ORDER BY created_at DESC LIMIT 1""", (phone, purpose))
    return r["ts"] if r else None


def _count_since(phone: str, since_ts: float) -> int:
    return many("""SELECT 1 FROM otp_challenges
                   WHERE phone_e164=%s AND created_at >= to_timestamp(%s)""",
                (phone, since_ts)).__len__()


# --- logic -------------------------------------------------------------------

def within_budget(last_send_ts: float | None, sends_last_hour: int,
                  sends_today: int, *, now: float, cooldown_s: int,
                  hourly: int, daily: int) -> None:
    if last_send_ts is not None and now - last_send_ts < cooldown_s:
        raise BudgetExceeded(f"resend cooldown ({cooldown_s}s)")
    if sends_last_hour >= hourly:
        raise BudgetExceeded(f"hourly cap ({hourly})")
    if sends_today >= daily:
        raise BudgetExceeded(f"daily cap ({daily})")


def check_code(stored_hash: str | None, attempts_left: int | None,
               expires_at_ts: float | None, consumed: bool, code: str,
               *, now: float) -> bool:
    if stored_hash is None:
        return False                     # unknown phone/purpose: generic fail
    if consumed:
        raise InvalidCode("code consumed")
    if expires_at_ts is not None and now > expires_at_ts:
        raise InvalidCode("code expired")
    if attempts_left is not None and attempts_left <= 0:
        raise InvalidCode("no attempts left")
    # Constant-time compare over the SHA-256 hex of the presented code.
    presented = hashlib.sha256(code.encode()).hexdigest()
    if not secrets.compare_digest(presented, stored_hash):
        raise InvalidCode("codes do not match")
    return True


def send_challenge(phone: str, purpose: str, channel: str = "sms") -> None:
    s = get_settings()
    now = time.time()
    within_budget(_last_send_ts(phone, purpose),
                  _count_since(phone, now - 3600),
                  _count_since(phone, now - 86400),
                  now=now, cooldown_s=s.otp_resend_cooldown_seconds,
                  hourly=s.otp_max_sends_per_hour, daily=s.otp_daily_cap)
    code = f"{secrets.randbelow(10 ** 6):06d}"
    if not _get_provider().send_otp(phone, code, channel):
        raise OtpSendError("provider rejected the send")
    _insert_challenge({
        "purpose": purpose, "phone": phone,
        "code_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "channel": channel, "expires_at": now + s.otp_code_ttl_seconds,
        "attempts_left": s.otp_max_verify_attempts,
        "created_at": now})


def verify_challenge(phone: str, purpose: str, code: str) -> bool:
    now = time.time()
    ch = _latest_active(phone, purpose, now)
    try:
        check_code(ch and ch["code_sha256"], ch and ch["attempts_left"],
                   ch and ch["expires_at_ts"], bool(ch and ch["consumed"]),
                   code, now=now)
    except InvalidCode as e:
        if ch and "expired" not in str(e) and "consumed" not in str(e):
            execute("UPDATE otp_challenges SET attempts_left=attempts_left-1 "
                    "WHERE id=%s", (ch["id"],))
        raise
    execute("UPDATE otp_challenges SET consumed_at=now() WHERE id=%s",
            (ch["id"],))
    return True
```

(Note: `verify_ssha` imported at top stays available for tests/tooling; unused here.)

- [ ] **Step 4: Green**

Run: `cd api && .venv/bin/python -m pytest tests/test_otp_service.py -v`
Expected: 6 PASS.

- [ ] **Step 5: Commit**

```bash
git add api/app/services/providers/__init__.py api/app/services/providers/console.py api/app/services/providers/twilio.py api/app/services/otp_service.py api/tests/test_otp_service.py
git commit -m "feat: pluggable otp providers + budget-aware challenge service"
```

### Task 4: Signup router (start / complete)

**Files:**
- Create: `api/app/routers/signup_router.py`, `api/app/services/idverify.py` (SEED only: `IdentityOutcome` + off-mode `outcome_for_mode`; Tasks 6–7 extend this module)
- Modify: `api/app/main.py` (include router)
- Test: `api/tests/test_signup_router.py`

**Interfaces:**
- Consumes: `otp_service.send_challenge/verify_challenge`, `ldap_admin.create_user/address_exists`, `db.execute/one`.
- Produces endpoints (spec §8.4 contract):
  - `POST /signup/start` `{email, display_name, phone_e164, account_type, guardian_phone?}` →
    `202 {"stage":"awaiting_otp","message":...}` | `409 Address already registered` |
    `422 validation` | `422 {"detail":"otp_unavailable"}`-shaped `503` when provider fails
  - `POST /signup/verify-otp` `{token, code}` → `200 {"stage":"awaiting_identity_choice","identity_options":[...],"tier":"tier1_phone"}` | `400 invalid/expired token` | `401 wrong code`
  - `POST /signup/complete` `{token, choice:{kind:"skip"}|{kind:"submit_id"}, password}` → ALWAYS `201` once OTP verified; body per §8.4 union: tier1 path `{"account":"active","tier":"tier1_phone","verification":"pending_identity","next_step":"..."}`, AUTO path adds `"verification":"auto_verified","tier":"tier2_identity"`; MANUAL/infra paths add `"identity_status":"queued_manual_review"|"auto_check_unavailable"`; `409 duplicate email`; `400 bad stage/token`.
- Module-level storage functions (monkeypatch targets): `_create_session(token,payload,ttl)`, `_get_session(token)`, `_update_session(token,payload,stage)`, `_delete_session(token)` — backed by `signup_sessions` table, TTL from `RECOVERY_RESET_SESSION_TTL_SECONDS`? NO — signup session TTL is fixed 900s (spec §8.2).
- Validation helpers exported for reuse: `valid_email(s)->bool` (local-part regex `^[a-z0-9][a-z0-9._-]{1,30}@` + domain = settings.mail_domain), `valid_phone(s)->bool` (`^\+[1-9]\d{7,14}$`), `password_ok(s)->bool` (≥ `password_min_length`).

- [ ] **Step 1: Failing tests**

```python
"""Signup flow against faked storage/LDAP/OTP boundaries (contract §8.4)."""
import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def world(monkeypatch):
    """Everything the router touches, swapped for in-memory fakes."""
    sessions: dict[str, dict] = {}
    ldap_created: list[tuple] = []
    otp_sent: list[str] = []

    import app.routers.signup_router as sr
    monkeypatch.setattr(sr, "_create_session",
                        lambda tok, payload, ttl=900:
                        sessions.update({tok: {"payload": payload,
                                               "stage": "awaiting_otp"}}))
    monkeypatch.setattr(sr, "_get_session", lambda tok: sessions.get(tok))
    monkeypatch.setattr(sr, "_update_session",
                        lambda tok, payload, stage:
                        sessions[tok].update({"payload": payload, "stage": stage})
                        or sessions[tok])
    monkeypatch.setattr(sr, "_delete_session",
                        lambda tok: sessions.pop(tok, None))
    monkeypatch.setattr(sr.ldap_admin, "address_exists",
                        lambda e: e == "taken@sovereign.mail")

    def fake_create(email, display_name, password):
        ldap_created.append((email, display_name, password))
    monkeypatch.setattr(sr.ldap_admin, "create_user", fake_create)

    def fake_send(phone, purpose, channel="sms"):
        otp_sent.append(phone)
    def fake_verify(phone, purpose, code):
        return code == "123456"
    monkeypatch.setattr(sr.otp_service, "send_challenge", fake_send)
    monkeypatch.setattr(sr.otp_service, "verify_challenge", fake_verify)

    # provisioning writes go through app.db; swap them so no Postgres is needed
    sql: list[tuple] = []
    import app.db as appdb
    monkeypatch.setattr(appdb, "execute", lambda q, p=(): sql.append((q, p)))
    monkeypatch.setattr(appdb, "one", lambda q, p=(): None)

    from fastapi.testclient import TestClient
    return {"client": TestClient(create_app()), "sessions": sessions,
            "ldap_created": ldap_created, "otp_sent": otp_sent, "sql": sql}


def _start(w, email="newuser@sovereign.mail", **over):
    body = {"email": email, "display_name": "New User",
            "phone_e164": "+911234567890", "account_type": "independent"}
    body |= over
    r = w["client"].post("/signup/start", json=body)
    assert r.status_code == 202, r.text
    return r.json()["session_token"]


def test_start_contract(w):
    r = w["client"].post("/signup/start", json={
        "email": "x@sovereign.mail", "display_name": "X",
        "phone_e164": "+911234567890", "account_type": "independent"})
    j = r.json()
    assert r.status_code == 202
    assert j["stage"] == "awaiting_otp"
    assert set(j) >= {"session_token", "stage", "message"}
    assert w["otp_sent"] == ["+911234567890"] * 2   # both starts sent an OTP


def test_duplicate_email_is_409_before_any_otp(w):
    r = w["client"].post("/signup/start", json={
        "email": "taken@sovereign.mail", "display_name": "T",
        "phone_e164": "+911234567891", "account_type": "independent"})
    assert r.status_code == 409
    assert w["otp_sent"] == []


def test_validation_rejects_bad_shapes(w):
    for bad in [{"email": "UPPER@sovereign.mail"},
                {"email": "weird@other.domain"},
                {"phone_e164": "09123456789"},
                {"phone_e164": "+123"},                # too short
                {"account_type": "guardian_managed"},  # guardian_phone missing
                ]:
        body = {"email": "ok@sovereign.mail", "display_name": "Ok",
                "phone_e164": "+911234567890", "account_type": "independent"}
        body |= bad
        assert w["client"].post("/signup/start", json=body).status_code == 422, bad
    # guardian_managed WITH guardian phone passes
    body = {"email": "kid@sovereign.mail", "display_name": "Kid",
            "phone_e164": "+911234567892",
            "account_type": "guardian_managed", "guardian_phone": "+919999999999"}
    assert w["client"].post("/signup/start", json=body).status_code == 202


def test_verify_then_complete_skip_tier1(w):
    tok = _start(w)
    r = w["client"].post("/signup/verify-otp", json={"token": tok, "code": "123456"})
    assert r.status_code == 200
    j = r.json()
    assert j["stage"] == "awaiting_identity_choice" and j["tier"] == "tier1_phone"

    done = w["client"].post("/signup/complete",
                            json={"token": tok, "choice": {"kind": "skip"},
                                  "password": "long-enough-password-1"})
    assert done.status_code == 201, done.text
    b = done.json()
    assert b["account"] == "active" and b["tier"] == "tier1_phone"
    assert b["verification"] == "pending_identity"
    assert w["ldap_created"][0][0] == "newuser@sovereign.mail"


def test_wrong_otp_is_401_and_keeps_stage(w):
    tok = _start(w)
    r = w["client"].post("/signup/verify-otp", json={"token": tok, "code": "000000"})
    assert r.status_code == 401
    assert w["sessions"][tok]["stage"] == "awaiting_otp"


def test_complete_requires_verified_otp(w):
    tok = _start(w)
    r = w["client"].post("/signup/complete",
                         json={"token": tok, "choice": {"kind": "skip"},
                               "password": "long-enough-password-1"})
    assert r.status_code == 400          # still awaiting_otp
    assert w["ldap_created"] == []


def test_weak_password_422_no_ldap_write(w):
    tok = _start(w)
    w["client"].post("/signup/verify-otp", json={"token": tok, "code": "123456"})
    r = w["client"].post("/signup/complete",
                         json={"token": tok, "choice": {"kind": "skip"},
                               "password": "short"})
    assert r.status_code == 422
    assert w["ldap_created"] == []


def test_off_mode_soft_fallback_contract(w, monkeypatch):
    """idverify off + skip-choice => plain tier1 (§8.4); no 503 anywhere here."""
    tok = _start(w)
    w["client"].post("/signup/verify-otp", json={"token": tok, "code": "123456"})
    r = w["client"].post("/signup/complete",
                         json={"token": tok, "choice": {"kind": "skip"},
                               "password": "long-enough-password-1"})
    assert r.status_code == 201
    assert "identity_status" not in r.json()
```

Run: `cd api && .venv/bin/python -m pytest tests/test_signup_router.py -v`
Expected: FAIL — no module `app.routers.signup_router`.

- [ ] **Step 2: Implement signup_router.py**

```python
"""Self-service signup: start -> verify-otp -> complete (spec §8).

Invariant under test: after a verified phone OTP, /signup/complete cannot fail
for identity-reasons — identity checks may only ADD information (soft-fallback),
never block provisioning. 503 lives solely at the OTP-send step.
"""
import re
import secrets
import time

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from ..config import get_settings
from ..services import ldap_admin, otp_service
from ..services.idverify import IdentityOutcome

router = APIRouter(prefix="/signup", tags=["signup"])

LOCAL_PART = re.compile(r"^[a-z0-9][a-z0-9._-]{1,30}$")
PHONE_E164 = re.compile(r"^\+[1-9]\d{7,14}$")


def valid_email(email: str) -> bool:
    local, _, domain = email.partition("@")
    return bool(local and domain == get_settings().mail_domain
                and LOCAL_PART.match(local))


def valid_phone(phone: str) -> bool:
    return bool(PHONE_E164.match(phone))


def password_ok(password: str) -> bool:
    return len(password) >= get_settings().password_min_length


# --- storage (module-level so tests can swap) --------------------------------

SIGNUP_SESSION_TTL_SECONDS = 900       # spec §8.2


def _create_session(token: str, payload: dict, ttl: int =
                    SIGNUP_SESSION_TTL_SECONDS) -> None:
    from ..db import execute
    execute("""INSERT INTO signup_sessions (token, payload_json, stage, expires_at)
               VALUES (%s, %s, 'awaiting_otp', to_timestamp(%s))""",
            (token, __import__("json").dumps(payload), time.time() + ttl))


def _get_session(token: str) -> dict | None:
    from ..db import one
    r = one("""SELECT payload_json, stage, extract(epoch from expires_at)::float AS exp
               FROM signup_sessions WHERE token=%s""", (token,))
    if not r or r["exp"] < time.time():
        return None
    return {"payload": r["payload_json"], "stage": r["stage"]}


def _update_session(token: str, payload: dict, stage: str) -> dict:
    from ..db import execute
    execute("UPDATE signup_sessions SET payload_json=%s, stage=%s WHERE token=%s",
            (__import__("json").dumps(payload), stage, token))
    return {"payload": payload, "stage": stage}


def _delete_session(token: str) -> None:
    from ..db import execute
    execute("DELETE FROM signup_sessions WHERE token=%s", (token,))


class StartBody(BaseModel):
    email: str
    display_name: str
    phone_e164: str
    account_type: str                 # independent | guardian_managed
    guardian_phone: str | None = None


class VerifyBody(BaseModel):
    token: str
    code: str


class CompleteBody(BaseModel):
    token: str
    choice: dict                      # {"kind":"skip"} | {"kind":"submit_id", ...}
    password: str


def _provision_account_strict(payload: dict, password: str) -> None:
    """Create LDAP entry + accounts row. Raises 409-shaped AddressTaken upward."""
    ldap_admin.create_user(payload["email"], payload["display_name"], password)
    from ..db import execute
    execute("""INSERT INTO accounts (email,display_name,phone_e164,account_type,
                                     guardian_phone,tier,verification,status)
               VALUES (%(email)s,%(name)s,%(phone)s,%(atype)s,%(gphone)s,
                       %(tier)s,%(verif)s,'active')
               ON CONFLICT (email) DO NOTHING""", {
        "email": payload["email"], "name": payload["display_name"],
        "phone": payload["phone_e164"], "atype": payload["account_type"],
        "gphone": payload.get("guardian_phone"),
        "tier": payload.get("final_tier", "tier1_phone"),
        "verif": payload.get("final_verification", "pending_identity")})


@router.post("/start", status_code=202)
def start(body: StartBody):
    if body.account_type not in ("independent", "guardian_managed"):
        raise HTTPException(422, "unknown account_type")
    if body.account_type == "guardian_managed" and not (
            body.guardian_phone and valid_phone(body.guardian_phone)):
        raise HTTPException(422, "guardian_phone required for guardian_managed")
    if not valid_email(body.email):
        raise HTTPException(422, "invalid email (local part lowercase alnum ._- , "
                                 f"domain must be {get_settings().mail_domain})")
    if not valid_phone(body.phone_e164):
        raise HTTPException(422, "phone must be E.164 like +911234567890")
    if ldap_admin.address_exists(body.email):
        raise HTTPException(409, "Address already registered")
    token = secrets.token_urlsafe(24)
    try:
        otp_service.send_challenge(body.phone_e164, "signup")
    except otp_service.BudgetExceeded as e:
        # Anti-enumeration posture: same shape as success-era responses; the
        # caller learns only "wait". Spec §15.3 keeps this deliberate.
        raise HTTPException(503, f"otp temporarily unavailable: {e}")
    except otp_service.OtpSendError as e:
        raise HTTPException(503, f"otp temporarily unavailable: {e}")
    _create_session(token, body.model_dump())
    return {"session_token": token, "stage": "awaiting_otp",
            "message": f"code sent to {body.phone_e164}"}


@router.post("/verify-otp")
def verify_otp(body: VerifyBody):
    sess = _get_session(body.token)
    if not sess or sess["stage"] != "awaiting_otp":
        raise HTTPException(400, "unknown or expired session")
    p = sess["payload"]
    try:
        otp_service.verify_challenge(p["phone_e164"], "signup", body.code)
    except otp_service.InvalidCode as e:
        raise HTTPException(401, str(e))
    except otp_service.OtpSendError as e:
        raise HTTPException(503, str(e))
    s = get_settings()
    options = [{"kind": "skip",
                "description": "Continue with Tier 1 (phone verified)"},
               {"kind": "submit_id",
                "description": f"Verify government ID for Tier 2 "
                               f"(mode: {s.idverify_mode})"}]
    _update_session(body.token, p, "awaiting_identity_choice")
    return {"stage": "awaiting_identity_choice", "tier": "tier1_phone",
            "identity_options": options}


@router.post("/complete", status_code=201)
def complete(body: CompleteBody):
    sess = _get_session(body.token)
    if not sess or sess["stage"] != "awaiting_identity_choice":
        raise HTTPException(400, "unknown session or OTP not yet verified")
    p = sess["payload"]
    kind = body.choice.get("kind")
    if kind not in ("skip", "submit_id"):
        raise HTTPException(422, "choice.kind must be skip|submit_id")
    if not password_ok(body.password):
        raise HTTPException(422, f"password must be at least "
                                 f"{get_settings().password_min_length} chars")
    final_tier, final_verification = "tier1_phone", "pending_identity"
    extra: dict = {}
    if kind == "submit_id":
        outcome = _run_identity_step(body.choice, p)     # never raises user-facing 5xx
        if outcome.tier == "tier2_identity":
            final_tier, final_verification = outcome.tier, outcome.verification
        elif outcome.reason_detail:
            extra = {"identity_status": outcome.identity_status,
                     "detail": outcome.reason_detail}
        else:
            extra = {"identity_status": outcome.identity_status}
    try:
        _provision_account_strict(p | {"final_tier": final_tier,
                                       "final_verification": final_verification},
                                  body.password)
    except ldap_admin.AddressTaken:
        raise HTTPException(409, "Address already registered")
    except ldap_admin.LdapUnavailable as e:
        # Pre-OTP-provisioning failure: safe to retry later; session kept.
        raise HTTPException(503, f"directory unavailable: {e}")
    _delete_session(body.token)
    out = {"account": "active", "email": p["email"],
           "tier": final_tier, "verification": final_verification,
           "message": ("Tier 1 active. You can submit an ID later "
                       "from account settings." if kind == "skip"
                       else "Account ready.")} | extra
    return out


def _run_identity_step(choice: dict, payload: dict) -> IdentityOutcome:
    """Delegates to idverify.outcome_for_mode. This task ships with off-mode
    handled there; AUTO/MANUAL dispatch completes in Task 7."""
    from ..services.idverify import outcome_for_mode
    return outcome_for_mode(get_settings().idverify_mode, choice,
                            payload.get("email", ""))
```

Create `api/app/services/idverify.py` (the SEED — Task 6 extends it):

```python
"""AUTO/MANUAL identity verification (spec §10). This seed carries only the
outcome type and off-mode behavior so the signup router can ship; the frozen-
contract subprocess runner lands in Task 6."""
from dataclasses import dataclass


@dataclass
class IdentityOutcome:
    tier: str                    # tier1_phone | tier2_identity
    verification: str            # pending_identity | auto_verified | ...
    identity_status: str | None  # extra field for the /signup/complete body
    reason_detail: str | None


def outcome_for_mode(mode: str, choice: dict | None = None,
                     payload_email: str = "") -> IdentityOutcome:
    if mode == "off":
        return IdentityOutcome(
            "tier1_phone", "pending_identity", "identity_checks_off",
            "ID submission disabled in this deployment (IDVERIFY_MODE=off)")
    raise NotImplementedError("Task 7 completes AUTO/MANUAL dispatch")
```

Modify `api/app/main.py`: add `from .routers.signup_router import router as signup_router` and `app.include_router(signup_router)` beside the existing includes.

- [ ] **Step 3: Green**

Run: `cd api && .venv/bin/python -m pytest tests/test_signup_router.py -v`
Expected: 8 PASS. Then full suite: `.venv/bin/python -m pytest -q` — all green.

- [ ] **Step 4: Commit**

```bash
git add api/app/routers/signup_router.py api/app/services/idverify.py api/app/main.py api/tests/test_signup_router.py
git commit -m "feat: signup start/verify-otp/complete with soft-fallback contract"
```

### Task 5: WAVE A LIVE GATE (codespace, Docker)

**Files:**
- Modify: none new — this task only RUNS things. Any fix found here amends earlier tasks.

**Interfaces:**
- Consumes: everything from Tasks 1–4.
- Produces: a green live run recorded in the PR/commit notes; `db-migrate.sh` proven re-runnable.

- [ ] **Step 1: Push from local machine** (codespace cannot push)

```bash
git push origin main
```

- [ ] **Step 2: On codespace — rebuild and migrate**

```bash
git pull --ff-only
docker compose build api && docker compose up -d
scripts/db-migrate.sh                       # twice: second run must be a no-op
docker compose exec postgres psql -U "$POSTGRES_USER" -d sovereign_app -c '\dt'
```
Expected: 9 tables listed; second migrate prints only the OK line; backfill rows present:
```bash
docker compose exec postgres psql -U "$POSTGRES_USER" -d sovereign_app \
  -tAc "SELECT email,tier FROM accounts ORDER BY email"
```

- [ ] **Step 3: Live signup via console OTP**

```bash
curl -s -X POST localhost:8000/signup/start -H 'content-type: application/json' \
  -d '{"email":"carol@sovereign.mail","display_name":"Carol",
       "phone_e164":"+918888888888","account_type":"independent"}'
docker compose logs api | grep "OTP for"        # read the code (console provider)
# then verify + complete with the printed code and a fresh session token
```
Expected: 202 → 200 (`awaiting_identity_choice`) → 201 tier1 body per §8.4; LDAP check:
`docker compose exec openldap ldapsearch -x -H ldap://localhost -b "dc=sovereign,dc=mail" "(mail=carol@sovereign.mail)" userPassword -D "cn=admin,dc=sovereign,dc=mail" -w "$LDAP_ROOT_PASSWORD"` shows a `{SSHA}` hash and NOTHING else schema-wise (Success Criterion 3 dry-run).

- [ ] **Step 4: Budget behavior live**

Fire 4 rapid `/signup/start` calls with distinct emails but the SAME phone → 4th must be `503 otp temporarily unavailable: hourly cap`. Then confirm no partial state: the challenge count in DB equals 3.

- [ ] **Step 5: Full local-style suite on codespace too**

```bash
cd api && .venv/bin/python -m pytest -q
```
Commit nothing unless fixes were needed (fix commits follow the same explicit-path rule). Wave A done.

---

## WAVE B — idverify + admin dashboard (Tasks 6–10)

### Task 6: Frozen-contract idverify runner + mock script

**Files:**
- Create: `scripts/mock-idverify.sh` (chmod +x)
- Modify: `api/app/services/idverify.py` (add runner + mapping beside the Task-4 seed)
- Test: `api/tests/test_idverify.py`

**Interfaces:**
- Produces: `idverify.IdentityOutcome` dataclass with fields `tier:str`, `verification:str`, `identity_status:str|None`, `reason_detail:str|None`; helper `outcome_for_mode(mode:str)->IdentityOutcome` used by signup's `_run_identity_step`.
- Produces: `idverify.run_auto_check(payload:dict)->dict` — raises `IdverifyInfraError` on timeout/non-zero exit/unparseable stdout/`contract_version != 1`. NEVER raises anything else outward; callers translate.
- Mock script modes via env `MOCK_IDVERIFY_MODE`: `verified_single` | `multi_minor` | `not_verified` | `infra_fail` | `slow`.

- [ ] **Step 1: Write scripts/mock-idverify.sh** (reference implementation of spec §10.1 contract)

```bash
#!/usr/bin/env bash
# Mock government-ID verifier implementing contract_version 1.
# Reads one JSON object on stdin, writes one JSON object on stdout, ALWAYS exits 0
# when the input is well-formed (verification failure is a RESULT, not an error).
set -euo pipefail
MODE="${MOCK_IDVERIFY_MODE:-verified_single}"
IN="$(cat)"
python3 - "$MODE" <<'PY'
import json, os, sys
mode = sys.argv[1]
try:
    inp = json.loads(sys.stdin.read() or "{}")
except json.JSONDecodeError:
    print("mock-idverify: stdin was not JSON", file=sys.stderr); sys.exit(64)
if inp.get("contract_version") != 1:
    print("mock-idverify: unsupported contract_version", file=sys.stderr); sys.exit(65)
out = {"contract_version": 1}
if mode == "verified_single":
    out |= {"verified": True,
            "identities": [{"type": inp.get("document_type", "generic"),
                            "number_masked": "••••1234",
                            "name": inp.get("full_name", ""),
                            "is_minor": False}],
            "warnings": []}
elif mode == "multi_minor":
    out |= {"verified": True,
            "identities": [
                {"type": "guardian", "number_masked": "••••0000",
                 "name": "Guardian", "is_minor": False},
                {"type": "dependent", "number_masked": "••••0001",
                 "name": "Child One", "is_minor": True},
                {"type": "dependent", "number_masked": "••••0002",
                 "name": "Child Two", "is_minor": True}],
            "warnings": ["multiple identities on document"]}
elif mode == "not_verified":
    out |= {"verified": False, "identities": [], "warnings": ["liveness failed"]}
elif mode == "infra_fail":
    print("upstream registry unreachable", file=sys.stderr)
    out |= {"verified": False, "identities": [],
            "warnings": ["upstream_infrastructure_error"]}
else:                                            # slow
    import time; time.sleep(120)
print(json.dumps(out))
PY
```

- [ ] **Step 2: Failing tests**

```python
"""Runner honors the frozen contract exactly as §10.1 states."""
import json

import pytest

from app.services import idverify as iv


def _run(monkeypatch, mode, payload=None, **run_kwargs):
    calls = {}
    def fake_run(cmd, input=None, capture_output=True, text=True, timeout=None):
        calls["timeout"] = timeout
        class R:
            returncode = fake_run.rc
            stdout = fake_run.out
            stderr = ""
        return R()
    fake_run.rc = run_kwargs.get("rc", 0)
    fake_run.out = run_kwargs.get("out") or json.dumps(
        {"contract_version": 1, "verified": False, "identities": [],
         "warnings": []})
    monkeypatch.setattr(iv.subprocess, "run", fake_run)
    monkeypatch.setattr(iv.get_settings, "cache_clear", lambda: None)
    monkeypatch.setattr("app.config.get_settings",
                        lambda: type("S", (), {
                            "idverify_script": "/verify/mock.sh",
                            "idverify_timeout_seconds": 20})())
    return iv.run_auto_check(payload or {
        "contract_version": 1, "full_name": "A B",
        "document_type": "national_id", "id_number": "X1234567",
        "consent_selfie": True})


def test_happy_path_parses_result(monkeypatch):
    out = _run(monkeypatch, "verified_single", out=json.dumps(
        {"contract_version": 1, "verified": True, "identities": [
            {"type": "national_id", "number_masked": "••••1234",
             "name": "A B", "is_minor": False}], "warnings": []}))
    assert out["verified"] is True and len(out["identities"]) == 1


def test_bad_contract_version_is_infra_error(monkeypatch):
    with pytest.raises(iv.IdverifyInfraError, match="contract_version"):
        _run(monkeypatch, "x", out=json.dumps({"contract_version": 2}))


def test_nonzero_exit_is_infra_error(monkeypatch):
    with pytest.raises(iv.IdverifyInfraError, match="exit"):
        _run(monkeypatch, "infra_fail", rc=67)


def test_garbage_stdout_is_infra_error(monkeypatch):
    with pytest.raises(iv.IdverifyInfraError, match="JSON"):
        _run(monkeypatch, "garbage", out="not json at all")


def test_timeout_is_infra_error(monkeypatch):
    import subprocess
    def boom(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=20)
    monkeypatch.setattr(iv.subprocess, "run", boom)
    monkeypatch.setattr("app.config.get_settings", lambda: type(
        "S", (), {"idverify_script": "/v.sh", "idverify_timeout_seconds": 20})())
    with pytest.raises(iv.IdverifyInfraError, match="timed out"):
        iv.run_auto_check({"contract_version": 1})


def test_tri_state_mapping():
    # verified single adult -> tier2 auto_verified
    o = iv.map_result({"verified": True, "identities": [{"is_minor": False}]},
                      email="u@sovereign.mail")
    assert (o.tier, o.verification) == ("tier2_identity", "auto_verified")
    assert o.identity_status is None
    # multi-identity -> MANUAL queue, masked summary only (§10.2)
    o = iv.map_result({"verified": True, "identities": [
        {"is_minor": False}, {"is_minor": True}], "warnings": []},
        email="f@sovereign.mail")
    assert (o.tier, o.verification, o.identity_status) == (
        "tier1_phone", "pending_identity", "queued_manual_review")
    assert o.reason_detail and "minor" in o.reason_detail.lower()
    assert "Child" not in json.dumps(o.reason_detail)   # masking: names never leak
    # not verified -> stays tier1 with explicit status
    o = iv.map_result({"verified": False, "identities": [], "warnings": ["x"]},
                      email="n@sovereign.mail")
    assert (o.tier, o.identity_status) == ("tier1_phone", "auto_check_not_verified")


def test_outcome_for_mode_off():
    o = iv.outcome_for_mode("off")
    assert o.tier == "tier1_phone"
    assert o.identity_status == "identity_checks_off"
```

Run: `cd api && .venv/bin/python -m pytest tests/test_idverify.py -v`
Expected: FAIL — ModuleNotFoundError.

- [ ] **Step 3: Extend api/app/services/idverify.py**

Full final module contents (supersedes the Task-4 seed; `IdentityOutcome` is unchanged):

```python
"""AUTO identity verification: subprocess runner over the frozen contract (§10).

Contract rules enforced HERE so a misbehaving verifier can never confuse the
signup router: well-formed-but-false is a RESULT; anything structurally wrong
(timeout, exit!=0, bad JSON, wrong contract_version) is IdverifyInfraError and
maps to the soft-fallback path upstream.
"""
import json
import logging
import subprocess
from dataclasses import dataclass

from ..config import get_settings

log = logging.getLogger(__name__)

CONTRACT_VERSION = 1


class IdverifyInfraError(Exception):
    pass


@dataclass
class IdentityOutcome:
    tier: str                    # tier1_phone | tier2_identity
    verification: str            # pending_identity | auto_verified | manual_pending...
    identity_status: str | None  # extra field for the /signup/complete body
    reason_detail: str | None


def run_auto_check(payload: dict) -> dict:
    s = get_settings()
    try:
        r = subprocess.run([s.idverify_script],
                           input=json.dumps(payload), capture_output=True,
                           text=True, timeout=s.idverify_timeout_seconds)
    except subprocess.TimeoutExpired as e:
        raise IdverifyInfraError(
            f"idverify timed out after {s.idverify_timeout_seconds}s") from e
    except OSError as e:
        raise IdverifyInfraError(f"idverify not executable: {e}") from e
    if r.returncode != 0:
        raise IdverifyInfraError(f"idverify exit {r.returncode}")
    try:
        out = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        raise IdverifyInfraError("idverify stdout was not JSON") from e
    if out.get("contract_version") != CONTRACT_VERSION:
        raise IdverifyInfraError("idverify contract_version mismatch")
    return out


def map_result(result: dict, *, email: str) -> IdentityOutcome:
    """Tri-state mapping per §10.2. Multi-identity payloads are summarized with
    COUNTS ONLY — names/types/masked numbers never leave this function."""
    ids = result.get("identities", [])
    if result.get("verified") and len(ids) == 1 and not ids[0].get("is_minor"):
        return IdentityOutcome("tier2_identity", "auto_verified", None, None)
    if result.get("verified"):
        minors = sum(1 for i in ids if i.get("is_minor"))
        adults = len(ids) - minors
        return IdentityOutcome(
            "tier1_phone", "pending_identity", "queued_manual_review",
            f"document carries {adults} adult and {minors} minor "
            "identit(y/ies) — routed to manual review")
    warn = ", ".join(str(w) for w in result.get("warnings", [])) or "unspecified"
    return IdentityOutcome("tier1_phone", "pending_identity",
                           "auto_check_not_verified", f"verifier said no ({warn})")


def outcome_for_mode(mode: str, choice: dict | None = None,
                     payload_email: str = "") -> IdentityOutcome:
    """Entry point used by the signup router (Task 7 wires AUTO/MANUAL through)."""
    if mode == "off":
        return IdentityOutcome(
            "tier1_phone", "pending_identity", "identity_checks_off",
            "ID submission disabled in this deployment (IDVERIFY_MODE=off)")
    raise NotImplementedError("Task 7 completes AUTO/MANUAL dispatch")
```

Also update the stub `_run_identity_step` in `api/app/routers/signup_router.py` to delegate:

```python
def _run_identity_step(choice: dict, payload: dict) -> IdentityOutcome:
    """Task 6 lands off-mode; Task 7 completes AUTO/MANUAL. Never raises
    user-facing 5xx: infra trouble becomes the soft-fallback union member."""
    from ..services.idverify import outcome_for_mode
    return outcome_for_mode(get_settings().idverify_mode, choice,
                            payload.get("email", ""))
```

This replaces Task 4's stub `_run_identity_step` wholesale (its `HTTPException(500, ...)` placeholder body goes away).

- [ ] **Step 4: Green**

Run: `cd api && .venv/bin/python -m pytest tests/test_idverify.py tests/test_signup_router.py -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/mock-idverify.sh api/app/services/idverify.py api/tests/test_idverify.py api/app/routers/signup_router.py
git commit -m "feat: frozen-contract idverify runner + tri-state mapping + mock verifier"
```

### Task 7: AUTO/MANUAL wiring into signup (choose-identity path)

**Files:**
- Modify: `api/app/services/idverify.py` (complete `outcome_for_mode`), `api/app/routers/signup_router.py` (pass choice through)
- Test: `api/tests/test_signup_router.py` (add cases)

**Interfaces:**
- Consumes: `idverify.run_auto_check/map_result`, `db.execute` (manual queue insert), `notifications.enqueue` — NOT YET (lands T11): manual-review INSERT goes straight to `verification_reviews` here; notification fan-out attaches in Task 11.
- Completes: `outcome_for_mode(mode, choice, email)` where `choice` may be `{"kind":"submit_id","full_name":...,"document_type":...,"id_number":...,"consent_selfie":true}`.

Behavior table (spec §8.4 × §10):

| IDVERIFY_MODE | submit_id path | skip path |
|---|---|---|
| `off` | soft-fallback union `identity_checks_off` | plain tier1 |
| `auto` | run mock → tri-state map | plain tier1 |
| `manual` | enqueue `policy_manual`, union `queued_manual_review` | plain tier1 |
| any + `IdverifyInfraError` | enqueue `auto_script_error`, union `auto_check_unavailable` | plain tier1 |

- [ ] **Step 1: Failing tests (append to tests/test_signup_router.py)**

```python
def _submit_id_choice():
    return {"kind": "submit_id", "full_name": "New User",
            "document_type": "national_id", "id_number": "AB1234567",
            "consent_selfie": True}


def test_auto_mode_verified_upgrades_tier(w, monkeypatch):
    monkeypatch.setattr(sr_settings(), "idverify_mode", "auto")

    def fake_run(payload):
        return {"contract_version": 1, "verified": True,
                "identities": [{"is_minor": False, "name": payload["full_name"],
                                "type": payload["document_type"],
                                "number_masked": "••••9999"}], "warnings": []}
    monkeypatch.setattr(idverify_mod(), "run_auto_check", fake_run)
    tok = _start(w)
    w["client"].post("/signup/verify-otp", json={"token": tok, "code": "123456"})
    r = w["client"].post("/signup/complete",
                         json={"token": tok, "choice": _submit_id_choice(),
                               "password": "long-enough-password-1"})
    b = r.json()
    assert r.status_code == 201
    assert (b["tier"], b["verification"]) == ("tier2_identity", "auto_verified")
    assert "identity_status" not in b
    # raw id number never persisted anywhere reachable:
    import json as j
    blob = j.dumps(w["sessions"])
    assert "AB1234567" not in blob


def test_manual_mode_queues_review_and_stays_tier1(w, monkeypatch):
    monkeypatch.setattr(sr_settings(), "idverify_mode", "manual")
    tok = _start(w)
    w["client"].post("/signup/verify-otp", json={"token": tok, "code": "123456"})
    r = w["client"].post("/signup/complete",
                         json={"token": tok, "choice": _submit_id_choice(),
                               "password": "long-enough-password-1"})
    b = r.json()
    assert r.status_code == 201
    assert (b["tier"], b["verification"]) == ("tier1_phone", "pending_identity")
    assert b["identity_status"] == "queued_manual_review"


def test_infra_failure_soft_fallback_queues_script_error(w, monkeypatch):
    monkeypatch.setattr(sr_settings(), "idverify_mode", "auto")
    def boom(payload):
        raise idverify_mod().IdverifyInfraError("script missing")
    monkeypatch.setattr(idverify_mod(), "run_auto_check", boom)
    tok = _start(w)
    w["client"].post("/signup/verify-otp", json={"token": tok, "code": "123456"})
    r = w["client"].post("/signup/complete",
                         json={"token": tok, "choice": _submit_id_choice(),
                               "password": "long-enough-password-1"})
    b = r.json()
    assert r.status_code == 201                      # invariant: complete NEVER fails post-OTP
    assert b["identity_status"] == "auto_check_unavailable"
    assert b["tier"] == "tier1_phone"
    # and a verification_reviews row was queued with reason auto_script_error:
    assert [r["reason"] for r in w["reviews"]] == ["auto_script_error"]


# small helpers used above; put them at module bottom of the test file
def sr_settings():
    import app.routers.signup_router as m
    return m.get_settings()


def idverify_mod():
    from app.services import idverify
    return idverify
```

Run: expected FAIL (mode plumbing missing).

- [ ] **Step 2: Implement**

In `api/app/services/idverify.py`, replace `outcome_for_mode`'s tail:

```python
def outcome_for_mode(mode: str, choice: dict | None = None,
                     payload_email: str = "") -> IdentityOutcome:
    if mode == "off":
        return IdentityOutcome(
            "tier1_phone", "pending_identity", "identity_checks_off",
            "ID submission disabled in this deployment (IDVERIFY_MODE=off)")
    choice = choice or {}
    payload = {"contract_version": CONTRACT_VERSION,
               "full_name": choice.get("full_name", ""),
               "document_type": choice.get("document_type", ""),
               "id_number": choice.get("id_number", ""),
               "consent_selfie": bool(choice.get("consent_selfie"))}
    if mode == "manual":
        _enqueue_review(payload_email, payload, reason="policy_manual",
                        detail="deployment runs manual-only verification")
        return IdentityOutcome("tier1_phone", "pending_identity",
                               "queued_manual_review",
                               "an operator will review your submission")
    assert mode == "auto", f"unknown idverify mode {mode!r}"
    try:
        result = run_auto_check(payload)
    except IdverifyInfraError as e:
        log.warning("idverify infra failure for %s: %s", payload_email, e)
        _enqueue_review(payload_email, payload, reason="auto_script_error",
                        detail=str(e))
        return IdentityOutcome("tier1_phone", "pending_identity",
                               "auto_check_unavailable",
                               "automatic verification is having trouble; "
                               "your submission was queued for review")
    return map_result(result, email=payload_email)


def _enqueue_review(email: str, payload: dict, *, reason: str,
                    detail: str) -> None:
    from ..db import execute
    execute("""INSERT INTO verification_reviews
               (email, payload_json, status, reason, error_detail)
               VALUES (%s, %s::jsonb, 'pending', %s, %s)""",
            (email, json.dumps(payload), reason, detail))

```

Extend the signup test file's `world()` fixture (add BEFORE the `return {...}` line):

```python
    reviews: list[dict] = []
    monkeypatch.setattr(idverify_mod(), "_enqueue_review",
                        lambda email, payload, *, reason, detail:
                        reviews.append({"email": email, "status": "pending",
                                        "reason": reason,
                                        "error_detail": detail}))
```

…and change the fixture's return statement to include the new key:

```python
    return {"client": TestClient(create_app()), "sessions": sessions,
            "ldap_created": ldap_created, "otp_sent": otp_sent, "sql": sql,
            "reviews": reviews}
```
(No DB locally — `_enqueue_review` is the only queue seam these tests need.)

- [ ] **Step 3: Green**

Run: `cd api && .venv/bin/python -m pytest -q`
Expected: full suite PASS.

- [ ] **Step 4: Commit**

```bash
git add api/app/services/idverify.py api/app/routers/signup_router.py api/tests/test_signup_router.py
git commit -m "feat: auto/manual idverify dispatch with soft-fallback queueing"
```

### Task 8: Admin RBAC — realm role, dual-mode dependency, cookie sessions

**Files:**
- Modify: `scripts/seed-keycloak.sh` (append role creation + assignment), `api/app/main.py` (include admin router)
- Create: `api/app/routers/admin_router.py` (auth half only: `/admin/login`, `/admin/callback`, `/admin/logout`; dependency + session store)
- Test: `api/tests/test_admin_dashboard.py` (auth half)

**Interfaces:**
- Consumes: existing `keycloak.get_discovery/build_authorize_url/exchange_code/LoginStateStore` (unchanged, reused verbatim); `auth.JWTVerifier.verify` via `get_verifier()`; `Settings.allowed_redirect_uris` (`http://localhost:*/*` already matches `/admin/callback`).
- Produces:
  - `require_admin(request) -> dict` FastAPI dependency. Bearer path: verify token, require `realm_access.roles ∋ "sovereign-admin"` else 403. Cookie path: `admin_session` cookie → in-memory `_SESSIONS[sid]` → claims; missing/expired → 403 for HTML routes / 401 JSON elsewhere.
  - `csrf_token_for(sid:str)->str`, `check_csrf(request, form_field:str)->None` (raises 403 on mismatch).
  - Endpoints: `GET /admin/login` → 302 Keycloak authorize (redirect_uri `{kc_frontend_url}/admin/callback`); `GET /admin/callback` → exchange → verify → role check → mint `sid = secrets.token_urlsafe(32)`, set cookie `HttpOnly; SameSite=Lax; Path=/admin` → 302 `/admin`; `GET /admin/logout` → drop session, clear cookie.
  - Realm role `sovereign-admin` assigned to `$SOVEREIGN_ADMIN_USER`.

- [ ] **Step 1: Append to scripts/seed-keycloak.sh** (idempotent — reuses the script's `$KCADM` pattern)

```bash
# --- sovereign-admin dashboard role (identity-auth-flow spec §11) -------------
$KCADM create roles -r "$KC_REALM" -s name=sovereign-admin \
  -s 'description=Admin dashboard access' >/dev/null || echo "role exists"
ADMIN_UID=$($KCADM get users -r "$KC_REALM" -q username="$SOVEREIGN_ADMIN_USER" \
  --fields id --format csv --noquotes | tail -1)
if [ -n "${ADMIN_UID}" ] && [ "${ADMIN_UID}" != "id" ]; then
  $KCADM add-users -r "$KC_REALM" --rname sovereign-admin "${ADMIN_UID}" >/dev/null 2>&1 \
    || $KCADM update "users/${ADMIN_UID}/role-mappings/realm" -r "$KC_REALM" \
         -z "sovereign-admin" 2>/dev/null \
    || echo "role mapping present or user pending first LDAP login"
else
  echo "NOTE: ${SOVEREIGN_ADMIN_USER} not yet imported from LDAP; run this seed again after their first login"
fi
```

- [ ] **Step 2: Failing tests**

```python
"""Admin auth: bearer-role gate + opaque cookie sessions + CSRF."""
import base64
import json

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

def _token(roles):
    payload = {"exp": 4102444800, "iss": "http://localhost:8080/realms/sovereign",
               "aud": "sovereign-mail-api", "sub": "admin-1",
               "email": "admin@sovereign.mail",
               "realm_access": {"roles": roles}}
    return "header." + base64.urlsafe_b64encode(
        json.dumps(payload).encode()).decode().rstrip("=")


ROLE_TOKEN = _token(["sovereign-admin"])
NO_ROLE_TOKEN = _token(["offline_access"])


@pytest.fixture
def world(monkeypatch):
    sessions: dict[str, dict] = {}
    states: dict[str, dict] = {}

    import app.routers.admin_router as ar
    monkeypatch.setattr(ar, "_sessions", sessions)
    monkeypatch.setattr(ar._login_states, "put", lambda s, d: states.update({s: d}))
    monkeypatch.setattr(ar._login_states, "pop", lambda s: states.pop(s, None))

    def fake_verify(token):
        assert token in (ROLE_TOKEN, NO_ROLE_TOKEN)
        return json.loads(base64.urlsafe_b64decode(
            token.split(".")[1] + "==").decode())
    monkeypatch.setattr(ar, "_verify", fake_verify)

    def fake_exchange(discovery, code, state_data):
        return {"access_token": ROLE_TOKEN if code == "good"
                else NO_ROLE_TOKEN}
    monkeypatch.setattr(ar.kc, "exchange_code", fake_exchange)

    def fake_authorize(discovery, redirect_uri, state, nonce, challenge):
        return f"http://kc/authorize?state={state}"
    monkeypatch.setattr(ar.kc, "build_authorize_url", fake_authorize)

    return {"client": TestClient(create_app()), "sessions": sessions}


def test_login_redirects_to_keycloak(world):
    r = world["client"].get("/admin/login", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"].startswith("http://kc/authorize")


def test_callback_good_role_sets_session_cookie(world):
    r = world["client"].get("/admin/login", follow_redirects=False)
    state = r.headers["location"].split("state=")[1]
    r2 = world["client"].get(f"/admin/callback?code=good&state={state}",
                             follow_redirects=False)
    assert r2.status_code == 302 and r2.headers["location"] == "/admin"
    cookie = r2.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie.lower()
    sid = cookie.split("admin_session=")[1].split(";")[0]
    assert sid in world["sessions"]
    # single-use state consumed:
    assert world["client"].get(
        f"/admin/callback?code=good&state={state}",
        follow_redirects=False).status_code == 400


def test_callback_without_role_is_403_no_cookie(world):
    r = world["client"].get("/admin/login", follow_redirects=False)
    state = r.headers["location"].split("state=")[1]
    r2 = world["client"].get(f"/admin/callback?code=norole&state={state}",
                             follow_redirects=False)
    assert r2.status_code == 403
    assert "admin_session" not in r2.headers.get("set-cookie", "")


def test_require_admin_bearer_path(world):
    ok = world["client"].get("/admin/api/reviews",
                             headers={"Authorization": f"Bearer {ROLE_TOKEN}"})
    assert ok.status_code != 403          # route lands in Task 9; not a 403-at-gate
    bad = world["client"].get("/admin/api/reviews",
                              headers={"Authorization": f"Bearer {NO_ROLE_TOKEN}"})
    assert bad.status_code == 403


```

Run: FAIL — no module.

- [ ] **Step 3: Implement admin_router.py (auth half)**

```python
"""Admin dashboard plumbing (spec §11): PKCE entry, opaque cookie sessions,
CSRF-guarded HTML posts, plus a bearer path for scripted checks.

Session model is deliberately the SAME in-memory shape as keycloak.LoginStateStore
(register #5 covers the Redis move when we scale past one replica).
"""
import secrets
import time

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse

from .. import keycloak as kc
from ..auth import get_verifier
from ..config import get_settings

router = APIRouter(prefix="/admin", tags=["admin"])

_sessions: dict[str, dict] = {}        # sid -> {claims, csrf, t}
_login_states = kc.LoginStateStore(ttl_seconds=600)

ADMIN_SESSION_TTL_SECONDS = 3600
ADMIN_COOKIE = "admin_session"


def _verify(token: str) -> dict:       # module-level so tests can swap
    return get_verifier().verify(token)


def _has_admin_role(claims: dict) -> bool:
    return "sovereign-admin" in (
        (claims or {}).get("realm_access", {}) or {}).get("roles", [])


def _session_from_cookie(request: Request) -> dict | None:
    sid = request.cookies.get(ADMIN_COOKIE)
    s = _sessions.get(sid or "")
    if not s or time.time() - s["t"] > ADMIN_SESSION_TTL_SECONDS:
        return None
    return s | {"sid": sid}


def require_admin(request: Request) -> dict:
    """Dual-mode gate. Bearer wins when present (scripted/API use); otherwise
    the browser cookie session must exist. Both paths demand the realm role."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            claims = _verify(auth.removeprefix("Bearer ").strip())
        except kc.KeycloakUnavailable as e:
            raise HTTPException(503, str(e))
        except Exception as e:                      # AuthError etc.
            raise HTTPException(401, f"invalid admin token: {e}")
        if not _has_admin_role(claims):
            raise HTTPException(403, "sovereign-admin role required")
        return claims
    sess = _session_from_cookie(request)
    if not sess or not _has_admin_role(sess["claims"]):
        raise HTTPException(403, "admin session required")
    return sess["claims"]


def csrf_token_for(sid: str) -> str:
    return _sessions[sid]["csrf"]


def check_csrf(request: Request, form_field_value: str | None) -> None:
    sess = _session_from_cookie(request)
    if not sess or not form_field_value or form_field_value != sess["csrf"]:
        raise HTTPException(403, "bad CSRF token")


@router.get("/login")
def admin_login():
    s = get_settings()
    discovery = kc.get_discovery()
    state, nonce = secrets.token_urlsafe(16), secrets.token_urlsafe(16)
    verifier_plain = secrets.token_urlsafe(32)
    import base64, hashlib
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier_plain.encode()).digest()).rstrip(b"=").decode()
    redirect_uri = f"{s.kc_frontend_url}/admin/callback"
    _login_states.put(state, {"redirect_uri": redirect_uri,
                              "verifier": verifier_plain, "nonce": nonce})
    return RedirectResponse(
        kc.build_authorize_url(discovery, redirect_uri, state, nonce, challenge),
        status_code=302)




@router.get("/callback")
def admin_callback(code: str = "", state: str = ""):
    st = _login_states.pop(state)
    if not st:
        raise HTTPException(400, "unknown or expired login state")
    s = get_settings()
    discovery = kc.get_discovery()
    tokens = kc.exchange_code(discovery, code, st)
    try:
        claims = _verify(tokens["access_token"])
    except Exception as e:
        raise HTTPException(401, f"token validation failed: {e}")
    if not _has_admin_role(claims):
        raise HTTPException(403, "your account lacks the sovereign-admin role")
    sid = secrets.token_urlsafe(32)
    _sessions[sid] = {"claims": claims, "csrf": secrets.token_urlsafe(24),
                      "t": time.time()}
    resp = RedirectResponse("/admin", status_code=302)
    resp.set_cookie(ADMIN_COOKIE, sid, httponly=True, samesite="lax",
                    path="/", max_age=ADMIN_SESSION_TTL_SECONDS)
    return resp


@router.get("/logout")
def admin_logout(request: Request):
    sid = request.cookies.get(ADMIN_COOKIE)
    _sessions.pop(sid or "", None)
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(ADMIN_COOKIE, path="/")
    return resp
```
Modify `main.py`: include `admin_router` beside the others (Task 9 adds the HTML routes to the same router).

Also note for the implementer: `KeycloakUnavailable` is NOT an `AuthError` subclass — the bearer branch catches it FIRST so a KC blip surfaces as 503, matching §18.

- [ ] **Step 4: Green**

Run: `cd api && .venv/bin/python -m pytest tests/test_admin_dashboard.py -v`
Expected: 4 PASS. (The `/admin/api/reviews` probes hit a not-yet-existing route at this point: 404 satisfies `!= 403` for the role-carrying token, and the no-role token still trips the gate with 401/403 — exactly what this task proves. Task 9 turns the first probe into a real 200.)

- [ ] **Step 5: Commit**

```bash
git add scripts/seed-keycloak.sh api/app/routers/admin_router.py api/app/main.py api/tests/test_admin_dashboard.py
git commit -m "feat: sovereign-admin realm role, dual-mode admin gate, cookie sessions"
```

### Task 9: Reviews queue + Jinja2 dashboard pages

**Files:**
- Create: `api/templates/admin/{base,reviews,review_detail}.html`, `api/static/admin.css`
- Modify: `api/app/routers/admin_router.py` (queue/pages/actions), `api/app/services/idverify.py` (add `list_pending/get_review/decide_review`)
- Test: `api/tests/test_admin_dashboard.py` (append page/action cases)

**Interfaces:**
- Consumes: `require_admin`, `csrf_token_for/check_csrf` from Task 8.
- Produces (service): `list_pending()->list[dict]`, `get_review(review_id:int)->dict|None`, `decide_review(review_id:int, decision:str, reviewer:str)->bool` (sets status approved|rejected, reviewed_by, decided_at; approve ALSO promotes the account row: `tier='tier2_identity', verification='manual_verified', id_source='manual'`).
- Produces (routes):
  - `GET /admin` → reviews list page (pending queue, newest first, masked summary columns: email, reason, created_at)
  - `GET /admin/reviews/{id}` → detail page showing ONLY masked payload fields (§10.2: counts, document type, masked number) + approve/reject buttons carrying the CSRF token
  - `POST /admin/reviews/{id}/decide` (form: decision, csrf) → 303 back to `/admin`
  - `GET /admin/api/reviews` → JSON queue (bearer path, for smoke asserts)

- [ ] **Step 1: Failing tests (append)**

```python
def _login(world):
    r = world["client"].get("/admin/login", follow_redirects=False)
    state = r.headers["location"].split("state=")[1]
    cb = world["client"].get(f"/admin/callback?code=good&state={state}",
                             follow_redirects=False)
    sid = cb.headers["set-cookie"].split("admin_session=")[1].split(";")[0]
    return sid, world["sessions"][sid]["csrf"]


def _login(world):
    r = world["client"].get("/admin/login", follow_redirects=False)
    state = r.headers["location"].split("state=")[1]
    cb = world["client"].get(f"/admin/callback?code=good&state={state}",
                             follow_redirects=False)
    sid = cb.headers["set-cookie"].split("admin_session=")[1].split(";")[0]
    return sid, world["sessions"][sid]["csrf"]


def test_csrf_required_for_html_posts(world):
    """(Relocated here from Task 8 — the decide ROUTE must exist to observe 403.)"""
    sid, csrf = _login(world)
    r = world["client"].post("/admin/reviews/1/decide",
                             data={"decision": "approve"},
                             cookies={"admin_session": sid})
    assert r.status_code == 403
    r2 = world["client"].post("/admin/reviews/1/decide",
                              data={"decision": "approve", "csrf": csrf},
                              cookies={"admin_session": sid})
    assert r2.status_code != 403


@pytest.fixture
def queue(monkeypatch):
    """In-memory stand-in for the review service storage."""
    rows = [{"review_id": 7, "email": "fam@sovereign.mail",
             "reason": "policy_manual", "status": "pending",
             "error_detail": None,
             "payload_masked": {"document_type": "national_id",
                                "identities_adult": 1, "identities_minor": 2},
             "created_at": "2026-08-25T10:00:00Z"}]

    import app.services.idverify as iv
    monkeypatch.setattr(iv, "list_pending", lambda: rows)
    monkeypatch.setattr(iv, "get_review",
                        lambda rid: next((r for r in rows
                                          if r["review_id"] == rid), None))
    def decide(rid, decision, reviewer):
        for r in rows:
            if r["review_id"] == rid and r["status"] == "pending":
                r["status"] = decision
                r["reviewed_by"] = reviewer
                return True
        return False
    monkeypatch.setattr(iv, "decide_review", decide)
    return rows


def test_queue_page_lists_pending_with_masks(world, queue):
    sid, _ = _login(world)
    html = world["client"].get("/admin", cookies={"admin_session": sid}).text
    assert "fam@sovereign.mail" in html and "policy_manual" in html
    assert "AB1234567" not in html          # raw numbers never reach templates


def test_decide_requires_csrf_then_flips_status(world, queue):
    sid, csrf = _login(world)
    r = world["client"].post("/admin/reviews/7/decide",
                             data={"decision": "approved"},
                             cookies={"admin_session": sid}, follow_redirects=False)
    assert r.status_code == 403
    r2 = world["client"].post("/admin/reviews/7/decide",
                              data={"decision": "approved", "csrf": csrf},
                              cookies={"admin_session": sid}, follow_redirects=False)
    assert r2.status_code == 303
    assert queue[0]["status"] == "approved"


def test_json_api_bearer_path(world, queue):
    r = world["client"].get("/admin/api/reviews",
                            headers={"Authorization": f"Bearer {ROLE_TOKEN}"})
    assert r.status_code == 200
    body = r.json()
    assert body["reviews"][0]["email"] == "fam@sovereign.mail"
    # masked columns ONLY — §10.2 forbids payload passthrough:
    assert set(body["reviews"][0]) <= {
        "review_id", "email", "reason", "status", "error_detail",
        "document_type", "identities_count", "created_at"}
```

Run: expected FAIL (routes don't render).

- [ ] **Step 2: Implement service functions** — append to `api/app/services/idverify.py`:

```python
# --- manual-review queue ------------------------------------------------------

_MASKED_COLUMNS = """review_id, email, reason, status, error_detail,
    payload_json->'document_type' AS document_type,
    COALESCE(jsonb_array_length(payload_json->'identities'), 0) AS identities_count,
    created_at"""


def list_pending() -> list[dict]:
    from ..db import many
    return many(f"""SELECT {_MASKED_COLUMNS} FROM verification_reviews
                    WHERE status='pending' ORDER BY created_at DESC""")


def get_review(review_id: int) -> dict | None:
    from ..db import one
    return one(f"SELECT {_MASKED_COLUMNS} FROM verification_reviews "
               "WHERE review_id=%s", (review_id,))


def decide_review(review_id: int, decision: str, reviewer: str) -> bool:
    if decision not in ("approved", "rejected"):
        raise ValueError(decision)
    from ..db import execute, one
    r = one("SELECT email FROM verification_reviews WHERE review_id=%s AND "
            "status='pending'", (review_id,))
    if not r:
        return False
    execute("""UPDATE verification_reviews
               SET status=%s, reviewed_by=%s, decided_at=now()
               WHERE review_id=%s""", (decision, reviewer, review_id))
    if decision == "approved":
        execute("""UPDATE accounts SET tier='tier2_identity',
                     verification='manual_verified', id_source='manual',
                     updated_at=now() WHERE email=%s""", (r["email"],))
    return True
```

Note the masking guarantee: SQL selects only `document_type` + identity COUNTS from `payload_json`; full payload never leaves the table toward templates.

- [ ] **Step 3: Implement routes + templates**

Append to `admin_router.py`:

```python
from pathlib import Path

from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from ..services import idverify as idv

_templates = Jinja2Templates(
    directory=str(Path(__file__).resolve().parents[2] / "templates"))


def _page(request: Request, name: str, **ctx) -> HTMLResponse:
    sess = _session_from_cookie(request)
    ctx |= {"csrf": sess["csrf"], "claims_email":
            (sess["claims"].get("email") if sess else "")}
    return _templates.TemplateResponse(request, name, ctx)


@router.get("", response_class=HTMLResponse)
@router.get("/", response_class=HTMLResponse)
def admin_home(request: Request):
    sess = _session_from_cookie(request)
    if not sess:
        return RedirectResponse("/admin/login", status_code=302)
    return _page(request, "admin/reviews.html", reviews=idv.list_pending())


@router.get("/reviews/{review_id}", response_class=HTMLResponse)
def review_detail(request: Request, review_id: int):
    sess = _session_from_cookie(request)
    if not sess:
        return RedirectResponse("/admin/login", status_code=302)
    rev = idv.get_review(review_id)
    if not rev:
        raise HTTPException(404, "no such review")
    return _page(request, "admin/review_detail.html", review=rev)


@router.post("/reviews/{review_id}/decide")
async def review_decide(request: Request, review_id: int):
    sess = _session_from_cookie(request)
    if not sess:
        return RedirectResponse("/admin/login", status_code=302)
    form = await request.form()
    check_csrf(request, form.get("csrf"))
    idv.decide_review(review_id, form.get("decision", ""), sess["claims"]["email"])
    return RedirectResponse("/admin", status_code=303)


@router.get("/api/reviews")
def api_reviews(claims: dict = Depends(require_admin)):
    return {"reviews": idv.list_pending()}


@router.post("/api/reviews/{review_id}/approve")
def api_approve(review_id: int, claims: dict = Depends(require_admin)):
    """Scripted-approval path used by smoke-test; HTML flow stays CSRF-guarded."""
    if not idv.decide_review(review_id, "approved", claims["email"]):
        raise HTTPException(404, "no pending review with that id")
    return {"ok": True}
```

(`from fastapi import Depends` at top; `require_admin` used directly as dependency for the JSON route.)

`api/templates/admin/base.html`:

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Sovereign Mail — Admin</title>
  <link rel="stylesheet" href="/static/admin.css">
</head>
<body>
  <header><h1>Sovereign Mail Admin</h1>
    {% if claims_email %}<span class="who">{{ claims_email }}</span>{% endif %}
  </header>
  <main>{% block content %}{% endblock %}</main>
</body>
</html>
```

`api/templates/admin/reviews.html`:

```html
{% extends "admin/base.html" %}
{% block content %}
<h2>Identity reviews awaiting decision</h2>
{% if not reviews %}<p>Queue empty.</p>{% endif %}
<table>
  <tr><th>ID</th><th>Email</th><th>Reason</th><th>Doc type</th><th>Identities</th><th>Created</th></tr>
  {% for r in reviews %}
  <tr>
    <td><a href="/admin/reviews/{{ r.review_id }}">{{ r.review_id }}</a></td>
    <td>{{ r.email }}</td><td>{{ r.reason }}</td>
    <td>{{ r.document_type }}</td><td>{{ r.identities_count }}</td>
    <td>{{ r.created_at }}</td>
  </tr>
  {% endfor %}
</table>
{% endblock %}
```

`api/templates/admin/review_detail.html`:

```html
{% extends "admin/base.html" %}
{% block content %}
<h2>Review {{ review.review_id }} — {{ review.email }}</h2>
<p>Reason: <b>{{ review.reason }}</b>
   {% if review.error_detail %}(detail: {{ review.error_detail }}){% endif %}</p>
<p>Document type: {{ review.document_type }} · Identities: {{ review.identities_count }}</p>
{% if review.status == 'pending' %}
<form method="post" action="/admin/reviews/{{ review.review_id }}/decide">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <button name="decision" value="approved">Approve Tier 2</button>
  <button name="decision" value="rejected">Reject</button>
</form>
{% else %}<p>Decision: <b>{{ review.status }}</b> by {{ review.reviewed_by }}
           at {{ review.decided_at }}</p>{% endif %}
<p><a href="/admin">← back to queue</a></p>
{% endblock %}
```

`api/static/admin.css` — plain system-font table styling, ~30 lines; content free-form but MUST set `table{border-collapse:collapse}` and readable cell padding. Wire static files in `create_app`: `from fastapi.staticfiles import StaticFiles` + `app.mount("/static", StaticFiles(directory=<repo>/static), name="static")`.

- [ ] **Step 4: Green**

Run: `cd api && .venv/bin/python -m pytest tests/test_admin_dashboard.py -v && .venv/bin/python -m pytest -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add api/templates/admin/base.html api/templates/admin/reviews.html api/templates/admin/review_detail.html api/static/admin.css api/app/routers/admin_router.py api/app/services/idverify.py api/tests/test_admin_dashboard.py api/app/main.py
git commit -m "feat: server-rendered admin review queue with masked payloads + csrf actions"
```

### Task 10: WAVE B LIVE GATE (codespace, Docker)

- [ ] **Step 1: Push local → pull codespace → rebuild** (same ritual as Task 5 Step 1–2; also `scripts/db-migrate.sh` no-op check)

- [ ] **Step 2: Seed role + prove RBAC**

```bash
source .env
scripts/seed-keycloak.sh                 # appends sovereign-admin role
docker compose restart api               # pick up new env if any changed
# bearer probe with a real admin token obtained through /login+PKCE helper:
curl -s localhost:8000/admin/api/reviews -H "Authorization: Bearer $ADMIN_TOKEN"
curl -si localhost:8000/admin/api/reviews -H "Authorization: Bearer $USER_TOKEN" | head -1   # 403
curl -si localhost:8000/admin | head -1                                                       # 302 -> /admin/login
```
Expected: admin sees `{"reviews":[...]}` (or seeded rows), non-admin gets 403 JSON, anonymous browser gets the redirect.

- [ ] **Step 3: Browserless dashboard round-trip**

Using the repo's existing PKCE login helper (smoke-test machinery) as `$SOVEREIGN_ADMIN_USER`: complete TOTP, then drive `GET /admin/login` → follow authorize URL → TOTP-consent POST → land `/admin/callback` → confirm cookie set → `GET /admin` returns the queue page HTML containing `<h1>Sovereign Mail Admin</h1>`.

- [ ] **Step 4: MANUAL mode live proof**

Set `IDVERIFY_MODE=manual` in `.env`, `docker compose up -d api`, run one signup with `choice.kind=submit_id`, confirm: response body has `identity_status: queued_manual_review`, queue page shows the row, Approve flips accounts.tier to `tier2_identity`/`verification manual_verified` (psql check). Revert `.env`.

---

## WAVE C — family + recovery + devices + smoke (Tasks 11–16)

### Task 11: Notifications service + account endpoints

**Files:**
- Create: `api/app/services/notifications.py`, `api/app/routers/account_router.py`
- Modify: `api/app/main.py` (include account router)
- Test: `api/tests/test_notifications.py`

**Interfaces:**
- Produces (`notifications`):
  - `notify(email:str, type:str, body:str)->dict` — inserts the in-app row (source of truth) and returns it
  - `fan_out_email(to_email:str, subject:str, body_text:str)->None` — reuses `smtp_client.build_mime` + `submit_message`; envelope From is `noreply@<mail_domain>`; raises NOTHING (best-effort, failures logged — email is a POINTER copy, the in-app row already exists)
  - `send_sms_alert(phone:str, body:str)->bool` — delegates to the configured provider's `send_sms` (recovery alerts only, spec §9 channel rule)
  - `list_for(email:str, limit:int=50)->list[dict]`
  - `mark_read(email:str, notif_id:int)->None`
- Endpoints: `GET /account/notifications`, `POST /account/notifications/{id}/read`, `GET /account/profile` (merged view: accounts row fields minus none — it's the user's own row), all behind `get_current_user` and scoped to the JWT email.

- [ ] **Step 1: Failing tests**

```python
"""Notifications: in-app rows are authoritative; email fan-out is best-effort."""
import pytest

from app.services import notifications as nf


@pytest.fixture
def rows(monkeypatch):
    store = []

    monkeypatch.setattr(nf, "_insert", lambda r: store.append(r) or r)
    monkeypatch.setattr(nf, "_fetch", lambda email, limit:
                        [r for r in store if r["email"] == email][-limit:])
    sent = []
    monkeypatch.setattr(nf, "_submit_mime",
                        lambda msg, rcpts: sent.append(rcpts) or (
                            (_ for _ in ()).throw(RuntimeError("smtp down"))
                            if len(sent) == 2 else None))
    return {"store": store, "sent": sent}


def test_notify_inserts_in_app_row(rows):
    n = nf.notify("a@sovereign.mail", "family_request_received",
                  "Someone requested to link with you. Open your app to review.")
    assert n["email"] == "a@sovereign.mail" and n["read_at"] is None


def test_fan_out_email_survives_smtp_failure(rows):
    nf.fan_out_email("a@sovereign.mail", "Sovereign Mail: new family request",
                     "Open your Sovereign Mail app to review this request.")
    # first send OK; force a second that raises inside _submit_mime
    try:
        nf.fan_out_email("a@sovereign.mail", "again", "body")
    except RuntimeError:
        raise AssertionError("email fan-out must never propagate failures")


def test_pointer_emails_carry_no_links(rows):
    captured = {}
    def fake_build(**kw):
        captured.update(kw)
        class M: pass
        return M()
    import app.smtp_client as sc
    orig = nf._build_mime
    nf._build_mime = fake_build          # noqa: deliberate direct swap for capture
    try:
        nf.fan_out_email("a@sovereign.mail", "subject", "text body")
    finally:
        nf._build_mime = orig
    assert "http" not in captured["text"].lower()
    assert captured["from_"].startswith("noreply@")
```

Run: FAIL — no module.

- [ ] **Step 2: Implement**

```python
"""Notification fan-out (spec §12): in-app rows are the source of truth;
EMAIL COPIES ARE POINTER-ONLY — they name the event and say 'open the app',
never carrying action URLs. SMS carries recovery alerts ONLY (§9 channel rule).
"""
import logging

from ..config import get_settings
from ..db import execute, many
from .providers.console import send_sms as _console_sms

log = logging.getLogger(__name__)


def _insert(row: dict) -> dict:
    execute("""INSERT INTO notifications (email, type, body)
               VALUES (%s,%s,%s)""", (row["email"], row["type"], row["body"]))
    return row | {"read_at": None}


def _fetch(email: str, limit: int) -> list[dict]:
    return many("""SELECT notif_id, type, body, link_ref, created_at, read_at
                   FROM notifications WHERE email=%s
                   ORDER BY created_at DESC LIMIT %s""", (email, limit))


def notify(email: str, type_: str, body: str) -> dict:
    return _insert({"email": email, "type": type_, "body": body})


def list_for(email: str, limit: int = 50) -> list[dict]:
    return _fetch(email, limit)


def mark_read(email: str, notif_id: int) -> None:
    execute("UPDATE notifications SET read_at=now() WHERE notif_id=%s AND email=%s",
            (notif_id, email))


def _build_mime(**kw):
    from ..smtp_client import build_mime
    return build_mime(kw["from_"], kw["to"], kw.get("cc") or [],
                      [], kw["subject"], kw["text"], None)


def _submit_mime(msg, rcpts):
    from ..smtp_client import submit_message
    submit_message(msg, rcpts)


def fan_out_email(to_email: str, subject: str, body_text: str) -> None:
    """Best-effort by design: the in-app notification ALREADY exists before we
    get here, and §12 forbids an email failure from surfacing as user error."""
    s = get_settings()
    try:
        msg = _build_mime(from_=f"noreply@{s.mail_domain}", to=[to_email],
                          subject=subject, text=body_text)
        _submit_mime(msg, [to_email])
    except Exception as e:                      # noqa: BLE001 — pointer copies never fail loudly
        log.warning("notification email to %s failed: %s", to_email, e)


def send_sms_alert(phone: str, body: str) -> bool:
    s = get_settings()
    if s.otp_provider == "twilio":
        from .providers import twilio
        return twilio.send_sms(phone, body)
    return _console_sms(phone, body)
```

`account_router.py`:

```python
from fastapi import APIRouter, Depends, HTTPException

from ..auth import get_current_user
from ..services import notifications as nf

router = APIRouter(prefix="/account", tags=["account"])


@router.get("/profile")
def profile(user: dict = Depends(get_current_user)):
    from ..db import one
    row = one("""SELECT email, display_name, phone_e164, account_type,
                        guardian_phone, tier, verification, status, created_at
                 FROM accounts WHERE email=%s""", (user["email"],))
    if not row:
        raise HTTPException(404, "no profile row (seeded-before-migration user?)")
    return row


@router.get("/notifications")
def my_notifications(user: dict = Depends(get_current_user)):
    return {"notifications": nf.list_for(user["email"])}


@router.post("/notifications/{notif_id}/read")
def mark(notif_id: int, user: dict = Depends(get_current_user)):
    nf.mark_read(user["email"], notif_id)
    return {"ok": True}
```

Wire into `main.py`.

- [ ] **Step 3: Green** — `.venv/bin/python -m pytest -q` all PASS.
- [ ] **Step 4: Commit**

```bash
git add api/app/services/notifications.py api/app/routers/account_router.py api/app/main.py api/tests/test_notifications.py
git commit -m "feat: in-app notifications with pointer-only email fan-out"
```

### Task 12: Device registry (hash-only storage + void hook)

**Files:**
- Create: `api/app/services/devices.py`, Test: `api/tests/test_devices.py`

**Interfaces:**
- Produces:
  - `mint() -> tuple[str, bytes]` — `(raw_device_id, raw_bytes)` where raw is `secrets.token_urlsafe(16)`; ONLY the SHA-256 hex of raw ever persists.
  - `hash_id(raw:str)->str` (sha256 hexdigest), `register(email,label,raw)->dict`, `resolve(raw)->dict|None` (joins accounts, bumps last_seen_at on hit), `list_for(email)->list[dict]`, `delete(email, device_hash)->bool`.
  - `VOID_HOOKS: list[callable[[str],None]]` + `fire_void(device_hash:str)->None` — recovery (Task 14) registers a callback that cancels any `pending_dwell`/`pending_family` request recognizing that device. Deleting a device fires the hook FIRST, then removes the row.
  - Endpoint additions in Task 13's router? NO — devices ride the ACCOUNT router (append here): `POST /account/devices {label}`, `GET /account/devices`, `DELETE /account/devices/{device_hash}`. Raw id is returned ONCE in the POST response; client stores it and sends `X-Device-ID`.

- [ ] **Step 1: Failing tests**

```python
import hashlib

import pytest

from app.services import devices as dv


@pytest.fixture
def world(monkeypatch):
    drows, arows, fired = {}, {"me@sovereign.mail": True}, []
    monkeypatch.setattr(dv, "_insert_row", lambda r: drows.setdefault(r["device_hash"], r))
    monkeypatch.setattr(dv, "_find_by_hash", lambda h: drows.get(h))
    monkeypatch.setattr(dv, "_rows_for", lambda e: [r for r in drows.values()
                                                    if r["email"] == e])
    monkeypatch.setattr(dv, "_drop_row", lambda h: drows.pop(h, None) is not None)
    monkeypatch.setattr(dv, "_bump_seen", lambda h: drows[h].update(
        {"last_seen_at": "bumped"}))
    dv.VOID_HOOKS.clear()
    dv.VOID_HOOKS.append(lambda h: fired.append(h))
    return {"drows": drows, "fired": fired}


def test_mint_returns_raw_and_never_stores_it(world):
    raw, raw_b = dv.mint()
    assert isinstance(raw, str) and len(raw_b) >= 16
    # nothing persisted yet at all:
    assert world["drows"] == {}


def test_register_stores_only_hash(world):
    raw, _ = dv.mint()
    row = dv.register("me@sovereign.mail", "Pixel 8", raw)
    stored = list(world["drows"].values())[0]
    assert stored["device_hash"] == hashlib.sha256(raw.encode()).hexdigest()
    assert raw not in str(world["drows"])
    assert "raw" not in row and "device_hash" in row


def test_resolve_hits_and_bumps(world):
    raw, _ = dv.mint()
    dv.register("me@sovereign.mail", "Pixel 8", raw)
    hit = dv.resolve(raw)
    assert hit and hit["email"] == "me@sovereign.mail"
    assert list(world["drows"].values())[0]["last_seen_at"] == "bumped"
    assert dv.resolve("garbage") is None


def test_delete_fires_void_hook_before_removal(world, monkeypatch):
    """§13 ordering guarantee: void hooks run BEFORE the row disappears."""
    order: list[str] = []

    real_hooks = list(dv.VOID_HOOKS)
    dv.VOID_HOOKS[:] = [lambda h: order.append("hook")]   # exactly one hook

    def spy_drop(h):
        order.append("drop")
        return True
    monkeypatch.setattr(dv, "_drop_row", spy_drop)

    raw, _ = dv.mint()
    row = dv.register("me@sovereign.mail", "D", raw)
    assert dv.delete("me@sovereign.mail", row["device_hash"]) is True
    assert order == ["hook", "drop"]        # hook fired BEFORE removal
    dv.VOID_HOOKS[:] = real_hooks


def test_delete_requires_owner_match(world):
    raw, _ = dv.mint()
    row = dv.register("me@sovereign.mail", "D", raw)
    other = dv.delete("intruder@sovereign.mail", row["device_hash"])
    assert other is False
```

Run: FAIL.

- [ ] **Step 2: Implement devices.py**

```python
"""Recognized devices (spec §14): the raw device secret lives ONLY on the
client; the server keeps SHA-256 hashes. A recognized device shortens RECOVERY
(never skips OTP) and its deletion immediately voids any pending recovery that
leaned on it (§13 delete-device-voids-request).
"""
import hashlib
import secrets
import time

from ..db import execute, many, one

VOID_HOOKS: list = []          # callables taking device_hash; recovery registers here


def hash_id(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def mint() -> tuple[str, int]:
    raw = secrets.token_urlsafe(16)
    return raw, len(raw)


# --- storage -----------------------------------------------------------------

def _insert_row(row: dict) -> dict:
    execute("""INSERT INTO devices (device_hash, email, label)
               VALUES (%(device_hash)s,%(email)s,%(label)s)
               ON CONFLICT (device_hash) DO UPDATE SET label=EXCLUDED.label""",
            row)
    return row


def _find_by_hash(h: str) -> dict | None:
    return one("""SELECT device_hash, email, label, created_at, last_seen_at
                  FROM devices WHERE device_hash=%s""", (h,))


def _rows_for(email: str) -> list[dict]:
    return many("""SELECT device_hash, label, created_at, last_seen_at
                   FROM devices WHERE email=%s ORDER BY created_at""", (email,))


def _drop_row(h: str) -> bool:
    cur = many("SELECT 1 FROM devices WHERE device_hash=%s", (h,))
    execute("DELETE FROM devices WHERE device_hash=%s", (h,))
    return bool(cur)


def _bump_seen(h: str) -> None:
    execute("UPDATE devices SET last_seen_at=now() WHERE device_hash=%s", (h,))


# --- api ----------------------------------------------------------------------

def register(email: str, label: str, raw: str) -> dict:
    row = {"device_hash": hash_id(raw), "email": email, "label": label}
    _insert_row(row)
    return row


def resolve(raw: str) -> dict | None:
    row = _find_by_hash(hash_id(raw))
    if row:
        _bump_seen(row["device_hash"])
    return row


def list_for(email: str) -> list[dict]:
    return _rows_for(email)


def fire_void(device_hash: str) -> None:
    for hook in VOID_HOOKS:
        hook(device_hash)


def delete(email: str, device_hash: str) -> bool:
    row = _find_by_hash(device_hash)
    if not row or row["email"] != email:
        return False
    fire_void(device_hash)               # BEFORE removal — §13 ordering guarantee
    return _drop_row(device_hash)
```

And append to `api/app/routers/account_router.py`:

```python
from ..services import devices as dv


class DeviceBody(BaseModel):
    label: str


@router.post("/devices")
def add_device(body: DeviceBody, user: dict = Depends(get_current_user)):
    raw, _ = dv.mint()
    row = dv.register(user["email"], body.label, raw)
    # The raw id crosses the wire exactly once; only its hash remains server-side.
    return {"device_id": raw, "label": row["label"],
            "header": "X-Device-ID", "device_hash": row["device_hash"]}


@router.get("/devices")
def my_devices(user: dict = Depends(get_current_user)):
    return {"devices": dv.list_for(user["email"])}


@router.delete("/devices/{device_hash}")
def remove_device(device_hash: str, user: dict = Depends(get_current_user)):
    if not dv.delete(user["email"], device_hash):
        raise HTTPException(404, "no such device for this account")
    return {"ok": True, "note": "any pending recovery relying on this device "
                                "was cancelled"}
```

(`from pydantic import BaseModel` at top of file.)

- [ ] **Step 3: Green** — full suite PASS (with the two edits called out above Step 1's Run).
- [ ] **Step 4: Commit**

```bash
git add api/app/services/devices.py api/app/routers/account_router.py api/tests/test_devices.py
git commit -m "feat: hashed device registry with recovery void hooks"
```

### Task 13: Family links — lifecycle, cooldown, pair rate-limit, pointer fan-out

**Files:**
- Create: `api/app/services/family.py`, `api/app/routers/family_router.py`
- Modify: `api/app/main.py` (include router)
- Test: `api/tests/test_family.py`

**Interfaces:**
- Consumes: `notifications.notify/fan_out_email`, `devices` (not directly — recovery does), `db.*`.
- Produces (`family` service): `request_link(requester_email, target_email)->dict` (raises `NoSuchTarget`, `AlreadyLinked`, `RateLimited`); `approve(link_id, actor_email)->None` (raises `NotAuthorized`); `revoke(link_id, actor_email)->None`; `active_links_for(email)->list[dict]` (approved AND usable); `pending_requests_for(email)->list[dict]`.
- Router endpoints (JWT-scoped): `POST /family/requests {target_email}` → `202 {link_id, expires_at}`; `POST /family/requests/{link_id}/approve|revoke` → `200`; `GET /family/links` → active+usable; `GET /family/requests` → incoming pending.
- Rules encoded: requester must be Tier 2 (422 otherwise); target must exist (404-shaped but generic message per anti-enumeration? NO — §15.3 anti-enumeration applies to RECOVERY only; family requests legitimately tell you the target doesn't exist: 404 "no such member"); pair rate-limit ≤2 requests/pair/rolling 24h; expiry 10 min; usable_at = approved_at + FAMILY_LINK_COOLDOWN_HOURS.

- [ ] **Step 1: Failing tests**

```python
import pytest

from app.services import family as fm


@pytest.fixture
def world(monkeypatch):
    links: dict[int, dict] = {}
    seq = {"n": 0}
    notes: list[tuple] = []
    emails = {"a@sovereign.mail": {"tier": "tier2_identity"},
              "b@sovereign.mail": {"tier": "tier1_phone"},
              "t2@sovereign.mail": {"tier": "tier2_identity"},
              "t1@sovereign.mail": {"tier": "tier1_phone"}}

    def fake_put(l):
        seq["n"] += 1
        l = l | {"link_id": seq["n"]}
        links[seq["n"]] = l
        return l
    monkeypatch.setattr(fm, "_put_link", fake_put)
    monkeypatch.setattr(fm, "_get_link", lambda lid: links.get(lid))
    monkeypatch.setattr(fm, "apply_status_change",
                        lambda name, p: links[p["link_id"]].update(
                            {"status": "approved" if name == "approve" else "revoked",
                             "approved_at_ts": p.get("approved_at_ts"),
                             "usable_at_ts": p.get("usable_at_ts")})
                        if name == "approve" else
                        links[p["link_id"]].update({"status": "revoked"}))
    monkeypatch.setattr(fm, "_account_tier", lambda e: emails[e]["tier"])
    monkeypatch.setattr(fm, "_pair_request_count", lambda a, b, since: sum(
        1 for l in links.values() if {l["requester_email"], l["target_email"]} ==
        {a, b} and l["created_at"] >= since))
    monkeypatch.setattr(fm.notifications, "notify",
                        lambda e, t, b: notes.append((e, t, b)) or {})
    monkeypatch.setattr(fm.notifications, "fan_out_email",
                        lambda *a, **k: notes.append(("email",) + a))
    now = 1_800_000_000.0
    monkeypatch.setattr(fm.time, "time", lambda: now)
    return {"links": links, "notes": notes, "emails": emails, "now": now}


def test_request_creates_pending_with_expiry(world):
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    assert l["status"] == "requested"
    assert l["expires_at_ts"] - world["now"] == 600            # 10-minute window
    kinds = [(e, t) for e, t, *_ in world["notes"]]
    assert ("t1@sovereign.mail", "family_request_received") in kinds
    assert ("a@sovereign.mail", "family_request_sent") in kinds


def test_tier2_gate_on_requester(world):
    with pytest.raises(fm.NotEligible):
        fm.request_link("b@sovereign.mail", "a@sovereign.mail")


def test_pair_rate_limit_two_per_day(world):
    fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    fm.request_link("a@sovereign.mail", "t1@sovereign.mail")   # supersedes previous? NO — counted
    with pytest.raises(fm.RateLimited):
        fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    # reverse direction counts toward the SAME pair budget:
    with pytest.raises(fm.RateLimited):
        fm.request_link("t1@sovereign.mail", "a@sovereign.mail")


def test_approve_sets_cooldown_usable_at(world):
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    fm.approve(l["link_id"], "t1@sovereign.mail")
    got = world["links"][l["link_id"]]
    assert got["status"] == "approved"
    assert got["usable_at_ts"] - got["approved_at_ts"] == 48 * 3600


def test_approve_by_wrong_party_is_403_shaped(world):
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    with pytest.raises(fm.NotAuthorized):
        fm.approve(l["link_id"], "t2@sovereign.mail")


def test_revoke_is_instant_and_notifies_both(world):
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    fm.approve(l["link_id"], "t1@sovereign.mail")
    fm.revoke(l["link_id"], "a@sovereign.mail")
    assert world["links"][l["link_id"]]["status"] == "revoked"
    assert any(t == "family_link_revoked" for _, t, _ in world["notes"])


def test_active_links_respects_cooldown_window(world, monkeypatch):
    l = fm.request_link("a@sovereign.mail", "t1@sovereign.mail")
    fm.approve(l["link_id"], "t1@sovereign.mail")
    assert fm.active_links_for("a@sovereign.mail") == []       # still cooling down
    future = world["now"] + 48 * 3600 + 1
    monkeypatch.setattr(fm.time, "time", lambda: future)       # jump past cooldown
    active = fm.active_links_for("a@sovereign.mail")
    assert len(active) == 1 and active[0]["link_id"] == l["link_id"]
```

Run: FAIL.

- [ ] **Step 2: Implement family.py**

```python
"""Family-link lifecycle (spec §12): tier-gated requests, approve-button-only
acceptance, approval cooldown before usability, instant revoke, pointer-only
notifications both directions, ≤2 requests per unordered pair per rolling 24h.
"""
import time

from ..config import get_settings
from ..db import execute, many, one
from . import notifications

REQUEST_TTL_SECONDS = 600


class NotEligible(Exception):
    pass


class NoSuchTarget(Exception):
    pass


class RateLimited(Exception):
    pass


class NotAuthorized(Exception):
    pass


# --- storage ------------------------------------------------------------------

def _put_link(l: dict) -> dict:
    rid = one("""INSERT INTO family_links (requester_email, target_email,
                                           status, expires_at)
                 VALUES (%s, %s, 'requested', to_timestamp(%s))
                 RETURNING link_id""",
              (l["requester"], l["target"], l["expires_at_ts"]))
    return l | {"link_id": rid["link_id"]}


def _get_link(link_id: int) -> dict | None:
    return one("""SELECT link_id,requester_email,target_email,status,
                         extract(epoch from created_at)::float AS created_at,
                         extract(epoch from expires_at)::float AS expires_at_ts,
                         extract(epoch from approved_at)::float AS approved_at_ts,
                         extract(epoch from usable_at)::float AS usable_at_ts
                  FROM family_links WHERE link_id=%s""", (link_id,))


_STATUS_CHANGE = {
    "approve": """UPDATE family_links SET status='approved',
                    approved_at=to_timestamp(%(approved_at_ts)s),
                    usable_at=to_timestamp(%(usable_at_ts)s)
                  WHERE link_id=%(link_id)s AND status='requested'""",
    "revoke":  """UPDATE family_links SET status='revoked', revoked_at=now(),
                    revoked_by=%(revoked_by)s
                  WHERE link_id=%(link_id)s""",
}


def apply_status_change(name: str, params: dict) -> None:
    execute(_STATUS_CHANGE[name], params)


def _account_tier(email: str) -> str | None:
    r = one("SELECT tier FROM accounts WHERE email=%s", (email,))
    return r and r["tier"]


def _pair_request_count(a: str, b: str, since_ts: float) -> int:
    return len(many("""SELECT 1 FROM family_links
                       WHERE ((requester_email=%s AND target_email=%s)
                           OR (requester_email=%s AND target_email=%s))
                         AND created_at >= to_timestamp(%s)""",
                    (a, b, b, a, since_ts)))


def active_links_for(email: str) -> list[dict]:
    now = time.time()
    return [r for r in many("""
        SELECT link_id, requester_email, target_email, status,
               extract(epoch from usable_at)::float AS usable_at_ts
        FROM family_links
        WHERE status='approved'
          AND (requester_email=%s OR target_email=%s)
          AND usable_at <= to_timestamp(%s)""", (email, email, now))
        if r["usable_at_ts"] <= now]


def pending_requests_for(email: str) -> list[dict]:
    return many("""SELECT link_id, requester_email, expires_at FROM family_links
                   WHERE target_email=%s AND status='requested'
                     AND expires_at > now()
                   ORDER BY created_at DESC""", (email,))


# --- lifecycle ---------------------------------------------------------------

def request_link(requester_email: str, target_email: str) -> dict:
    if _account_tier(requester_email) != "tier2_identity":
        raise NotEligible("family linking requires Tier 2 identity verification")
    if not _account_tier(target_email):
        raise NoSuchTarget("no such member")
    if requester_email == target_email:
        raise NoSuchTarget("cannot link yourself")
    if _pair_request_count(requester_email, target_email,
                           time.time() - 86400) >= 2:
        raise RateLimited("too many requests between these accounts today")
    now = time.time()
    link = {"requester": requester_email, "target": target_email,
            "status": "requested", "created_at": now,
            "expires_at_ts": now + REQUEST_TTL_SECONDS,
            "approved_clause": None, "usable_clause": None}
    stored = _put_link(link)
    notifications.notify(target_email, "family_request_received",
                         f"{requester_email} asked to link accounts with you. "
                         "Open your app to approve or ignore.")
    notifications.notify(requester_email, "family_request_sent",
                         f"Request sent to {target_email}. They have "
                         f"{REQUEST_TTL_SECONDS // 60} minutes to respond.")
    notifications.fan_out_email(
        target_email, "Sovereign Mail: family link request",
        f"{requester_email} requested to link with your account. Open your "
        "Sovereign Mail app to review. This mailbox does not accept actions "
        "by reply.")
    return stored


def approve(link_id: int, actor_email: str) -> None:
    link = _require_actor(link_id, actor_email, side="target")
    now = time.time()
    if link["status"] != "requested" or now > link["expires_at_ts"]:
        raise NoSuchTarget("request no longer active")
    apply_status_change("approve",
                        {"link_id": link["link_id"],
                         "approved_at_ts": now,
                         "usable_at_ts":
                             now + get_settings().family_link_cooldown_hours * 3600})
    for who in (link["requester_email"], link["target_email"]):
        notifications.notify(who, "family_link_approved",
                             "Family link approved. Recovery assistance becomes "
                             "available after the safety cooldown.")


def revoke(link_id: int, actor_email: str) -> None:
    link = _require_actor(link_id, actor_email, side="either")
    apply_status_change("revoke",
                        {"link_id": link["link_id"], "revoked_by": actor_email})
    for who in (link["requester_email"], link["target_email"]):
        notifications.notify(who, "family_link_revoked",
                             "A family link was revoked. It can no longer assist "
                             "recovery.")


def _require_actor(link_id: int, actor_email: str, *, side: str) -> dict:
    link = _get_link(link_id)
    if not link:
        raise NoSuchTarget("no such link")
    allowed = ({link["target_email"]} if side == "target"
               else {link["requester_email"], link["target_email"]})
    if actor_email not in allowed:
        raise NotAuthorized("not your link")
    return link
```

> **Note for the implementer:** the tests swap `_put_link/_get_link/apply_status_change/_pair_request_count/_account_tier` at module level; `_put_link` returns the link WITH its id in both production (INSERT…RETURNING) and the fake, so no separate id seam exists.

- [ ] **Step 3: Implement family_router.py**

```python
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..auth import get_current_user
from ..services import family as fm

router = APIRouter(prefix="/family", tags=["family"])


class RequestBody(BaseModel):
    target_email: str


@router.post("/requests", status_code=202)
def create(body: RequestBody, user: dict = Depends(get_current_user)):
    try:
        link = fm.request_link(user["email"], body.target_email.lower())
    except fm.NotEligible as e:
        raise HTTPException(422, str(e))
    except fm.NoSuchTarget as e:
        raise HTTPException(404, str(e))
    except fm.RateLimited as e:
        raise HTTPException(429, str(e))
    return {"link_id": link["link_id"],
            "expires_within_seconds": fm.REQUEST_TTL_SECONDS}


@router.post("/requests/{link_id}/approve")
def approve(link_id: int, user: dict = Depends(get_current_user)):
    try:
        fm.approve(link_id, user["email"])
    except fm.NoSuchTarget as e:
        raise HTTPException(404, str(e))
    except fm.NotAuthorized as e:
        raise HTTPException(403, str(e))
    return {"ok": True}


@router.post("/requests/{link_id}/revoke")
def revoke(link_id: int, user: dict = Depends(get_current_user)):
    try:
        fm.revoke(link_id, user["email"])
    except fm.NoSuchTarget as e:
        raise HTTPException(404, str(e))
    except fm.NotAuthorized as e:
        raise HTTPException(403, str(e))
    return {"ok": True}


@router.get("/links")
def links(user: dict = Depends(get_current_user)):
    return {"links": fm.active_links_for(user["email"])}


@router.get("/requests")
def incoming(user: dict = Depends(get_current_user)):
    return {"requests": fm.pending_requests_for(user["email"])}
```

The fixture above already patches `apply_status_change`; run everything green.

- [ ] **Step 4: Green** — full suite PASS.
- [ ] **Step 5: Commit**

```bash
git add api/app/services/family.py api/app/routers/family_router.py api/app/main.py api/tests/test_family.py
git commit -m "feat: family links with cooldown, pair rate-limit, pointer-only notices"
```

### Task 14: Recovery state machine — dwell, family windows, silent budgets

**Files:**
- Create: `api/app/services/recovery.py`, `api/app/routers/recovery_router.py`
- Modify: `api/app/main.py` (include router), `api/app/routers/account_router.py` (device deletion already fires `fire_void` — register the recovery canceller here)
- Test: `api/tests/test_recovery.py`

**Interfaces:**
- Consumes: `otp_service.send_challenge/verify_challenge` (purpose `"recovery"`), `devices.resolve/fire_void`, `family.active_links_for`, `notifications.notify/send_sms_alert/fan_out_email`, `ldap_admin.set_password`.
- Produces endpoints (all anti-enumeration responses BYTE-IDENTICAL for known vs unknown emails, §15.3):
  - `POST /recovery/start` `{email}` (+optional `X-Device-ID` header) → always `202 {"received":true}` (even when rate-silently-dropped, unknown email, or fully expired everything). Side effects differ only server-side.
  - `GET /recovery/status` `{email}` → `202 {"received":true}` (no state leak; clients poll nothing — they wait for contact channels).
  - `POST /recovery/verify-otp` `{email, code}` → `200 {"stage": "<current branch>"}` where stage ∈ `pending_family|pending_dwell|pending_admin|expired`; wrong code → `401` IDENTICAL shape regardless of attempt count.
  - `POST /recovery/family-approve` `{requester_email}` (member JWT; acts on that member's newest actionable request for the caller's linked requester) → `200 {"ok":true}` | 404-generic.
  - `POST /recovery/complete` `{email, new_password}` (+`X-Device-ID`) → `201 {"reset":true}` ONLY when OTP verified AND (dwell elapsed since authorized_at on the device path | family approved | admin granted); otherwise `403 {"detail":"not_ready"}` (same body for all not-yet reasons); expired/denied → `400 {"detail":"invalid_request"}`.
  - `POST /recovery/cancel` `{email}` with owner-or-member JWT → cancels active request (`cancel_reason`).
- Service functions (test seams are the `_load_active/_save/_count_recent` trio):
  - `start_recovery(email, device_raw|None, *, now=None)->dict` — internal result dict may say anything; the ROUTER flattens to the constant body.
  - `verify_otp(email, code)->str` (returns branch stage), `family_approve(member_email, requester_email)->bool`,
  - `maybe_complete(email, new_password, device_raw|None)->tuple[str,int]` (status, http-code),
  - `void_requests_for_device(device_hash)->None` (registered into `devices.VOID_HOOKS` at import),
  - `admin_grant(req_id, reviewer)->bool` (dashboard route lands with it).

State rules (spec §13 — implement EXACTLY):

1. Start ALWAYS sends an OTP challenge first (budget-guarded by `otp_service`; its BudgetExceeded counts toward this task's own ≤3/hour budget too — both raise → silent accept-and-drop).
2. Attempt budget: ≥ `RECOVERY_MAX_ATTEMPTS_PER_HOUR` starts in the trailing hour for that email → create NOTHING, return normally.
3. Any earlier active request for the email is SUPERSEDED (status `cancelled`, reason `superseded`) before creating the new one.
4. Branch pick at OTP-VERIFY time (not at start): family link usable → `pending_family` with `expires_at = now + RECOVERY_REQUEST_TTL_SECONDS`; recognized device → `pending_dwell`, `authorized_at = now` (dwell clock starts NOW, not at start); neither → `pending_admin`.
5. Expired `pending_family` flips lazily to `expired` on next touch. NO auto-transition to dwell (register #13).
6. Complete requires: OTP verified flag AND branch-specific satisfaction. Device path: `now >= authorized_at + RECOVERY_MIN_DWELL_SECONDS`. On success: `ldap_admin.set_password`, accounts row untouched, request `completed`, notifications + SMS alert fired ("your password was reset — if this wasn't you, ...").
7. Deleting a device (Task 12 hook) cancels any active request whose `recognizing_device_hash` matches (`cancel_reason=device_removed`).
8. Owner/member cancel anytime → `cancelled`.

- [ ] **Step 1: Failing tests**

```python
"""Recovery: friction everywhere, silence outward (spec §13, §15.3)."""
import json

import pytest

from app.services import devices as dv
from app.services import recovery as rc


START_BODY = b'{"received":true}'


@pytest.fixture
def w(monkeypatch):
    reqs: dict[str, dict] = {}
    seq = {"n": 0}
    store = {"accounts": {"alice@sovereign.mail": True,
                          "bob@sovereign.mail": True}}
    events: list[tuple] = []
    links: list[dict] = []
    clock = {"t": 1_800_000_000.0}

    def req_id():
        seq["n"] += 1
        return f"rq-{seq['n']}"

    monkeypatch.setattr(rc.time, "time", lambda: clock["t"])
    monkeypatch.setattr(rc, "_account_exists", lambda e: store["accounts"].get(e, False))
    monkeypatch.setattr(rc, "_save", lambda r: reqs.__setitem__(r["req_id"], r) or r)
    monkeypatch.setattr(rc, "_active_for", lambda e: next(
        (r for r in reqs.values() if r["email"] == e
         and r["status"] in ("awaiting_phone", "pending_family",
                             "pending_dwell", "pending_admin")), None))
    monkeypatch.setattr(rc, "_get", lambda rid: reqs.get(rid))
    monkeypatch.setattr(rc, "_new_id", req_id)
    monkeypatch.setattr(rc, "_starts_in_last_hour", lambda e, t: sum(
        1 for r in reqs.values() if r["email"] == e and r["created_at"] > t))
    from app.services import otp_service as _ot

    def fake_verify(phone, purpose, code):
        if code != "123456":
            raise _ot.InvalidCode("codes do not match")
        return True
    monkeypatch.setattr(rc.otp_service, "send_challenge",
                        lambda *a, **k: events.append(("otp_sent", a[0])))
    monkeypatch.setattr(rc.otp_service, "verify_challenge", fake_verify)
    monkeypatch.setattr(rc, "_phone_for",
                        lambda e: "+seed-" + e.split("@")[0])
    monkeypatch.setattr(rc.family, "active_links_for",
                        lambda e: [l for l in links if l["member_of"] == e])
    monkeypatch.setattr(dv, "resolve", lambda raw: None)
    monkeypatch.setattr(rc.notifications, "notify",
                        lambda e, t, b: events.append(("note", e, t)))
    monkeypatch.setattr(rc.notifications, "fan_out_email",
                        lambda *a, **k: events.append(("email", a[0])))
    monkeypatch.setattr(rc.notifications, "send_sms_alert",
                        lambda p, b: events.append(("sms", p)) or True)
    monkeypatch.setattr(rc.ldap_admin, "set_password",
                        lambda e, p: events.append(("pwset", e)))

    def advance(seconds):
        clock["t"] += seconds

    return {"reqs": reqs, "events": events, "links": links,
            "advance": advance, "store": store}


def test_unknown_and_known_email_byte_identical(w):
    a = rc.start_recovery("nobody@sovereign.mail", None)
    b = rc.start_recovery("alice@sovereign.mail", None)
    assert rc.public_view(a) == rc.public_view(b) == json.loads(START_BODY)


def test_start_always_sends_otp_when_known_and_budgeted(w):
    rc.start_recovery("alice@sovereign.mail", None)
    assert ("otp_sent", "+seed-alice") in [
        ("otp_sent", e[1]) for e in w["events"] if e[0] == "otp_sent"]


def test_attempt_budget_is_silent(w):
    for _ in range(int(rc_max())):
        rc.start_recovery("alice@sovereign.mail", None)
    n_before = len([e for e in w["events"] if e[0] == "otp_sent"])
    out = rc.start_recovery("alice@sovereign.mail", None)   # over budget
    assert rc.public_view(out) == json.loads(START_BODY)     # looks normal...
    n_after = len([e for e in w["events"] if e[0] == "otp_sent"])
    assert n_after == n_before                               # ...but did NOTHING


def rc_max():
    from app.config import get_settings
    return get_settings().recovery_max_attempts_per_hour


def test_supersede_cancels_previous(w):
    rc.start_recovery("alice@sovereign.mail", None)
    first = [r for r in w["reqs"].values() if r["email"] == "alice@sovereign.mail"][0]
    rc.start_recovery("alice@sovereign.mail", None)
    assert first["status"] == "cancelled"
    assert first["cancel_reason"] == "superseded"


def test_branch_pick_pending_admin_without_factors(w):
    out = rc.start_recovery("alice@sovereign.mail", None)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_admin"


def test_device_path_requires_full_dwell(w, monkeypatch):
    raw = "devraw123"
    dev = {"device_hash": "h" * 64, "email": "alice@sovereign.mail"}
    monkeypatch.setattr(dv, "resolve", lambda r: dev if r == raw else None)
    out = rc.start_recovery("alice@sovereign.mail", raw)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_dwell"
    # too early:
    w["advance"](rc_min_dwell() - 10)
    assert rc.maybe_complete("alice@sovereign.mail", "new-password-long",
                             raw)[:1] == ("not_ready", 403)
    # past the dwell wall:
    w["advance"](20)
    status, code = rc.maybe_complete("alice@sovereign.mail",
                                     "new-password-long", raw)
    assert (status, code) == ("completed", 201)
    assert ("pwset", "alice@sovereign.mail") in w["events"]
    assert ("sms",) == tuple(e[:1] for e in w["events"] if e[0] == "sms")[0]


def rc_min_dwell():
    from app.config import get_settings
    return get_settings().recovery_min_dwell_seconds


def test_family_window_expiry_no_auto_dwell_fallback(w, monkeypatch):
    """§13/register#13: even WITH a recognized device, an EXPIRED family window
    stays dead — the user must start over and consume a fresh attempt."""
    w["links"].append({"member_of": "alice@sovereign.mail"})
    raw = None
    out = rc.start_recovery("alice@sovereign.mail", raw)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_family"
    ttl = ttl_seconds()
    w["advance"](ttl + 1)
    assert rc._refresh_state(out)["status"] == "expired"      # lazy flip
    status, code = rc.maybe_complete("alice@sovereign.mail",
                                     "new-password-long", raw)
    assert (status, code) == ("invalid_request", 400)         # NOT a dwell path


def ttl_seconds():
    from app.config import get_settings
    return get_settings().recovery_request_ttl_seconds


def test_family_approve_unlocks_completion(w):
    w["links"].append({"member_of": "alice@sovereign.mail"})
    out = rc.start_recovery("alice@sovereign.mail", None)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert rc.family_approve("member@sovereign.mail", "alice@sovereign.mail")
    assert w["reqs"][out["req_id"]]["decided_by"] == "member@sovereign.mail"
    status, code = rc.maybe_complete("alice@sovereign.mail",
                                     "new-password-long", None)
    assert (status, code) == ("completed", 201)


def test_delete_device_voids_pending_dwell(w, monkeypatch):
    raw = "devrawXYZ"
    dev = {"device_hash": "abcd" * 16, "email": "alice@sovereign.mail"}
    monkeypatch.setattr(dv, "resolve", lambda r: dev if r == raw else None)
    out = rc.start_recovery("alice@sovereign.mail", raw)
    rc.verify_otp("alice@sovereign.mail", "123456")
    assert out["status"] == "pending_dwell"
    dv.fire_void(dev["device_hash"])                          # what account_router DELETE triggers
    assert out["status"] == "cancelled"
    assert out["cancel_reason"] == "device_removed"


def test_wrong_otp_never_advances(w):
    out = rc.start_recovery("alice@sovereign.mail", None)
    with pytest.raises(Exception):
        rc.verify_otp("alice@sovereign.mail", "000000")
    assert out["status"] == "awaiting_phone"
```

Run: FAIL — no module.

- [ ] **Step 2: Implement recovery.py**

```python
"""Account recovery (spec §13): OTP always; device dwell / family approval /
admin grant as the OR-leg. Outward-facing views are CONSTANT by design — see
public_view(). Every timing rule here exists because a stolen second factor
must still hit a human-speed wall.
"""
import secrets
import time

from ..config import get_settings
from ..db import execute, many, one
from . import devices, family, ldap_admin, notifications, otp_service

PENDING_BRANCHES = ("pending_family", "pending_dwell", "pending_admin")


class WrongCode(Exception):
    pass


# --- storage ------------------------------------------------------------------

def _new_id() -> str:
    return "rq-" + secrets.token_urlsafe(12)


def _account_exists(email: str) -> bool:
    return one("SELECT 1 FROM accounts WHERE email=%s", (email,)) is not None


def _save(r: dict) -> dict:
    execute("""INSERT INTO recovery_requests
               (req_id,email,status,recognizing_device_hash,recognized_device,
                authorized_at,decided_by_member,cancel_reason,expires_at)
               VALUES (%(req_id)s,%(email)s,%(status)s,%(recog)s,%(recognized)s,
                       %(authorized_clause)s,%(decided_by)s,%(cancel_reason)s,
                       to_timestamp(%(expires_at)s))
               ON CONFLICT (req_id) DO UPDATE SET
                 status=EXCLUDED.status, authorized_at=EXCLUDED.authorized_at,
                 decided_by_member=EXCLUDED.decided_by_member,
                 cancel_reason=EXCLUDED.cancel_reason""", r)
    return r


def _get(req_id: str) -> dict | None:
    return one("""SELECT req_id,email,status,recognizing_device_hash AS recog,
                         recognized_device,
                         extract(epoch from authorized_at)::float AS authorized_at_ts,
                         decided_by_member, cancel_reason,
                         extract(epoch from created_at)::float AS created_at,
                         extract(epoch from expires_at)::float AS expires_at
                  FROM recovery_requests WHERE req_id=%s""", (req_id,))


def _active_for(email: str) -> dict | None:
    row = one("""SELECT req_id FROM recovery_requests WHERE email=%s
                 AND status IN ('awaiting_phone','pending_family',
                                'pending_dwell','pending_admin')
                 ORDER BY created_at DESC LIMIT 1""", (email,))
    return _get(row["req_id"]) if row else None


def _starts_in_last_hour(email: str, since_ts: float) -> int:
    return len(many("""SELECT 1 FROM recovery_requests WHERE email=%s
                       AND created_at > to_timestamp(%s)""", (email, since_ts)))


def _phone_for(email: str) -> str:
    r = one("SELECT phone_e164 FROM accounts WHERE email=%s", (email,))
    return r["phone_e164"] if r else ""


# --- public envelope ----------------------------------------------------------

def public_view(internal_result: dict) -> dict:
    """THE anti-enumeration constant. Nothing about existence, budget, or
    branch may vary this body."""
    return {"received": True}


# --- lifecycle ------------------------------------------------------------------

def _cancel(r: dict, reason: str) -> dict:
    r |= {"status": "cancelled", "cancel_reason": reason}
    return _save(_with_clauses(r))


def _with_clauses(r: dict) -> dict:
    """authorized_at is written as an epoch; _save maps None->NULL via clause key."""
    r.setdefault("authorized_clause",
                 f"to_timestamp({r['authorized_at_ts']})" if r.get("authorized_at_ts") else "NULL")
    return r


def start_recovery(email: str, device_raw: str | None) -> dict:
    s = get_settings()
    now = time.time()
    known = _account_exists(email)
    within_budget = _starts_in_last_hour(
        email, now - 3600) < s.recovery_max_attempts_per_hour if known else False
    if known and within_budget:
        prev = _active_for(email)
        if prev:
            _cancel(prev, "superseded")
        try:
            otp_service.send_challenge(_phone_for(email), "recovery")
        except (otp_service.BudgetExceeded, otp_service.OtpSendError):
            return {"received": True}            # silent drop, nothing persisted
        dev = devices.resolve(device_raw) if device_raw else None
        rec = _save(_with_clauses({
            "req_id": _new_id(), "email": email, "status": "awaiting_phone",
            "recog": dev["device_hash"] if dev else None,
            "recognized": bool(dev), "authorized_at_ts": None,
            "decided_by": None, "cancel_reason": None,
            "created_at": now, "expires_at": now}))
        notifications.notify(email, "recovery_started",
                             "A recovery was started for your account. If this "
                             "wasn't you, open the app and cancel it.")
        notifications.fan_out_email(
            email, "Sovereign Mail: recovery started",
            "A password recovery was started for your account. Open your "
            "Sovereign Mail app to review or cancel. This mailbox does not "
            "accept actions by reply.")
        return public_view(rec)
    return {"received": True}                    # unknown OR over-budget: same view


def verify_otp(email: str, code: str) -> str:
    r = _active_for(email)
    if not r or r["status"] != "awaiting_phone":
        raise WrongCode("no active recovery")
    otp_service.verify_challenge(_phone_for(email), "recovery", code)
    s = get_settings()
    now = time.time()
    linked = family.active_links_for(email)
    if linked:
        r |= {"status": "pending_family",
              "expires_at": now + s.recovery_request_ttl_seconds}
    elif r["recognized"]:
        r |= {"status": "pending_dwell", "authorized_at_ts": now}
    else:
        r |= {"status": "pending_admin"}
    _save(_with_clauses(r))
    return r["status"]


def family_approve(member_email: str, requester_email: str) -> bool:
    r = _active_for(requester_email)
    if not r or r["status"] != "pending_family":
        return False
    if time.time() > r["expires_at"]:
        r |= {"status": "expired"}
        _save(_with_clauses(r))
        return False
    r |= {"status": "authorized", "decided_by": member_email,
          "authorized_at_ts": time.time()}
    _save(_with_clauses(r))
    return True


def _refresh_state(r: dict) -> dict:
    if r["status"] == "pending_family" and time.time() > r["expires_at"]:
        r |= {"status": "expired"}              # lazy flip; NO dwell fallback
        _save(_with_clauses(r))
    return r


def maybe_complete(email: str, new_password: str,
                   device_raw: str | None) -> tuple[str, int]:
    r = _active_for(email)
    if not r:
        return "invalid_request", 400
    r = _refresh_state(r)
    if r["status"] == "cancelled" or r["status"] == "expired":
        return "invalid_request", 400
    if r["status"] == "pending_family":
        return "not_ready", 403
    if r["status"] == "pending_admin":
        return "not_ready", 403
    if r["status"] == "pending_dwell":
        s = get_settings()
        if device_raw is None or r["recog"] != (
                devices.resolve(device_raw) or {}).get("device_hash"):
            return "not_ready", 403             # same device must finish the wait
        if time.time() < r["authorized_at_ts"] + s.recovery_min_dwell_seconds:
            return "not_ready", 403
    if r["status"] != "authorized":
        return "invalid_request", 400
    ldap_admin.set_password(email, new_password)
    r |= {"status": "completed"}
    _save(_with_clauses(r))
    acct_phone = _phone_for(email)
    notifications.notify(email, "password_reset_completed",
                         "Your password was reset. If this wasn't you, contact "
                         "your administrator immediately.")
    notifications.send_sms_alert(acct_phone,
                                 "Sovereign Mail: your password was just "
                                 "reset. If this wasn't you, act now.")
    return "completed", 201


def cancel(email: str, actor_email: str) -> bool:
    r = _active_for(email)
    if not r:
        return False
    _cancel(r, f"cancelled_by:{actor_email}")
    return True


def void_requests_for_device(device_hash: str) -> None:
    row = one("""SELECT req_id FROM recovery_requests
                 WHERE recognizing_device_hash=%s
                   AND status IN ('awaiting_phone','pending_family',
                                  'pending_dwell')""", (device_hash,))
    if row:
        r = _get(row["req_id"])
        _cancel(r, "device_removed")


devices.VOID_HOOKS.append(void_requests_for_device)


def admin_grant(req_id: str, reviewer: str) -> bool:
    r = _get(req_id)
    if not r or r["status"] != "pending_admin":
        return False
    r |= {"status": "authorized", "decided_by": f"admin:{reviewer}",
          "authorized_at_ts": time.time()}
    _save(_with_clauses(r))
    return True
```

- [ ] **Step 3: Implement recovery_router.py**

```python
"""Every handler returns through ONE of two constant envelopes so known vs
unknown emails, budget drops, and branch differences are indistinguishable on
the wire (§15.3)."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from ..auth import get_current_user
from ..config import get_settings
from ..services import devices, recovery as rc

router = APIRouter(prefix="/recovery", tags=["recovery"])

OK_BODY = {"received": True}


class EmailBody(BaseModel):
    email: str


class CodeBody(BaseModel):
    email: str
    code: str


class PasswordBody(BaseModel):
    email: str
    new_password: str


class ApproveBody(BaseModel):
    requester_email: str


@router.post("/start")
def start(body: EmailBody, request: Request):
    rc.start_recovery(body.email.lower(), request.headers.get("X-Device-ID"))
    return OK_BODY


@router.post("/verify-otp")
def verify(body: CodeBody):
    try:
        stage = rc.verify_otp(body.email.lower(), body.code)
    except rc.WrongCode:
        raise HTTPException(401, "invalid code")
    except Exception:                            # otp_service.InvalidCode etc.
        raise HTTPException(401, "invalid code")
    return {"stage": stage}


@router.post("/family-approve")
def fam_approve(body: ApproveBody, user: dict = Depends(get_current_user)):
    if not rc.family_approve(user["email"], body.requester_email.lower()):
        raise HTTPException(404, "no such request")
    return {"ok": True}


@router.post("/complete")
def complete(body: PasswordBody, request: Request):
    if get_settings().password_min_length > len(body.new_password):
        raise HTTPException(422, "password too short")
    status, code = rc.maybe_complete(body.email.lower(), body.new_password,
                                     request.headers.get("X-Device-ID"))
    if code == 201:
        return {"reset": True}
    raise HTTPException(code, status)


@router.post("/cancel")
def cancel(body: EmailBody, user: dict = Depends(get_current_user)):
    # Owner cancelling their own request; family-side cancellation rides the
    # same endpoint with their own JWT (both are 'a party with standing').
    rc.cancel(body.email.lower(), user["email"])
    return OK_BODY
```

And in `account_router.py`'s `remove_device`, the existing `dv.delete` call already triggers the registered `void_requests_for_device` — add nothing there beyond the response note already present.

- [ ] **Step 4: Green** — full suite PASS.
- [ ] **Step 5: Commit**

```bash
git add api/app/services/recovery.py api/app/routers/recovery_router.py api/app/main.py api/tests/test_recovery.py
git commit -m "feat: recovery state machine with dwell friction, family windows, silent budgets"
```

### Task 15: Smoke-test extension + README operator guide

**Files:**
- Modify: `scripts/smoke-test.sh` (append Phase 5+), `docs/README.md` (operator guide sections)

**Interfaces:**
- Consumes: every endpoint from Tasks 4–14; env overrides `FAMILY_LINK_COOLDOWN_HOURS=0`, `RECOVERY_MIN_DWELL_SECONDS=5` documented for smoke runs.

- [ ] **Step 1: Extend scripts/smoke-test.sh** (append; keep the existing phases untouched):

```bash
################################## PHASE 5: identity subsystem ##################################
log "PHASE 5: signup + tiers + admin queue + family + recovery"

py_signup() {  # $1=email $2=phone -> prints session token; asserts 202
  curl -s -o /tmp/su.json -w '%{http_code}' -X POST localhost:8000/signup/start \
    -H 'content-type: application/json' \
    -d "{\"email\":\"$1\",\"display_name\":\"Smoke User\",\"phone_e164\":\"$2\",
         \"account_type\":\"independent\"}" | grep -q 202 || fail "signup/start $1"
  python3 -c 'import json;print(json.load(open("/tmp/su.json"))["session_token"])'
}

TOK=$(py_signup carol@sovereign.mail +918000000001)
OTP_CODE=$(docker compose logs api | grep "OTP for +918000000001" | tail -1 | grep -oE '[0-9]{6}$')
curl -sf -X POST localhost:8000/signup/verify-otp -H 'content-type: application/json' \
  -d "{\"token\":\"$TOK\",\"code\":\"$OTP_CODE\"}" >/dev/null || fail "verify-otp"

# tier1 skip path:
curl -sf -X POST localhost:8000/signup/complete -H 'content-type: application/json' \
  -d "{\"token\":\"$TOK\",\"choice\":{\"kind\":\"skip\"},\"password\":\"smoke-password-123\"}" \
  | grep -q '"tier1_phone"' || fail "tier1 complete"
# LDAP row exists with SSHA:
docker compose exec -T openldap ldapsearch -x -b "dc=sovereign,dc=mail" \
  "(mail=carol@sovereign.mail)" userPassword \
  -D "cn=admin,dc=sovereign,dc=mail" -y /run/secrets/.ldappass 2>/dev/null \
  | grep -q "{SSHA}" || docker compose exec -T openldap ldapsearch -x -b "dc=sovereign,dc=mail" \
  "(mail=carol@sovereign.mail)" userPassword -D "cn=admin,dc=sovereign,dc=mail" \
  -w "$LDAP_ROOT_PASSWORD" | grep -q "{SSHA}" || fail "ldap SSHA row"

# MANUAL idverify round-trip (IDVERIFY_MODE=manual expected during smoke):
TOK2=$(py_signup dave@sovereign.mail +918000000002)
CODE2=$(docker compose logs api | grep "OTP for +918000000002" | tail -1 | grep -oE '[0-9]{6}$')
curl -sf -X POST localhost:8000/signup/verify-otp -H 'content-type: application/json' \
  -d "{\"token\":\"$TOK2\",\"code\":\"$CODE2\"}" >/dev/null
curl -sf -X POST localhost:8000/signup/complete -H 'content-type: application/json' \
  -d "{\"token\":\"$TOK2\",\"choice\":{\"kind\":\"submit_id\",\"full_name\":\"Dave\",
       \"document_type\":\"national_id\",\"id_number\":\"XX999999\",
       \"consent_selfie\":true},\"password\":\"smoke-password-123\"}" \
  | grep -q 'queued_manual_review' || fail "manual queue body"

# ADMIN: bearer gate + queue + approve (ADMIN_TOKEN minted by the existing PKCE helper logged in as $SOVEREIGN_ADMIN_USER)
curl -sf localhost:8000/admin/api/reviews -H "Authorization: Bearer $ADMIN_TOKEN" \
  | grep -q dave@sovereign.mail || fail "admin queue empty"
RID=$(curl -sf localhost:8000/admin/api/reviews -H "Authorization: Bearer $ADMIN_TOKEN" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["reviews"][0]["review_id"])')
curl -sf -X POST "localhost:8000/admin/api/reviews/$RID/approve" \
  -H "Authorization: Bearer $ADMIN_TOKEN" >/dev/null || fail "approve"
docker compose exec -T postgres psql -U "$POSTGRES_USER" -d sovereign_app -tAc \
  "SELECT tier||'/'||verification FROM accounts WHERE email='dave@sovereign.mail'" \
  | grep -q "tier2_identity/manual_verified" || fail "tier2 promotion"

# FAMILY: carol(tier2 after manual approve? NO—carol stayed tier1) -> use dave as requester
curl -sf -X POST localhost:8000/family/requests -H "Authorization: Bearer $CAROL_TOKEN" \
  -H 'content-type: application/json' -d '{"target_email":"alice@sovereign.mail"}' >/dev/null \
  && fail "tier1 requester must be rejected 422"
curl -sf -X POST localhost:8000/family/requests -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'content-type: application/json' -d '{"target_email":"carol@sovereign.mail"}' >/dev/null || fail "family request"
# alice approves via her JWT (existing helper mints USER_TOKEN for alice):
LID=$(curl -sf localhost:8000/family/requests -H "Authorization: Bearer $ALICE_TOKEN" \
  | python3 -c 'import json,sys;print(json.load(sys.stdin)["requests"][0]["link_id"])')
curl -sf -X POST "localhost:8000/family/requests/$LID/approve" \
  -H "Authorization: Bearer $ALICE_TOKEN" >/dev/null || fail "family approve"
# pointer-only proof:
docker compose logs api | grep "notification email" >/dev/null && true
curl -sf localhost:8025/api/v2/messages | python3 -c '
import json,sys
msgs=json.load(sys.stdin)["messages"]
fam=[m for m in msgs if "family link request" in m["Subject"]]
assert fam, "no family email landed"
body=fam[0]["Content"]["Body"].lower()
assert "http" not in body, "POINTER-ONLY VIOLATION: link in email body"
print("pointer-only OK")' || fail "family pointer email"

# RECOVERY (smoke overrides make dwell 5s):
curl -s -X POST localhost:8000/recovery/start -H 'content-type: application/json' \
  -d '{"email":"alice@sovereign.mail"}' | grep -q received || fail "recovery start"
RCODE=$(docker compose logs api | grep "OTP for ${TEST_PHONE_ALICE}" | tail -1 | grep -oE '[0-9]{6}$')
STAGE=$(curl -sf -X POST localhost:8000/recovery/verify-otp -H 'content-type: application/json' \
  -d "{\"email\":\"alice@sovereign.mail\",\"code\":\"$RCODE\"}" | python3 -c 'import json,sys;print(json.load(sys.stdin)["stage"])')
case "$STAGE" in
  pending_dwell) sleep 6 ;;   # RECOVERY_MIN_DWELL_SECONDS=5 override
  pending_family)
    LREQ=$(curl -sf -X POST localhost:8000/recovery/family-approve \
             -H "Authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
             -d '{"requester_email":"alice@sovereign.mail"}') ;;
  *) fail "unexpected recovery stage $STAGE" ;;
esac
curl -sf -X POST localhost:8000/recovery/complete -H 'content-type: application/json' \
  -d '{"email":"alice@sovereign.mail","new_password":"recovered-pass-123"}' \
  | grep -q '"reset":true' || fail "recovery complete"

# ANTI-ENUMERATION pin (Success Criterion 1 of §23):
A=$(curl -s -X POST localhost:8000/recovery/start -H 'content-type: application/json' \
      -d '{"email":"ghost@sovereign.mail"}'; echo)
B=$(curl -s -X POST localhost:8000/recovery/start -H 'content-type: application/json' \
      -d '{"email":"alice@sovereign.mail"}'; echo)
[ "$A" = "$B" ] || fail "anti-enumeration bodies differ"
log "PHASE 5 OK"
```

Notes for the implementer: (a) dashboard approval is exercised over the bearer JSON route (`/admin/api/reviews/{id}/approve`, Task 9) so the smoke stays browserless; the HTML CSRF flow is covered by pytest instead; (b) `$ADMIN_TOKEN/$ALICE_TOKEN/$CAROL_TOKEN` come from the existing PKCE login helper — parameterize the helper on username so minting three tokens is three calls; (c) smoke runs expect `IDVERIFY_MODE=manual` and the two override envs (`FAMILY_LINK_COOLDOWN_HOURS=0`, `RECOVERY_MIN_DWELL_SECONDS=5`) exported before `docker compose up -d api`.

- [ ] **Step 2: README operator guide additions** (`docs/README.md`)

Append these sections (write full prose, ~1 screen each):
1. **Self-service signup** — what users see, tier meanings, IDVERIFY_MODE values and how to switch, console-provider DEV warning.
2. **Admin dashboard** — who gets access (`sovereign-admin` role + `$SOVEREIGN_ADMIN_USER`), how to log in (`/admin/login`), what approve/reject do, assisted-recovery grants.
3. **Recovery runbook** — the four outcomes a user can hit (dwell/family/admin/expired), what the operator does for `pending_admin` assists, why dwell exists, the smoke-time env overrides.
4. **Secret inventory pointer** — table referencing spec §15.1 including the interim LDAP admin DN row and Twilio creds handling.
5. **Family links** — cooldown semantics, revoke, pointer-only email guarantee.

- [ ] **Step 3: Commit**

```bash
git add scripts/smoke-test.sh docs/README.md api/app/routers/admin_router.py
git commit -m "feat: phase-5 smoke coverage + operator guide for identity subsystem"
```

### Task 16: FINAL GATE — full stack live run (codespace)

- [ ] **Step 1: Push local → codespace `git pull --ff-only`**
- [ ] **Step 2: Fresh-stack rebuild**

```bash
docker compose down -v && docker compose up -d --build
scripts/gen-certs.sh && scripts/gen-dkim.sh && scripts/seed-ldap.sh && scripts/seed-keycloak.sh
scripts/db-migrate.sh && scripts/db-migrate.sh       # twice: idempotency proof
```
Wait healthy (`docker compose ps` — all `healthy`).

- [ ] **Step 3: Full extended smoke exit 0**

```bash
FAMILY_LINK_COOLDOWN_HOURS=0 RECOVERY_MIN_DWELL_SECONDS=5 IDVERIFY_MODE=manual \
  docker compose up -d api
bash scripts/smoke-test.sh; echo "EXIT=$?"
```
Expected: `EXIT=0` including `PHASE 5 OK` and the anti-enumeration pin line.

- [ ] **Step 4: Success-criteria audit (spec §23)**

1. Smoke exit 0 ✓ (record output tail in notes)
2. Schema audit — unchanged LDAP schema:
```bash
docker compose exec openldap slapcat -b dc=sovereign,dc=mail 2>/dev/null | \
  grep -E "structuralObjectClass|objectClass:" | sort -u
```
Compare against pre-subsystem output (only inetOrgPerson classes; NO custom schema classes).
3. Byte-identical recovery pin shown in Phase 5 ✓
4. `docs/README.md` newcomer walkthrough followed once manually — flag anything stale.

- [ ] **Step 5: Restore prod-ish env on codespace** (remove smoke overrides), final push of any fix commits from local. Wave C done; report results and STOP — implementation dispatch beyond this plan needs explicit approval.

---

## Plan Self-Review Notes (for the executor's benefit — checked at write time)

- **Spec coverage:** §8 signup → T4/T7; §9 OTP → T3; §10 idverify → T6/T7; §11 admin/dashboard → T8/T9; §12 family → T13; §13 recovery → T12(void hooks)+T14; §14 devices → T12; §16 config → T1; migrations/backfill → T1; smoke/README → T15/T16; success-criteria audits → T16 Step 4.
- **Known seams:** local tests never touch Postgres/LDAP/Docker — every service exposes small module-level storage functions as swap points (repo precedent). Live behavior is proven exactly at Tasks 5, 10, 16.
- **Deliberate silences:** recovery attempt-budget overruns return the constant body (tested); `public_view()` is the single place allowed to know that shape.
