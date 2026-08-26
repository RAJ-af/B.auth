"""AUTO identity verification: subprocess runner over the frozen contract (§10).

Contract rules enforced HERE so a misbehaving verifier can never confuse the
signup router: well-formed-but-false is a RESULT; anything structurally wrong
(timeout, exit!=0, bad JSON, wrong contract_version) is IdverifyInfraError and
maps to the soft-fallback path upstream.
"""
import json
import logging
import os
import re
import signal
import subprocess
from dataclasses import dataclass

from ..config import get_settings

log = logging.getLogger(__name__)

CONTRACT_VERSION = 1

# Verifier-controlled warning strings reach the signup response body via
# map_result's reason_detail, so only token-shaped warnings are ever echoed.
_WARN = re.compile(r"^[a-z0-9_]{1,40}$")


class IdverifyInfraError(Exception):
    pass


class AccountMissingForReview(Exception):
    """Approval tried to promote an email with no accounts row — a loud domain
    failure, never a silent True (routers map it to 409)."""


@dataclass
class IdentityOutcome:
    tier: str                    # tier1_phone | tier2_identity
    verification: str            # pending_identity | auto_verified | manual_pending...
    identity_status: str | None  # extra field for the /signup/complete body
    reason_detail: str | None
    # §10.2 multi-identity PAUSE: when set, signup stops before provisioning
    # and the client must pick one offered identity (/signup/identity-choice).
    pause_choices: list[dict] | None = None
    # §8.2 single-MINOR document: no pause — provision straight to a
    # guardian_managed tier2 account (guardian_phone assigned by the router).
    guardian_minor: bool = False


def run_auto_check(payload: dict) -> dict:
    s = get_settings()
    try:
        proc = subprocess.Popen([s.idverify_script], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, start_new_session=True)
    except OSError as e:
        raise IdverifyInfraError(f"idverify not executable: {e}") from e
    try:
        out, err = proc.communicate(input=json.dumps(payload),
                                    timeout=s.idverify_timeout_seconds)
    except subprocess.TimeoutExpired:
        # subprocess.run's timeout only killed the direct child; a verifier
        # that forks workers leaked them as orphans. start_new_session puts
        # the whole tree in its own process group, so SIGKILL the GROUP.
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()               # reap the killed tree
        raise IdverifyInfraError(
            f"idverify timed out after {s.idverify_timeout_seconds}s")
    finally:
        for f in (proc.stdin, proc.stdout, proc.stderr):
            if f:
                try: f.close()
                except OSError: pass
    if proc.returncode != 0:
        raise IdverifyInfraError(f"idverify exit {proc.returncode}")
    try:
        out = json.loads(out)
    except json.JSONDecodeError as e:
        raise IdverifyInfraError("idverify stdout was not JSON") from e
    if not isinstance(out, dict):
        raise IdverifyInfraError("idverify stdout was not a JSON object")
    if out.get("contract_version") is not CONTRACT_VERSION:
        raise IdverifyInfraError("idverify contract_version mismatch")
    # Shape-fence exactly what map_result dereferences: a verifier returning
    # {"verified": true, "identities": [null]} must surface as infra error,
    # never as an AttributeError -> user-facing 500 after a paid OTP.
    if not isinstance(out.get("verified"), bool):
        raise IdverifyInfraError("idverify 'verified' was not a boolean")
    ids = out.get("identities", [])
    if not isinstance(ids, list) or any(not isinstance(i, dict) for i in ids):
        raise IdverifyInfraError(
            "idverify 'identities' was not a list of objects")
    return out


def _mask_name(name: str) -> str:
    """§10.2 masking style: 'Ravi Kumar' -> 'R*** K***'. Only masked names may
    cross into signup responses or session payloads."""
    parts = [p for p in str(name or "").split() if p]
    return " ".join(p[0] + "***" for p in parts) or "***"


def _choices(ids: list[dict]) -> list[dict]:
    """The §8.4 pause union member's choice rows: id_ref (verifier-supplied,
    else a stable positional fallback), MASKED name, id_type, is_minor."""
    out = []
    for n, ident in enumerate(ids, start=1):
        out.append({"id_ref": ident.get("id_ref") or f"id-{n}",
                    "name_masked": _mask_name(ident.get("name", "")),
                    "id_type": ident.get("id_type") or ident.get("type")
                    or "unknown_id_type",
                    "is_minor": bool(ident.get("is_minor"))})
    return out


def map_result(result: dict, *, email: str) -> IdentityOutcome:
    """Mapping per §10.2/§10.3. Exactly one NON-minor identity -> tier2;
    MULTIPLE identities -> PAUSE with masked choices (user picks which
    identity this account is for); exactly one MINOR identity ->
    guardian-managed tier2, no pause; zero/false -> verified:false tier1.
    Multi-identity payloads expose MASKED choices only — raw names/types/
    numbers never leave this function."""
    ids = result.get("identities", [])
    if result.get("verified") and len(ids) == 1 and not ids[0].get("is_minor"):
        return IdentityOutcome("tier2_identity", "auto_verified", None, None)
    if result.get("verified") and len(ids) > 1:
        return IdentityOutcome("tier1_phone", "pending_identity",
                               "choose_identity", None,
                               pause_choices=_choices(ids))
    if result.get("verified") and len(ids) == 1:
        # Single MINOR document: straight to guardian-managed Tier 2 (§8.2) —
        # the ID system's is_minor flag is honored structurally, no pause.
        return IdentityOutcome("tier2_identity", "auto_verified", None, None,
                               guardian_minor=True)
    warns = [w for w in result.get("warnings", [])
             if isinstance(w, str) and _WARN.fullmatch(w)] or ["unspecified"]
    warn = ", ".join(warns)
    return IdentityOutcome("tier1_phone", "pending_identity",
                           "auto_check_not_verified", f"verifier said no ({warn})")


def outcome_for_mode(mode: str, choice: dict | None = None,
                     payload_email: str = "") -> IdentityOutcome:
    """Entry point used by the signup router: dispatch per IDVERIFY_MODE."""
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
    # Settings pins idverify_mode to off|auto|manual at boot; this assert is
    # dead-code defense for direct callers only.
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
    """Queue an operator review row. Notification fan-out attaches in Task 11;
    manual-review INSERTs go straight to verification_reviews until then."""
    from ..db import execute
    execute("""INSERT INTO verification_reviews
               (email, payload_json, status, reason, error_detail)
               VALUES (%s, %s::jsonb, 'pending', %s, %s)""",
            (email, json.dumps(payload), reason, detail))


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
    from ..db import one, tx
    r = one("SELECT email FROM verification_reviews WHERE review_id=%s AND "
            "status='pending'", (review_id,))
    if not r:
        return False
    # ONE transaction: the review flip and the tier-2 promotion commit together
    # or not at all. A missing accounts row (rowcount != 1) raises INSIDE the
    # tx, so the review is NOT left flipped to approved over a ghost account.
    with tx() as conn:
        conn.execute("""UPDATE verification_reviews
                        SET status=%s, reviewed_by=%s, decided_at=now()
                        WHERE review_id=%s""", (decision, reviewer, review_id))
        if decision == "approved":
            cur = conn.execute(
                """UPDATE accounts SET tier='tier2_identity',
                     verification='manual_verified', id_source='manual',
                     updated_at=now() WHERE email=%s""", (r["email"],))
            if cur.rowcount != 1:
                raise AccountMissingForReview(
                    f"no accounts row for reviewed address {r['email']}")
    return True
