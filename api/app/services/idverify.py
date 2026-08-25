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
