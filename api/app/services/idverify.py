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


@dataclass
class IdentityOutcome:
    tier: str                    # tier1_phone | tier2_identity
    verification: str            # pending_identity | auto_verified | manual_pending...
    identity_status: str | None  # extra field for the /signup/complete body
    reason_detail: str | None


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
    warns = [w for w in result.get("warnings", [])
             if isinstance(w, str) and _WARN.fullmatch(w)] or ["unspecified"]
    warn = ", ".join(warns)
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
