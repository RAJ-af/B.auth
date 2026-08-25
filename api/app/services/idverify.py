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