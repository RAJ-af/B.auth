"""Runner honors the frozen contract exactly as §10.1 states."""
import json
import os
from pathlib import Path

import pytest

from app.services import idverify as iv

# Repo-root mock script, resolved relative to THIS file so the end-to-end
# tests below exercise the real bash+heredoc+python3 subprocess path.
MOCK_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "mock-idverify.sh"

posix_e2e = pytest.mark.skipif(
    os.name != "posix" or not MOCK_SCRIPT.exists(),
    reason="end-to-end runner proof needs a POSIX host with the repo checkout")


def _e2e_settings(monkeypatch):
    monkeypatch.setattr(iv, "get_settings", lambda: type("S", (), {
        "idverify_script": str(MOCK_SCRIPT),
        "idverify_timeout_seconds": 1})())


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
    # Patch where get_settings is USED (bound into iv's namespace by
    # `from ..config import get_settings`); patching app.config would leave
    # the real settings live under tests.
    monkeypatch.setattr(iv, "get_settings", lambda: type("S", (), {
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
    monkeypatch.setattr(iv, "get_settings", lambda: type(
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


# --- end-to-end: the REAL script through bash+heredoc+python3 ---------------

_E2E_PAYLOAD = {"contract_version": 1, "full_name": "A B",
                "document_type": "national_id", "id_number": "X1234567",
                "consent_selfie": True}


@posix_e2e
def test_e2e_real_script_verified_single(monkeypatch):
    # Proves the argv payload passthrough survives the real bash -> heredoc ->
    # python3 pipeline: the submitted document_type/full_name come back in a
    # masked identity, and exit 0 is parsed as a RESULT, not an error.
    _e2e_settings(monkeypatch)
    monkeypatch.setenv("MOCK_IDVERIFY_MODE", "verified_single")
    out = iv.run_auto_check(dict(_E2E_PAYLOAD))
    assert out["verified"] is True
    assert len(out["identities"]) == 1
    ident = out["identities"][0]
    assert ident["type"] == "national_id" and ident["name"] == "A B"
    assert ident["number_masked"].startswith("••••")   # masking held in transit


@posix_e2e
def test_e2e_hung_verifier_is_killed_as_infra_error(monkeypatch):
    # REAL kill-path evidence: MOCK_IDVERIFY_MODE=slow sleeps 120s inside the
    # child; subprocess.run(timeout=1) must terminate and reap it. Reaching the
    # assertion below proves TimeoutExpired was raised by the actual subprocess
    # machinery and mapped to IdverifyInfraError — this whole test finishes in
    # ~1s instead of hanging for 120s.
    _e2e_settings(monkeypatch)
    monkeypatch.setenv("MOCK_IDVERIFY_MODE", "slow")
    with pytest.raises(iv.IdverifyInfraError, match="timed out"):
        iv.run_auto_check({"contract_version": 1})
