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
