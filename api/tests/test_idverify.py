"""Runner honors the frozen contract exactly as §10.1 states."""
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from app.services import idverify as iv

# Repo-root mock script, resolved relative to THIS file so the end-to-end
# tests below exercise the real bash+heredoc+python3 subprocess path.
MOCK_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "mock-idverify.sh"

posix_e2e = pytest.mark.skipif(
    os.name != "posix" or not MOCK_SCRIPT.exists(),
    reason="end-to-end runner proof needs a POSIX host with the repo checkout")


def _e2e_settings(monkeypatch, timeout):
    monkeypatch.setattr(iv, "get_settings", lambda: type("S", (), {
        "idverify_script": str(MOCK_SCRIPT),
        "idverify_timeout_seconds": timeout})())


def _run(monkeypatch, mode, payload=None, **run_kwargs):
    calls = {}
    def fake_popen(cmd, *a, **k):
        class R:
            stdin = stdout = stderr = None
            pid = 2 ** 30        # beyond any pid_max: killpg no-ops as ESRCH
            returncode = fake_popen.rc
            def communicate(self, input=None, timeout=None):
                calls["timeout"] = timeout
                if fake_popen.hang:
                    raise subprocess.TimeoutExpired(cmd=cmd, timeout=timeout)
                return fake_popen.out, ""
        return R()
    fake_popen.rc = run_kwargs.get("rc", 0)
    fake_popen.hang = run_kwargs.get("hang", False)
    fake_popen.out = run_kwargs.get("out") or json.dumps(
        {"contract_version": 1, "verified": False, "identities": [],
         "warnings": []})
    monkeypatch.setattr(iv.subprocess, "Popen", fake_popen)
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


def test_valid_json_but_not_object_is_infra_error(monkeypatch):
    # null/[1,2]/42/"s" parse fine but would explode later on out.get(...)
    # as AttributeError -> user-facing 500; the runner must fence them.
    for blob in ("null", "[1, 2]", "42", "\"s\""):
        with pytest.raises(iv.IdverifyInfraError, match="not a JSON object"):
            _run(monkeypatch, "x", out=blob)


def test_coerced_contract_version_is_infra_error(monkeypatch):
    # True == 1 and 1.0 == 1 under ==/!=; the frozen contract wants the
    # integer literal, so the check is identity-based.
    for blob in ('{"contract_version": true}', '{"contract_version": 1.0}'):
        with pytest.raises(iv.IdverifyInfraError, match="contract_version"):
            _run(monkeypatch, "x", out=blob)


def test_non_bool_verified_is_infra_error(monkeypatch):
    # map_result branches on verified truthiness; a verifier-typed string like
    # "yes" must die at the runner boundary, not steer a tier decision.
    with pytest.raises(iv.IdverifyInfraError, match="'verified' was not"):
        _run(monkeypatch, "x", out=json.dumps(
            {"contract_version": 1, "verified": "yes", "identities": [],
             "warnings": []}))


def test_identities_with_null_entry_is_infra_error(monkeypatch):
    # {"identities":[null]} once slipped past top-level-only guards into
    # ids[0].get(...) -> AttributeError -> user-facing 500 after a paid OTP;
    # the boundary must reject any non-object entry.
    with pytest.raises(iv.IdverifyInfraError, match="list of objects"):
        _run(monkeypatch, "x", out=json.dumps(
            {"contract_version": 1, "verified": True, "identities": [None],
             "warnings": []}))


def test_timeout_is_infra_error(monkeypatch):
    def fake_popen(*a, **k):
        class R:
            stdin = stdout = stderr = None
            pid = 2 ** 30           # no such process group: killpg no-ops
            returncode = None
            attempts = 0
            def communicate(self, input=None, timeout=None):
                R.attempts += 1
                if R.attempts == 1:          # first wait: the hang
                    raise subprocess.TimeoutExpired(cmd="x", timeout=20)
                return "", ""                # post-SIGKILL reap
        return R()
    monkeypatch.setattr(iv.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(iv, "get_settings", lambda: type(
        "S", (), {"idverify_script": "/v.sh", "idverify_timeout_seconds": 20})())
    with pytest.raises(iv.IdverifyInfraError, match="timed out"):
        iv.run_auto_check({"contract_version": 1})


def test_warning_echo_is_token_filtered():
    # Only ^[a-z0-9_]{1,40}$ warnings may reach reason_detail (which lands in
    # the signup response body); everything hostile degrades to "unspecified".
    o = iv.map_result({"verified": False, "identities": [],
                       "warnings": ["upstream_infrastructure_error",
                                    "<script>alert(1)</script>", "A" * 100,
                                    None, 7]},
                      email="n@sovereign.mail")
    assert o.reason_detail == \
        "verifier said no (upstream_infrastructure_error)"


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


# --- decide_review: atomic flip + loud failure on missing accounts row -------

class _FakeCursor:
    def __init__(self, rowcount):
        self.rowcount = rowcount


class _FakeConn:
    """Stand-in for db.tx()'s connection; records every executed statement."""

    def __init__(self, promote_rowcount=1):
        self.executed: list[tuple] = []
        self.promote_rowcount = promote_rowcount

    def execute(self, q, p=()):
        self.executed.append((q, p))
        if "UPDATE accounts" in q:
            return _FakeCursor(self.promote_rowcount)
        return _FakeCursor(1)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False                      # real tx() would roll back on raise


def _fake_db(monkeypatch, conn):
    import app.db as appdb
    monkeypatch.setattr(appdb, "one",
                        lambda q, p=(): {"email": "fam@sovereign.mail"})
    monkeypatch.setattr(appdb, "tx", lambda: conn)


def test_decide_review_approval_promotes_and_returns_true(monkeypatch):
    conn = _FakeConn(promote_rowcount=1)
    _fake_db(monkeypatch, conn)
    assert iv.decide_review(7, "approved", "op@sovereign.mail") is True
    assert len(conn.executed) == 2        # review flip + promotion, one tx
    assert any("UPDATE accounts" in q for q, _ in conn.executed)


def test_decide_review_missing_account_fails_loud_not_flipped(monkeypatch):
    """Approval over a ghost account must RAISE (router -> 409), and because
    the raise happens inside tx(), the review is never left 'approved'."""
    conn = _FakeConn(promote_rowcount=0)   # UPDATE accounts matched nothing
    _fake_db(monkeypatch, conn)
    with pytest.raises(iv.AccountMissingForReview, match="no accounts row"):
        iv.decide_review(7, "approved", "op@sovereign.mail")


def test_decide_review_rejection_touches_no_accounts_row(monkeypatch):
    conn = _FakeConn()
    _fake_db(monkeypatch, conn)
    assert iv.decide_review(7, "rejected", "op@sovereign.mail") is True
    assert not any("UPDATE accounts" in q for q, _ in conn.executed)


def test_decide_review_unknown_or_decided_is_false(monkeypatch):
    import app.db as appdb
    monkeypatch.setattr(appdb, "one", lambda q, p=(): None)
    monkeypatch.setattr(appdb, "tx", lambda: _FakeConn())
    assert iv.decide_review(99, "approved", "op") is False


# --- end-to-end: the REAL script through bash+heredoc+python3 ---------------

_E2E_PAYLOAD = {"contract_version": 1, "full_name": "A B",
                "document_type": "national_id", "id_number": "X1234567",
                "consent_selfie": True}


@posix_e2e
def test_e2e_real_script_verified_single(monkeypatch):
    # Proves the argv payload passthrough survives the real bash -> heredoc ->
    # python3 pipeline: the submitted document_type/full_name come back in a
    # masked identity, and exit 0 is parsed as a RESULT, not an error.
    # Ceiling is production-like: success path must never approach it, and
    # process spawn on constrained hosts (PRoot/ARM) can cost ~1-2s.
    _e2e_settings(monkeypatch, timeout=20)
    monkeypatch.setenv("MOCK_IDVERIFY_MODE", "verified_single")
    out = iv.run_auto_check(dict(_E2E_PAYLOAD))
    assert out["verified"] is True
    assert len(out["identities"]) == 1
    ident = out["identities"][0]
    assert ident["type"] == "national_id" and ident["name"] == "A B"
    assert ident["number_masked"].startswith("••••")   # masking held in transit


@posix_e2e
def test_e2e_mock_slow_mode_times_out_as_infra_error(monkeypatch):
    # The mock's slow branch sleeps 120s inside the child; the runner's
    # ceiling must surface as IdverifyInfraError, never as a raw TimeoutExpired.
    # 10s >> spawn latency on constrained hosts yet << the 120s sleep, so the
    # timeout is still guaranteed to fire.
    _e2e_settings(monkeypatch, timeout=10)
    monkeypatch.setenv("MOCK_IDVERIFY_MODE", "slow")
    with pytest.raises(iv.IdverifyInfraError, match="timed out"):
        iv.run_auto_check({"contract_version": 1})


@posix_e2e
def test_e2e_timeout_kills_whole_process_tree(monkeypatch, tmp_path):
    """REAL TREE-death proof. The verifier forks a grandchild that records its
    pid in $GUARD then sleeps 120s alongside its 120s-sleeping parent bash.
    After the runner's 1s timeout BOTH must be gone — the pre-Popen runner
    left exactly such grandchildren orphaned (ppid=1) past 80s."""
    script = tmp_path / "hung-verifier.sh"
    script.write_text(
        '#!/usr/bin/env bash\n'
        "python3 -c \"import os, pathlib, time;"
        "pathlib.Path(os.environ['GUARD']).write_text(str(os.getpid()));"
        "time.sleep(120)\" &\n"
        "sleep 120\n")
    script.chmod(0o755)
    guard = tmp_path / "guard.pid"
    monkeypatch.setenv("GUARD", str(guard))
    monkeypatch.setattr(iv, "get_settings", lambda: type("S", (), {
        "idverify_script": str(script),
        # 6s: comfortably above process-spawn latency on constrained hosts
        # (PRoot/ARM measured ~1-2s) so the grandchild always gets to record
        # its pid, yet far below the 120s sleeps, so the kill still fires.
        "idverify_timeout_seconds": 6})())
    with pytest.raises(iv.IdverifyInfraError, match="timed out"):
        iv.run_auto_check({"contract_version": 1})
    # The grandchild had the whole ceiling window to record its pid.
    deadline = time.monotonic() + 5.0
    while not guard.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert guard.exists(), "grandchild never wrote its pid"
    pid = int(guard.read_text().strip())
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break                        # grandchild is gone: tree kill proven
        time.sleep(0.05)
    else:
        # A SIGKILLed orphan can linger briefly as an unreaped zombie, for
        # which os.kill(pid, 0) still succeeds; only that state counts as dead.
        try:
            stat = open(f"/proc/{pid}/stat", "rb").read()
            state = stat.rsplit(b")", 1)[1].split()[0]
        except OSError:
            state = b"?"
        assert state == b"Z", f"grandchild {pid} SURVIVED the process-group kill"
