"""Regression tests for the U2 host-import guard (api/app/config.py).

The guard exists because importing app.* with the repo .env discoverable from
the CWD once echoed every secret through a Settings ValidationError — two full
rotation cycles overnight. These pins keep it from silently regressing.
Detection models the leak vector (.env discoverable from cwd/ancestors), NOT
containerhood: GitHub Codespace hosts are themselves dev containers, so a
/.dockerenv heuristic is blind exactly at the incident site (found live during
this wave's verification and replaced).
"""
import os
import subprocess
import sys
from pathlib import Path

from app.config import _host_settings_import_blocked, _repo_env_discoverable

API_DIR = Path(__file__).resolve().parent.parent


def _tree_with_env(tmp_path: Path) -> Path:
    (tmp_path / "repo").mkdir()
    (tmp_path / "repo" / ".env").write_text("KEY=val\n")
    (tmp_path / "repo" / "api").mkdir()
    return tmp_path / "repo" / "api"


def test_env_in_cwd_or_ancestor_is_discoverable(tmp_path):
    api = _tree_with_env(tmp_path)
    assert _repo_env_discoverable(str(api))            # ancestor .env
    assert _repo_env_discoverable(str(tmp_path / "repo"))  # cwd .env itself
    clean = tmp_path / "elsewhere"
    clean.mkdir()
    assert not _repo_env_discoverable(str(clean))      # no .env chain: safe


def test_host_import_blocked_without_pytest(tmp_path, monkeypatch):
    # The U2 shape: fresh interpreter on a repo checkout. Simulated via a
    # temp repo tree so the assertion cannot depend on THIS checkout's layout.
    monkeypatch.delenv("SOVEREIGN_ALLOW_HOST_SETTINGS", raising=False)
    assert _host_settings_import_blocked(start=str(_tree_with_env(tmp_path)),
                                         modules=set())


def test_clean_cwd_is_allowed(tmp_path):
    # No .env anywhere up the chain -> pydantic would find nothing anyway;
    # importing is harmless and must not be blocked.
    clean = tmp_path / "clean"
    clean.mkdir()
    assert not _host_settings_import_blocked(start=str(clean), modules=set())


def test_pytest_exempt_and_env_override(monkeypatch):
    monkeypatch.delenv("SOVEREIGN_ALLOW_HOST_SETTINGS", raising=False)
    # The suite itself imports app.* on the host by design...
    assert not _host_settings_import_blocked(modules={"pytest"})
    # ...and a deliberate host-side probe can still opt in via the env var.
    monkeypatch.setenv("SOVEREIGN_ALLOW_HOST_SETTINGS", "1")
    assert not _host_settings_import_blocked(modules=set())


def test_subprocess_host_import_raises_clear_error():
    # Truest simulation of the crime scene: REAL fresh interpreter (no pytest
    # in sys.modules) importing the module from this repo's api dir — which
    # has .env two levels up. Must fail loudly BEFORE any Settings class even
    # gets defined.
    env = {k: v for k, v in os.environ.items()
           if k != "SOVEREIGN_ALLOW_HOST_SETTINGS"}
    r = subprocess.run([sys.executable, "-c", "import app.config"],
                       cwd=API_DIR, env=env, capture_output=True, text=True)
    assert r.returncode != 0, "host-side import must be refused"
    assert "Refusing to load app settings" in r.stderr
    assert "SOVEREIGN_ALLOW_HOST_SETTINGS" in r.stderr


def test_subprocess_override_flag_allows_deliberate_host_use():
    # Positive control: same import WITH the explicit escape hatch succeeds
    # (plain import defines the Settings class only; nothing validates yet).
    env = dict(os.environ)
    env["SOVEREIGN_ALLOW_HOST_SETTINGS"] = "1"
    r = subprocess.run([sys.executable, "-c", "import app.config; print('ok')"],
                       cwd=API_DIR, env=env, capture_output=True, text=True)
    assert r.returncode == 0 and "ok" in r.stdout
