"""Regression tests for the U2 host-import guard (api/app/config.py).

The guard exists because importing app.* on a host checkout once let
Settings(extra='forbid') discover the repo .env and echo every secret through
a ValidationError — two full rotation cycles overnight. These pins keep it
from silently regressing.
"""
import os
import subprocess
import sys
from pathlib import Path

from app.config import _host_settings_import_blocked

API_DIR = Path(__file__).resolve().parent.parent


def test_container_execution_is_allowed():
    # /.dockerenv present -> never blocked, whatever sys.modules contains.
    assert not _host_settings_import_blocked(dockerenv_path="/bin/sh",
                                             modules={"pytest"})


def test_host_import_blocked_without_pytest():
    # Host checkout, fresh interpreter (no pytest in modules) -> BLOCKED.
    # This is exactly the U2 shape: `python3 -c "import app.config"` on the
    # codespace host from the repo root.
    assert _host_settings_import_blocked(modules=set())


def test_pytest_exempt_and_env_override(monkeypatch):
    # The suite itself imports app.* on the host by design...
    assert not _host_settings_import_blocked(modules={"pytest"})
    # ...and a deliberate host-side probe can still opt in via the env var.
    monkeypatch.setenv("SOVEREIGN_ALLOW_HOST_SETTINGS", "1")
    assert not _host_settings_import_blocked(modules=set())
    monkeypatch.delenv("SOVEREIGN_ALLOW_HOST_SETTINGS", raising=False)


def test_subprocess_host_import_raises_clear_error():
    # Truest simulation: a REAL fresh interpreter importing the module from
    # the api dir, no pytest anywhere in its sys.modules. Must fail loudly
    # with actionable text BEFORE any Settings class is even defined.
    env = {k: v for k, v in os.environ.items()
           if k != "SOVEREIGN_ALLOW_HOST_SETTINGS"}
    r = subprocess.run([sys.executable, "-c", "import app.config"],
                       cwd=API_DIR, env=env, capture_output=True, text=True)
    assert r.returncode != 0, "host-side import must be refused"
    assert "Refusing to load app settings OUTSIDE a container" in r.stderr
    assert "SOVEREIGN_ALLOW_HOST_SETTINGS" in r.stderr


def test_subprocess_override_flag_allows_deliberate_host_use():
    # Positive control: same import WITH the explicit escape hatch succeeds
    # (plain import defines the Settings class only; nothing validates yet).
    env = dict(os.environ)
    env["SOVEREIGN_ALLOW_HOST_SETTINGS"] = "1"
    r = subprocess.run([sys.executable, "-c", "import app.config; print('ok')"],
                       cwd=API_DIR, env=env, capture_output=True, text=True)
    assert r.returncode == 0 and "ok" in r.stdout
