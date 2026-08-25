import os

# Tests that exercise base_dn() derive the DN from Settings.mail_domain.
# Default is "sovereign.mail"; LDAP-admin tests expect "test.mail" to match
# their hard-coded @test.mail addresses. Must be set before any app module is
# imported because app.main calls get_settings() at import time (lru_cache).
os.environ["MAIL_DOMAIN"] = "test.mail"

# Smoke-time overrides (FAMILY_LINK_COOLDOWN_HOURS=0 etc.) live in the host
# .env that live-run harnesses export; pin the suite to defaults so timing
# assertions (48h cooldown) stay deterministic regardless of ambient env.
os.environ["FAMILY_LINK_COOLDOWN_HOURS"] = "48"
os.environ["RECOVERY_MIN_DWELL_SECONDS"] = "600"

import pytest
from fastapi.testclient import TestClient
from app.main import create_app


@pytest.fixture
def client():
    return TestClient(create_app())
