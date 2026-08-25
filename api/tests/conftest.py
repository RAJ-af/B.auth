import os

# Tests that exercise base_dn() derive the DN from Settings.mail_domain.
# Default is "sovereign.mail"; LDAP-admin tests expect "test.mail" to match
# their hard-coded @test.mail addresses. Must be set before any app module is
# imported because app.main calls get_settings() at import time (lru_cache).
os.environ["MAIL_DOMAIN"] = "test.mail"

import pytest
from fastapi.testclient import TestClient
from app.main import create_app


@pytest.fixture
def client():
    return TestClient(create_app())
