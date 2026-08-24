import time, pytest, httpx
from app import keycloak as kc
from app.auth import AuthError

# Discovery document as Keycloak advertises it under the Ruling 5 hostname pin:
# absolute endpoint URLs point at the HOST-facing frontend (localhost:<port>),
# unreachable from inside the compose network. The advertised token_endpoint
# here is an adversarial host that must NEVER be contacted server-side (Ruling 5b).
DISCOVERY = {"authorization_endpoint": "http://kc.test/auth",
             "token_endpoint": "http://adversary.invalid/token"}

TOKEN_PATH = "/realms/sovereign/protocol/openid-connect/token"

@pytest.fixture
def fake_upstream(monkeypatch):
    calls = {}
    def handler(request: httpx.Request) -> httpx.Response:
        calls["last"] = request
        # Discovery + token are served ONLY at the explicit settings-derived
        # network paths on the keycloak host (defaults: http://keycloak:8080,
        # realm sovereign). Anything else — including the advertised
        # adversary.invalid endpoint — gets 404.
        if request.url.host == "keycloak" and \
           request.url.path == "/realms/sovereign/.well-known/openid-configuration":
            return httpx.Response(200, json=DISCOVERY)
        if request.url.host == "keycloak" and request.url.path == TOKEN_PATH:
            if b"code=rejected" in request.content:  # grant rejection branch
                return httpx.Response(400, json={"error": "invalid_grant"})
            return httpx.Response(200, json={"access_token": "at", "refresh_token": "rt",
                                             "id_token": "it", "expires_in": 300})
        return httpx.Response(404)
    transport = httpx.MockTransport(handler)
    # Factory must yield a FRESH client per call (production semantics): the
    # code under test uses clients as context managers, which closes them —
    # sharing one instance would fail the second request with
    # "Cannot reopen a client instance".
    monkeypatch.setattr(kc, "_client_factory",
                        lambda: httpx.Client(transport=transport))
    kc._discovery_cache.clear()
    return calls

def test_authorize_url_contains_pkce_params(fake_upstream):
    url = kc.build_authorize_url(DISCOVERY, "http://localhost:8000/auth/callback",
                                 "st1", "n1", "cc1")
    assert "response_type=code" in url and "code_challenge=cc1" in url
    assert "code_challenge_method=S256" in url and "state=st1" in url

def test_state_store_ttl(fake_upstream):
    st = kc.LoginStateStore(ttl_seconds=600)
    st.put("s1", {"verifier": "v"})
    assert st.pop("s1")["verifier"] == "v"
    assert st.pop("s1") is None          # single-use
    st.put("s2", {"verifier": "v", "t": time.time() - 999})
    assert st.pop("s2") is None          # expired

def test_exchange_happy_path(fake_upstream):
    d = kc.get_discovery()
    out = kc.exchange_code(d, "the-code", {"verifier": "vv", "redirect_uri": "http://x/cb"})
    assert out["access_token"] == "at"
    body = fake_upstream["last"].content.decode()
    assert "grant_type=authorization_code" in body and "code_verifier=vv" in body

# Ruling 5b regression guard (Task 4 spike): post-spike, discovery advertises
# host-facing localhost URLs that are unreachable from inside containers. The
# server-side exchange MUST derive its token endpoint from Settings instead of
# following the advertised absolute URL. The fixture serves tokens only at the
# explicit network path, so any implementation that follows discovery gets a
# 404 from adversary.invalid and fails into AuthError.
def test_exchange_ignores_advertised_token_endpoint(fake_upstream):
    d = kc.get_discovery()
    assert d["token_endpoint"] == "http://adversary.invalid/token"
    out = kc.exchange_code(d, "the-code",
                           {"verifier": "vv", "redirect_uri": "http://x/cb"})
    assert out["access_token"] == "at"
    last = fake_upstream["last"]
    assert last.url.host == "keycloak"
    assert last.url.path == TOKEN_PATH

def test_exchange_rejection_maps_to_auth_error(fake_upstream):
    d = kc.get_discovery()
    with pytest.raises(AuthError) as ei:
        kc.exchange_code(d, "rejected", {"verifier": "vv", "redirect_uri": "http://x/cb"})
    assert ei.value.status_code == 401
