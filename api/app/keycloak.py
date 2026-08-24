import logging, time
import httpx
from app.auth import AuthError
from app.config import get_settings

log = logging.getLogger(__name__)

class KeycloakUnavailable(Exception): pass

def _client_factory() -> httpx.Client:
    return httpx.Client(timeout=15.0)

_discovery_cache: dict = {}

def get_discovery() -> dict:
    s = get_settings()
    key = s.keycloak_base_url
    hit = _discovery_cache.get(key)
    if hit and time.time() - hit["t"] < 3600:
        return hit["d"]
    url = f"{key}/realms/{s.kc_realm}/.well-known/openid-configuration"
    try:
        with _client_factory() as c:
            d = c.get(url).raise_for_status().json()
    except Exception as e:
        log.warning("discovery failed: %s", e)
        raise KeycloakUnavailable(str(e)) from e
    _discovery_cache[key] = {"t": time.time(), "d": d}
    return d

def build_authorize_url(discovery: dict, redirect_uri: str, state: str,
                        nonce: str, code_challenge: str) -> str:
    from urllib.parse import urlencode
    q = urlencode({"response_type": "code", "client_id": get_settings().kc_app_client,
                   "redirect_uri": redirect_uri, "scope": "openid email profile",
                   "state": state, "nonce": nonce,
                   "code_challenge": code_challenge, "code_challenge_method": "S256"})
    # Asymmetry per ledger Ruling 5/5b: the authorize URL's consumer is the
    # HOST-side browser/app, where the advertised localhost frontend IS
    # reachable — so unlike exchange_code, following the discovery-advertised
    # authorization_endpoint here is correct.
    return f"{discovery['authorization_endpoint']}?{q}"

class LoginStateStore:
    def __init__(self, ttl_seconds: int = 600):
        self.ttl, self._store = ttl_seconds, {}
    def put(self, state: str, data: dict) -> None:
        # setdefault so a caller-supplied timestamp wins (lets the TTL test
        # inject an aged entry); production callers never pass "t".
        data.setdefault("t", time.time()); self._store[state] = data
    def pop(self, state: str) -> dict | None:
        d = self._store.pop(state, None)
        if not d or time.time() - d["t"] > self.ttl:
            return None
        return d

_state_store: LoginStateStore | None = None
def get_state_store() -> LoginStateStore:
    global _state_store
    _state_store = _state_store or LoginStateStore()
    return _state_store

def exchange_code(discovery: dict, code: str, state_data: dict) -> dict:
    s = get_settings()
    # Ruling 5b: NEVER follow discovery-advertised absolute URLs server-side.
    # Post-spike they point at the host-facing frontend (localhost:<port>),
    # unreachable from inside the api container; derive the network path from
    # Settings instead. The discovery parameter stays for interface stability.
    token_url = f"{s.keycloak_base_url}/realms/{s.kc_realm}/protocol/openid-connect/token"
    data = {"grant_type": "authorization_code", "client_id": s.kc_app_client,
            "code": code, "redirect_uri": state_data["redirect_uri"],
            "code_verifier": state_data["verifier"]}
    try:
        with _client_factory() as c:
            r = c.post(token_url, data=data)
    except Exception as e:
        log.warning("code exchange failed: %s", e)
        raise KeycloakUnavailable(str(e)) from e
    if r.status_code != 200:
        raise AuthError(401, f"code exchange failed ({r.status_code})")
    return r.json()
