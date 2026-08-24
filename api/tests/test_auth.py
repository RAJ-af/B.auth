import time, jwt as pyjwt, pytest
from tests.mock_jwks import make_jwks_server, mint
from app.auth import JWTVerifier, AuthError

ISSUER = "http://keycloak:8080/realms/sovereign"
AUD = "sovereign-mail-api"

@pytest.fixture(scope="module")
def jwks():
    h = make_jwks_server(); yield h; h["server"].shutdown()

def claims(**over):
    now = int(time.time())
    base = {"exp": now + 300, "iss": ISSUER, "aud": AUD, "sub": "u-123",
            "email": "alice@sovereign.mail", "preferred_username": "alice@sovereign.mail"}
    base.update(over); return base

def test_valid_token_verifies(jwks):
    v = JWTVerifier(ISSUER, AUD, jwks_url=jwks["url"])
    out = v.verify(mint(jwks, claims()))
    assert out["email"].endswith("@sovereign.mail")

def test_bad_signature_rejected(jwks):
    v = JWTVerifier(ISSUER, AUD, jwks_url=jwks["url"])
    other = make_jwks_server("other-key")  # different keypair, same URL? no—its own server
    with pytest.raises(AuthError): v.verify(mint(other, claims()))
    other["server"].shutdown()

def test_expired_rejected(jwks):
    v = JWTVerifier(ISSUER, AUD, jwks_url=jwks["url"])
    with pytest.raises(AuthError): v.verify(mint(jwks, claims(exp=int(time.time()) - 10)))

def test_wrong_aud_rejected(jwks):
    v = JWTVerifier(ISSUER, AUD, jwks_url=jwks["url"])
    with pytest.raises(AuthError): v.verify(mint(jwks, claims(aud="someone-else")))

def test_unknown_kid_triggers_refetch(jwks):
    v = JWTVerifier(ISSUER, AUD, jwks_url=jwks["url"])
    assert v.verify(mint(jwks, claims(), kid=jwks["kid"]))

# Ruling 5 regression guard (Task 4 spike): the issuer STRING a token carries
# (host-facing, e.g. http://localhost:8080/...) must be validated independently of
# where the JWKS is fetched from (compose network, http://keycloak:8080/...).
def test_issuer_and_jwks_url_are_independent(jwks):
    local_iss = "http://localhost:8080/realms/sovereign"
    v = JWTVerifier(local_iss, AUD, jwks_url=jwks["url"])
    ok = mint(jwks, claims(iss=local_iss))
    assert v.verify(ok)["sub"] == "u-123"
    with pytest.raises(AuthError):
        v.verify(mint(jwks, claims(iss="http://keycloak:8080/realms/sovereign")))
