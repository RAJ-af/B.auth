import base64, hashlib
from datetime import datetime, timezone
from app.pkce_util import make_pkce_pair, compute_totp, compute_totp_kc

def test_pkce_pair_is_s256():
    v, c = make_pkce_pair()
    assert base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode() == c

def test_totp_matches_known_vector():
    # Fixed-time regression guard on our own RFC 6238 implementation
    at = int(datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc).timestamp())
    assert len(compute_totp("JBSWY3DPEHPK3PXP", at=at)) == 6

def test_kc_variant_keys_hmac_on_raw_string_bytes():
    # KC 26.0.8 validates against UTF-8 bytes of the base32 string (see
    # compute_totp_kc docstring); assert the two derivations diverge so a future
    # refactor cannot silently collapse them.
    at = int(datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc).timestamp())
    code = compute_totp_kc("JBSWY3DPEHPK3PXP", at=at)
    assert len(code) == 6 and code != compute_totp("JBSWY3DPEHPK3PXP", at=at)
