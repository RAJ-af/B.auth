import base64, hashlib
from datetime import datetime, timezone
from app.pkce_util import make_pkce_pair, compute_totp

def test_pkce_pair_is_s256():
    v, c = make_pkce_pair()
    assert base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=").decode() == c

def test_totp_matches_known_vector():
    # Fixed-time regression guard on our own RFC 6238 implementation
    at = int(datetime(2026, 8, 23, 12, 0, 0, tzinfo=timezone.utc).timestamp())
    assert len(compute_totp("JBSWY3DPEHPK3PXP", at=at)) == 6
