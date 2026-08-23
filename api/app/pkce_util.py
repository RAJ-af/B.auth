"""PKCE + TOTP helpers shared by browserless login and smoke tests."""
import base64, hashlib, secrets

def make_pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge

def compute_totp(secret_b32: str, at: int | None = None) -> str:
    import struct, time, hmac
    idx = int(at if at is not None else time.time()) // 30
    key = base64.b32decode(secret_b32, casefold=True)
    msg = struct.pack(">Q", idx)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code = (int.from_bytes(digest[o:o+4], "big") & 0x7FFFFFFF) % 10**6
    return f"{code:06d}"
