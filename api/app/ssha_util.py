"""{SSHA} salted-SHA-1 userPassword scheme (what OpenLDAP binds require).

Weak by modern KDF standards — accepted deliberately because the LDAP federation
binds against it; register #10 tracks stronger-scheme investigation. The API only
ever GENERATES hashes; verify_ssha exists for tests and tooling.
"""
import base64
import hashlib
import secrets


def ssha(password: str) -> str:
    salt = secrets.token_bytes(4)
    digest = hashlib.sha1(password.encode() + salt).digest()
    return "{SSHA}" + base64.b64encode(digest + salt).decode()


def verify_ssha(password: str, stored: str) -> bool:
    try:
        raw = base64.b64decode(stored.removeprefix("{SSHA}"))
        digest, salt = raw[:-4], raw[-4:]
        return secrets.compare_digest(
            hashlib.sha1(password.encode() + salt).digest(), digest)
    except Exception:
        return False