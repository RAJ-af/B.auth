"""Recognized devices (spec §14): the raw device secret lives ONLY on the
client; the server keeps SHA-256 hashes. A recognized device shortens RECOVERY
(never skips OTP) and its deletion immediately voids any pending recovery that
leaned on it (§13 delete-device-voids-request).
"""
import hashlib
import secrets
import time

from ..db import execute, many, one

VOID_HOOKS: list = []          # callables taking device_hash; recovery registers here


def hash_id(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def mint() -> tuple[str, bytes]:
    raw = secrets.token_urlsafe(16)
    return raw, raw.encode()


# --- storage -----------------------------------------------------------------

def _insert_row(row: dict) -> dict:
    execute("""INSERT INTO devices (device_hash, email, label)
               VALUES (%s,%s,%s)
               ON CONFLICT (device_hash) DO UPDATE SET label=EXCLUDED.label""",
            (row["device_hash"], row["email"], row["label"]))
    return row


def _find_by_hash(h: str) -> dict | None:
    return one("""SELECT device_hash, email, label, created_at, last_seen_at
                  FROM devices WHERE device_hash=%s""", (h,))


def _rows_for(email: str) -> list[dict]:
    return many("""SELECT device_hash, label, created_at, last_seen_at
                   FROM devices WHERE email=%s ORDER BY created_at""", (email,))


def _drop_row(h: str) -> bool:
    cur = many("SELECT 1 FROM devices WHERE device_hash=%s", (h,))
    execute("DELETE FROM devices WHERE device_hash=%s", (h,))
    return bool(cur)


def _bump_seen(h: str) -> None:
    execute("UPDATE devices SET last_seen_at=now() WHERE device_hash=%s", (h,))


# --- api ----------------------------------------------------------------------

def register(email: str, label: str, raw: str) -> dict:
    row = {"device_hash": hash_id(raw), "email": email, "label": label}
    _insert_row(row)
    return row


def resolve(raw: str) -> dict | None:
    row = _find_by_hash(hash_id(raw))
    if row:
        _bump_seen(row["device_hash"])
    return row


def list_for(email: str) -> list[dict]:
    return _rows_for(email)


def fire_void(device_hash: str) -> None:
    for hook in VOID_HOOKS:
        hook(device_hash)


def delete(email: str, device_hash: str) -> bool:
    row = _find_by_hash(device_hash)
    if not row or row["email"] != email:
        return False
    fire_void(device_hash)               # BEFORE removal — §13 ordering guarantee
    return _drop_row(device_hash)
