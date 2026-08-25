"""sovereign_app access: one psycopg connection per operation (MVP scale).

Deliberately boring: no pool, no ORM. A connection leak under load would show up
as wave-gate failures long before it matters at deployment scale (register #12
covers the production sweep). All SQL lives in the services that need it; this
module only owns connectivity and row shaping.
"""
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row

from .config import get_settings


def conn_kwargs() -> dict:
    s = get_settings()
    return {"host": s.postgres_host, "port": s.postgres_port,
            "dbname": s.sovereign_app_db, "user": s.postgres_user,
            "password": s.postgres_password}


@contextmanager
def tx():
    conn = psycopg.connect(**conn_kwargs(), row_factory=dict_row)
    try:
        with conn:                       # commits on success, rolls back on error
            yield conn
    finally:
        conn.close()


def execute(query: str, params: tuple = ()) -> None:
    with tx() as conn:
        conn.execute(query, params)


def one(query: str, params: tuple = ()) -> dict | None:
    with tx() as conn:
        return conn.execute(query, params).fetchone()


def many(query: str, params: tuple = ()) -> list[dict]:
    with tx() as conn:
        return conn.execute(query, params).fetchall()