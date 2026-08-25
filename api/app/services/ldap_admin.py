"""The ONLY module allowed to write to OpenLDAP (spec §4 isolation rule).

Interim posture (accepted, temporary — spec §15.1): binds as the GLOBAL admin DN.
The Phase-2 swap to a least-privilege bind DN touches exactly this file. Exposed
surface is deliberately two verbs: create_user, set_password.
"""
import logging
import re

from ldap3 import Connection, MODIFY_REPLACE, Server

from ..config import get_settings
from ..ssha_util import ssha

log = logging.getLogger(__name__)

# Mirrors the signup layer's charset exactly (controller ruling — do not widen).
_EMAIL_LOCAL = re.compile(r"[a-z0-9][a-z0-9._-]{0,30}")


class LdapUnavailable(Exception):
    pass


class AddressTaken(Exception):
    pass


def _validated_email(email: str) -> str:
    """Last-line defense before DN/filter interpolation at the write boundary."""
    local = email.partition("@")[0]
    if not _EMAIL_LOCAL.fullmatch(local) \
            or email != f"{local}@{get_settings().mail_domain}":
        raise ValueError("email rejected at LDAP write boundary")
    return email


def base_dn() -> str:
    return "dc=" + get_settings().mail_domain.replace(".", ",dc=")


def _connect():
    s = get_settings()
    try:
        return Connection(
            Server(s.ldap_host, port=389),
            user=f"cn=admin,{base_dn()}",
            password=s.ldap_admin_password,
            auto_bind=True,
            raise_exceptions=False,
        )
    except Exception as e:                      # noqa: BLE001 — wrap everything
        raise LdapUnavailable(str(e)) from e


def address_exists(email: str) -> bool:
    _validated_email(email)
    with _connect() as c:
        c.search(f"ou=people,{base_dn()}", f"(mail={email})",
                 attributes=["mail"])
        if c.response is None or c.result.get("result") != 0:
            raise LdapUnavailable(
                f"address probe failed: "
                f"{c.result.get('description', 'no response')}")
        return bool(c.entries)


def create_user(email: str, display_name: str, password: str) -> None:
    _validated_email(email)
    dn = f"mail={email},ou=people,{base_dn()}"
    with _connect() as c:
        ok = c.add(dn, ["inetOrgPerson"],
                   {"cn": display_name, "sn": display_name, "mail": email,
                    "userPassword": ssha(password)})
        desc = str(c.result.get("description", ""))
    if ok:
        log.info("ldap user created: %s", email)
        return
    if "entryAlreadyExists" in desc:
        raise AddressTaken(email)
    raise LdapUnavailable(f"ldap add failed: {desc}")


def set_password(email: str, password: str) -> None:
    _validated_email(email)
    dn = f"mail={email},ou=people,{base_dn()}"
    with _connect() as c:
        ok = c.modify(dn, {"userPassword": [(MODIFY_REPLACE, ssha(password))]})
        desc = str(c.result.get("description", ""))
    if not ok:
        raise LdapUnavailable(f"ldap modify failed: {desc}")