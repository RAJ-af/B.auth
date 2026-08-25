"""The ONLY module allowed to write to OpenLDAP (spec §4 isolation rule).

Interim posture (accepted, temporary — spec §15.1): binds as the GLOBAL admin DN.
The Phase-2 swap to a least-privilege bind DN touches exactly this file. Exposed
surface is deliberately two verbs: create_user, set_password.
"""
import logging

from ldap3 import MODIFY_REPLACE, Server

from ..config import get_settings
from ..ssha_util import ssha

log = logging.getLogger(__name__)


class LdapUnavailable(Exception):
    pass


class AddressTaken(Exception):
    pass


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
    with _connect() as c:
        c.search(f"ou=people,{base_dn()}", f"(mail={email})",
                 attributes=["mail"])
        return bool(c.entries)


def create_user(email: str, display_name: str, password: str) -> None:
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
    dn = f"mail={email},ou=people,{base_dn()}"
    with _connect() as c:
        ok = c.modify(dn, {"userPassword": [(MODIFY_REPLACE, ssha(password))]})
        desc = str(c.result.get("description", ""))
    if not ok:
        raise LdapUnavailable(f"ldap modify failed: {desc}")