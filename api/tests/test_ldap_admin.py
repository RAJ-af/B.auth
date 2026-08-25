import pytest
from app.services import ldap_admin


class FakeConn:
    """Records ops; emulates ldap3 result semantics."""
    last = None
    def __init__(self, *a, **k):
        self.ops = []
        self.entries = []
        self.result = {}
        self.add_ok = True
        FakeConn.last = self
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def search(self, base, filt, **k):
        self.ops.append(("search", base, filt))
        self.entries = [] if "taken@test" in filt else [{"mail": filt}]
    def add(self, dn, cls, attrs):
        self.ops.append(("add", dn, cls, attrs))
        if "taken@test" in dn:
            self.result = {"description": "entryAlreadyExists"}; return False
        self.result = {"description": "success"}; return True
    def modify(self, dn, changes):
        self.ops.append(("modify", dn, changes)); return True


@pytest.fixture
def fake_conn(monkeypatch):
    monkeypatch.setattr(ldap_admin, "_connect", FakeConn)
    return FakeConn


def test_create_user_shape(fake_conn):
    ldap_admin.create_user("new@test.mail", "Test Citizen", "pw-long-enough")
    _, dn, classes, attrs = FakeConn.last.ops[-1]
    assert dn == "mail=new@test.mail,ou=people,dc=test,dc=mail"
    assert classes == ["inetOrgPerson"]
    assert attrs["mail"] == "new@test.mail"
    assert attrs["userPassword"].startswith("{SSHA}")
    assert attrs["cn"] == attrs["sn"] == "Test Citizen"


def test_duplicate_is_address_taken(fake_conn):
    with pytest.raises(ldap_admin.AddressTaken):
        ldap_admin.create_user("taken@test.mail", "X", "pw-long-enough")


def test_set_password_modifies_userpassword(fake_conn):
    ldap_admin.set_password("alice@test.mail", "brand-new-pw")
    _, dn, changes = FakeConn.last.ops[-1]
    assert dn.endswith(",ou=people,dc=test,dc=mail")
    assert changes["userPassword"][0][0] == "MODIFY_REPLACE"
    assert changes["userPassword"][0][1].startswith("{SSHA}")


# --- FIX 1: real _connect construction path (regression) ---------------------

def test_connect_binds_global_admin_dn(monkeypatch):
    """REGRESSION: _connect used to raise NameError — Connection was never
    imported, silently surfacing as LdapUnavailable. Patches ldap3 names at
    the module boundary (NOT _connect) so the real path executes."""
    captured = {}

    class FakeServer:
        def __init__(self, host, port=None):
            captured["host"], captured["port"] = host, port

    class BoundConn:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def fake_connection(server, user=None, password=None, **kw):
        captured["user"] = user
        captured["password"] = password
        return BoundConn()

    monkeypatch.setattr(ldap_admin, "Server", FakeServer)
    monkeypatch.setattr(ldap_admin, "Connection", fake_connection)

    conn = ldap_admin._connect()
    assert isinstance(conn, BoundConn)
    assert captured["user"] == f"cn=admin,{ldap_admin.base_dn()}"
    assert isinstance(captured["password"], str)   # value deliberately uninspected


# --- FIX 2: email validated before any connection attempt --------------------

@pytest.mark.parametrize("bad_email", [
    "x*)(objectClass=*@test.mail",   # LDAP filter/DN metachar payload
    "Admin@test.mail",               # uppercase local part
    "first+last@test.mail",          # '+' forbidden in local part
    "user@sovereign.mail",           # wrong domain vs Settings.mail_domain
])
def test_invalid_email_rejected_before_any_connection(monkeypatch, bad_email):
    def boom(*a, **k):
        raise AssertionError("connection attempted despite invalid email")
    monkeypatch.setattr(ldap_admin, "Server", boom)
    monkeypatch.setattr(ldap_admin, "Connection", boom)
    for call in (
        lambda: ldap_admin.create_user(bad_email, "X", "pw-long-enough"),
        lambda: ldap_admin.set_password(bad_email, "brand-new-pw"),
        lambda: ldap_admin.address_exists(bad_email),
    ):
        with pytest.raises(ValueError):
            call()


# --- FIX 3: address_exists separates outage from absence ---------------------

class StaticSearchConn:
    """Emulates a successful ldap3 search returning canned entries."""
    def __init__(self, entries):
        self.entries = entries
        self.response = list(entries)
        self.result = {"result": 0, "description": "success"}
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def search(self, base, filt, **k): pass


def test_address_exists_true_when_entry_found(monkeypatch):
    monkeypatch.setattr(ldap_admin, "_connect",
                        lambda: StaticSearchConn([{"mail": "hit"}]))
    assert ldap_admin.address_exists("taken@test.mail") is True


def test_address_exists_false_when_mailbox_free(monkeypatch):
    monkeypatch.setattr(ldap_admin, "_connect", lambda: StaticSearchConn([]))
    assert ldap_admin.address_exists("free@test.mail") is False


def test_failed_probe_raises_unavailable_not_silent_false(monkeypatch):
    class OutageConn(StaticSearchConn):
        def __init__(self):
            super().__init__([])
            self.response = None
            self.result = {"result": 53, "description": "unwillingToPerform"}
    monkeypatch.setattr(ldap_admin, "_connect", OutageConn)
    with pytest.raises(ldap_admin.LdapUnavailable):
        ldap_admin.address_exists("anyone@test.mail")