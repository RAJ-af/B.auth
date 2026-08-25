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
    ldap_admin.set_password("a@test.mail", "brand-new-pw")
    _, dn, changes = FakeConn.last.ops[-1]
    assert dn.endswith(",ou=people,dc=test,dc=mail")
    assert changes["userPassword"][0][0] == "MODIFY_REPLACE"
    assert changes["userPassword"][0][1].startswith("{SSHA}")