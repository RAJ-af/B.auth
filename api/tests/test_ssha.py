from app.ssha_util import ssha, verify_ssha


def test_format_and_roundtrip():
    stored = ssha("correct horse battery staple")
    assert stored.startswith("{SSHA}")
    assert verify_ssha("correct horse battery staple", stored)


def test_wrong_password_fails():
    stored = ssha("secret-one")
    assert not verify_ssha("secret-two", stored)


def test_salts_are_fresh():
    assert ssha("x") != ssha("x")          # same password, different salt