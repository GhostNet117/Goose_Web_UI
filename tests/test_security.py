import pytest

from goose_web import security, winsec


def test_password_roundtrip():
    h = security.hash_password("Correct-Horse-9")
    assert h.startswith("scrypt$32768$8$1$")
    assert security.verify_password("Correct-Horse-9", h)
    assert not security.verify_password("correct-horse-9", h)
    assert not security.verify_password("x", None)
    assert not security.verify_password("x", "garbage")
    assert not security.needs_rehash(h)


def test_password_policy():
    assert security.password_problems("ChangeMe", 10)
    assert security.password_problems("alice2xxxx", 10, "alice2xxxx")
    assert not security.password_problems("Blue-Kettle-42", 10)
    # spec 007: 12+ characters (never lower), all four character classes
    assert "must be at least 12 characters" in security.password_problems("Blue-Kettl4", 10)
    assert security.password_problems("a very long passphrase here", 10)
    assert not security.password_problems("A very long passphrase 4 here", 10)


def test_tokens():
    t = security.new_token()
    assert len(t) >= 40
    assert security.token_hash(t) == security.token_hash(t)
    assert security.consteq("a", "a") and not security.consteq("a", "b")


def test_totp_rfc6238_vector():
    # RFC 6238 SHA1 test secret "12345678901234567890", T=59 -> 94287082 (8 digits) -> 287082 (6)
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert security.totp(secret, at=59) == "287082"
    assert security.verify_totp(secret, "287082", at=59 + 30)  # within the +-1 window
    assert not security.verify_totp(secret, "287082", at=59 + 120)
    s = security.new_totp_secret()
    assert security.verify_totp(s, security.totp(s))
    assert security.totp_uri(s, "alice").startswith("otpauth://totp/Goose%20Web%3Aalice?")


def test_rate_limiter():
    rl = security.RateLimiter(3, 60)
    assert all(rl.hit("k") for _ in range(3))
    assert not rl.hit("k")
    rl.reset("k")
    assert rl.hit("k")


@pytest.mark.parametrize("bad", ["", "..", "a/b", "CON", "_system", "x" * 80, "a b", "-x"])
def test_safe_name_rejects(bad):
    with pytest.raises(ValueError):
        security.safe_name(bad)


def test_safe_name_accepts():
    assert security.safe_name("alice.smith-2") == "alice.smith-2"


def test_winsec_reports():
    assert winsec.integrity_level() in {"low", "medium", "high", "system", "unknown", "root", "user"}
    assert isinstance(winsec.is_elevated(), bool)
    if winsec.IS_WINDOWS:
        assert winsec.current_user_sid().startswith("S-1-5-")
        sid, name = winsec.file_owner(__file__)
        assert sid.startswith("S-1-")
