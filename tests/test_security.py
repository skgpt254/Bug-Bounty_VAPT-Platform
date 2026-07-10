import time

from app.config import is_public_http_target, settings
from app.core.scope import UnsafeScopeRegexError, validate_scope_regex
from app.core import security


def test_session_token_round_trips(monkeypatch, tmp_path):
    monkeypatch.setattr(security, "_SECRET_FILE", tmp_path / ".session_secret")
    token = security.make_session_token()
    assert security.verify_session_token(token)


def test_session_token_rejects_tampered_signature(monkeypatch, tmp_path):
    monkeypatch.setattr(security, "_SECRET_FILE", tmp_path / ".session_secret")
    token = security.make_session_token()
    expiry, _sig = token.split(".", 1)
    forged = f"{expiry}.deadbeef"
    assert not security.verify_session_token(forged)


def test_session_token_rejects_expired(monkeypatch, tmp_path):
    monkeypatch.setattr(security, "_SECRET_FILE", tmp_path / ".session_secret")
    expired = f"{int(time.time()) - 10}.{security._sign(str(int(time.time()) - 10))}"
    assert not security.verify_session_token(expired)


def test_auth_enabled_reflects_app_password(monkeypatch):
    monkeypatch.setattr(settings, "app_password", "")
    assert not security.auth_enabled()
    monkeypatch.setattr(settings, "app_password", "secret123")
    assert security.auth_enabled()


def test_ssrf_guard_rejects_private_and_loopback_targets():
    assert not is_public_http_target("http://127.0.0.1/hook")
    assert not is_public_http_target("http://localhost:8000/hook")
    assert not is_public_http_target("http://10.0.0.5/hook")
    assert not is_public_http_target("http://169.254.169.254/latest/meta-data/")
    assert not is_public_http_target("ftp://example.com/hook")


def test_ssrf_guard_allows_public_https():
    assert is_public_http_target("https://hooks.slack.com/services/T000/B000/xxx")


def test_scope_regex_rejects_redos_shape():
    try:
        validate_scope_regex(r"(a+)+$")
        assert False, "expected UnsafeScopeRegexError"
    except UnsafeScopeRegexError:
        pass


def test_scope_regex_accepts_normal_pattern():
    validate_scope_regex(r"(^|\.)example\.com$")  # should not raise


def test_scope_regex_rejects_overlong_pattern():
    try:
        validate_scope_regex("a" * 1000)
        assert False, "expected UnsafeScopeRegexError"
    except UnsafeScopeRegexError:
        pass


def test_workspace_slug_prevents_path_traversal():
    assert ".." not in settings.safe_workspace_slug("../../etc/passwd")
    assert "/" not in settings.safe_workspace_slug("/etc/passwd")
    assert settings.safe_workspace_slug("My Cool Program!") == "My_Cool_Program"
