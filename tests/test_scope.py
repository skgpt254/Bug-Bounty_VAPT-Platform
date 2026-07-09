from app.core.scope import ScopeFilter
from app.models import Program


def _program(scope, out_of_scope=""):
    return Program(name="t", root_domain="example.com", scope_regex=scope, out_of_scope_regex=out_of_scope)


def test_in_scope_matches_subdomains():
    sf = ScopeFilter(_program(r".*\.example\.com$|^example\.com$"))
    assert sf.in_scope("api.example.com")
    assert sf.in_scope("example.com")
    assert not sf.in_scope("example.com.evil.net")
    assert not sf.in_scope("notexample.com")


def test_out_of_scope_overrides_scope():
    sf = ScopeFilter(_program(r".*\.example\.com$", out_of_scope=r"^mail\.example\.com$"))
    assert sf.in_scope("api.example.com")
    assert not sf.in_scope("mail.example.com")


def test_filter_list():
    sf = ScopeFilter(_program(r".*\.example\.com$"))
    hosts = ["api.example.com", "evil.com", "www.example.com"]
    assert sf.filter(hosts) == ["api.example.com", "www.example.com"]


def test_enforce_scope_disabled_allows_everything(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "enforce_scope", False)
    sf = ScopeFilter(_program(r"^nomatch$"))
    assert sf.in_scope("anything.at.all")
