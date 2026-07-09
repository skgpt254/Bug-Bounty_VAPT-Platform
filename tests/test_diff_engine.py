from app.core.diff_engine import fingerprint


def test_fingerprint_stable():
    a = fingerprint("nuclei", "https://api.example.com/admin", "exposed admin panel")
    b = fingerprint("nuclei", "https://api.example.com/admin", "exposed admin panel")
    assert a == b


def test_fingerprint_case_insensitive():
    a = fingerprint("nuclei", "https://API.example.com/Admin", "Exposed Admin Panel")
    b = fingerprint("nuclei", "https://api.example.com/admin", "exposed admin panel")
    assert a == b


def test_fingerprint_differs_by_target():
    a = fingerprint("nuclei", "https://a.example.com/admin", "exposed admin panel")
    b = fingerprint("nuclei", "https://b.example.com/admin", "exposed admin panel")
    assert a != b


def test_fingerprint_differs_by_type():
    a = fingerprint("nuclei", "https://a.example.com/x", "same name")
    b = fingerprint("cors", "https://a.example.com/x", "same name")
    assert a != b
