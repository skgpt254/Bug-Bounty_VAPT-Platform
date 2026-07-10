import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    researcher_name: str = "researcher"
    researcher_contact: str = "security-research@example.com"

    global_rate_limit: float = 5.0
    workspace_dir: str = "./workspaces"

    database_url: str = "sqlite+aiosqlite:///./bugbounty.db"

    # ---- OSINT / passive-source API keys — every one of these is optional.
    # Sources that need a key simply skip themselves (logged, not fatal) if
    # it isn't set. See app/core/phases/passive_recon.py and enrichment.py
    # for what each key unlocks.
    github_token: str = ""            # GitHub code search for leaked subdomains
    shodan_api_key: str = ""          # InternetDB + host search, favicon-hash pivoting
    censys_api_id: str = ""           # Censys Search v2 (host/cert search)
    censys_api_secret: str = ""
    securitytrails_api_key: str = ""  # historical DNS + subdomain enumeration
    virustotal_api_key: str = ""      # passive DNS + subdomain enumeration
    urlscan_api_key: str = ""         # urlscan.io search (works unauthenticated too, key raises quota)
    chaos_api_key: str = ""           # ProjectDiscovery Chaos dataset
    binaryedge_api_key: str = ""      # BinaryEdge passive DNS/subdomains
    leakix_api_key: str = ""          # LeakIX exposed-service search

    alert_webhook_url: str = ""

    enable_scheduler: bool = True
    enforce_scope: bool = True

    # ---- Access control ----
    # If set, every request (API + dashboard) must present it. JSON API:
    # `X-API-Key` header. Dashboard: a login form sets a signed session
    # cookie. Leave blank only for a strictly local/loopback deployment.
    app_password: str = ""
    session_secret: str = ""  # auto-generated at first run if left blank; see security.py

    # Wordlists — point these at SecLists if installed, otherwise the built-in
    # fallback wordlists in app/wordlists/ are used (smaller, no dependency).
    seclists_dir: str = "/usr/share/wordlists/seclists"

    @property
    def workspace_path(self) -> Path:
        p = Path(self.workspace_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def bb_header(self) -> dict[str, str]:
        """Attribution header sent on every active request, per bug-bounty norms."""
        return {
            "X-Bug-Bounty": f"researcher={self.researcher_name}; contact={self.researcher_contact}"
        }

    def safe_workspace_slug(self, name: str) -> str:
        """Collapse an arbitrary program name into a filesystem-safe slug.
        Prevents path traversal (`../../etc`) or absolute-path injection
        (`/etc/passwd`) via a program name into workspace_path.
        """
        slug = re.sub(r"[^a-zA-Z0-9_-]+", "_", name).strip("_")
        return slug[:80] or "program"


def is_public_http_target(url: str) -> bool:
    """SSRF guard for anything the app posts to based on user input (webhook
    URLs, etc.): only plain https/http to a public, non-loopback,
    non-link-local, non-private hostname/IP is allowed.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host:
        return False
    if host in ("localhost",) or host.endswith(".local"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    except ValueError:
        pass  # hostname, not a literal IP — fine, DNS-level SSRF (rebinding) is out of scope for this guard
    return True


settings = Settings()
