from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    researcher_name: str = "researcher"
    researcher_contact: str = "security-research@example.com"

    global_rate_limit: float = 5.0
    workspace_dir: str = "./workspaces"

    database_url: str = "sqlite+aiosqlite:///./bugbounty.db"

    github_token: str = ""
    alert_webhook_url: str = ""

    enable_scheduler: bool = True
    enforce_scope: bool = True

    # Wordlists — point these at SecLists if installed, otherwise the built-in
    # fallback wordlists in app/core/wordlists/ are used (smaller, no dependency).
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


settings = Settings()
