import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    # datetime.utcnow() is deprecated since 3.12; this gives the same naive
    # UTC value (compatible with the existing naive DateTime columns) via
    # the non-deprecated API.
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanMode(str, enum.Enum):
    FULL = "full"          # every phase, including slow/expensive ones
    INCREMENTAL = "incremental"  # fast passive+http diff pass, used by the scheduler


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Enum storage/DB ordering is alphabetical by member name, not by actual
# risk rank — anything that needs to sort findings by severity must use
# this map instead of ORDER BY severity (see dashboard.py, api/findings.py).
SEVERITY_RANK = {
    Severity.CRITICAL.value: 4,
    Severity.HIGH.value: 3,
    Severity.MEDIUM.value: 2,
    Severity.LOW.value: 1,
    Severity.INFO.value: 0,
}


class Program(Base):
    """A bug bounty program / VAPT engagement. The unit of scope."""

    __tablename__ = "programs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    root_domain: Mapped[str] = mapped_column(String(255))
    scope_regex: Mapped[str] = mapped_column(String(500))
    out_of_scope_regex: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    # Continuous monitoring
    monitoring_enabled: Mapped[bool] = mapped_column(default=False)
    monitoring_interval_minutes: Mapped[int] = mapped_column(Integer, default=360)
    webhook_url: Mapped[str] = mapped_column(String(500), default="")

    scan_runs: Mapped[list["ScanRun"]] = relationship(back_populates="program", cascade="all, delete-orphan")


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    mode: Mapped[ScanMode] = mapped_column(Enum(ScanMode), default=ScanMode.FULL)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.QUEUED)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    workspace_path: Mapped[str] = mapped_column(String(500), default="")
    error: Mapped[str] = mapped_column(Text, default="")
    # Which phases actually ran, comma separated — useful for the dashboard.
    phases_run: Mapped[str] = mapped_column(String(500), default="")
    # True if the root domain has a wildcard DNS record — when set, resolved
    # subdomains alone are weaker evidence of a real host (see dns_resolve.py).
    wildcard_dns: Mapped[bool] = mapped_column(default=False)

    program: Mapped["Program"] = relationship(back_populates="scan_runs")
    subdomains: Mapped[list["Subdomain"]] = relationship(back_populates="scan_run", cascade="all, delete-orphan")
    endpoints: Mapped[list["Endpoint"]] = relationship(back_populates="scan_run", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship(back_populates="scan_run", cascade="all, delete-orphan")


class Subdomain(Base):
    __tablename__ = "subdomains"
    __table_args__ = (UniqueConstraint("scan_run_id", "hostname", name="uq_subdomain_per_run"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"))
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    resolved_ip: Mapped[str] = mapped_column(String(64), default="")
    source: Mapped[str] = mapped_column(String(120), default="")  # which tool(s) found it
    is_new: Mapped[bool] = mapped_column(default=False)  # relative to previous run
    # True when the zone has wildcard DNS and this host's resolution is
    # therefore not strong evidence of a real, intentionally-provisioned
    # host — surfaced in the UI instead of silently presented as fact.
    wildcard_suspect: Mapped[bool] = mapped_column(default=False)

    scan_run: Mapped["ScanRun"] = relationship(back_populates="subdomains")


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (UniqueConstraint("scan_run_id", "url", name="uq_endpoint_per_run"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"))
    url: Mapped[str] = mapped_column(String(1000), index=True)
    status_code: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(500), default="")
    tech: Mapped[str] = mapped_column(String(500), default="")
    content_length: Mapped[int] = mapped_column(Integer, default=0)
    is_new: Mapped[bool] = mapped_column(default=False)

    scan_run: Mapped["ScanRun"] = relationship(back_populates="endpoints")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    scan_run_id: Mapped[int] = mapped_column(ForeignKey("scan_runs.id"))

    finding_type: Mapped[str] = mapped_column(String(64))  # nuclei|cors|takeover|cloud|secret|fuzz
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.INFO)
    target: Mapped[str] = mapped_column(String(1000))
    name: Mapped[str] = mapped_column(String(500))
    detail: Mapped[str] = mapped_column(Text, default="")
    # "confirmed" (tool/signature-verified, e.g. nuclei template match,
    # trufflehog-verified secret) vs "unconfirmed" (heuristic/fingerprint
    # match that can false-positive, e.g. CNAME-pattern takeover guess).
    # Surfaced in the UI so a researcher doesn't treat a guess as a fact.
    confidence: Mapped[str] = mapped_column(String(20), default="confirmed")
    # Stable dedupe key: hash of (finding_type, target, name). Used to detect
    # "new" findings across runs without relying on exact-text matching.
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    is_new: Mapped[bool] = mapped_column(default=False)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    scan_run: Mapped["ScanRun"] = relationship(back_populates="findings")


class AlertLog(Base):
    """Records what was already alerted on, so continuous monitoring never spams twice."""

    __tablename__ = "alert_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("programs.id"))
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    sent_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
