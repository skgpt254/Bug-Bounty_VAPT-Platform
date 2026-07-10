from datetime import datetime

from pydantic import BaseModel, Field


class ProgramCreate(BaseModel):
    name: str
    root_domain: str
    scope_regex: str
    out_of_scope_regex: str = ""
    monitoring_enabled: bool = False
    monitoring_interval_minutes: int = Field(default=360, ge=15)
    webhook_url: str = ""


class ProgramOut(BaseModel):
    id: int
    name: str
    root_domain: str
    scope_regex: str
    out_of_scope_regex: str
    monitoring_enabled: bool
    monitoring_interval_minutes: int
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanTrigger(BaseModel):
    mode: str = "full"  # "full" | "incremental"


class ScanRunOut(BaseModel):
    id: int
    program_id: int
    mode: str
    status: str
    started_at: datetime
    finished_at: datetime | None
    phases_run: str
    error: str
    wildcard_dns: bool = False

    model_config = {"from_attributes": True}


class FindingOut(BaseModel):
    id: int
    finding_type: str
    severity: str
    target: str
    name: str
    detail: str
    confidence: str = "confirmed"
    is_new: bool
    first_seen_at: datetime

    model_config = {"from_attributes": True}


class DiffOut(BaseModel):
    baseline_scan_id: int | None
    current_scan_id: int
    new_subdomains: list[str]
    removed_subdomains: list[str]
    new_endpoints: list[str]
    new_findings: list[FindingOut]
