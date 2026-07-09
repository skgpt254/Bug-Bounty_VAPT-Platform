import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.database import Base
from app.core import diff_engine
from app.models import Program, ScanRun, ScanStatus, ScanMode, Subdomain, Finding


@pytest.mark.asyncio
async def test_diff_marks_new_assets_and_findings_only_on_second_run():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)

    async with Session() as session:
        program = Program(name="p", root_domain="example.com", scope_regex=".*")
        session.add(program)
        await session.commit()
        await session.refresh(program)

        # --- run 1: baseline ---
        run1 = ScanRun(program_id=program.id, mode=ScanMode.FULL, status=ScanStatus.COMPLETED)
        session.add(run1)
        await session.commit()
        await session.refresh(run1)

        session.add(Subdomain(program_id=program.id, scan_run_id=run1.id, hostname="api.example.com"))
        session.add(Finding(
            program_id=program.id, scan_run_id=run1.id, finding_type="nuclei", severity="medium",
            target="https://api.example.com", name="old finding",
            fingerprint=diff_engine.fingerprint("nuclei", "https://api.example.com", "old finding"),
        ))
        await session.commit()

        diff1 = await diff_engine.compute_diff(session, program, run1)
        assert diff1.baseline_scan_id is None  # first scan — no baseline yet
        assert diff1.new_findings == []        # never alert-worthy on day one

        # --- run 2: one new host, one new finding, old finding repeats ---
        run2 = ScanRun(program_id=program.id, mode=ScanMode.INCREMENTAL, status=ScanStatus.COMPLETED)
        session.add(run2)
        await session.commit()
        await session.refresh(run2)

        session.add(Subdomain(program_id=program.id, scan_run_id=run2.id, hostname="api.example.com"))
        session.add(Subdomain(program_id=program.id, scan_run_id=run2.id, hostname="new.example.com"))
        session.add(Finding(
            program_id=program.id, scan_run_id=run2.id, finding_type="nuclei", severity="medium",
            target="https://api.example.com", name="old finding",
            fingerprint=diff_engine.fingerprint("nuclei", "https://api.example.com", "old finding"),
        ))
        session.add(Finding(
            program_id=program.id, scan_run_id=run2.id, finding_type="nuclei", severity="high",
            target="https://new.example.com", name="brand new finding",
            fingerprint=diff_engine.fingerprint("nuclei", "https://new.example.com", "brand new finding"),
        ))
        await session.commit()

        diff2 = await diff_engine.compute_diff(session, program, run2)
        assert diff2.baseline_scan_id == run1.id
        assert diff2.new_subdomains == ["new.example.com"]
        assert len(diff2.new_findings) == 1
        assert diff2.new_findings[0].name == "brand new finding"

    await engine.dispose()
