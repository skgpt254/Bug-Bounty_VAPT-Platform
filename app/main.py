from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api import dashboard, diffs, findings, programs, scans
from app.core.scheduler import load_all_schedules, scheduler
from app.config import settings
from app.database import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("bugbounty.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    if settings.enable_scheduler:
        await load_all_schedules()
        scheduler.start()
        logger.info("continuous monitoring scheduler started")
    yield
    if scheduler.running:
        scheduler.shutdown(wait=False)


app = FastAPI(
    title="Bug Bounty & VAPT Automation Platform",
    description="Automated passive + active recon, vulnerability scanning, "
                "diffing and continuous monitoring for authorized security testing.",
    version="1.0.0",
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(programs.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(diffs.router)
app.include_router(dashboard.router)


@app.get("/api/health")
async def health():
    return {"status": "ok"}
