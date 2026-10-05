"""Bounded, process-local background jobs with immutable polling snapshots."""

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Literal
from uuid import uuid4

from fastapi import HTTPException

DescriptionSource = Literal["auto", "advisories", "opencve"]
BatchRunner = Callable[[list[str], bool, DescriptionSource], Awaitable[list[dict[str, object]]]]
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class JobSnapshot:
    job_id: str
    status: Literal["pending", "completed", "failed"] = "pending"
    results: list[dict[str, object]] | None = None
    error_code: int | None = None
    error_message: str | None = None


@dataclass
class _Job:
    snapshot: JobSnapshot
    finished_at: float | None = None


class AnalysisJobs:
    def __init__(
        self,
        runner: BatchRunner,
        *,
        retention_seconds: float = 3600,
        capacity: int = 100,
        concurrency: int = 2,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._clock = clock
        self._runner = runner
        self._retention_seconds = retention_seconds
        self._capacity = capacity
        self._semaphore = asyncio.Semaphore(concurrency)
        self._jobs: dict[str, _Job] = {}
        self._tasks: set[asyncio.Task[None]] = set()
        self._closed = False

    def _expire(self) -> None:
        now = self._clock()
        expired = [
            job_id
            for job_id, job in self._jobs.items()
            if job.finished_at is not None and now - job.finished_at >= self._retention_seconds
        ]
        for job_id in expired:
            del self._jobs[job_id]

    def submit(
        self, cve_ids: list[str], compact: bool, description_source: DescriptionSource
    ) -> JobSnapshot:
        self._expire()
        if self._closed:
            raise HTTPException(status_code=503, detail="Analysis worker is shutting down")
        if len(self._jobs) >= self._capacity:
            raise HTTPException(status_code=503, detail="Analysis job capacity reached")
        snapshot = JobSnapshot(job_id=str(uuid4()))
        self._jobs[snapshot.job_id] = _Job(snapshot)
        task = asyncio.create_task(
            self._run(snapshot.job_id, list(cve_ids), compact, description_source),
            name=f"cve-analysis-{snapshot.job_id}",
        )
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        # This snapshot always represents acceptance, even for an instant runner.
        return snapshot

    def get(self, job_id: str) -> JobSnapshot:
        self._expire()
        job = self._jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="Analysis job not found or expired")
        return job.snapshot

    async def _run(
        self, job_id: str, cve_ids: list[str], compact: bool, description_source: DescriptionSource
    ) -> None:
        job = self._jobs[job_id]
        try:
            async with self._semaphore:
                results = await self._runner(cve_ids, compact, description_source)
            job.snapshot = JobSnapshot(job_id=job_id, status="completed", results=results)
        except asyncio.CancelledError:
            job.snapshot = JobSnapshot(
                job_id=job_id, status="failed", error_code=503,
                error_message="Analysis interrupted by server shutdown",
            )
            raise
        except HTTPException as exc:
            job.snapshot = JobSnapshot(
                job_id=job_id, status="failed", error_code=exc.status_code,
                error_message=str(exc.detail),
            )
        except Exception:
            logger.exception("Background CVE analysis failed", extra={"job_id": job_id})
            job.snapshot = JobSnapshot(
                job_id=job_id, status="failed", error_code=500,
                error_message="Analysis failed; see server logs for details",
            )
        finally:
            job.finished_at = self._clock()

    async def close(self) -> None:
        self._closed = True
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._jobs.clear()
