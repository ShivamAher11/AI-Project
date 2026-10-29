import logging
import os
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from .db import new_session
from .models import Analysis
from .storage import remove_analysis_files

logger = logging.getLogger("api.cleanup")
TERMINAL_STATES = {"COMPLETED", "PARTIAL", "FAILED", "CANCELLED"}


def cleanup_on_startup() -> None:
    """Apply the solo-mode startup TTL and stale-heartbeat sweep."""
    data_root = os.getenv("DATA_ROOT", "/data")
    ttl_hours = max(1, min(168, int(os.getenv("TTL_HOURS", "24"))))
    now = datetime.now(timezone.utc)
    expired_before = now - timedelta(hours=ttl_hours)
    stale_before = now - timedelta(seconds=90)
    with new_session() as session:
        expired = list(session.scalars(select(Analysis).where(Analysis.created_at < expired_before)))
        for analysis in expired:
            try:
                remove_analysis_files(data_root, str(analysis.id))
            except OSError:
                logger.warning("expired_analysis_file_cleanup_failed")
            session.delete(analysis)

        stale = list(
            session.scalars(
                select(Analysis).where(
                    Analysis.heartbeat_at.is_not(None),
                    Analysis.heartbeat_at < stale_before,
                    Analysis.status.not_in(TERMINAL_STATES),
                )
            )
        )
        for analysis in stale:
            analysis.status = "FAILED"
            analysis.stage = "FAILED"
            analysis.error_code = "WORKER_STALE"
            analysis.error_message = "The worker stopped reporting progress. Re-upload to try again."
            analysis.completed_at = now
        session.commit()
