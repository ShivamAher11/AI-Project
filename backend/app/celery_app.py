import os

from celery import Celery


celery_app = Celery(
    "analysis_jobs",
    broker=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    include=["worker.tasks"],
)
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_ignore_result=True,
    task_track_started=True,
    task_acks_late=True,
    worker_pool="prefork",
    worker_concurrency=1,
    worker_prefetch_multiplier=1,
    task_default_queue="analyses",
    task_routes={"worker.tasks.analyze": {"queue": "analyses"}},
    broker_connection_retry_on_startup=True,
)
