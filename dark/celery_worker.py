#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DARK Distributed Celery Worker — Redis broker + PostgreSQL/Redis backend.

Run in distributed mode:
  celery -A celery_worker worker --loglevel=info --concurrency=4
"""
from __future__ import annotations

import os
import socket
import sys
from pathlib import Path
from typing import Any, Dict

APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

import engine  # noqa: E402
import enterprise_db as edb  # noqa: E402

REDIS_URL = os.environ.get("DARK_REDIS_URL", "redis://redis:6379/0")
RESULT_BACKEND = os.environ.get("DARK_RESULT_BACKEND", REDIS_URL)
POSTGRES_DSN = os.environ.get("DARK_POSTGRES_DSN", "postgresql://dark:dark@postgres:5432/dark")

try:
    from celery import Celery  # type: ignore
    CELERY_AVAILABLE = True
except ImportError:
    Celery = None
    CELERY_AVAILABLE = False

TASK_MAP = {
    "web-scan": engine.run_web_scan,
    "network-scan": engine.run_network_scan,
    "dns-recon": engine.run_dns_recon,
    "hash-crack": engine.crack_hashes,
    "cloud-audit": engine.run_cloud_audit,
    "container-audit": engine.run_container_audit,
    "sast-audit": engine.run_sast_audit,
    "api-audit": engine.run_api_audit,
    "forensics": engine.run_forensics_audit,
}


def execute_task_payload(kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    worker_id = f"worker-{socket.gethostname()}"
    edb.upsert_worker(worker_id, f"Distributed Worker ({socket.gethostname()})", active_jobs=1)
    try:
        fn = TASK_MAP.get(kind)
        if not fn:
            return {"error": f"Unknown task kind: {kind}"}
        return fn(**(payload or {}))
    finally:
        edb.upsert_worker(worker_id, f"Distributed Worker ({socket.gethostname()})", active_jobs=0)


if CELERY_AVAILABLE:
    celery_app = Celery("dark_worker", broker=REDIS_URL, backend=RESULT_BACKEND)
    celery_app.conf.update(
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        task_acks_late=True,
        worker_prefetch_multiplier=1,
    )

    @celery_app.task(name="dark.execute_job", bind=True)
    def run_distributed_job(self, kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return execute_task_payload(kind, payload)
else:
    celery_app = None
    run_distributed_job = execute_task_payload
