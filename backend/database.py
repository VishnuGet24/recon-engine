"""SQLite persistence for scan history."""

from __future__ import annotations

import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional


BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "recon_scans.db")

_DB_LOCK = threading.Lock()


def _get_connection() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    """Initialize SQLite schema for scan history."""
    with _DB_LOCK:
        with _get_connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_history (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    scan_mode TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    risk_score REAL,
                    risk_level TEXT,
                    cdn_provider TEXT,
                    hosting_provider TEXT,
                    status TEXT NOT NULL
                )
                """
            )
            connection.commit()


def save_scan_result(
    scan_id: str,
    target: str,
    scan_mode: str,
    timestamp: str,
    risk_score: Optional[float] = None,
    risk_level: Optional[str] = None,
    cdn_provider: Optional[str] = None,
    hosting_provider: Optional[str] = None,
    status: str = "running",
) -> None:
    """Insert or update a scan history record."""
    with _DB_LOCK:
        with _get_connection() as connection:
            connection.execute(
                """
                INSERT INTO scan_history (
                    scan_id, target, scan_mode, timestamp, risk_score,
                    risk_level, cdn_provider, hosting_provider, status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    target = excluded.target,
                    scan_mode = excluded.scan_mode,
                    timestamp = excluded.timestamp,
                    risk_score = excluded.risk_score,
                    risk_level = excluded.risk_level,
                    cdn_provider = excluded.cdn_provider,
                    hosting_provider = excluded.hosting_provider,
                    status = excluded.status
                """,
                (
                    scan_id,
                    target,
                    scan_mode,
                    timestamp,
                    risk_score,
                    risk_level,
                    cdn_provider,
                    hosting_provider,
                    status,
                ),
            )
            connection.commit()


def get_scan_history(limit: int = 100) -> List[Dict[str, Any]]:
    """Return recent scan history records ordered by timestamp descending."""
    safe_limit = max(1, min(int(limit), 500))
    with _get_connection() as connection:
        rows = connection.execute(
            """
            SELECT scan_id, target, scan_mode, timestamp, risk_score, risk_level,
                   cdn_provider, hosting_provider, status
            FROM scan_history
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    """Return one scan record by scan_id."""
    with _get_connection() as connection:
        row = connection.execute(
            """
            SELECT scan_id, target, scan_mode, timestamp, risk_score, risk_level,
                   cdn_provider, hosting_provider, status
            FROM scan_history
            WHERE scan_id = ?
            """,
            (scan_id,),
        ).fetchone()
    return dict(row) if row else None

