"""
ImmuDB client for run_history tracking.

Each pipeline job appends three rows (immuDB is append-only by design):
  status='running'   → on job start  (returns job_id UUID)
  status='completed' → on success
  status='failed'    → on failure

Connection env vars (set in .env):
  IMMUDB_HOST, IMMUDB_PORT, IMMUDB_USER, IMMUDB_PASSWORD, IMMUDB_DATABASE
"""

import json
import os
import uuid
from datetime import datetime, timezone

try:
    from immudb import ImmudbClient
    _IMMUDB_AVAILABLE = True
except ImportError:
    _IMMUDB_AVAILABLE = False
    print("Warning: immudb-py not installed — run_history logging disabled.")

_TABLE = "run_history"
_client = None


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def _get_client():
    global _client
    if _client is not None:
        return _client
    if not _IMMUDB_AVAILABLE:
        return None

    host     = os.getenv("IMMUDB_HOST", "localhost")
    port     = os.getenv("IMMUDB_PORT", "3322")
    user     = os.getenv("IMMUDB_USER", "immudb")
    password = os.getenv("IMMUDB_PASSWORD", "immudb")
    database = os.getenv("IMMUDB_DATABASE", "defaultdb")

    try:
        client = ImmudbClient(f"{host}:{port}")
        client.login(user, password)
        client.useDatabase(database.encode())
        _ensure_table(client)
        _client = client
        print(f"Connected to immuDB at {host}:{port} db={database}")
        return client
    except Exception as exc:
        print(f"Warning: immuDB unavailable — run_history disabled: {exc}")
        return None


def _ensure_table(client):
    client.sqlExec(f"""
        CREATE TABLE IF NOT EXISTS {_TABLE} (
            id               INTEGER AUTO_INCREMENT,
            job_id           VARCHAR[36],
            username         VARCHAR[255],
            blob_url         VARCHAR[1024],
            technique        VARCHAR[50],
            run_config       VARCHAR[4096],
            status           VARCHAR[20],
            started_at       VARCHAR[50],
            completed_at     VARCHAR[50],
            duration_ms      INTEGER,
            output_blob_url  VARCHAR[1024],
            error_message    VARCHAR[4096],
            session_id       VARCHAR[255],
            PRIMARY KEY id
        )
    """, {})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(columns, row) -> dict:
    record = {}
    for col, val in zip(columns, row.values):
        name = col.name
        if val.null:
            record[name] = None
        elif hasattr(val, 'n') and val.n is not None:
            record[name] = val.n
        elif hasattr(val, 's') and val.s is not None:
            record[name] = val.s
        elif hasattr(val, 'b'):
            record[name] = val.b
        else:
            record[name] = None
    return record


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_run_start(username: str, blob_url: str, technique: str,
                    run_config: dict, session_id: str = None) -> str | None:
    """
    Insert a status='running' row.
    Returns a UUID job_id (used as run_id in the job response).
    Returns None if immuDB is unavailable — callers treat this as non-fatal.
    """
    client = _get_client()
    if client is None:
        return None

    job_id = str(uuid.uuid4())
    try:
        client.sqlExec(f"""
            INSERT INTO {_TABLE}
                (job_id, username, blob_url, technique, run_config,
                 status, started_at, session_id)
            VALUES
                (@job_id, @username, @blob_url, @technique, @run_config,
                 @status, @started_at, @session_id)
        """, {
            "job_id":     job_id,
            "username":   username or "",
            "blob_url":   blob_url or "",
            "technique":  technique or "",
            "run_config": json.dumps(run_config) if run_config else "{}",
            "status":     "running",
            "started_at": _now_iso(),
            "session_id": session_id or "",
        })
        return job_id
    except Exception as exc:
        print(f"immuDB write_run_start error: {exc}")
        return None


def write_run_complete(job_id: str, username: str, blob_url: str,
                       technique: str, run_config: dict, session_id: str,
                       started_at: str, output_blob_url: str,
                       duration_ms: int) -> None:
    """Insert a status='completed' row."""
    client = _get_client()
    if client is None:
        return
    try:
        client.sqlExec(f"""
            INSERT INTO {_TABLE}
                (job_id, username, blob_url, technique, run_config,
                 status, started_at, completed_at, duration_ms,
                 output_blob_url, session_id)
            VALUES
                (@job_id, @username, @blob_url, @technique, @run_config,
                 @status, @started_at, @completed_at, @duration_ms,
                 @output_blob_url, @session_id)
        """, {
            "job_id":          job_id or "",
            "username":        username or "",
            "blob_url":        blob_url or "",
            "technique":       technique or "",
            "run_config":      json.dumps(run_config) if run_config else "{}",
            "status":          "completed",
            "started_at":      started_at or "",
            "completed_at":    _now_iso(),
            "duration_ms":     duration_ms or 0,
            "output_blob_url": output_blob_url or "",
            "session_id":      session_id or "",
        })
    except Exception as exc:
        print(f"immuDB write_run_complete error: {exc}")


def write_run_fail(job_id: str, username: str, blob_url: str,
                   technique: str, run_config: dict, session_id: str,
                   started_at: str, error_message: str) -> None:
    """Insert a status='failed' row."""
    client = _get_client()
    if client is None:
        return
    try:
        client.sqlExec(f"""
            INSERT INTO {_TABLE}
                (job_id, username, blob_url, technique, run_config,
                 status, started_at, completed_at, error_message, session_id)
            VALUES
                (@job_id, @username, @blob_url, @technique, @run_config,
                 @status, @started_at, @completed_at, @error_message, @session_id)
        """, {
            "job_id":        job_id or "",
            "username":      username or "",
            "blob_url":      blob_url or "",
            "technique":     technique or "",
            "run_config":    json.dumps(run_config) if run_config else "{}",
            "status":        "failed",
            "started_at":    started_at or "",
            "completed_at":  _now_iso(),
            "error_message": error_message or "",
            "session_id":    session_id or "",
        })
    except Exception as exc:
        print(f"immuDB write_run_fail error: {exc}")


def get_latest_run(blob_url: str, username: str = None) -> dict | None:
    """
    Return the latest run_history row for blob_url (optionally filtered by
    username). Returns None if not found or immuDB is unavailable.
    """
    client = _get_client()
    if client is None:
        return None
    try:
        if username:
            result = client.sqlQuery(f"""
                SELECT id, job_id, username, blob_url, technique, run_config,
                       status, started_at, completed_at, duration_ms,
                       output_blob_url, error_message, session_id
                FROM {_TABLE}
                WHERE blob_url=@blob_url AND username=@username
                ORDER BY id DESC
                LIMIT 1
            """, {"blob_url": blob_url, "username": username})
        else:
            result = client.sqlQuery(f"""
                SELECT id, job_id, username, blob_url, technique, run_config,
                       status, started_at, completed_at, duration_ms,
                       output_blob_url, error_message, session_id
                FROM {_TABLE}
                WHERE blob_url=@blob_url
                ORDER BY id DESC
                LIMIT 1
            """, {"blob_url": blob_url})

        if not result or not result.rows:
            return None

        record = _row_to_dict(result.columns, result.rows[0])

        if record.get("run_config"):
            try:
                record["run_config"] = json.loads(record["run_config"])
            except Exception:
                pass

        return record
    except Exception as exc:
        print(f"immuDB get_latest_run error: {exc}")
        return None
