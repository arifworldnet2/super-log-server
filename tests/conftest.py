"""
conftest.py - Pytest fixtures and infrastructure for Super LOG Server tests.
Provides:
  - Database connection fixtures (standard and read-only mode)
  - FastAPI TestClient fixtures (authenticated and unauthenticated)
  - MikroTik Syslog UDP packet crafter helpers
  - Query plan explainer helper (explain_query)
  - High-precision query latency measurement helper
"""

import os
import sys
import time
import sqlite3
import pytest
from typing import Dict, Any, List, Optional, Tuple

# Ensure codebase root is in sys.path
CODEBASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if CODEBASE_DIR not in sys.path:
    sys.path.insert(0, CODEBASE_DIR)

DB_FILE = os.path.join(CODEBASE_DIR, "xtreamlog.db")


@pytest.fixture(scope="function")
def db_conn():
    """Provides an active database connection using database.get_connection() and closes safely."""
    import database
    conn = database.get_connection()
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


@pytest.fixture(scope="function")
def db_ro_conn():
    """
    Provides a read-only SQLite connection to xtreamlog.db.
    Safe for non-blocking concurrent queries against live WAL logs.
    """
    db_uri = f"file:{os.path.abspath(DB_FILE)}?mode=ro"
    conn = sqlite3.connect(db_uri, uri=True, timeout=15.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA cache_size = -64000;")
        conn.execute("PRAGMA mmap_size = 1073741824;")
        conn.execute("PRAGMA temp_store = MEMORY;")
    except Exception:
        pass
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass


@pytest.fixture(scope="session")
def auth_client():
    """Provides a FastAPI TestClient with authenticated admin session cookie."""
    from server import app
    from fastapi.testclient import TestClient
    with TestClient(app, raise_server_exceptions=False) as client:
        client.cookies.set("xtream_user", "arif")
        yield client


@pytest.fixture(scope="session")
def unauth_client():
    """Provides an unauthenticated FastAPI TestClient without session cookie."""
    from server import app
    from fastapi.testclient import TestClient
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


@pytest.fixture
def craft_nat_packet():
    """
    Helper fixture to craft MikroTik NAT and Syslog packets in authentic format.
    Example output:
    <134>Nov 21 03:00:00 SuperNet_R06 forward: in:ether1 out:ether2, proto TCP (ACK), 10.24.111.114:43758->172.217.112.4:443, NAT (10.24.111.114:43758->103.54.108.114:43758)->172.217.112.4:443, len 52
    """
    def _crafter(
        router: str = "SuperNet_R06",
        proto: str = "TCP",
        src_ip: str = "10.24.111.114",
        src_port: int = 43758,
        nat_ip: str = "103.54.108.114",
        nat_port: int = 43758,
        dst_ip: str = "172.217.112.4",
        dst_port: int = 443,
        username: Optional[str] = None,
        in_if: str = "ether1",
        out_if: str = "ether2",
        timestamp_str: str = "Nov 21 03:00:00",
        flags: str = "(ACK)"
    ) -> str:
        in_interface = f"<pppoe-{username}>" if username else in_if
        return (
            f"<134>{timestamp_str} {router} forward: in:{in_interface} out:{out_if}, "
            f"proto {proto} {flags}, {src_ip}:{src_port}->{dst_ip}:{dst_port}, "
            f"NAT ({src_ip}:{src_port}->{nat_ip}:{nat_port})->{dst_ip}:{dst_port}, len 52"
        )
    return _crafter


@pytest.fixture
def craft_acct_login():
    """Helper fixture to craft MikroTik acct_login script syslog lines."""
    def _crafter(
        user: str = "test_subagent_user",
        mac: str = "98:4A:6B:4E:88:50",
        session: str = "*81000001",
        ip: str = "10.24.34.27"
    ) -> str:
        return f"acct_login {user} {mac} {session} {ip}"
    return _crafter


@pytest.fixture
def craft_acct_logout():
    """Helper fixture to craft MikroTik acct_logout script syslog lines."""
    def _crafter(
        user: str = "test_subagent_user",
        mac: str = "98:4A:6B:4E:88:50",
        session: str = "*81000001",
        ip: str = "10.24.34.27",
        bytes_in: int = 1048576,
        bytes_out: int = 2097152,
        uptime: str = "1h20m"
    ) -> str:
        return f"acct_logout {user} {mac} {session} {ip} {bytes_in} {bytes_out} {uptime}"
    return _crafter


def explain_query(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> Dict[str, Any]:
    """
    Executes EXPLAIN QUERY PLAN on the given SQL and returns structured breakdown:
    - plan_rows: list of raw tuples
    - plan_str: formatted concatenated plan detail
    - has_scan: whether a full table SCAN of nat_logs is performed without an index
    - has_temp_btree: whether a temporary B-tree is created for sorting
    - indexes_used: list of index names identified in the plan
    """
    cursor = conn.cursor()
    cursor.execute(f"EXPLAIN QUERY PLAN {sql}", params)
    rows = cursor.fetchall()

    plan_details = [r[3] if len(r) > 3 else str(r) for r in rows]
    plan_str = " -> ".join(plan_details)

    # Detect full table scan on nat_logs:
    has_scan = False
    for detail in plan_details:
        if "SCAN" in detail and "nat_logs" in detail:
            if "USING INDEX" not in detail and "USING COVERING INDEX" not in detail:
                has_scan = True

    # Detect temporary B-tree
    has_temp_btree = any("USE TEMP B-TREE" in d or "TEMP B-TREE" in d for d in plan_details)

    # Extract used indexes
    indexes_used = []
    for detail in plan_details:
        if "USING INDEX" in detail:
            parts = detail.split("USING INDEX ")
            if len(parts) > 1:
                idx = parts[1].split()[0].strip()
                indexes_used.append(idx)
        elif "USING COVERING INDEX" in detail:
            parts = detail.split("USING COVERING INDEX ")
            if len(parts) > 1:
                idx = parts[1].split()[0].strip()
                indexes_used.append(idx)

    return {
        "rows": rows,
        "plan_str": plan_str,
        "has_scan": has_scan,
        "has_temp_btree": has_temp_btree,
        "indexes_used": indexes_used
    }


def measure_query_latency(
    conn: sqlite3.Connection,
    sql: str,
    params: tuple = (),
    warmup: bool = True,
    iterations: int = 3
) -> float:
    """
    Executes query multiple times with high precision timer and returns average execution time in ms.
    """
    cursor = conn.cursor()
    if warmup:
        try:
            cursor.execute(sql, params)
            cursor.fetchall()
        except Exception:
            pass

    times = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        cursor.execute(sql, params)
        _ = cursor.fetchall()
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000.0)

    return sum(times) / len(times) if times else 0.0
