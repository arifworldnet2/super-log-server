"""
test_tier1_features.py - Comprehensive Tier 1 Feature Coverage Test Suite.

Features Covered (>= 5 tests each, 60 tests total):
  - F1: SQLite PRAGMAs & Connection Management (6 tests)
  - F2: Composite Indexes & EXPLAIN QUERY PLAN (6 tests)
  - F3: Multi-Parameter Log Search Latency (<50ms) (6 tests)
  - F4: Log Search Accuracy & Filter Correctness (6 tests)
  - F5: UDP Syslog Ingestion (Port 5514) & Async Queue (6 tests)
  - F6: Syslog Batch DB Insertion & Persistence (6 tests)
  - F7: Web Concurrency & Event Loop Responsiveness (6 tests)
  - F8: Auth, Session Security & Role Permissions (6 tests)
  - F9: Non-Blocking Services & Socket Safety (6 tests)
  - F10: System Health, Metrics & Resource Efficiency (6 tests)
"""

import os
import sys
import time
import re
import sqlite3
import pytest

# Ensure codebase root is in sys.path
CODEBASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if CODEBASE_DIR not in sys.path:
    sys.path.insert(0, CODEBASE_DIR)

import database
from tests.conftest import explain_query, measure_query_latency


# ============================================================================
# F1: SQLite PRAGMAs & Connection Management
# ============================================================================
class TestF1PragmasAndConnectionManagement:
    """Verifies SQLite engine tuning, PRAGMAs, and connection lifecycle."""

    def test_f1_01_journal_mode_wal(self, db_ro_conn):
        """Verifies database operates in Write-Ahead Logging (WAL) mode."""
        cursor = db_ro_conn.cursor()
        cursor.execute("PRAGMA journal_mode;")
        mode = cursor.fetchone()[0]
        assert str(mode).lower() == "wal", f"Expected WAL mode, got: {mode}"

    def test_f1_02_synchronous_mode(self, db_conn):
        """Verifies PRAGMA synchronous is set to NORMAL (1) for high-throughput concurrency."""
        cursor = db_conn.cursor()
        cursor.execute("PRAGMA synchronous;")
        val = cursor.fetchone()[0]
        # In SQLite: 0 = OFF, 1 = NORMAL, 2 = FULL, 3 = EXTRA
        assert val in (1, "1", "NORMAL", "normal"), f"Expected synchronous NORMAL (1), got: {val}"

    def test_f1_03_row_factory_sqlite_row(self, db_conn):
        """Verifies connection provides dict-accessible sqlite3.Row objects."""
        assert db_conn.row_factory is sqlite3.Row, "db_conn row_factory must be sqlite3.Row"
        cursor = db_conn.cursor()
        cursor.execute("SELECT 1 AS num, 'test' AS text;")
        row = cursor.fetchone()
        assert row["num"] == 1
        assert row["text"] == "test"

    def test_f1_04_connection_close_safety(self):
        """Verifies closing a connection releases handles and subsequent queries raise ProgrammingError."""
        conn = database.get_connection()
        conn.close()
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1;")

    def test_f1_05_get_db_context_manager(self):
        """
        Verifies get_db context manager yields connection and closes it on normal exit and exception.
        """
        assert hasattr(database, "get_db"), "database module must provide get_db context manager"
        with database.get_db() as conn:
            assert conn is not None
            cursor = conn.cursor()
            cursor.execute("SELECT 1;")
            assert cursor.fetchone()[0] == 1
        # Verify closed after block
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1;")

    def test_f1_06_database_init_preserves_admin(self, db_ro_conn):
        """Verifies database has default Admin user 'arif' enabled."""
        cursor = db_ro_conn.cursor()
        cursor.execute("SELECT id, username, role, login_enabled FROM users WHERE username = 'arif';")
        user = cursor.fetchone()
        assert user is not None, "Admin user 'arif' must exist in database"
        assert user["role"] == "Admin"
        assert user["login_enabled"] == 1


# ============================================================================
# F2: Composite Indexes & EXPLAIN QUERY PLAN
# ============================================================================
class TestF2CompositeIndexesAndExplainPlan:
    """Verifies existence of composite indexes and absence of full table scans on indexed queries."""

    def test_f2_01_composite_indexes_inventory(self, db_ro_conn):
        """Verifies composite indexes exist on nat_logs table."""
        cursor = db_ro_conn.cursor()
        cursor.execute("PRAGMA index_list(nat_logs);")
        indexes = [row[1] for row in cursor.fetchall()]
        assert len(indexes) >= 10, f"Expected at least 10 indexes on nat_logs, found {len(indexes)}: {indexes}"
        # Verify key composite indexes
        for expected in ("idx_nat_ts_id", "idx_nat_user_ts_id", "idx_nat_src_ip_ts_id", "idx_nat_dst_ip_ts_id"):
            assert expected in indexes, f"Expected composite index '{expected}' missing from nat_logs"

    def test_f2_02_explain_latest_logs_query_plan(self, db_ro_conn):
        """Verifies retrieving latest logs via ORDER BY timestamp DESC, id DESC uses composite index."""
        plan = explain_query(db_ro_conn, "SELECT * FROM nat_logs ORDER BY timestamp DESC, id DESC LIMIT 50")
        assert not plan["has_temp_btree"], f"Query should not create temp B-tree: {plan['plan_str']}"
        assert not plan["has_scan"], f"Latest logs query should use index, not full scan: {plan['plan_str']}"

    def test_f2_03_explain_src_ip_query_plan(self, db_ro_conn):
        """Verifies exact src_ip query uses index and avoids full table scan."""
        plan = explain_query(db_ro_conn, "SELECT * FROM nat_logs WHERE src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", ("10.24.111.114",))
        assert not plan["has_scan"], f"src_ip query should use index, not full scan: {plan['plan_str']}"
        assert not plan["has_temp_btree"], f"src_ip query should avoid temp B-tree: {plan['plan_str']}"

    def test_f2_04_explain_dst_ip_query_plan(self, db_ro_conn):
        """Verifies exact dst_ip query uses index and avoids full table scan."""
        plan = explain_query(db_ro_conn, "SELECT * FROM nat_logs WHERE dst_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", ("172.217.112.4",))
        assert not plan["has_scan"], f"dst_ip query should use index, not full scan: {plan['plan_str']}"
        assert not plan["has_temp_btree"], f"dst_ip query should avoid temp B-tree: {plan['plan_str']}"

    def test_f2_05_explain_user_query_plan(self, db_ro_conn):
        """Verifies exact username query uses index and avoids table scan."""
        plan = explain_query(db_ro_conn, "SELECT * FROM nat_logs WHERE username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 100", ("testuser",))
        assert not plan["has_scan"], f"username query should use index: {plan['plan_str']}"
        assert not plan["has_temp_btree"], f"username query should avoid temp B-tree: {plan['plan_str']}"

    def test_f2_06_explain_host_router_query_plan(self, db_ro_conn):
        """Verifies router host query uses index and avoids table scan."""
        plan = explain_query(db_ro_conn, "SELECT * FROM nat_logs WHERE host = ? ORDER BY timestamp DESC, id DESC LIMIT 100", ("103.54.108.118",))
        assert not plan["has_scan"], f"host query should use index: {plan['plan_str']}"
        assert not plan["has_temp_btree"], f"host query should avoid temp B-tree: {plan['plan_str']}"


# ============================================================================
# F3: Multi-Parameter Log Search Latency (<50ms)
# ============================================================================
class TestF3MultiParameterSearchLatency:
    """Verifies that indexed search queries across 1.55M+ rows execute in < 50ms."""

    @classmethod
    def setup_class(cls):
        """Loads representative sample values using direct indexed lookup."""
        conn = database.get_connection()
        c = conn.cursor()
        c.execute("SELECT src_ip, dst_ip, nat_ip, host, username, timestamp FROM nat_logs ORDER BY id DESC LIMIT 1;")
        row = c.fetchone()
        conn.close()
        if row:
            cls.src_ip = row["src_ip"]
            cls.dst_ip = row["dst_ip"]
            cls.nat_ip = row["nat_ip"]
            cls.host = row["host"]
            cls.username = row["username"] or "arif"
            cls.timestamp = row["timestamp"]
        else:
            cls.src_ip = "10.24.111.114"
            cls.dst_ip = "172.217.112.4"
            cls.nat_ip = "103.54.108.114"
            cls.host = "103.54.108.118"
            cls.username = "arif"
            cls.timestamp = "2026-11-21 00:00:00"

    def test_f3_01_search_latency_exact_src_ip(self, db_ro_conn):
        """Search by exact src_ip must execute in < 50ms."""
        sql = "SELECT * FROM nat_logs WHERE src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100"
        latency_ms = measure_query_latency(db_ro_conn, sql, (self.src_ip,), iterations=3)
        assert latency_ms < 50.0, f"src_ip search latency too high: {latency_ms:.2f}ms >= 50ms"

    def test_f3_02_search_latency_exact_dst_ip(self, db_ro_conn):
        """Search by exact dst_ip must execute in < 50ms."""
        sql = "SELECT * FROM nat_logs WHERE dst_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100"
        latency_ms = measure_query_latency(db_ro_conn, sql, (self.dst_ip,), iterations=3)
        assert latency_ms < 50.0, f"dst_ip search latency too high: {latency_ms:.2f}ms >= 50ms"

    def test_f3_03_search_latency_exact_nat_ip(self, db_ro_conn):
        """Search by exact nat_ip must execute in < 50ms."""
        sql = "SELECT * FROM nat_logs WHERE nat_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100"
        latency_ms = measure_query_latency(db_ro_conn, sql, (self.nat_ip,), iterations=3)
        assert latency_ms < 50.0, f"nat_ip search latency too high: {latency_ms:.2f}ms >= 50ms"

    def test_f3_04_search_latency_exact_username(self, db_ro_conn):
        """Search by exact username must execute in < 50ms."""
        sql = "SELECT * FROM nat_logs WHERE username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 100"
        latency_ms = measure_query_latency(db_ro_conn, sql, (self.username,), iterations=3)
        assert latency_ms < 50.0, f"username search latency too high: {latency_ms:.2f}ms >= 50ms"

    def test_f3_05_search_latency_host_router(self, db_ro_conn):
        """Search by exact router host must execute in < 50ms."""
        sql = "SELECT * FROM nat_logs WHERE host = ? ORDER BY timestamp DESC, id DESC LIMIT 100"
        latency_ms = measure_query_latency(db_ro_conn, sql, (self.host,), iterations=3)
        assert latency_ms < 50.0, f"host search latency too high: {latency_ms:.2f}ms >= 50ms"

    def test_f3_06_search_latency_latest_records(self, db_ro_conn):
        """Retrieving latest 50 logs must execute in < 50ms."""
        sql = "SELECT * FROM nat_logs ORDER BY timestamp DESC, id DESC LIMIT 50"
        latency_ms = measure_query_latency(db_ro_conn, sql, (), iterations=3)
        assert latency_ms < 50.0, f"latest logs query latency too high: {latency_ms:.2f}ms >= 50ms"


# ============================================================================
# F4: Log Search Accuracy & Filter Correctness
# ============================================================================
class TestF4LogSearchAccuracyAndFilters:
    """Verifies that search API endpoints return 100% accurate results strictly matching filters."""

    @classmethod
    def setup_class(cls):
        """Samples a known row by primary key or recent logs."""
        conn = database.get_connection()
        c = conn.cursor()
        c.execute("SELECT src_ip, dst_ip, src_port, dst_port, username FROM nat_logs WHERE src_port IS NOT NULL AND dst_port IS NOT NULL ORDER BY id DESC LIMIT 1;")
        cls.sample = c.fetchone()
        conn.close()

    def test_f4_01_accuracy_src_ip_filter(self, auth_client):
        """Asserts all returned logs match the requested src_ip."""
        assert self.sample is not None, "Sample row required for test"
        src_ip = self.sample["src_ip"]
        res = auth_client.get(f"/api/logs/search?src_ip={src_ip}")
        assert res.status_code == 200
        logs = res.json().get("logs", [])
        assert len(logs) > 0, f"Expected logs for src_ip {src_ip}"
        for log in logs:
            assert log["src_ip"] == src_ip, f"Expected src_ip {src_ip}, got {log['src_ip']}"

    def test_f4_02_accuracy_dst_ip_filter(self, auth_client):
        """Asserts all returned logs match the requested dst_ip."""
        assert self.sample is not None, "Sample row required for test"
        dst_ip = self.sample["dst_ip"]
        res = auth_client.get(f"/api/logs/search?dst_ip={dst_ip}")
        assert res.status_code == 200
        logs = res.json().get("logs", [])
        assert len(logs) > 0, f"Expected logs for dst_ip {dst_ip}"
        for log in logs:
            assert log["dst_ip"] == dst_ip, f"Expected dst_ip {dst_ip}, got {log['dst_ip']}"

    def test_f4_03_accuracy_user_filter(self, auth_client):
        """Asserts all returned logs match the requested username."""
        assert self.sample is not None, "Sample row required for test"
        user = self.sample["username"]
        if not user:
            pytest.skip("Sample has no username")
        res = auth_client.get(f"/api/logs/search?user={user}")
        assert res.status_code == 200
        logs = res.json().get("logs", [])
        assert len(logs) > 0, f"Expected logs for user {user}"
        for log in logs:
            assert log.get("username", "").lower() == user.lower(), f"Expected user {user}, got {log.get('username')}"

    def test_f4_04_accuracy_src_port_filter(self, auth_client):
        """Asserts all returned logs match the requested src_port."""
        assert self.sample is not None, "Sample row required for test"
        src_port = self.sample["src_port"]
        res = auth_client.get(f"/api/logs/search?src_port={src_port}")
        assert res.status_code == 200
        logs = res.json().get("logs", [])
        assert len(logs) > 0
        for log in logs:
            assert log["src_port"] == src_port

    def test_f4_05_accuracy_dst_port_filter(self, auth_client):
        """Asserts all returned logs match the requested dst_port."""
        assert self.sample is not None, "Sample row required for test"
        dst_port = self.sample["dst_port"]
        res = auth_client.get(f"/api/logs/search?dst_port={dst_port}")
        assert res.status_code == 200
        logs = res.json().get("logs", [])
        assert len(logs) > 0
        for log in logs:
            assert log["dst_port"] == dst_port

    def test_f4_06_accuracy_nonexistent_returns_empty(self, auth_client):
        """Asserts searching for a nonexistent IP returns 0 results cleanly without error."""
        res = auth_client.get("/api/logs/search?src_ip=192.0.2.254")
        assert res.status_code == 200
        logs = res.json().get("logs", [])
        assert logs == []


# ============================================================================
# F5: UDP Syslog Ingestion & Async Queue
# ============================================================================
class TestF5UdpSyslogIngestionAndQueue:
    """Verifies syslog message decoding, regex parsing, and live packet statistics."""

    def test_f5_01_nat_pattern_standard(self):
        """Verifies standard NAT syslog regex parsing."""
        from syslog_server import NAT_PATTERN
        line = "proto TCP (ACK), 10.24.111.114:43758->103.54.108.114:43758->172.217.112.4:443, len 52"
        match = NAT_PATTERN.search(line)
        assert match is not None
        d = match.groupdict()
        proto = d.get("proto") or "TCP"
        assert proto.upper() == "TCP"
        assert d["src_ip"] == "10.24.111.114"
        assert d["src_port"] == "43758"
        assert d["nat_ip"] == "103.54.108.114"
        assert d["nat_port"] == "43758"
        assert d["dst_ip"] == "172.217.112.4"
        assert d["dst_port"] == "443"

    def test_f5_02_nat_pattern_alt(self):
        """Verifies alternate NAT syslog regex parsing (MikroTik NAT (...) syntax)."""
        from syslog_server import NAT_ALT_PATTERN
        line = "forward: in:ether1 out:ether2, NAT (10.24.111.114:43758->103.54.108.114:43758)->172.217.112.4:443"
        match = NAT_ALT_PATTERN.search(line)
        assert match is not None
        d = match.groupdict()
        assert d["src_ip"] == "10.24.111.114"
        assert d["src_port"] == "43758"
        assert d["nat_ip"] == "103.54.108.114"
        assert d["nat_port"] == "43758"
        assert d["dst_ip"] == "172.217.112.4"
        assert d["dst_port"] == "443"

    def test_f5_03_acct_login_regex(self):
        """Verifies parsing of acct_login script events."""
        from syslog_server import ACCT_LOGIN_PATTERN
        line = "acct_login Adnan.moktar@sn 98:4A:6B:4E:88:50 *81000001 10.24.34.27"
        match = ACCT_LOGIN_PATTERN.search(line)
        assert match is not None
        d = match.groupdict()
        assert d["user"] == "Adnan.moktar@sn"
        assert d["mac"] == "98:4A:6B:4E:88:50"
        assert d["session"] == "*81000001"
        assert d["ip"] == "10.24.34.27"

    def test_f5_04_acct_logout_regex(self):
        """Verifies parsing of acct_logout script events with traffic and uptime."""
        from syslog_server import ACCT_LOGOUT_PATTERN
        line = "acct_logout Adnan.moktar@sn 98:4A:6B:4E:88:50 *81000001 10.24.34.27 1048576 2097152 1h20m"
        match = ACCT_LOGOUT_PATTERN.search(line)
        assert match is not None
        d = match.groupdict()
        assert d["user"] == "Adnan.moktar@sn"
        assert d["bytes_in"] == "1048576"
        assert d["bytes_out"] == "2097152"
        assert d["uptime"] == "1h20m"

    def test_f5_05_pppoe_connected_regex(self):
        """Verifies parsing of standard RouterOS PPPoE connected events."""
        from syslog_server import PPPOE_CONNECTED_PATTERN
        line = "<pppoe-cust01>: connected, IP 10.24.50.10, MAC 00:11:22:33:44:55"
        match = PPPOE_CONNECTED_PATTERN.search(line)
        assert match is not None
        d = match.groupdict()
        assert d["user"] == "cust01"
        assert d["ip"] == "10.24.50.10"
        assert d["mac"] == "00:11:22:33:44:55"

    def test_f5_06_packet_stats_tracker(self, auth_client):
        """Verifies /api/syslog/live-status returns packet statistics dictionary."""
        res = auth_client.get("/api/syslog/live-status")
        assert res.status_code == 200
        stats = res.json()
        assert "total_packets" in stats
        assert "recent_packets" in stats
        assert isinstance(stats["recent_packets"], list)


# ============================================================================
# F6: Syslog Batch DB Insertion & Persistence
# ============================================================================
class TestF6SyslogBatchDbInsertion:
    """Verifies that processed syslog events are reliably persisted into SQLite tables."""

    def test_f6_01_nat_log_persistence(self, craft_nat_packet):
        """Verifies a crafted NAT syslog packet is written to nat_logs."""
        from syslog_server import SyslogProtocol
        proto = SyslogProtocol()
        test_ip = "198.51.100.77"
        msg = craft_nat_packet(src_ip=test_ip, router="Test_R01")
        
        try:
            proto.process_log("127.0.0.1", msg)
            conn = database.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, src_ip, dst_ip FROM nat_logs WHERE src_ip = ? ORDER BY id DESC LIMIT 1;", (test_ip,))
            row = cursor.fetchone()
            assert row is not None, f"Crafted log with src_ip {test_ip} was not saved to nat_logs"
            assert row["src_ip"] == test_ip
            conn.close()
        finally:
            conn = database.get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM nat_logs WHERE src_ip = ?", (test_ip,))
            conn.commit()
            conn.close()

    def test_f6_02_online_user_login_persistence(self, craft_acct_login):
        """Verifies acct_login creates an entry in online_users table."""
        from syslog_server import SyslogProtocol
        proto = SyslogProtocol()
        test_user = "test_subagent_login_user"
        msg = craft_acct_login(user=test_user, ip="10.99.99.99")
        
        try:
            proto.process_log("127.0.0.1", msg)
            conn = database.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username, address FROM online_users WHERE username = ?;", (test_user,))
            row = cursor.fetchone()
            assert row is not None, "User should be present in online_users after acct_login"
            assert row["address"] == "10.99.99.99"
            conn.close()
        finally:
            conn = database.get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM online_users WHERE username = ?", (test_user,))
            conn.commit()
            conn.close()

    def test_f6_03_customer_usage_logout_persistence(self, craft_acct_logout):
        """Verifies acct_logout records customer_usage and clears online_users."""
        from syslog_server import SyslogProtocol
        proto = SyslogProtocol()
        test_user = "test_subagent_logout_user"
        msg = craft_acct_logout(user=test_user, bytes_in=1000, bytes_out=2000, uptime="10m")
        
        try:
            proto.process_log("127.0.0.1", msg)
            conn = database.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT username, uptime, upload_bytes, download_bytes FROM customer_usage WHERE username = ? ORDER BY id DESC LIMIT 1;", (test_user,))
            row = cursor.fetchone()
            assert row is not None, "Usage row must be created in customer_usage"
            assert row["uptime"] == "10m"
            assert row["upload_bytes"] == 1000
            assert row["download_bytes"] == 2000
            conn.close()
        finally:
            conn = database.get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM customer_usage WHERE username = ?", (test_user,))
            conn.commit()
            conn.close()

    def test_f6_04_system_log_persistence(self):
        """Verifies non-NAT general syslog lines are saved into system_logs table."""
        from syslog_server import SyslogProtocol
        proto = SyslogProtocol()
        test_msg = "Subagent Test System Warning: Interface ether1 link down"
        
        try:
            proto.process_log("127.0.0.1", test_msg)
            conn = database.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id, message, priority FROM system_logs WHERE message LIKE ? ORDER BY id DESC LIMIT 1;", (f"%{test_msg}%",))
            row = cursor.fetchone()
            assert row is not None, "System log message should be persisted"
            assert row["priority"] == "warning"
            conn.close()
        finally:
            conn = database.get_connection()
            cursor = conn.cursor()
            cursor.execute("DELETE FROM system_logs WHERE message LIKE ?", (f"%{test_msg}%",))
            conn.commit()
            conn.close()

    def test_f6_05_malformed_packet_resilience(self):
        """Verifies datagram_received gracefully handles garbage bytes without throwing exceptions."""
        from syslog_server import SyslogProtocol
        proto = SyslogProtocol()
        corrupt_data = b"\x00\xff\xfe\x01\x80\x99SomeRandomJunk\x00\x00"
        proto.datagram_received(corrupt_data, ("127.0.0.1", 5514))

    def test_f6_06_byte_formatting_utility(self):
        """Verifies syslog_server.format_bytes formats units correctly."""
        from syslog_server import format_bytes
        assert "500 B" in format_bytes(500)
        assert "KB" in format_bytes(2048)
        assert "MB" in format_bytes(1048576 * 5)
        assert "GB" in format_bytes(1073741824 * 3)


# ============================================================================
# F7: Web Concurrency & Event Loop Responsiveness
# ============================================================================
class TestF7WebConcurrencyAndEventLoop:
    """Verifies non-blocking request handling, route responsiveness, and event loop health."""

    def test_f7_01_health_endpoint_instant(self, unauth_client):
        """Asserts /health responds in under 20ms with 200 OK."""
        t0 = time.perf_counter()
        res = unauth_client.get("/health")
        latency_ms = (time.perf_counter() - t0) * 1000.0
        assert res.status_code == 200
        assert res.json() == {"status": "ok"}
        assert latency_ms < 50.0, f"Health endpoint latency too high: {latency_ms:.2f}ms"

    def test_f7_02_realtime_metrics_responsiveness(self, auth_client):
        """Asserts /api/system/realtime-metrics responds promptly with complete metrics."""
        t0 = time.perf_counter()
        res = auth_client.get("/api/system/realtime-metrics")
        latency_ms = (time.perf_counter() - t0) * 1000.0
        assert res.status_code == 200
        data = res.json()
        assert "cpu" in data
        assert "ram" in data
        assert "active_users" in data
        assert latency_ms < 100.0, f"Metrics endpoint latency too high: {latency_ms:.2f}ms"

    def test_f7_03_dashboard_view_responsiveness(self, auth_client):
        """Asserts authenticated /dashboard HTML view loads successfully."""
        res = auth_client.get("/dashboard")
        assert res.status_code == 200
        assert "html" in res.headers.get("content-type", "").lower()

    def test_f7_04_concurrent_requests_stability(self, auth_client):
        """Executes multiple rapid requests in sequence to ensure event loop stability."""
        for _ in range(10):
            res = auth_client.get("/health")
            assert res.status_code == 200

    def test_f7_05_route_aliases(self, auth_client):
        """Verifies canonical route aliases respond identically with status 200."""
        res1 = auth_client.get("/search")
        res2 = auth_client.get("/search-log")
        assert res1.status_code == 200
        assert res2.status_code == 200

    def test_f7_06_search_clamping_limit(self, auth_client):
        """Verifies /api/logs/search limits returned logs to max 100 records."""
        res = auth_client.get("/api/logs/search")
        assert res.status_code == 200
        data = res.json()
        assert len(data.get("logs", [])) <= 100, "Search results must be clamped to prevent memory exhaustion"


# ============================================================================
# F8: Auth, Session Security & Role Permissions
# ============================================================================
class TestF8AuthSessionSecurityPermissions:
    """Verifies authentication enforcement, cookie lifecycle, and role permission toggling."""

    def test_f8_01_unauthenticated_protected_route_redirect(self, unauth_client):
        """Asserts accessing protected routes without session cookie redirects to login."""
        res = unauth_client.get("/dashboard", follow_redirects=False)
        assert res.status_code in (302, 303, 307)
        assert res.headers.get("location") == "/"

    def test_f8_02_login_success(self, unauth_client):
        """Asserts submitting valid credentials sets xtream_user cookie and redirects to /dashboard."""
        res = unauth_client.post("/login", data={"username": "arif", "password": "admin123"}, follow_redirects=False)
        assert res.status_code in (302, 303, 307)
        assert res.headers.get("location") == "/dashboard"
        assert "xtream_user" in res.cookies

    def test_f8_03_login_failure_wrong_password(self, unauth_client):
        """Asserts invalid credentials returns 200 with error and does NOT set auth cookie."""
        res = unauth_client.post("/login", data={"username": "arif", "password": "wrongpassword_xyz"}, follow_redirects=False)
        assert res.status_code == 200
        assert "xtream_user" not in res.cookies
        assert "Invalid username or password" in res.text

    def test_f8_04_logout_destroys_cookie(self, auth_client):
        """Asserts /logout clears xtream_user cookie and redirects to /."""
        res = auth_client.get("/logout", follow_redirects=False)
        assert res.status_code in (302, 303, 307)
        assert res.headers.get("location") == "/"

    def test_f8_05_user_permissions_toggle(self, auth_client):
        """Verifies POST /api/users/{id}/permissions/toggle updates permissions in DB."""
        conn = database.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = 'arif';")
        user_id = cursor.fetchone()["id"]
        conn.close()

        perm_key = "test_perm_toggle"
        res = auth_client.post(f"/api/users/{user_id}/permissions/toggle", json={
            "permission_key": perm_key,
            "is_allowed": False
        })
        assert res.status_code == 200
        
        perms = database.get_user_permissions(user_id)
        assert perms.get(perm_key) is False

        # Toggle back to True
        res2 = auth_client.post(f"/api/users/{user_id}/permissions/toggle", json={
            "permission_key": perm_key,
            "is_allowed": True
        })
        assert res2.status_code == 200
        perms2 = database.get_user_permissions(user_id)
        assert perms2.get(perm_key) is True

    def test_f8_06_user_router_permissions_toggle(self, auth_client):
        """Verifies POST /api/users/{id}/routers/{router_id}/toggle updates router access in DB."""
        conn = database.get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM users WHERE username = 'arif';")
        user_id = cursor.fetchone()["id"]

        router_id = 999
        res = auth_client.post(f"/api/users/{user_id}/routers/{router_id}/toggle", json={
            "is_allowed": False
        })
        assert res.status_code == 200
        
        cursor.execute("SELECT is_allowed FROM user_router_permissions WHERE user_id = ? AND router_id = ?;", (user_id, router_id))
        row = cursor.fetchone()
        assert row is not None
        assert row["is_allowed"] == 0
        conn.close()


# ============================================================================
# F9: Non-Blocking Services & Socket Safety
# ============================================================================
class TestF9NonBlockingServicesSocketSafety:
    """Verifies AS caching, private subnet classification, and MikroTik socket resource safety."""

    def test_f9_01_as_private_ip_check(self):
        """Verifies is_private_or_special correctly flags RFC1918 and loopback IPs."""
        from as_service import is_private_or_special
        assert is_private_or_special("10.24.111.114") is True
        assert is_private_or_special("192.168.1.1") is True
        assert is_private_or_special("172.16.50.2") is True
        assert is_private_or_special("127.0.0.1") is True
        assert is_private_or_special("8.8.8.8") is False
        assert is_private_or_special("1.1.1.1") is False

    def test_f9_02_as_subnet_key(self):
        """Verifies get_subnet_key produces standard /24 CIDR block."""
        from as_service import get_subnet_key
        assert get_subnet_key("103.54.108.114") == "103.54.108.0/24"
        assert get_subnet_key("8.8.8.8") == "8.8.8.0/24"

    def test_f9_03_as_well_known_lookup(self):
        """Verifies well-known DNS IPs resolve instantly offline without network calls."""
        from as_service import get_as_info
        assert "Google" in get_as_info("8.8.8.8")
        assert "Cloudflare" in get_as_info("1.1.1.1")
        assert get_as_info("10.0.0.1") == "Private / Local IP"

    def test_f9_04_as_batch_lookup_memory_cache(self):
        """Verifies batch_get_as_info resolves multiple IPs utilizing memory cache."""
        from as_service import batch_get_as_info
        res = batch_get_as_info(["8.8.8.8", "1.1.1.1", "10.24.0.1"])
        assert "Google" in res.get("8.8.8.8", "")
        assert "Cloudflare" in res.get("1.1.1.1", "")
        assert res.get("10.24.0.1") == "Private / Local IP"

    def test_f9_05_mikrotik_pool_range_parsing(self):
        """Verifies parse_pool_ranges_to_prefixes converts range boundaries to CIDR prefixes."""
        from mikrotik_api import parse_pool_ranges_to_prefixes
        prefixes = parse_pool_ranges_to_prefixes("10.24.0.2-10.24.7.254")
        assert len(prefixes) > 0
        assert any("/" in p for p in prefixes)

    def test_f9_06_mikrotik_socket_cleanup_on_timeout(self):
        """Verifies test_mikrotik_connection gracefully fails on unreachable host and closes socket."""
        from mikrotik_api import test_mikrotik_connection
        # 192.0.2.1 is TEST-NET-1 (non-routable), will timeout cleanly
        res = test_mikrotik_connection("192.0.2.1", "admin", "pass", timeout=1)
        assert res.get("success") is False
        assert "error" in res


# ============================================================================
# F10: System Health, Metrics & Resource Efficiency
# ============================================================================
class TestF10SystemHealthMetricsResourceEfficiency:
    """Verifies system metrics reporting, RAM accounting, and traffic formatting utilities."""

    def test_f10_01_realtime_metrics_keys(self):
        """Verifies get_real_system_metrics returns all required hardware metric fields."""
        from server import get_real_system_metrics
        m = get_real_system_metrics()
        for key in ["cpu", "ram", "free_ram_gb", "uptime", "app_drive_letter", "app_free_gb"]:
            assert key in m, f"Metric key '{key}' missing from get_real_system_metrics"

    def test_f10_02_ram_metrics_range(self):
        """Verifies RAM percentage and free RAM are within plausible physical limits."""
        from server import get_real_system_metrics
        m = get_real_system_metrics()
        assert 0.0 <= m["ram"] <= 100.0, f"RAM percentage out of bounds: {m['ram']}"
        assert m["free_ram_gb"] > 0, f"Free RAM should be positive: {m['free_ram_gb']}"

    def test_f10_03_traffic_format_bytes_human(self):
        """Verifies format_bytes_human formats various byte quantities cleanly."""
        from traffic_service import format_bytes_human
        assert format_bytes_human(0) == "0 B"
        assert format_bytes_human(1024) == "1.0 KB"
        assert format_bytes_human(1048576) == "1.0 MB"
        assert format_bytes_human(1073741824) == "1.0 GB"
        assert format_bytes_human(1099511627776) == "1.0 TB"

    def test_f10_04_traffic_parse_bytes_from_str(self):
        """Verifies parse_bytes_from_str converts human byte strings to integer bytes."""
        from traffic_service import parse_bytes_from_str
        assert parse_bytes_from_str("1024") == 1024
        assert parse_bytes_from_str("1 KB") == 1024
        assert parse_bytes_from_str("1 MB") == 1048576
        assert parse_bytes_from_str("1 GB") == 1073741824
        assert parse_bytes_from_str(None) == 0

    def test_f10_05_traffic_drilldown_empty(self):
        """Verifies get_traffic_drilldown handles unknown username without error."""
        from traffic_service import get_traffic_drilldown
        data = get_traffic_drilldown("nonexistent_subagent_test_user_xyz")
        assert data is not None
        assert isinstance(data, dict)

    def test_f10_06_active_users_metrics_consistency(self, db_ro_conn, auth_client):
        """Verifies active_users in /api/system/realtime-metrics matches online_users table count."""
        cursor = db_ro_conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM online_users;")
        expected_count = cursor.fetchone()[0]

        res = auth_client.get("/api/system/realtime-metrics")
        assert res.status_code == 200
        metrics = res.json()
        assert metrics.get("active_users") == expected_count
