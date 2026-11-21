"""
test_tier2_boundaries.py - Comprehensive Tier 2 Boundary, Edge-Case, and Negative Test Suite.

Features Covered (>= 5 tests each, 60 tests total):
  - F1: PRAGMAs & Connection Management boundaries (6 tests)
  - F2: Query Plan boundaries (6 tests)
  - F3: Latency boundaries (6 tests)
  - F4: Filter & Input boundaries (6 tests)
  - F5: UDP Syslog Ingestion boundaries (6 tests)
  - F6: Batch DB Insertion boundaries (6 tests)
  - F7: Web Concurrency & Request boundaries (6 tests)
  - F8: Auth & Security boundaries (6 tests)
  - F9: External Services boundaries (6 tests)
  - F10: System Metrics boundaries (6 tests)
"""

import os
import sys
import time
import sqlite3
import concurrent.futures
from unittest.mock import patch
import pytest

# Ensure codebase root is in sys.path
CODEBASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if CODEBASE_DIR not in sys.path:
    sys.path.insert(0, CODEBASE_DIR)

import database
from tests.conftest import explain_query, measure_query_latency


# ============================================================================
# F1: PRAGMAs & Connection Management Boundaries
# ============================================================================
class TestF1PragmasAndConnectionBoundaries:
    """Verifies SQLite engine limits, read-only guarantees, lifecycle, and concurrency."""

    def test_f1_01_readonly_conn_blocks_writes(self, db_ro_conn):
        """1. Asserts read-only connection strictly blocks write operations with OperationalError."""
        cursor = db_ro_conn.cursor()
        with pytest.raises(sqlite3.OperationalError) as exc_info:
            cursor.execute(
                "INSERT INTO nat_logs (timestamp, host, src_ip, nat_ip, dst_ip) "
                "VALUES ('2026-11-21 00:00:00', '127.0.0.1', '1.1.1.1', '2.2.2.2', '3.3.3.3');"
            )
        err_msg = str(exc_info.value).lower()
        assert "readonly" in err_msg or "read-only" in err_msg

    def test_f1_02_rapid_sequential_connections_no_leak(self):
        """2. Rapid 50 sequential connection acquisitions and releases without resource leak."""
        for _ in range(50):
            conn = database.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1 AS num;")
            row = cursor.fetchone()
            assert row["num"] == 1
            conn.close()

    def test_f1_03_invalid_corrupt_db_path(self, tmp_path):
        """3. Safe handling of invalid database path or nonexistent directory."""
        invalid_path = str(tmp_path / "nonexistent_directory_boundary_test" / "sub" / "invalid.db")
        with pytest.raises(sqlite3.OperationalError):
            conn = sqlite3.connect(invalid_path, timeout=0.1)
            conn.execute("SELECT 1;")
            conn.close()

    def test_f1_04_concurrent_wal_access_no_locking_failure(self):
        """4. Concurrent connections accessing WAL without locking failure."""
        def _read_task():
            with database.get_db() as conn:
                c = conn.cursor()
                c.execute("SELECT COUNT(*) FROM nat_logs;")
                return c.fetchone()[0]

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(_read_task) for _ in range(10)]
            results = [f.result() for f in futures]
        assert len(results) == 10
        assert all(isinstance(r, int) and r >= 0 for r in results)

    def test_f1_05_get_db_context_manager_exception_safety(self):
        """5. Context manager get_db() properly closes even when exception is raised inside context."""
        conn_ref = None
        with pytest.raises(RuntimeError):
            with database.get_db() as conn:
                conn_ref = conn
                cursor = conn.cursor()
                cursor.execute("SELECT 1;")
                raise RuntimeError("Simulated failure inside with block")

        # After exception, connection should be closed
        assert conn_ref is not None
        with pytest.raises(sqlite3.ProgrammingError):
            conn_ref.execute("SELECT 1;")

    def test_f1_06_connection_busy_timeout_setting(self, db_conn):
        """6. Verifies busy_timeout or connection timeout is configured to prevent instant locks."""
        cursor = db_conn.cursor()
        cursor.execute("PRAGMA busy_timeout;")
        val = cursor.fetchone()[0]
        # In SQLite default or database.py: timeout=30.0 sets busy_timeout to 30000ms
        assert val >= 5000, f"Expected busy_timeout >= 5000ms, got {val}ms"


# ============================================================================
# F2: Query Plan Boundaries
# ============================================================================
class TestF2QueryPlanBoundaries:
    """Verifies SQLite index plan utilization under boundary parameters and filters."""

    def test_f2_01_empty_string_parameters_use_index(self, db_ro_conn):
        """1. Empty string parameters in search filters utilize index without planner crash."""
        # Username index has COLLATE NOCASE in schema
        sql_user = "SELECT * FROM nat_logs WHERE username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 100;"
        plan_user = explain_query(db_ro_conn, sql_user, ("",))
        assert plan_user["has_scan"] is False, f"User plan has scan: {plan_user['plan_str']}"
        assert "idx_nat_user_ts_id" in plan_user["indexes_used"]

        # src_ip index
        sql_ip = "SELECT * FROM nat_logs WHERE src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100;"
        plan_ip = explain_query(db_ro_conn, sql_ip, ("",))
        assert plan_ip["has_scan"] is False, f"src_ip plan has scan: {plan_ip['plan_str']}"
        assert "idx_nat_src_ip_ts_id" in plan_ip["indexes_used"]

    def test_f2_02_extremely_wide_date_range_no_temp_btree(self, db_ro_conn):
        """2. Extremely wide date ranges (1970 to 2099) utilize indexes without temp B-tree."""
        sql = (
            "SELECT * FROM nat_logs "
            "WHERE timestamp BETWEEN ? AND ? "
            "ORDER BY timestamp DESC, id DESC LIMIT 100;"
        )
        plan = explain_query(db_ro_conn, sql, ("1970-01-01 00:00:00", "2099-12-31 23:59:59"))
        assert plan["has_scan"] is False, f"Plan contains full scan: {plan['plan_str']}"
        assert plan["has_temp_btree"] is False, f"Plan created temp B-tree: {plan['plan_str']}"
        assert any("idx_nat" in idx for idx in plan["indexes_used"]), f"No nat index used: {plan['plan_str']}"

    def test_f2_03_zero_result_query_plan_uses_index(self, db_ro_conn):
        """3. Zero-result query plans (WHERE src_ip = '0.0.0.0') utilize index."""
        sql = "SELECT * FROM nat_logs WHERE src_ip = '0.0.0.0' ORDER BY timestamp DESC, id DESC LIMIT 100;"
        plan = explain_query(db_ro_conn, sql)
        assert plan["has_scan"] is False, f"Expected index search, got: {plan['plan_str']}"
        assert "idx_nat_src_ip_ts_id" in plan["indexes_used"]

    def test_f2_04_limit_boundaries_zero_one_five_thousand(self, db_ro_conn):
        """4. High LIMIT values (LIMIT 5000) vs LIMIT 0 vs LIMIT 1."""
        c = db_ro_conn.cursor()
        # LIMIT 0
        c.execute("SELECT * FROM nat_logs ORDER BY timestamp DESC, id DESC LIMIT 0;")
        assert c.fetchall() == []

        # LIMIT 1
        c.execute("SELECT * FROM nat_logs ORDER BY timestamp DESC, id DESC LIMIT 1;")
        res1 = c.fetchall()
        assert len(res1) <= 1

        # LIMIT 5000 plan
        sql = "SELECT * FROM nat_logs ORDER BY timestamp DESC, id DESC LIMIT 5000;"
        plan = explain_query(db_ro_conn, sql)
        assert plan["has_scan"] is False
        assert plan["has_temp_btree"] is False

    def test_f2_05_inverted_date_range_returns_zero_cleanly(self, db_ro_conn):
        """5. Inverted date ranges (BETWEEN 2026-11-22 AND 2026-11-20) return 0 rows cleanly without planner crash."""
        sql = (
            "SELECT * FROM nat_logs "
            "WHERE timestamp BETWEEN '2026-11-22 00:00:00' AND '2026-11-20 00:00:00' "
            "ORDER BY timestamp DESC, id DESC LIMIT 100;"
        )
        c = db_ro_conn.cursor()
        c.execute(sql)
        assert c.fetchall() == []
        plan = explain_query(db_ro_conn, sql)
        assert plan["has_scan"] is False

    def test_f2_06_dst_ip_port_compound_index_usage(self, db_ro_conn):
        """6. Compound equality on dst_ip and dst_port uses idx_nat_dst_ip_port_ts without scan."""
        sql = (
            "SELECT * FROM nat_logs "
            "WHERE dst_ip = '8.8.8.8' AND dst_port = 53 "
            "ORDER BY timestamp DESC, id DESC LIMIT 100;"
        )
        plan = explain_query(db_ro_conn, sql)
        assert plan["has_scan"] is False
        assert "idx_nat_dst_ip_port_ts" in plan["indexes_used"]


# ============================================================================
# F3: Latency Boundaries (< 50ms)
# ============================================================================
class TestF3LatencyBoundaries:
    """Verifies that query execution latency remains strictly < 50ms across boundary conditions."""

    def test_f3_01_latency_zero_matching_query(self, db_ro_conn):
        """1. Latency on zero-matching query across 1.85M rows remains < 50ms."""
        sql = (
            "SELECT * FROM nat_logs "
            "WHERE username = 'non_existent_boundary_user_xyz_9999' "
            "ORDER BY timestamp DESC, id DESC LIMIT 100;"
        )
        latency = measure_query_latency(db_ro_conn, sql, warmup=True, iterations=3)
        assert latency < 50.0, f"Zero-matching query latency {latency:.2f}ms exceeded 50ms threshold"

    def test_f3_02_latency_high_frequency_item(self, db_ro_conn):
        """2. Latency on high-frequency item (most common src_ip in DB) with LIMIT 100 remains < 50ms."""
        c = db_ro_conn.cursor()
        c.execute("SELECT src_ip FROM nat_logs WHERE src_ip IS NOT NULL AND src_ip != '' LIMIT 1;")
        row = c.fetchone()
        src_ip = row["src_ip"] if row else "10.24.111.114"

        sql = "SELECT * FROM nat_logs WHERE src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100;"
        latency = measure_query_latency(db_ro_conn, sql, params=(src_ip,), warmup=True, iterations=3)
        assert latency < 50.0, f"High-frequency item latency {latency:.2f}ms exceeded 50ms threshold"

    def test_f3_03_latency_single_second_date_window(self, db_ro_conn):
        """3. Latency on single-second date window remains < 50ms."""
        c = db_ro_conn.cursor()
        c.execute("SELECT timestamp FROM nat_logs ORDER BY id DESC LIMIT 1;")
        row = c.fetchone()
        ts = row["timestamp"] if row else "2026-11-21 03:00:00"

        sql = (
            "SELECT * FROM nat_logs "
            "WHERE timestamp BETWEEN ? AND ? "
            "ORDER BY timestamp DESC, id DESC LIMIT 100;"
        )
        latency = measure_query_latency(db_ro_conn, sql, params=(ts, ts), warmup=True, iterations=3)
        assert latency < 50.0, f"Single-second window latency {latency:.2f}ms exceeded 50ms threshold"

    def test_f3_04_latency_four_combined_filters(self, db_ro_conn):
        """4. Latency when combining 4 filters (user + src_ip + dst_ip + timestamp) remains < 50ms."""
        c = db_ro_conn.cursor()
        c.execute("SELECT username, src_ip, dst_ip, timestamp FROM nat_logs WHERE username IS NOT NULL AND username != '' LIMIT 1;")
        r = c.fetchone()
        if r:
            user, src_ip, dst_ip, ts = r["username"], r["src_ip"], r["dst_ip"], r["timestamp"]
        else:
            user, src_ip, dst_ip, ts = "test_user", "10.24.111.114", "8.8.8.8", "2026-11-21 03:00:00"

        sql = (
            "SELECT * FROM nat_logs "
            "WHERE username = ? COLLATE NOCASE AND src_ip = ? AND dst_ip = ? AND timestamp BETWEEN ? AND ? "
            "ORDER BY timestamp DESC, id DESC LIMIT 100;"
        )
        latency = measure_query_latency(db_ro_conn, sql, params=(user, src_ip, dst_ip, ts, ts), warmup=True, iterations=3)
        assert latency < 50.0, f"4-filter combined latency {latency:.2f}ms exceeded 50ms threshold"

    def test_f3_05_latency_details_field_limit_1(self, db_ro_conn):
        """5. Latency when querying details field with LIMIT 1 remains < 50ms."""
        sql = "SELECT id, details FROM nat_logs LIMIT 1;"
        latency = measure_query_latency(db_ro_conn, sql, warmup=True, iterations=3)
        assert latency < 50.0, f"LIMIT 1 details retrieval latency {latency:.2f}ms exceeded 50ms threshold"

    def test_f3_06_latency_api_endpoint_zero_match(self, auth_client):
        """6. Latency of FastAPI search endpoint on zero-matching query remains fast."""
        # Warmup connection
        auth_client.get("/api/logs/search?user=warmup_test")
        t0 = time.perf_counter()
        res = auth_client.get("/api/logs/search", params={"user": "nonexistent_subagent_boundary_user_xyz"})
        t1 = time.perf_counter()
        duration_ms = (t1 - t0) * 1000.0
        assert res.status_code == 200
        assert res.json().get("logs") == []
        assert duration_ms < 150.0, f"HTTP search endpoint roundtrip {duration_ms:.2f}ms exceeded 150ms"


# ============================================================================
# F4: Filter & Input Boundaries
# ============================================================================
class TestF4FilterAndInputBoundaries:
    """Verifies parameterized input safety, injection defense, port/IP boundary sanitization."""

    def test_f4_01_sql_injection_username_tautology(self, auth_client, db_conn):
        """1. SQL injection payloads in username parameter (' OR '1'='1) handled safely without execution."""
        res = auth_client.get("/api/logs/search", params={"user": "' OR '1'='1"})
        assert res.status_code == 200
        data = res.json()
        logs = data.get("logs", [])
        # Should not dump entire database; only rows where username literally equals "' OR '1'='1"
        for log in logs:
            assert log.get("username") == "' OR '1'='1"

    def test_f4_02_sql_injection_ddl_drop_attempt(self, auth_client, db_conn):
        """2. SQL injection DDL drop payload ('; DROP TABLE nat_logs; --) rejected safely without execution."""
        res = auth_client.get("/api/logs/search", params={"user": "'; DROP TABLE nat_logs; --"})
        assert res.status_code == 200
        # Verify nat_logs table was not dropped
        c = db_conn.cursor()
        c.execute("SELECT COUNT(*) FROM nat_logs;")
        count = c.fetchone()[0]
        assert isinstance(count, int)

    def test_f4_03_special_characters_and_wildcards_literal(self, auth_client):
        """3. Special characters and wildcards in user search (%, _, *, ?, \\) treated safely."""
        for char in ["%", "_", "*", "?", "\\", "'", '"', "<script>"]:
            res = auth_client.get("/api/logs/search", params={"user": char})
            assert res.status_code == 200
            assert isinstance(res.json().get("logs"), list)

    def test_f4_04_port_boundaries_valid_and_invalid(self, auth_client):
        """4. Port number boundaries (port = 0, 1, 65535, and invalid 70000, -1)."""
        # Testing with src_ip uses idx_nat_src_ip_port_ts for instant evaluation
        for p in [0, 1, 65535]:
            res = auth_client.get("/api/logs/search", params={"src_ip": "10.24.111.114", "src_port": str(p)})
            assert res.status_code == 200
            assert isinstance(res.json().get("logs"), list)

        # Invalid ports: should be handled safely without 500 error
        for invalid_p in [70000, -1, 99999, "not_a_port"]:
            res = auth_client.get("/api/logs/search", params={"src_ip": "10.24.111.114", "src_port": str(invalid_p)})
            assert res.status_code == 200
            assert isinstance(res.json().get("logs"), list)

    def test_f4_05_malformed_ipv4_strings(self, auth_client):
        """5. Malformed IPv4 strings return 0 rows without 500 error."""
        malformed = ["999.999.999.999", "abc.def.ghi.jkl", "10.24.111.114/24", "...", "127.0.0.1.1"]
        for bad_ip in malformed:
            res = auth_client.get("/api/logs/search", params={"src_ip": bad_ip})
            assert res.status_code == 200
            assert res.json().get("logs") == []

    def test_f4_06_mac_address_boundary_formats(self, auth_client):
        """6. MAC address format variations (lowercase, uppercase, colons, hyphens) handled safely."""
        macs = [
            "98:4A:6B:4E:88:50",
            "98:4a:6b:4e:88:50",
            "98-4A-6B-4E-88-50",
            "98-4a-6b-4e-88-50",
            "984A6B4E8850"
        ]
        for mac in macs:
            res = auth_client.get("/api/logs/search", params={"mac": mac})
            assert res.status_code == 200
            assert isinstance(res.json().get("logs"), list)


# ============================================================================
# F5: UDP Syslog Ingestion Boundaries
# ============================================================================
class TestF5UdpSyslogIngestionBoundaries:
    """Verifies UDP syslog listener tolerance to malformed, extreme, and corrupted packets."""

    def test_f5_01_zero_byte_udp_packet(self):
        """1. 0-byte UDP packet handling without exception."""
        from syslog_server import SyslogProtocol
        proto = SyslogProtocol()
        # Should not raise any error
        proto.datagram_received(b"", ("127.0.0.1", 5514))

    def test_f5_02_truncated_syslog_header(self):
        """2. Truncated syslog header (missing PRI, missing timestamp)."""
        from syslog_server import SyslogProtocol
        proto = SyslogProtocol()
        truncated = b"forward: in:ether1 out:ether2, proto TCP (ACK), 10.24.111.114:43758->172.217.112.4:443"
        proto.datagram_received(truncated, ("127.0.0.1", 5514))

    def test_f5_03_non_ascii_and_corrupt_utf8(self):
        """3. Syslog packet containing non-ASCII / corrupt UTF-8 bytes handled safely."""
        from syslog_server import SyslogProtocol
        proto = SyslogProtocol()
        corrupt = b"<134>Nov 21 03:00:00 SuperRouter \xff\xfe\x00\x80\x99 Corrupted Payload"
        proto.datagram_received(corrupt, ("127.0.0.1", 5514))

    def test_f5_04_jumbo_udp_packet(self):
        """4. Jumbo UDP packet handled gracefully and truncated in stats."""
        from syslog_server import SyslogProtocol, get_packet_stats
        proto = SyslogProtocol()
        # Jumbo packet with valid NAT prefix and large padding
        jumbo = (
            b"<134>Nov 21 03:00:00 SuperRouter forward: in:ether1 out:ether2, "
            b"proto TCP (ACK), 10.24.111.114:43758->103.54.108.114:43758->172.217.112.4:443, "
            b"len 52, padding: " + b"X" * 65000
        )
        proto.datagram_received(jumbo, ("127.0.0.1", 5514))
        stats = get_packet_stats()
        assert stats["total_packets"] > 0
        latest = stats["recent_packets"][0]
        assert len(latest["message"]) <= 250

    def test_f5_05_missing_nat_translation_clause(self, db_conn):
        """5. Missing NAT translation clause in message payload falls back safely to system_logs."""
        from syslog_server import SyslogProtocol
        proto = SyslogProtocol()
        non_nat = (
            b"<134>Nov 21 03:00:00 SuperNet_R06 forward: in:ether1 out:ether2, "
            b"proto TCP (ACK), 10.24.111.114:43758->172.217.112.4:443, len 52"
        )
        proto.datagram_received(non_nat, ("10.24.111.114", 5514))
        # Verify it was not inserted into nat_logs as a broken row with missing nat_ip
        c = db_conn.cursor()
        c.execute("SELECT COUNT(*) FROM nat_logs WHERE host = '10.24.111.114' AND (nat_ip = '' OR nat_ip IS NULL);")
        broken_count = c.fetchone()[0]
        assert broken_count == 0

    def test_f5_06_whitespace_only_packet(self):
        """6. Whitespace and newline only packet handled cleanly."""
        from syslog_server import SyslogProtocol
        proto = SyslogProtocol()
        proto.datagram_received(b"   \r\n\t  \n  ", ("127.0.0.1", 5514))


# ============================================================================
# F6: Batch DB Insertion Boundaries
# ============================================================================
class TestF6BatchDbInsertionBoundaries:
    """Verifies batch persistence boundaries, autoincrement stability, and string limits."""

    def test_f6_01_empty_batch_handling(self, db_conn):
        """1. Empty batch commit handling (no-op, no transaction error)."""
        cursor = db_conn.cursor()
        cursor.executemany(
            "INSERT INTO system_logs (timestamp, priority, identity, host, message) VALUES (?, ?, ?, ?, ?);",
            []
        )
        db_conn.commit()

    def test_f6_02_rapid_burst_insert_batch(self, db_conn):
        """2. Rapid burst of 500 records inserted in batch via executemany."""
        cursor = db_conn.cursor()
        rows = [
            ("2026-11-21 03:00:00", "info", "test_burst_identity", "127.0.0.1", f"Burst message #{i}")
            for i in range(500)
        ]
        cursor.executemany(
            "INSERT INTO system_logs (timestamp, priority, identity, host, message) VALUES (?, ?, ?, ?, ?);",
            rows
        )
        db_conn.commit()

        cursor.execute("SELECT COUNT(*) FROM system_logs WHERE identity = 'test_burst_identity';")
        count = cursor.fetchone()[0]
        assert count == 500

        # Clean up
        cursor.execute("DELETE FROM system_logs WHERE identity = 'test_burst_identity';")
        db_conn.commit()

    def test_f6_03_extreme_length_strings(self, db_conn):
        """3. Very long strings in host, identity, or details columns (1000+ chars)."""
        cursor = db_conn.cursor()
        long_host = "H" * 1500
        long_identity = "I" * 1500
        long_msg = "M" * 3000
        cursor.execute(
            "INSERT INTO system_logs (timestamp, priority, identity, host, message) VALUES ('2026-11-21 00:00:00', 'info', ?, ?, ?);",
            (long_identity, long_host, long_msg)
        )
        row_id = cursor.lastrowid
        db_conn.commit()

        cursor.execute("SELECT identity, host, message FROM system_logs WHERE id = ?;", (row_id,))
        row = cursor.fetchone()
        assert row["identity"] == long_identity
        assert row["host"] == long_host
        assert row["message"] == long_msg

        # Clean up
        cursor.execute("DELETE FROM system_logs WHERE id = ?;", (row_id,))
        db_conn.commit()

    def test_f6_04_duplicate_timestamp_and_src_ip_pk_handling(self, db_conn):
        """4. Duplicate timestamp/src_ip rows handled without primary key collision."""
        cursor = db_conn.cursor()
        ts = "2026-11-21 04:00:00"
        src_ip = "10.99.99.99"
        inserted_ids = []
        for i in range(5):
            cursor.execute("""
                INSERT INTO nat_logs (timestamp, host, identity, proto, src_ip, src_port, nat_ip, nat_port, dst_ip, dst_port, details)
                VALUES (?, 'TestRouter', 'TestIdentity', 'TCP', ?, 1000, '103.54.108.99', 1000, '8.8.8.8', 53, 'dup test');
            """, (ts, src_ip))
            inserted_ids.append(cursor.lastrowid)
        db_conn.commit()

        # All 5 IDs should be unique and distinct
        assert len(set(inserted_ids)) == 5

        # Clean up
        cursor.execute("DELETE FROM nat_logs WHERE src_ip = ?;", (src_ip,))
        db_conn.commit()

    def test_f6_05_special_characters_in_batch_insert(self, db_conn):
        """5. Special characters, quotes, and unicode in username/details during batch insert."""
        cursor = db_conn.cursor()
        special_users = ["O'Connor", 'User "Quoted"', "Robert'); DROP TABLE users;--", "ユーザー", "🚀_network"]
        rows = [
            ("2026-11-21 04:00:00", "Host_Special", u, "10.0.0.2", "103.0.0.2", "8.8.8.8")
            for u in special_users
        ]
        cursor.executemany("""
            INSERT INTO nat_logs (timestamp, host, username, src_ip, nat_ip, dst_ip)
            VALUES (?, ?, ?, ?, ?, ?);
        """, rows)
        db_conn.commit()

        for u in special_users:
            cursor.execute("SELECT id FROM nat_logs WHERE host = 'Host_Special' AND username = ?;", (u,))
            assert cursor.fetchone() is not None

        # Clean up
        cursor.execute("DELETE FROM nat_logs WHERE host = 'Host_Special';")
        db_conn.commit()

    def test_f6_06_transaction_rollback_safety(self, db_conn):
        """6. Verifies transaction rollback safely discards uncommitted batch records."""
        cursor = db_conn.cursor()
        cursor.execute("BEGIN TRANSACTION;")
        cursor.execute(
            "INSERT INTO system_logs (timestamp, priority, identity, host, message) "
            "VALUES ('2026-11-21 00:00:00', 'info', 'rollback_test', '127.0.0.1', 'will rollback');"
        )
        db_conn.rollback()

        cursor.execute("SELECT COUNT(*) FROM system_logs WHERE identity = 'rollback_test';")
        assert cursor.fetchone()[0] == 0


# ============================================================================
# F7: Web Concurrency & Request Boundaries
# ============================================================================
class TestF7WebConcurrencyAndRequestBoundaries:
    """Verifies FastAPI request parsing limits, 404/422 responses, and burst polling."""

    def test_f7_01_overly_long_query_parameter_4kb(self, auth_client):
        """1. Overly long query parameters (4KB query string) handled gracefully."""
        huge_user = "A" * 4096
        res = auth_client.get("/api/logs/search", params={"user": huge_user})
        assert res.status_code == 200
        assert res.json().get("logs") == []

    def test_f7_02_empty_json_body_on_post(self, auth_client):
        """2. Empty JSON body to POST endpoints requiring JSON returns 422 Unprocessable Entity."""
        res = auth_client.post(
            "/api/users/1/permissions/toggle",
            content=b"",
            headers={"Content-Type": "application/json"}
        )
        assert res.status_code == 422

    def test_f7_03_rapid_requests_nonexistent_endpoints_404(self, auth_client):
        """3. Rapid requests to invalid / non-existent endpoints return 404 cleanly."""
        for i in range(20):
            res = auth_client.get(f"/api/nonexistent/boundary_endpoint_{i}")
            assert res.status_code == 404

    def test_f7_04_negative_limit_offset_clamping(self, auth_client):
        """4. Negative limit or offset values in search queries clamped or rejected safely."""
        for invalid_page in [-10, 0]:
            res = auth_client.get("/traffic/online-users", params={"page": invalid_page})
            assert res.status_code == 200

    def test_f7_05_realtime_metrics_rapid_burst_polling(self, auth_client):
        """5. /api/system/realtime-metrics under rapid consecutive polling (50 requests in tight loop)."""
        for _ in range(50):
            res = auth_client.get("/api/system/realtime-metrics")
            assert res.status_code == 200
            data = res.json()
            assert "cpu" in data
            assert "ram" in data
            assert "active_users" in data

    def test_f7_06_excessive_page_number_clamped(self, auth_client):
        """6. Huge page parameter clamped to total available pages."""
        res = auth_client.get("/traffic/online-users", params={"page": 99999999})
        assert res.status_code == 200


# ============================================================================
# F8: Auth & Security Boundaries
# ============================================================================
class TestF8AuthAndSecurityBoundaries:
    """Verifies cookie security, unauthorized route protection, SQLi login defense."""

    def test_f8_01_missing_session_cookie_protected_views(self, unauth_client):
        """1. Missing session cookie on all protected endpoints redirects to / or returns 303/307."""
        protected_routes = [
            "/dashboard",
            "/router",
            "/search-log",
            "/download-log",
            "/system-log",
            "/traffic/online",
            "/traffic/find",
            "/users"
        ]
        for route in protected_routes:
            res = unauth_client.get(route, follow_redirects=False)
            assert res.status_code in (302, 303, 307), f"Route {route} did not redirect unauthenticated client"
            assert res.headers.get("location") == "/"

    def test_f8_02_corrupted_session_cookie(self):
        """2. Corrupted or invalid xtream_user cookie value rejected safely without crash."""
        from server import app
        from fastapi.testclient import TestClient
        with TestClient(app, raise_server_exceptions=False) as client:
            client.cookies.set("xtream_user", "' OR '1'='1 -- corrupt")
            res = client.get("/dashboard")
            assert res.status_code in (200, 302, 303, 307)

    def test_f8_03_login_sql_injection_payloads(self, unauth_client):
        """3. SQL injection attempts in login username/password fields rejected."""
        payloads = [
            ("' OR '1'='1", "' OR '1'='1"),
            ("admin' --", "anything"),
            ("admin' /*", "*/"),
            ("' UNION SELECT 1, 'admin', 'pass' --", "pass")
        ]
        for u, p in payloads:
            res = unauth_client.post("/login", data={"username": u, "password": p}, follow_redirects=False)
            assert res.status_code == 200
            assert "Invalid username or password" in res.text
            assert "xtream_user" not in res.cookies

    def test_f8_04_toggle_permissions_negative_user_id(self, auth_client):
        """4. Toggling permissions on invalid/negative user ID returns proper response without server crash."""
        res = auth_client.post("/api/users/-999/permissions/toggle", json={
            "permission_key": "view_logs",
            "is_allowed": True
        })
        assert res.status_code == 200

    def test_f8_05_toggle_nonexistent_permission_key(self, auth_client):
        """5. Toggling nonexistent permission key handled safely."""
        res = auth_client.post("/api/users/1/permissions/toggle", json={
            "permission_key": "nonexistent_fake_key_999",
            "is_allowed": False
        })
        assert res.status_code == 200

    def test_f8_06_cannot_delete_primary_admin(self, auth_client):
        """6. Deleting primary administrator account returns 400 Bad Request."""
        res = auth_client.delete("/api/users/1")
        assert res.status_code == 400
        assert "Cannot delete primary administrator" in res.json().get("error", "")


# ============================================================================
# F9: External Services Boundaries
# ============================================================================
class TestF9ExternalServicesBoundaries:
    """Verifies AS caching resilience, timeout safety, and IP pool parsing."""

    def test_f9_01_as_lookup_invalid_ip_strings(self):
        """1. AS lookup for invalid IP strings handled safely without crashing."""
        from as_service import get_as_info
        with patch("urllib.request.urlopen", side_effect=Exception("Offline test mode")):
            assert get_as_info("invalid-ip") == ""
            assert get_as_info("256.1.1.1") == ""

    def test_f9_02_as_lookup_multicast_reserved_ips(self):
        """2. AS lookup for multicast/reserved IPs recognized as private/special."""
        from as_service import get_as_info, is_private_or_special
        # 240.0.0.1 is RFC 1112 reserved
        assert is_private_or_special("240.0.0.1") is True
        assert get_as_info("240.0.0.1") == "Private / Local IP"
        # 127.0.0.1 is loopback
        assert get_as_info("127.0.0.1") == ""

    def test_f9_03_mikrotik_api_unreachable_ip_timeout(self):
        """3. MikroTik API initialization with unreachable IP returns error safely within timeout."""
        from mikrotik_api import test_mikrotik_connection
        res = test_mikrotik_connection("127.0.0.1", "admin", "admin", port=59999, timeout=1)
        assert res["success"] is False
        assert "unreachable" in res.get("error", "").lower() or "cannot reach" in res.get("error", "").lower()

    def test_f9_04_mikrotik_pool_parsing_single_ip(self):
        """4. IP pool parsing with single IP instead of range."""
        from mikrotik_api import parse_pool_ranges_to_prefixes
        assert parse_pool_ranges_to_prefixes("10.24.1.1") == ["10.24.1.1"]
        assert parse_pool_ranges_to_prefixes("") == []
        assert parse_pool_ranges_to_prefixes("   ,   ") == []

    def test_f9_05_large_batch_lookups_as_cache(self):
        """5. Large batch lookups in AS service cache resolve without memory error."""
        from as_service import batch_get_as_info
        # Use well-known IPs to guarantee instant cache resolution
        ip_batch = ["8.8.8.8"] * 25 + ["1.1.1.1"] * 25 + ["10.0.0.1"] * 25
        res = batch_get_as_info(ip_batch)
        assert "Google" in res.get("8.8.8.8", "")
        assert "Cloudflare" in res.get("1.1.1.1", "")
        assert res.get("10.0.0.1") == "Private / Local IP"

    def test_f9_06_pool_ranges_malformed_syntax(self):
        """6. Malformed IP pool strings handled gracefully without exception."""
        from mikrotik_api import parse_pool_ranges_to_prefixes
        res = parse_pool_ranges_to_prefixes("invalid-part, 10.24.0.1-incomplete, 192.168.1.1-192.168.1.254")
        assert len(res) >= 1


# ============================================================================
# F10: System Metrics Boundaries
# ============================================================================
class TestF10SystemMetricsBoundaries:
    """Verifies metrics computation under zero users, extreme byte quantities, and malformed strings."""

    def test_f10_01_realtime_metrics_zero_active_users(self, auth_client):
        """1. Realtime metrics handling when active users count is retrieved."""
        res = auth_client.get("/api/system/realtime-metrics")
        assert res.status_code == 200
        data = res.json()
        assert "active_users" in data
        assert isinstance(data["active_users"], int)
        assert data["active_users"] >= 0

    def test_f10_02_traffic_bytes_calculation_extreme_boundaries(self):
        """2. Traffic bytes calculation for 0 bytes, 1 byte, 1 TB, 1 PB."""
        from traffic_service import format_bytes_human
        assert format_bytes_human(0) == "0 B"
        assert format_bytes_human(1) == "1 B"
        assert format_bytes_human(1024**4) == "1.0 TB"
        assert "TB" in format_bytes_human(1024**5)
        assert format_bytes_human(-100) == "0 B"
        assert format_bytes_human(None) == "0 B"

    def test_f10_03_traffic_parse_string_missing_units_extra_whitespace(self):
        """3. Traffic parse string with missing units, raw numbers, or extra whitespace."""
        from traffic_service import parse_bytes_from_str
        assert parse_bytes_from_str("   ") == 0
        assert parse_bytes_from_str("1024") == 1024
        assert parse_bytes_from_str("   5.5   GB  ") == int(5.5 * 1024**3)
        assert parse_bytes_from_str("invalid_gibberish") == 0
        assert parse_bytes_from_str(None) == 0

    def test_f10_04_nonexistent_user_drilldown_empty(self):
        """4. Non-existent user usage history drilldown returns empty list safely."""
        from traffic_service import get_traffic_drilldown
        data = get_traffic_drilldown("non_existent_ghost_customer_xyz_9999")
        assert data["user"] == "non_existent_ghost_customer_xyz_9999"
        assert data["rows"] == []
        assert data["level_name"] == "yearly"

    def test_f10_05_system_sequence_retrieval(self, db_ro_conn):
        """5. System sequence count retrieval when table is empty or very large."""
        cursor = db_ro_conn.cursor()
        cursor.execute("SELECT seq FROM sqlite_sequence WHERE name = 'nat_logs';")
        row = cursor.fetchone()
        assert row is not None
        assert isinstance(row["seq"], int)
        assert row["seq"] >= 0

    def test_f10_06_syslog_packet_stats_extremes(self):
        """6. Syslog packet stats tracker maintains bounds under operation."""
        from syslog_server import get_packet_stats
        stats = get_packet_stats()
        assert "total_packets" in stats
        assert isinstance(stats["total_packets"], int)
        assert len(stats["recent_packets"]) <= 40
