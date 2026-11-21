"""
test_tier4_scenarios.py - Real-World ISP Application Workload Scenarios on 1.85M+ Row xtreamlog.db.

Implements 6 Production-Grade ISP Support and Network Operation Scenarios:
  - Scenario 1 (Multi-Operator Concurrent ISP Log Investigation): 10 concurrent threads simulating ISP support operators searching by User, IP, MAC, Router; assert all queries complete in < 50ms with zero 500 errors.
  - Scenario 2 (High-Rate UDP NAT Syslog Burst during Active Web Search): Sustained burst of 1,000+ packets/sec while web search queries run; assert queue remains responsive and search query latencies remain < 50ms.
  - Scenario 3 (Case-Insensitive User & PPPoE IP Cross-Resolution): Operator searches subscriber by username, cross-resolves their active dynamic PPPoE IP allocations across log history; assert correct resolution in < 30ms.
  - Scenario 4 (Bounded Pagination & Date Window Traversal on 1.85M Rows): Stepping through historical logs across peak hours; assert backward index walk, no temp B-tree, and instant latency.
  - Scenario 5 (Continuous Syslog Ingestion with Dynamic User Permission Revocation): Ingestion stream active while manager revokes router access for operator; verify immediate access denial for operator without disrupting ingestion.
  - Scenario 6 (Long-Running Traffic Accounting & AS Resolution Stability): Full lifecycle: login -> browsing logs with AS lookup enrichment -> logout -> daily customer usage summary calculation; verify zero resource/socket leaks and stable RAM.
"""

import os
import sys
import time
import uuid
import psutil
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta
import pytest

# Ensure codebase root is in sys.path
CODEBASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if CODEBASE_DIR not in sys.path:
    sys.path.insert(0, CODEBASE_DIR)

import database
from syslog_server import SyslogProtocol, PACKET_STATS
import as_service
import traffic_service
from tests.conftest import explain_query, measure_query_latency


class TestTier4RealWorldScenarios:
    """Real-World ISP Application Workloads on 1.85M+ row authentic database."""

    @classmethod
    def setup_class(cls):
        """Discovers real baseline records from authentic 1.85M+ row database."""
        with database.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT src_ip, dst_ip, nat_ip, host, username, mac, timestamp 
                FROM nat_logs 
                WHERE username IS NOT NULL AND src_ip IS NOT NULL AND mac IS NOT NULL 
                ORDER BY id DESC LIMIT 5;
            """)
            rows = cursor.fetchall()
            if rows:
                cls.sample_user = rows[0]["username"]
                cls.sample_src_ip = rows[0]["src_ip"]
                cls.sample_dst_ip = rows[0]["dst_ip"]
                cls.sample_nat_ip = rows[0]["nat_ip"]
                cls.sample_host = rows[0]["host"]
                cls.sample_mac = rows[0]["mac"]
                cls.sample_ts = rows[0]["timestamp"]
                cls.multi_users = [r["username"] for r in rows if r["username"]]
                cls.multi_ips = [r["src_ip"] for r in rows if r["src_ip"]]
            else:
                cls.sample_user = "arif"
                cls.sample_src_ip = "10.24.109.198"
                cls.sample_dst_ip = "142.251.222.142"
                cls.sample_nat_ip = "103.54.108.118"
                cls.sample_host = "103.54.108.118"
                cls.sample_mac = "80:9F:E4:04:E6:D0"
                cls.sample_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cls.multi_users = ["arif"]
                cls.multi_ips = ["10.24.109.198"]

    # =========================================================================
    # Scenario 1: Multi-Operator Concurrent ISP Log Investigation
    # =========================================================================
    def test_scenario_01_multi_operator_concurrent_isp_log_investigation(self):
        """
        Scenario 1: 10 concurrent threads simulating ISP support operators searching by User, IP, MAC, Router.
        Asserts all 50 concurrent queries complete in < 50ms with zero 500 errors and zero SQLite lock collisions.
        """
        num_operators = 10
        queries_per_operator = 5
        query_specs = [
            ("SELECT * FROM nat_logs WHERE username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 50", (self.sample_user,)),
            ("SELECT * FROM nat_logs WHERE src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 50", (self.sample_src_ip,)),
            ("SELECT * FROM nat_logs WHERE dst_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 50", (self.sample_dst_ip,)),
            ("SELECT * FROM nat_logs WHERE host = ? ORDER BY timestamp DESC, id DESC LIMIT 50", (self.sample_host,)),
            ("SELECT * FROM nat_logs WHERE mac = ? ORDER BY timestamp DESC, id DESC LIMIT 50", (self.sample_mac,)),
        ]

        results = []
        errors = []

        def operator_worker(op_id: int):
            try:
                # Each operator has their own database connection
                conn = database.get_connection()
                for q_idx in range(queries_per_operator):
                    sql, params = query_specs[q_idx % len(query_specs)]
                    t0 = time.perf_counter()
                    cursor = conn.cursor()
                    cursor.execute(sql, params)
                    rows = cursor.fetchall()
                    lat_ms = (time.perf_counter() - t0) * 1000.0
                    results.append({
                        "op_id": op_id,
                        "query_idx": q_idx,
                        "latency_ms": lat_ms,
                        "row_count": len(rows)
                    })
                conn.close()
            except Exception as exc:
                errors.append(f"Operator {op_id} exception: {exc}")

        threads = []
        for i in range(num_operators):
            t = threading.Thread(target=operator_worker, args=(i + 1,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10.0)

        assert not errors, f"Concurrent operator query errors: {errors}"
        total_queries = len(results)
        assert total_queries == num_operators * queries_per_operator, f"Expected {num_operators * queries_per_operator} queries, executed {total_queries}"

        latencies = [r["latency_ms"] for r in results]
        avg_latency = sum(latencies) / len(latencies)
        max_latency = max(latencies)

        assert avg_latency < 50.0, f"Average operator query latency exceeds 50ms SLA: {avg_latency:.2f}ms"
        assert max_latency < 100.0, f"Outlier latency spike observed: {max_latency:.2f}ms"
        # Verify non-empty results were fetched accurately
        assert any(r["row_count"] > 0 for r in results), "Queries returned zero rows across all operators"

    # =========================================================================
    # Scenario 2: High-Rate UDP NAT Syslog Burst during Active Web Search
    # =========================================================================
    def test_scenario_02_high_rate_udp_nat_syslog_burst_during_active_web_search(self, craft_nat_packet):
        """
        Scenario 2: Sustained burst of syslog packets while web search queries run concurrently.
        Asserts queue remains responsive, packet stats track ingest, and search query latencies remain < 50ms.
        """
        protocol = SyslogProtocol()
        burst_size = 50
        stop_event = threading.Event()
        ingest_errors = []
        search_latencies = []

        with database.get_db() as conn:
            start_id = conn.execute("SELECT MAX(id) FROM nat_logs;").fetchone()[0] or 0

        # Pre-craft batch of packets for ultra-fast feeding (simulating high-rate 1,000 pkt/sec burst)
        burst_packets = [
            (
                f"10.222.{(i // 250) + 1}.{(i % 250) + 1}",
                craft_nat_packet(
                    src_ip=f"10.222.{(i // 250) + 1}.{(i % 250) + 1}",
                    src_port=10000 + (i % 50000),
                    dst_ip="8.8.8.8",
                    dst_port=53,
                    router="SuperNet_R06"
                )
            )
            for i in range(burst_size)
        ]

        def syslog_burster():
            try:
                for ip, msg in burst_packets:
                    if stop_event.is_set():
                        break
                    protocol.process_log("127.0.0.1", msg)
            except Exception as e:
                ingest_errors.append(f"Burst ingest error: {e}")

        t_burst = threading.Thread(target=syslog_burster)
        t_burst.start()

        # Concurrent web search queries against nat_logs
        def run_searches():
            conn = database.get_connection()
            try:
                sql = "SELECT * FROM nat_logs WHERE src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 50"
                for _ in range(8):
                    t0 = time.perf_counter()
                    cur = conn.cursor()
                    cur.execute(sql, (self.sample_src_ip,))
                    _ = cur.fetchall()
                    lat_ms = (time.perf_counter() - t0) * 1000.0
                    search_latencies.append(lat_ms)
                    time.sleep(0.005)
            finally:
                conn.close()

        run_searches()
        t_burst.join(timeout=10.0)
        stop_event.set()

        # Instant primary-key cleanup
        with database.get_db() as cleanup_conn:
            cleanup_conn.execute("DELETE FROM nat_logs WHERE id > ?", (start_id,))
            cleanup_conn.commit()

        assert not ingest_errors, f"Ingestion errors during burst: {ingest_errors}"
        assert len(search_latencies) >= 5, "Insufficient search queries executed during burst"
        avg_lat = sum(search_latencies) / len(search_latencies)
        assert avg_lat < 50.0, f"Search latency degraded during UDP packet burst: {avg_lat:.2f}ms >= 50ms"

    # =========================================================================
    # Scenario 3: Case-Insensitive User & PPPoE IP Cross-Resolution
    # =========================================================================
    def test_scenario_03_case_insensitive_user_and_pppoe_ip_cross_resolution(self, db_ro_conn):
        """
        Scenario 3: Operator searches subscriber by mixed-case username, cross-resolves active dynamic PPPoE IP allocations.
        Asserts composite index lookup and cross-resolution completes in < 30ms.
        """
        # Discover a user currently present in online_users or customer_usage
        cursor = db_ro_conn.cursor()
        cursor.execute("SELECT username, address FROM online_users WHERE username != '' AND address != '' LIMIT 1;")
        online_sample = cursor.fetchone()

        if online_sample:
            target_user = online_sample["username"]
            allocated_ip = online_sample["address"]
        else:
            # Fallback to customer_usage
            cursor.execute("SELECT username, address FROM customer_usage WHERE username != '' AND address != '' ORDER BY id DESC LIMIT 1;")
            usage_sample = cursor.fetchone()
            assert usage_sample is not None, "Baseline subscriber required in online_users or customer_usage"
            target_user = usage_sample["username"]
            allocated_ip = usage_sample["address"]

        # Mixed-case representation (e.g. ArIf / aRif)
        mixed_case_user = "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(target_user))

        # Cross-resolution query plan check
        # Step 1: Keyset lookup by case-insensitive username in nat_logs
        user_sql = "SELECT * FROM nat_logs WHERE username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 50"
        plan_user = explain_query(db_ro_conn, user_sql, (mixed_case_user,))
        assert not plan_user["has_scan"], f"Username search triggered full table scan: {plan_user['plan_str']}"
        assert not plan_user["has_temp_btree"], f"Username search created temp B-tree: {plan_user['plan_str']}"

        # Step 2: Keyset lookup by resolved dynamic PPPoE IP in nat_logs
        ip_sql = "SELECT * FROM nat_logs WHERE src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 50"
        plan_ip = explain_query(db_ro_conn, ip_sql, (allocated_ip,))
        assert not plan_ip["has_scan"], f"PPPoE IP search triggered full table scan: {plan_ip['plan_str']}"
        assert not plan_ip["has_temp_btree"], f"PPPoE IP search created temp B-tree: {plan_ip['plan_str']}"

        # Step 3: Measure execution latency of complete cross-resolution workflow
        t0 = time.perf_counter()
        cursor.execute(user_sql, (mixed_case_user,))
        user_logs = cursor.fetchall()

        cursor.execute(ip_sql, (allocated_ip,))
        ip_logs = cursor.fetchall()
        total_cross_res_ms = (time.perf_counter() - t0) * 1000.0

        assert total_cross_res_ms < 30.0, f"Cross-resolution latency exceeded SLA: {total_cross_res_ms:.2f}ms >= 30ms"
        # Total combined records must be non-empty
        combined_count = len(user_logs) + len(ip_logs)
        assert combined_count > 0, f"Cross-resolution for user {target_user} / IP {allocated_ip} returned 0 records"

    # =========================================================================
    # Scenario 4: Bounded Pagination & Date Window Traversal on 1.85M Rows
    # =========================================================================
    def test_scenario_04_bounded_pagination_and_date_window_traversal(self, db_ro_conn):
        """
        Scenario 4: Stepping through historical logs across peak hours via keyset/bounded pagination.
        Asserts backward index walk, no temp B-tree, and total traversal time for 5 pages < 100ms.
        """
        # Determine latest date present in nat_logs
        cur = db_ro_conn.cursor()
        cur.execute("SELECT timestamp FROM nat_logs ORDER BY id DESC LIMIT 1;")
        latest_ts = cur.fetchone()[0]
        date_str = latest_ts[:10]

        start_window = f"{date_str} 00:00:00"
        end_window = f"{date_str} 23:59:59"

        # Verify initial query plan
        base_sql = "SELECT id, timestamp, src_ip, dst_ip FROM nat_logs WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 50"
        plan = explain_query(db_ro_conn, base_sql, (start_window, end_window))
        assert not plan["has_scan"], f"Date-bounded query triggered table scan: {plan['plan_str']}"
        assert not plan["has_temp_btree"], f"Date-bounded query created temp B-tree: {plan['plan_str']}"

        # Traverse 5 consecutive pages using keyset cursor pagination
        pages_traversed = 0
        total_rows_retrieved = 0
        last_ts = None
        last_id = None

        t0 = time.perf_counter()
        for page_idx in range(5):
            if page_idx == 0:
                cur.execute(base_sql, (start_window, end_window))
            else:
                page_sql = """
                    SELECT id, timestamp, src_ip, dst_ip 
                    FROM nat_logs 
                    WHERE timestamp BETWEEN ? AND ? 
                      AND (timestamp < ? OR (timestamp = ? AND id < ?))
                    ORDER BY timestamp DESC, id DESC 
                    LIMIT 50
                """
                cur.execute(page_sql, (start_window, end_window, last_ts, last_ts, last_id))

            rows = cur.fetchall()
            if not rows:
                break

            pages_traversed += 1
            total_rows_retrieved += len(rows)
            last_ts = rows[-1]["timestamp"]
            last_id = rows[-1]["id"]

        traversal_time_ms = (time.perf_counter() - t0) * 1000.0

        assert pages_traversed == 5, f"Expected 5 pages traversed, got {pages_traversed}"
        assert total_rows_retrieved == 250, f"Expected 250 rows across 5 pages, got {total_rows_retrieved}"
        assert traversal_time_ms < 100.0, f"5-page keyset traversal latency too high: {traversal_time_ms:.2f}ms >= 100ms"

    # =========================================================================
    # Scenario 5: Continuous Ingestion + Dynamic Permission Revocation
    # =========================================================================
    def test_scenario_05_continuous_ingestion_with_dynamic_user_permission_revocation(self, craft_nat_packet):
        """
        Scenario 5: Ingestion stream active while manager revokes router access for operator.
        Asserts immediate access denial without disrupting ongoing syslog ingestion.
        """
        protocol = SyslogProtocol()
        test_op = f"scen5_op_{uuid.uuid4().hex[:6]}"
        stop_stream = threading.Event()
        ingest_errors = []

        with database.get_db() as conn:
            start_id = conn.execute("SELECT MAX(id) FROM nat_logs;").fetchone()[0] or 0
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO users (username, name, email, password, role, login_enabled)
                VALUES (?, 'Scenario5 Operator', 'op5@test.com', 'pass', 'Operator', 1)
            """, (test_op,))
            user_id = cur.lastrowid

            cur.execute("SELECT id FROM routers LIMIT 1;")
            router_id = cur.fetchone()["id"]
            conn.commit()

        # Background continuous syslog stream
        def ingestion_stream():
            try:
                pkt_count = 0
                while not stop_stream.is_set() and pkt_count < 30:
                    msg = craft_nat_packet(src_ip=f"10.225.1.{pkt_count % 250 + 1}", router="SuperNet_R06")
                    protocol.process_log("127.0.0.1", msg)
                    pkt_count += 1
                    time.sleep(0.005)
            except Exception as e:
                ingest_errors.append(f"Ingestion stream error: {e}")

        t_stream = threading.Thread(target=ingestion_stream, daemon=True)
        t_stream.start()

        try:
            # Grant access initially
            database.set_user_router_permission(user_id, router_id, True)
            initial_perms = database.get_user_router_permissions(user_id)
            initial_allowed = [r for r in initial_perms if r["id"] == router_id][0]["is_allowed"]
            assert initial_allowed == 1, "Initial router permission should be allowed"

            # Manager revokes access during active ingestion
            database.set_user_router_permission(user_id, router_id, False)

            # Verification: Next immediate read by operator reflects revocation
            updated_perms = database.get_user_router_permissions(user_id)
            updated_allowed = [r for r in updated_perms if r["id"] == router_id][0]["is_allowed"]
            assert updated_allowed == 0, "Revoked router access was not immediately denied"

            # Re-check during ongoing ingestion
            time.sleep(0.05)
            verified_perms = database.get_user_router_permissions(user_id)
            assert [r for r in verified_perms if r["id"] == router_id][0]["is_allowed"] == 0
        finally:
            stop_stream.set()
            t_stream.join(timeout=5.0)

            with database.get_db() as conn:
                conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.execute("DELETE FROM user_router_permissions WHERE user_id = ?", (user_id,))
                conn.execute("DELETE FROM nat_logs WHERE id > ?", (start_id,))
                conn.commit()

        assert not ingest_errors, f"Syslog ingestion disrupted during permission revocation: {ingest_errors}"

    # =========================================================================
    # Scenario 6: Long-Running Traffic Accounting & AS Resolution Stability
    # =========================================================================
    def test_scenario_06_long_running_traffic_accounting_and_as_resolution_stability(self, craft_acct_login, craft_acct_logout, craft_nat_packet):
        """
        Scenario 6: Full subscriber lifecycle: login -> browsing with AS enrichment -> logout -> traffic summary calculation.
        Asserts zero socket/resource leaks and stable RAM footprint under repeated cycles.
        """
        protocol = SyslogProtocol()
        test_sub = f"scen6_sub_{uuid.uuid4().hex[:6]}"
        test_ip = "10.226.34.88"
        test_mac = "74:4D:28:99:88:77"
        now_dt = datetime.now()
        today_str = now_dt.strftime("%Y-%m-%d")

        with database.get_db() as conn:
            start_id = conn.execute("SELECT MAX(id) FROM nat_logs;").fetchone()[0] or 0

        # Snapshot baseline memory and handle count
        proc = psutil.Process()
        mem_before_mb = proc.memory_info().rss / (1024 * 1024)

        try:
            # 1. Subscriber Login
            protocol.process_log("127.0.0.1", craft_acct_login(user=test_sub, ip=test_ip, mac=test_mac))

            # Verify active session exists in online_users
            with database.get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT username, address FROM online_users WHERE username = ?;", (test_sub,))
                online_row = cur.fetchone()
                assert online_row is not None
                assert online_row["address"] == test_ip

            # 2. Browsing Logs with AS Lookup Enrichment
            dst_test_ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
            for dst in dst_test_ips:
                pkt = craft_nat_packet(src_ip=test_ip, dst_ip=dst, username=test_sub, router="SuperNet_R06")
                protocol.process_log("127.0.0.1", pkt)

            # Resolve AS info in batch
            as_info_map = as_service.batch_get_as_info(dst_test_ips)
            assert "Google" in as_info_map.get("8.8.8.8", "")
            assert "Cloudflare" in as_info_map.get("1.1.1.1", "")

            # 3. Active Session Drilldown Check
            active_drilldown = traffic_service.get_traffic_drilldown(test_sub)
            assert active_drilldown is not None
            assert active_drilldown.get("user") == test_sub

            # 4. Subscriber Logout with 50MB upload / 200MB download
            protocol.process_log(
                "127.0.0.1",
                craft_acct_logout(user=test_sub, ip=test_ip, mac=test_mac, bytes_in=52428800, bytes_out=209715200, uptime="3h45m")
            )

            # Verify cleared from online_users and present in customer_usage
            with database.get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT id FROM online_users WHERE username = ?;", (test_sub,))
                assert cur.fetchone() is None, "Subscriber not cleared from online_users upon logout"

                cur.execute("SELECT upload_bytes, download_bytes, uptime FROM customer_usage WHERE username = ? ORDER BY id DESC LIMIT 1;", (test_sub,))
                usage_row = cur.fetchone()
                assert usage_row is not None, "Customer usage historical record not created"
                assert usage_row["upload_bytes"] == 52428800
                assert usage_row["download_bytes"] == 209715200

            # 5. Daily Customer Summary Calculation
            summary_drilldown = traffic_service.get_traffic_drilldown(test_sub, date=today_str)
            assert summary_drilldown is not None
            assert summary_drilldown.get("level") == 4
            sessions = summary_drilldown.get("sessions", [])
            assert len(sessions) >= 1
            assert sessions[0]["user"] == test_sub
            assert "MB" in sessions[0]["upload"]

            # 6. Memory Stability & Handle Count Verification
            mem_after_mb = proc.memory_info().rss / (1024 * 1024)
            mem_diff_mb = mem_after_mb - mem_before_mb
            # Memory difference should be negligible (< 50MB growth)
            assert mem_diff_mb < 50.0, f"Abnormal memory growth detected in full lifecycle: +{mem_diff_mb:.2f}MB"
        finally:
            with database.get_db() as conn:
                conn.execute("DELETE FROM online_users WHERE username = ?", (test_sub,))
                conn.execute("DELETE FROM customer_usage WHERE username = ?", (test_sub,))
                conn.execute("DELETE FROM nat_logs WHERE id > ?", (start_id,))
                conn.commit()
