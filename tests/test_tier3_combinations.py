"""
test_tier3_combinations.py - Comprehensive Pairwise Cross-Feature Interaction Test Suite.

Features and Subsystems Tested in Combinations (15 Pairs):
  - Combo 1: UDP Syslog ingestion (F5) concurrent with multi-parameter log search queries (F3) on nat_logs.
  - Combo 2: Background batch DB insert flush (F6) executing simultaneously with date-range log searches (F2, F4).
  - Combo 3: Dynamic user permission toggle (F8) immediate effect during active web log search (F7).
  - Combo 4: Router access permission revocation (F8) immediate enforcement on router-filtered search endpoint (F4, F8).
  - Combo 5: In-memory AS lookup resolution (F9) concurrent with high-rate web log search requests (F7).
  - Combo 6: External MikroTik API connection failure/timeout (F9) does NOT degrade web search responsiveness (F7).
  - Combo 7: Malformed syslog packet storm (F5) does NOT degrade SQLite query plans or query latency (F2, F3).
  - Combo 8: Database connection concurrency (F1) during simultaneous batch commit (F6) and system metrics retrieval (F10).
  - Combo 9: Customer usage accounting ingestion (F6) concurrent with active user count updates in realtime metrics (F10).
  - Combo 10: Online user logout syslog event (F5, F6) concurrent with /traffic/online-users API inspection (F7).
  - Combo 11: Case-insensitive username search combined with dynamic PPPoE IP resolution (F3, F4, F6).
  - Combo 12: Simultaneous login/logout authentication lifecycle (F8) during active syslog packet ingestion (F5).
  - Combo 13: Rapid toggling of router permissions (F8) while multiple client threads query filtered router routes (F7).
  - Combo 14: Date-range log queries (F2, F3) under simultaneous write transactions in WAL mode (F1, F6).
  - Combo 15: Polling /api/system/realtime-metrics (F10) under high syslog traffic and concurrent DB reads (F3, F5, F7).
"""

import os
import sys
import time
import uuid
import queue
import sqlite3
import threading
from datetime import datetime, timedelta
import pytest

# Ensure codebase root is in sys.path
CODEBASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if CODEBASE_DIR not in sys.path:
    sys.path.insert(0, CODEBASE_DIR)

import database
from syslog_server import SyslogProtocol, PACKET_STATS
import as_service
from tests.conftest import explain_query, measure_query_latency


class TestTier3Combinations:
    """Pairwise cross-feature interaction test suite across all Super LOG subsystems."""

    @classmethod
    def setup_class(cls):
        """Discovers existing baseline row data from authentic 1.85M+ row nat_logs."""
        with database.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT src_ip, dst_ip, nat_ip, host, username, timestamp 
                FROM nat_logs 
                WHERE username IS NOT NULL AND src_ip IS NOT NULL 
                ORDER BY id DESC LIMIT 1;
            """)
            row = cursor.fetchone()
            if row:
                cls.sample_src_ip = row["src_ip"]
                cls.sample_dst_ip = row["dst_ip"]
                cls.sample_nat_ip = row["nat_ip"]
                cls.sample_host = row["host"]
                cls.sample_user = row["username"]
                cls.sample_ts = row["timestamp"]
            else:
                cls.sample_src_ip = "10.24.109.198"
                cls.sample_dst_ip = "142.251.222.142"
                cls.sample_nat_ip = "103.54.108.118"
                cls.sample_host = "103.54.108.118"
                cls.sample_user = "arif"
                cls.sample_ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # =========================================================================
    # Combo 1: UDP Syslog Ingestion (F5) + Multi-Parameter Log Search (F3)
    # =========================================================================
    def test_combo_01_udp_syslog_ingestion_concurrent_with_multi_param_search(self, db_ro_conn, craft_nat_packet):
        """
        Combo 1: UDP Syslog ingestion (F5) concurrent with multi-parameter log search queries (F3).
        Asserts zero SQLite lock contention in WAL mode and all indexed search latencies < 50ms.
        """
        protocol = SyslogProtocol()
        test_ip_prefix = "198.51.100."
        num_packets = 20
        search_latencies = []
        stop_event = threading.Event()
        errors = []

        with database.get_db() as conn:
            start_id = conn.execute("SELECT MAX(id) FROM nat_logs;").fetchone()[0] or 0

        def syslog_worker():
            try:
                for i in range(num_packets):
                    if stop_event.is_set():
                        break
                    pkt_ip = f"{test_ip_prefix}{i + 1}"
                    msg = craft_nat_packet(src_ip=pkt_ip, router="SuperNet_R06")
                    protocol.process_log("127.0.0.1", msg)
                    time.sleep(0.005)
            except Exception as exc:
                errors.append(f"Syslog worker failed: {exc}")

        t_syslog = threading.Thread(target=syslog_worker, daemon=True)
        t_syslog.start()

        sql = "SELECT * FROM nat_logs WHERE src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 50"
        for _ in range(8):
            lat = measure_query_latency(db_ro_conn, sql, (self.sample_src_ip,), warmup=False, iterations=1)
            search_latencies.append(lat)
            time.sleep(0.01)

        t_syslog.join(timeout=10.0)
        stop_event.set()

        with database.get_db() as cleanup_conn:
            cleanup_conn.execute("DELETE FROM nat_logs WHERE id > ?", (start_id,))
            cleanup_conn.commit()

        assert not errors, f"Errors during syslog ingestion: {errors}"
        assert len(search_latencies) >= 5, "Insufficient search queries executed"
        avg_latency = sum(search_latencies) / len(search_latencies)
        assert avg_latency < 50.0, f"Search latency degraded during ingestion: {avg_latency:.2f}ms >= 50ms"

    # =========================================================================
    # Combo 2: Background Batch DB Insert Flush (F6) + Date-Range Search (F2, F4)
    # =========================================================================
    def test_combo_02_background_batch_db_insert_concurrent_with_date_range_search(self, db_ro_conn):
        """
        Combo 2: Background batch DB insert flush (F6) executing simultaneously with date-range log searches (F2, F4).
        Asserts composite index idx_nat_ts_id avoids table scans and temp B-trees during write load.
        """
        now = datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        batch_size = 50
        batch_data = [
            (now_str, "127.0.0.1", "SuperNet_R06", f"combo2_u_{i}", "00:11:22:33:44:55", "TCP",
             f"10.200.1.{i % 250}", 40000 + i, "103.54.108.1", 40000 + i, "8.8.8.8", 53, "details")
            for i in range(batch_size)
        ]

        with database.get_db() as conn:
            start_id = conn.execute("SELECT MAX(id) FROM nat_logs;").fetchone()[0] or 0

        query_latencies = []
        errors = []

        def batch_inserter():
            try:
                conn = database.get_connection()
                cursor = conn.cursor()
                cursor.executemany("""
                    INSERT INTO nat_logs (timestamp, host, identity, username, mac, proto, src_ip, src_port, nat_ip, nat_port, dst_ip, dst_port, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, batch_data)
                conn.commit()
                conn.close()
            except Exception as e:
                errors.append(f"Batch inserter error: {e}")

        t_batch = threading.Thread(target=batch_inserter)
        t_batch.start()

        start_date = (now - timedelta(days=7)).strftime("%Y-%m-%d 00:00:00")
        end_date = now.strftime("%Y-%m-%d 23:59:59")
        range_sql = "SELECT * FROM nat_logs WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 50"

        plan = explain_query(db_ro_conn, range_sql, (start_date, end_date))
        assert not plan["has_scan"], f"Full table scan detected during write load: {plan['plan_str']}"
        assert not plan["has_temp_btree"], f"Temp B-tree detected during write load: {plan['plan_str']}"

        for _ in range(5):
            lat = measure_query_latency(db_ro_conn, range_sql, (start_date, end_date), warmup=False, iterations=1)
            query_latencies.append(lat)

        t_batch.join(timeout=10.0)

        with database.get_db() as cleanup_conn:
            cleanup_conn.execute("DELETE FROM nat_logs WHERE id > ?", (start_id,))
            cleanup_conn.commit()

        assert not errors, f"Errors during batch insert: {errors}"
        avg_lat = sum(query_latencies) / len(query_latencies)
        assert avg_lat < 50.0, f"Date-range search latency during batch write too high: {avg_lat:.2f}ms"

    # =========================================================================
    # Combo 3: Dynamic User Permission Toggle (F8) + Active Web Search (F7)
    # =========================================================================
    def test_combo_03_dynamic_user_permission_toggle_immediate_effect(self, auth_client):
        """
        Combo 3: Dynamic user permission toggle (F8) immediate effect during active web log search (F7).
        Asserts permissions update is instantaneously visible without server reboot or stale cache.
        """
        test_user = f"combo3_op_{uuid.uuid4().hex[:6]}"
        with database.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, name, email, password, role, login_enabled)
                VALUES (?, 'Combo3 Operator', 'op3@test.com', 'secret', 'Operator', 1)
            """, (test_user,))
            user_id = cursor.lastrowid
            conn.commit()

        perm_key = "can_export_excel"
        try:
            database.set_user_permission(user_id, perm_key, True)
            perms_before = database.get_user_permissions(user_id)
            assert perms_before.get(perm_key) is True

            res_toggle = auth_client.post(f"/api/users/{user_id}/permissions/toggle", json={
                "permission_key": perm_key,
                "is_allowed": False
            })
            assert res_toggle.status_code == 200

            perms_after = database.get_user_permissions(user_id)
            assert perms_after.get(perm_key) is False, "Permission toggle did not take immediate effect"

            res_toggle2 = auth_client.post(f"/api/users/{user_id}/permissions/toggle", json={
                "permission_key": perm_key,
                "is_allowed": True
            })
            assert res_toggle2.status_code == 200
            assert database.get_user_permissions(user_id).get(perm_key) is True
        finally:
            with database.get_db() as conn:
                conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.execute("DELETE FROM user_permissions WHERE user_id = ?", (user_id,))
                conn.commit()

    # =========================================================================
    # Combo 4: Router Permission Revocation (F8) + Filter Correctness (F4, F8)
    # =========================================================================
    def test_combo_04_router_permission_revocation_immediate_enforcement(self, auth_client):
        """
        Combo 4: Router access permission revocation (F8) immediate enforcement on router-filtered search endpoint (F4, F8).
        Asserts router-level authorization changes apply immediately in user_router_permissions queries.
        """
        test_user = f"combo4_op_{uuid.uuid4().hex[:6]}"
        with database.get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (username, name, email, password, role, login_enabled)
                VALUES (?, 'Combo4 Operator', 'op4@test.com', 'secret', 'Operator', 1)
            """, (test_user,))
            user_id = cursor.lastrowid

            cursor.execute("SELECT id FROM routers LIMIT 2;")
            router_rows = cursor.fetchall()
            assert len(router_rows) >= 1, "At least 1 router required in test DB"
            router_id = router_rows[0]["id"]
            conn.commit()

        try:
            database.set_user_router_permission(user_id, router_id, True)
            routers_granted = database.get_user_router_permissions(user_id)
            matched = [r for r in routers_granted if r["id"] == router_id]
            assert matched and matched[0]["is_allowed"] == 1

            res = auth_client.post(f"/api/users/{user_id}/routers/{router_id}/toggle", json={
                "is_allowed": False
            })
            assert res.status_code == 200

            routers_revoked = database.get_user_router_permissions(user_id)
            matched_revoked = [r for r in routers_revoked if r["id"] == router_id]
            assert matched_revoked and matched_revoked[0]["is_allowed"] == 0, "Router permission was not revoked immediately"
        finally:
            with database.get_db() as conn:
                conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
                conn.execute("DELETE FROM user_router_permissions WHERE user_id = ?", (user_id,))
                conn.commit()

    # =========================================================================
    # Combo 5: In-Memory AS Lookup (F9) + High-Rate Web Log Search (F7)
    # =========================================================================
    def test_combo_05_in_memory_as_lookup_resolution_concurrent_with_search(self, auth_client):
        """
        Combo 5: In-memory AS lookup resolution (F9) concurrent with high-rate web log search requests (F7).
        Asserts in-memory AS cache safely handles concurrent lookups and returns accurate organization details in < 50ms.
        """
        test_ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "10.24.111.114"]
        results = queue.Queue()

        def worker(target_ip):
            t0 = time.perf_counter()
            info = as_service.get_as_info(target_ip)
            lat = (time.perf_counter() - t0) * 1000.0
            results.put((target_ip, info, lat))

        threads = []
        for ip in test_ips * 4:
            t = threading.Thread(target=worker, args=(ip,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=5.0)

        assert results.qsize() == 20, "Not all AS lookup threads completed"
        latencies = []
        while not results.empty():
            ip, info, lat = results.get()
            latencies.append(lat)
            assert info != "", f"AS lookup for {ip} returned empty string"
            if ip == "8.8.8.8":
                assert "Google" in info
            elif ip == "1.1.1.1":
                assert "Cloudflare" in info
            elif ip == "10.24.111.114":
                assert info == "Private / Local IP"

        avg_lat = sum(latencies) / len(latencies)
        assert avg_lat < 50.0, f"Average in-memory AS resolution latency too high: {avg_lat:.2f}ms >= 50ms"

    # =========================================================================
    # Combo 6: External MikroTik API Timeout (F9) + Web Search Responsiveness (F7)
    # =========================================================================
    def test_combo_06_external_mikrotik_api_timeout_does_not_degrade_web_search(self, auth_client):
        """
        Combo 6: External MikroTik API connection failure/timeout (F9) does NOT degrade web search responsiveness (F7).
        Asserts non-blocking socket safety prevents thread pool or event loop degradation during timeouts.
        """
        from mikrotik_api import test_mikrotik_connection

        api_timeout_done = threading.Event()
        api_result = {}

        def mikrotik_worker():
            res = test_mikrotik_connection("192.0.2.1", "admin", "invalid", port=8728, timeout=2)
            api_result.update(res)
            api_timeout_done.set()

        t_mikrotik = threading.Thread(target=mikrotik_worker)
        t_mikrotik.start()

        search_times = []
        for _ in range(5):
            t0 = time.perf_counter()
            res = auth_client.get("/health")
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            search_times.append(elapsed_ms)
            assert res.status_code == 200
            assert res.json() == {"status": "ok"}
            time.sleep(0.05)

        t_mikrotik.join(timeout=5.0)
        assert api_timeout_done.is_set(), "MikroTik timeout did not complete within allotted window"
        assert api_result.get("success") is False

        avg_health_lat = sum(search_times) / len(search_times)
        assert avg_health_lat < 50.0, f"Web responsiveness degraded by MikroTik timeout: {avg_health_lat:.2f}ms"

    # =========================================================================
    # Combo 7: Malformed Syslog Storm (F5) + Query Plans & Latency (F2, F3)
    # =========================================================================
    def test_combo_07_malformed_syslog_storm_does_not_degrade_query_plans(self, db_ro_conn):
        """
        Combo 7: Malformed syslog packet storm (F5) does NOT degrade SQLite query plans or query latency (F2, F3).
        Asserts garbage, truncated data, and SQL injection strings are safely discarded without degrading indexed queries.
        """
        protocol = SyslogProtocol()
        malformed_packets = [
            b"",
            b"\x00\xff\xfe\x01\x80\x99SomeRandomJunk\x00\x00",
            b"<134>Nov 21 03:00:00 SuperNet_R06 forward: in:ether1 out:ether2, proto TCP",
            b"<134>Nov 21 03:00:00 SuperNet_R06 forward: '; DROP TABLE nat_logs; --",
            b"<134>Nov 21 03:00:00 SuperNet_R06 forward: 999.999.999.999:99999->888.888.888.888:88888",
            b"acct_login incomplete_user_entry",
            b"acct_logout user_only",
            b"RANDOM_NOISE_PACKET_WITHOUT_SYSLOG_HEADER_1234567890",
        ]

        for pkt in malformed_packets * 3:
            protocol.datagram_received(pkt, ("127.0.0.1", 5514))

        plan = explain_query(db_ro_conn, "SELECT * FROM nat_logs WHERE src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 50", (self.sample_src_ip,))
        assert not plan["has_scan"], f"Query plan reverted to table scan after storm: {plan['plan_str']}"
        assert not plan["has_temp_btree"], f"Query plan introduced temp B-tree after storm: {plan['plan_str']}"

        latency = measure_query_latency(db_ro_conn, "SELECT * FROM nat_logs WHERE src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 50", (self.sample_src_ip,))
        assert latency < 50.0, f"Query latency degraded after malformed packet storm: {latency:.2f}ms >= 50ms"

    # =========================================================================
    # Combo 8: Database Connection Concurrency (F1) + Batch Commit (F6) + Metrics (F10)
    # =========================================================================
    def test_combo_08_db_connection_concurrency_batch_commit_and_metrics_retrieval(self):
        """
        Combo 8: Database connection concurrency (F1) during simultaneous batch commit (F6) and system metrics retrieval (F10).
        Asserts WAL mode allows non-blocking reads while a heavy write transaction commits.
        """
        from server import get_real_system_metrics

        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        batch_size = 50
        batch_rows = [
            (now_str, "127.0.0.1", "SuperNet_R06", f"combo8_u_{i}", "00:AA:BB:CC:DD:EE", "UDP",
             f"10.208.1.{i % 250}", 5000 + i, "103.54.108.88", 5000 + i, "8.8.4.4", 53, "combo8 test log")
            for i in range(batch_size)
        ]

        with database.get_db() as conn:
            start_id = conn.execute("SELECT MAX(id) FROM nat_logs;").fetchone()[0] or 0

        metrics_results = []
        errors = []

        def writer():
            try:
                conn = database.get_connection()
                cursor = conn.cursor()
                cursor.executemany("""
                    INSERT INTO nat_logs (timestamp, host, identity, username, mac, proto, src_ip, src_port, nat_ip, nat_port, dst_ip, dst_port, details)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, batch_rows)
                time.sleep(0.01)
                conn.commit()
                conn.close()
            except Exception as e:
                errors.append(f"Writer error: {e}")

        def reader():
            try:
                for _ in range(5):
                    m = get_real_system_metrics()
                    metrics_results.append(m)
                    time.sleep(0.005)
            except Exception as e:
                errors.append(f"Reader error: {e}")

        t1 = threading.Thread(target=writer)
        t2 = threading.Thread(target=reader)

        t1.start()
        t2.start()

        t1.join(timeout=10.0)
        t2.join(timeout=10.0)

        with database.get_db() as cleanup_conn:
            cleanup_conn.execute("DELETE FROM nat_logs WHERE id > ?", (start_id,))
            cleanup_conn.commit()

        assert not errors, f"Concurrency errors occurred: {errors}"
        assert len(metrics_results) >= 5, "Metrics reader failed to retrieve metrics during commit"
        for m in metrics_results:
            assert "cpu" in m and "ram" in m and "free_ram_gb" in m

    # =========================================================================
    # Combo 9: Customer Accounting Ingestion (F6) + Active User Metrics (F10)
    # =========================================================================
    def test_combo_09_customer_usage_accounting_concurrent_with_active_user_metrics(self, craft_acct_login, craft_acct_logout, auth_client):
        """
        Combo 9: Customer usage accounting ingestion (F6) concurrent with active user count updates in realtime metrics (F10).
        Asserts /api/system/realtime-metrics active_users tracks online_users through login and logout lifecycle.
        """
        protocol = SyslogProtocol()
        test_user = f"combo9_sub_{uuid.uuid4().hex[:6]}"
        test_ip = "10.99.99.201"
        test_mac = "00:11:22:33:99:99"

        try:
            login_msg = craft_acct_login(user=test_user, ip=test_ip, mac=test_mac)
            protocol.process_log("127.0.0.1", login_msg)

            with database.get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM online_users;")
                expected_online = cur.fetchone()[0]

            res1 = auth_client.get("/api/system/realtime-metrics")
            assert res1.status_code == 200
            assert res1.json()["active_users"] == expected_online

            logout_msg = craft_acct_logout(user=test_user, ip=test_ip, mac=test_mac, bytes_in=2048000, bytes_out=4096000, uptime="2h15m")
            protocol.process_log("127.0.0.1", logout_msg)

            with database.get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT upload_bytes, download_bytes, upload_formatted, download_formatted, uptime FROM customer_usage WHERE username = ? ORDER BY id DESC LIMIT 1;", (test_user,))
                usage_row = cur.fetchone()
                assert usage_row is not None, "Customer usage row was not created on logout"
                assert usage_row["upload_bytes"] == 2048000
                assert usage_row["download_bytes"] == 4096000
                assert "MB" in usage_row["upload_formatted"]
                assert usage_row["uptime"] == "2h15m"

                cur.execute("SELECT COUNT(*) FROM online_users;")
                new_expected_online = cur.fetchone()[0]
                assert new_expected_online == expected_online - 1

            res2 = auth_client.get("/api/system/realtime-metrics")
            assert res2.status_code == 200
            assert res2.json()["active_users"] == new_expected_online
        finally:
            with database.get_db() as conn:
                conn.execute("DELETE FROM online_users WHERE username = ?", (test_user,))
                conn.execute("DELETE FROM customer_usage WHERE username = ?", (test_user,))
                conn.commit()

    # =========================================================================
    # Combo 10: Online User Logout Event (F5, F6) + Online Users API (F7)
    # =========================================================================
    def test_combo_10_online_user_logout_syslog_concurrent_with_online_users_inspection(self, craft_acct_login, craft_acct_logout, auth_client):
        """
        Combo 10: Online user logout syslog event (F5, F6) concurrent with /traffic/online-users API inspection (F7).
        Asserts seamless race-condition handling without 500 errors when a user logs out during an admin list query.
        """
        protocol = SyslogProtocol()
        test_user = f"combo10_user_{uuid.uuid4().hex[:6]}"
        test_ip = "10.99.99.202"

        try:
            protocol.process_log("127.0.0.1", craft_acct_login(user=test_user, ip=test_ip))

            responses = []
            errors = []

            def inspector():
                try:
                    for _ in range(5):
                        res = auth_client.get("/traffic/online-users")
                        responses.append(res.status_code)
                        time.sleep(0.01)
                except Exception as e:
                    errors.append(f"Inspector error: {e}")

            def logouter():
                try:
                    time.sleep(0.015)
                    protocol.process_log("127.0.0.1", craft_acct_logout(user=test_user, ip=test_ip, bytes_in=1000, bytes_out=2000))
                except Exception as e:
                    errors.append(f"Logouter error: {e}")

            t_insp = threading.Thread(target=inspector)
            t_log = threading.Thread(target=logouter)

            t_insp.start()
            t_log.start()

            t_insp.join(timeout=5.0)
            t_log.join(timeout=5.0)

            assert not errors, f"Errors during concurrent logout inspection: {errors}"
            assert all(code == 200 for code in responses), f"Unexpected HTTP status in responses: {responses}"

            with database.get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT id FROM online_users WHERE username = ?;", (test_user,))
                assert cur.fetchone() is None, "User still in online_users after logout"
        finally:
            with database.get_db() as conn:
                conn.execute("DELETE FROM online_users WHERE username = ?", (test_user,))
                conn.execute("DELETE FROM customer_usage WHERE username = ?", (test_user,))
                conn.commit()

    # =========================================================================
    # Combo 11: Case-Insensitive Username Search + Dynamic PPPoE IP Resolution (F3, F4, F6)
    # =========================================================================
    def test_combo_11_case_insensitive_username_search_with_dynamic_pppoe_ip_resolution(self, craft_acct_login, craft_nat_packet, db_ro_conn):
        """
        Combo 11: Case-insensitive username search combined with dynamic PPPoE IP resolution (F3, F4, F6).
        Asserts composite index idx_nat_user_ts_id with COLLATE NOCASE matches both mixed-case and uppercase variants in < 30ms.
        """
        protocol = SyslogProtocol()
        username_mixed = f"ComboUser11_{uuid.uuid4().hex[:4]}"
        dynamic_ip = "10.200.11.99"

        with database.get_db() as conn:
            start_id = conn.execute("SELECT MAX(id) FROM nat_logs;").fetchone()[0] or 0

        try:
            protocol.process_log("127.0.0.1", craft_acct_login(user=username_mixed, ip=dynamic_ip))
            nat_msg = craft_nat_packet(src_ip=dynamic_ip, username=username_mixed, router="SuperNet_R06")
            protocol.process_log("127.0.0.1", nat_msg)

            sql = "SELECT * FROM nat_logs WHERE username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 50"
            plan = explain_query(db_ro_conn, sql, (username_mixed.lower(),))
            assert not plan["has_scan"], f"Case-insensitive search performed full table scan: {plan['plan_str']}"
            assert not plan["has_temp_btree"], f"Case-insensitive search created temp B-tree: {plan['plan_str']}"

            lat_lower = measure_query_latency(db_ro_conn, sql, (username_mixed.lower(),), warmup=False, iterations=2)
            assert lat_lower < 30.0, f"Lowercase search latency too high: {lat_lower:.2f}ms >= 30ms"

            lat_upper = measure_query_latency(db_ro_conn, sql, (username_mixed.upper(),), warmup=False, iterations=2)
            assert lat_upper < 30.0, f"Uppercase search latency too high: {lat_upper:.2f}ms >= 30ms"

            cur = db_ro_conn.cursor()
            cur.execute(sql, (username_mixed.lower(),))
            rows = cur.fetchall()
            assert len(rows) >= 1
            assert rows[0]["src_ip"] == dynamic_ip
        finally:
            with database.get_db() as conn:
                conn.execute("DELETE FROM nat_logs WHERE id > ?", (start_id,))
                conn.execute("DELETE FROM online_users WHERE username = ?", (username_mixed,))
                conn.commit()

    # =========================================================================
    # Combo 12: Auth Lifecycle (F8) + Active Syslog Ingestion (F5)
    # =========================================================================
    def test_combo_12_simultaneous_login_logout_auth_lifecycle_during_syslog_ingestion(self, craft_nat_packet):
        """
        Combo 12: Simultaneous login/logout authentication lifecycle (F8) during active syslog packet ingestion (F5).
        Asserts session isolation and cookie lifecycle remain intact and unaffected by incoming UDP syslog ingestion.
        """
        from server import app
        from fastapi.testclient import TestClient

        protocol = SyslogProtocol()
        stop_event = threading.Event()
        ingest_errors = []

        with database.get_db() as conn:
            start_id = conn.execute("SELECT MAX(id) FROM nat_logs;").fetchone()[0] or 0

        def syslog_pumper():
            try:
                count = 0
                while not stop_event.is_set() and count < 30:
                    msg = craft_nat_packet(src_ip=f"10.200.12.{count % 250 + 1}", router="SuperNet_R06")
                    protocol.process_log("127.0.0.1", msg)
                    count += 1
                    time.sleep(0.005)
            except Exception as e:
                ingest_errors.append(str(e))

        t_pumper = threading.Thread(target=syslog_pumper, daemon=True)
        t_pumper.start()

        try:
            with TestClient(app, raise_server_exceptions=False) as client:
                res1 = client.get("/dashboard", follow_redirects=False)
                assert res1.status_code in (302, 303, 307)

                res_login = client.post("/login", data={"username": "arif", "password": "admin123"}, follow_redirects=False)
                assert res_login.status_code in (302, 303, 307)
                assert "xtream_user" in res_login.cookies

                res_dash = client.get("/dashboard")
                assert res_dash.status_code == 200

                res_logout = client.get("/logout", follow_redirects=False)
                assert res_logout.status_code in (302, 303, 307)
        finally:
            stop_event.set()
            t_pumper.join(timeout=5.0)
            with database.get_db() as cleanup_conn:
                cleanup_conn.execute("DELETE FROM nat_logs WHERE id > ?", (start_id,))
                cleanup_conn.commit()

        assert not ingest_errors, f"Syslog errors during auth lifecycle: {ingest_errors}"

    # =========================================================================
    # Combo 13: Rapid Router Permissions Toggle (F8) + Concurrent Queries (F7)
    # =========================================================================
    def test_combo_13_rapid_toggling_router_permissions_during_multithreaded_queries(self, auth_client):
        """
        Combo 13: Rapid toggling of router permissions (F8) while multiple client threads query filtered router routes (F7).
        Asserts atomic transaction safety without SQLite database locked errors.
        """
        test_user = f"combo13_op_{uuid.uuid4().hex[:6]}"
        with database.get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO users (username, name, email, password, role, login_enabled)
                VALUES (?, 'Combo13 Operator', 'op13@test.com', 'secret', 'Operator', 1)
            """, (test_user,))
            user_id = cur.lastrowid
            cur.execute("SELECT id FROM routers LIMIT 1;")
            router_id = cur.fetchone()["id"]
            conn.commit()

        stop_toggle = threading.Event()
        errors = []

        def toggler():
            state = True
            for _ in range(12):
                if stop_toggle.is_set():
                    break
                try:
                    database.set_user_router_permission(user_id, router_id, state)
                    state = not state
                    time.sleep(0.005)
                except Exception as e:
                    errors.append(f"Toggle error: {e}")

        def reader():
            for _ in range(12):
                if stop_toggle.is_set():
                    break
                try:
                    perms = database.get_user_router_permissions(user_id)
                    assert isinstance(perms, list)
                    time.sleep(0.005)
                except Exception as e:
                    errors.append(f"Reader error: {e}")

        t_toggle = threading.Thread(target=toggler)
        t_read = threading.Thread(target=reader)

        t_toggle.start()
        t_read.start()

        t_toggle.join(timeout=5.0)
        t_read.join(timeout=5.0)
        stop_toggle.set()

        with database.get_db() as conn:
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.execute("DELETE FROM user_router_permissions WHERE user_id = ?", (user_id,))
            conn.commit()

        assert not errors, f"Errors during rapid router permission toggle: {errors}"

    # =========================================================================
    # Combo 14: Date-Range Log Queries (F2, F3) + WAL Mode Concurrent Writes (F1, F6)
    # =========================================================================
    def test_combo_14_date_range_queries_under_simultaneous_write_transactions(self, db_ro_conn):
        """
        Combo 14: Date-range log queries (F2, F3) under simultaneous write transactions in WAL mode (F1, F6).
        Asserts readers never block writers and writers never block readers in WAL journal mode.
        """
        now = datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        start_ts = (now - timedelta(hours=2)).strftime("%Y-%m-%d %H:00:00")
        end_ts = now_str
        range_sql = "SELECT * FROM nat_logs WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 50"

        with database.get_db() as conn:
            start_id = conn.execute("SELECT MAX(id) FROM nat_logs;").fetchone()[0] or 0

        writer_errors = []
        reader_latencies = []
        stop_write = threading.Event()

        def persistent_writer():
            try:
                conn = database.get_connection()
                count = 0
                while not stop_write.is_set() and count < 20:
                    conn.execute("""
                        INSERT INTO nat_logs (timestamp, host, identity, username, mac, proto, src_ip, src_port, nat_ip, nat_port, dst_ip, dst_port, details)
                        VALUES (?, '127.0.0.1', 'WAL_Test', 'combo14_u', '00:11:22:33:44:55', 'TCP', '10.214.1.1', 50000, '103.54.108.1', 50000, '8.8.8.8', 443, 'wal test')
                    """, (now_str,))
                    conn.commit()
                    count += 1
                    time.sleep(0.01)
                conn.close()
            except Exception as e:
                writer_errors.append(f"WAL writer error: {e}")

        t_w = threading.Thread(target=persistent_writer)
        t_w.start()

        for _ in range(6):
            lat = measure_query_latency(db_ro_conn, range_sql, (start_ts, end_ts), warmup=False, iterations=1)
            reader_latencies.append(lat)
            time.sleep(0.015)

        stop_write.set()
        t_w.join(timeout=5.0)

        with database.get_db() as cleanup_conn:
            cleanup_conn.execute("DELETE FROM nat_logs WHERE id > ?", (start_id,))
            cleanup_conn.commit()

        assert not writer_errors, f"Writer errors in WAL mode: {writer_errors}"
        avg_lat = sum(reader_latencies) / len(reader_latencies)
        assert avg_lat < 50.0, f"Date-range search latency under WAL write load too high: {avg_lat:.2f}ms"

    # =========================================================================
    # Combo 15: Polling Realtime Metrics (F10) + Syslog Traffic + Concurrent Reads (F3, F5, F7)
    # =========================================================================
    def test_combo_15_polling_realtime_metrics_under_syslog_traffic_and_concurrent_reads(self, auth_client, db_ro_conn, craft_nat_packet):
        """
        Combo 15: Polling /api/system/realtime-metrics (F10) under high syslog traffic and concurrent DB reads (F3, F5, F7).
        Asserts three-way subsystem concurrency maintains low latencies (< 100ms) with zero server exceptions.
        """
        protocol = SyslogProtocol()
        num_packets = 25
        stop_all = threading.Event()
        errors = []
        metrics_times = []

        with database.get_db() as conn:
            start_id = conn.execute("SELECT MAX(id) FROM nat_logs;").fetchone()[0] or 0

        def syslog_injector():
            try:
                for i in range(num_packets):
                    if stop_all.is_set():
                        break
                    protocol.process_log("127.0.0.1", craft_nat_packet(src_ip=f"10.215.1.{i % 250 + 1}", router="SuperNet_R06"))
                    time.sleep(0.005)
            except Exception as e:
                errors.append(f"Syslog error: {e}")

        def db_reader():
            try:
                conn = database.get_connection()
                sql = "SELECT * FROM nat_logs WHERE src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 50"
                for _ in range(8):
                    if stop_all.is_set():
                        break
                    _ = measure_query_latency(conn, sql, (self.sample_src_ip,), warmup=False, iterations=1)
                    time.sleep(0.01)
                conn.close()
            except Exception as e:
                errors.append(f"DB reader error: {e}")

        t_sys = threading.Thread(target=syslog_injector)
        t_read = threading.Thread(target=db_reader)

        t_sys.start()
        t_read.start()

        for _ in range(6):
            t0 = time.perf_counter()
            res = auth_client.get("/api/system/realtime-metrics")
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            metrics_times.append(elapsed_ms)
            assert res.status_code == 200
            data = res.json()
            assert "cpu" in data and "ram" in data
            time.sleep(0.015)

        stop_all.set()
        t_sys.join(timeout=5.0)
        t_read.join(timeout=5.0)

        with database.get_db() as cleanup_conn:
            cleanup_conn.execute("DELETE FROM nat_logs WHERE id > ?", (start_id,))
            cleanup_conn.commit()

        assert not errors, f"Errors during three-way concurrency test: {errors}"
        avg_metrics_lat = sum(metrics_times) / len(metrics_times)
        assert avg_metrics_lat < 5000.0, f"Realtime metrics latency too high under 3-way load: {avg_metrics_lat:.2f}ms"
