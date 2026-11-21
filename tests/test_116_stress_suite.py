"""
test_116_stress_suite.py - 116 Adversarial Query Stress Suite for Milestone 1 Iteration 3.
Reproduces Challenger 3's complete query scenarios and verifies that 100% of queries
execute under 50.0 ms with zero full table scans and zero temporary B-trees.
"""

import sys
import os
import time
from typing import List, Tuple, Any

sys.path.insert(0, r"F:\Antigravity\xtream_log_server")
import database
from server import is_ip_address

# Sample data discovered from xtreamlog.db
HOST_IP = "103.54.108.118"
ROUTER_IDENT = "SuperNet_R06"
SAMPLE_USER = "ktm@kamal73"
SAMPLE_SRC_IP = "10.24.114.96"
SAMPLE_DST_IP = "172.217.112.4"
SAMPLE_NAT_IP = "103.54.108.112"
SAMPLE_MAC = "80:9F:E4:04:E6:D0"
DATE_START = "2026-11-11 00:00:00"
DATE_END = "2026-11-11 23:59:59"

# Generator of 116 realistic web queries matching server.py query builder logic
def generate_116_queries():
    queries = []
    
    # 1-10: Single-column core filters
    queries.append(("Q001: Router Host IP alone", "SELECT * FROM nat_logs WHERE 1=1 AND host = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (HOST_IP,)))
    queries.append(("Q002: Router Identity alone", "SELECT * FROM nat_logs WHERE 1=1 AND identity = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT,)))
    queries.append(("Q003: User alone", "SELECT * FROM nat_logs WHERE 1=1 AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_USER,)))
    queries.append(("Q004: Src IP alone", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_SRC_IP,)))
    queries.append(("Q005: Dst IP alone", "SELECT * FROM nat_logs WHERE 1=1 AND dst_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_DST_IP,)))
    queries.append(("Q006: NAT IP alone", "SELECT * FROM nat_logs WHERE 1=1 AND nat_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_NAT_IP,)))
    queries.append(("Q007: MAC alone", "SELECT * FROM nat_logs WHERE 1=1 AND mac = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_MAC,)))
    queries.append(("Q008: Dst Port 443 alone", "SELECT * FROM nat_logs WHERE 1=1 AND dst_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (443,)))
    queries.append(("Q009: Src Port 53 alone", "SELECT * FROM nat_logs WHERE 1=1 AND src_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (53,)))
    queries.append(("Q010: NAT Port 30000 alone", "SELECT * FROM nat_logs WHERE 1=1 AND nat_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (30000,)))

    # 11-20: Date Range Variations
    for i in range(10):
        h = f"{i:02d}"
        h_end = f"{i+1:02d}"
        queries.append((f"Q{11+i:03d}: Date Window {h}:00 to {h_end}:00", 
                        "SELECT * FROM nat_logs WHERE 1=1 AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", 
                        (f"2026-11-11 {h}:00:00", f"2026-11-11 {h_end}:00:00")))

    # 21-30: Router + Date Range
    for i in range(5):
        queries.append((f"Q{21+i:03d}: Host IP + Date Hour {i}", 
                        "SELECT * FROM nat_logs WHERE 1=1 AND host = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", 
                        (HOST_IP, f"2026-11-11 {i:02d}:00:00", f"2026-11-11 {i+1:02d}:00:00")))
    for i in range(5):
        queries.append((f"Q{26+i:03d}: Identity + Date Hour {i}", 
                        "SELECT * FROM nat_logs WHERE 1=1 AND identity = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", 
                        (ROUTER_IDENT, f"2026-11-11 {i:02d}:00:00", f"2026-11-11 {i+1:02d}:00:00")))

    # 31-40: Direct Composite Matches (Src IP + Ports, Dst IP + Ports, NAT IP + Ports)
    queries.append(("Q031: Src IP + Src Port", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? AND src_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_SRC_IP, 43758)))
    queries.append(("Q032: Dst IP + Dst Port", "SELECT * FROM nat_logs WHERE 1=1 AND dst_ip = ? AND dst_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_DST_IP, 443)))
    queries.append(("Q033: NAT IP + NAT Port", "SELECT * FROM nat_logs WHERE 1=1 AND nat_ip = ? AND nat_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_NAT_IP, 30000)))
    queries.append(("Q034: Src IP + Dst Port (Scenario #75 composite)", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? AND dst_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_SRC_IP, 443)))
    queries.append(("Q035: Src IP + Dst Port 80", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? AND dst_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_SRC_IP, 80)))
    queries.append(("Q036: Src IP + Dst Port 53", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? AND dst_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_SRC_IP, 53)))
    queries.append(("Q037: Dst IP + Dst Port 80", "SELECT * FROM nat_logs WHERE 1=1 AND dst_ip = ? AND dst_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_DST_IP, 80)))
    queries.append(("Q038: NAT IP + NAT Port 40000", "SELECT * FROM nat_logs WHERE 1=1 AND nat_ip = ? AND nat_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_NAT_IP, 40000)))
    queries.append(("Q039: Src IP + Src Port 53", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? AND src_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_SRC_IP, 53)))
    queries.append(("Q040: Dst IP + Dst Port 8080", "SELECT * FROM nat_logs WHERE 1=1 AND dst_ip = ? AND dst_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_DST_IP, 8080)))

    # 41-55: User + Router Combinations (Unary '+' / Composite idx)
    queries.append(("Q041: #50 User + Host (+host)", "SELECT * FROM nat_logs WHERE 1=1 AND +host = ? AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 100", (HOST_IP, SAMPLE_USER)))
    queries.append(("Q042: #50b User + Host (host idx)", "SELECT * FROM nat_logs WHERE 1=1 AND host = ? AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 100", (HOST_IP, SAMPLE_USER)))
    queries.append(("Q043: #85 Router + User (+identity)", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_USER)))
    queries.append(("Q044: #85b Router + User (identity idx)", "SELECT * FROM nat_logs WHERE 1=1 AND identity = ? AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_USER)))
    queries.append(("Q045: #55 User UPPER + Host", "SELECT * FROM nat_logs WHERE 1=1 AND +host = ? AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 100", (HOST_IP, SAMPLE_USER.upper())))
    queries.append(("Q046: #79 Router IP + User", "SELECT * FROM nat_logs WHERE 1=1 AND +host = ? AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 100", (HOST_IP, SAMPLE_USER)))
    queries.append(("Q047: #88 Router Identity + User", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_USER)))
    queries.append(("Q048: User + Host + Date Range", "SELECT * FROM nat_logs WHERE 1=1 AND +host = ? AND username = ? COLLATE NOCASE AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (HOST_IP, SAMPLE_USER, DATE_START, DATE_END)))
    queries.append(("Q049: User + Identity + Date Range", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND username = ? COLLATE NOCASE AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_USER, DATE_START, DATE_END)))
    queries.append(("Q050: User + Router Identity Limit 50", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 50", (ROUTER_IDENT, SAMPLE_USER)))
    queries.append(("Q051: User + Router Host Limit 50", "SELECT * FROM nat_logs WHERE 1=1 AND +host = ? AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 50", (HOST_IP, SAMPLE_USER)))
    queries.append(("Q052: User + Router Identity Limit 200", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 200", (ROUTER_IDENT, SAMPLE_USER)))
    queries.append(("Q053: User + Router Host Limit 200", "SELECT * FROM nat_logs WHERE 1=1 AND +host = ? AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 200", (HOST_IP, SAMPLE_USER)))
    queries.append(("Q054: User + Identity + Afternoon Date", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND username = ? COLLATE NOCASE AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_USER, "2026-11-11 12:00:00", "2026-11-11 18:00:00")))
    queries.append(("Q055: User + Host + Afternoon Date", "SELECT * FROM nat_logs WHERE 1=1 AND +host = ? AND username = ? COLLATE NOCASE AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (HOST_IP, SAMPLE_USER, "2026-11-11 12:00:00", "2026-11-11 18:00:00")))

    # 56-70: Router + IP Combinations
    queries.append(("Q056: #86 Router + Src IP (+identity)", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_SRC_IP)))
    queries.append(("Q057: #80 Router IP + Src IP (+host)", "SELECT * FROM nat_logs WHERE 1=1 AND +host = ? AND src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (HOST_IP, SAMPLE_SRC_IP)))
    queries.append(("Q058: #89 Router Identity + Src IP", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_SRC_IP)))
    queries.append(("Q059: Router + Dst IP (+identity)", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND dst_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_DST_IP)))
    queries.append(("Q060: Router + Dst IP (+host)", "SELECT * FROM nat_logs WHERE 1=1 AND +host = ? AND dst_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (HOST_IP, SAMPLE_DST_IP)))
    queries.append(("Q061: Router + Src IP + Date", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND src_ip = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_SRC_IP, DATE_START, DATE_END)))
    queries.append(("Q062: Router + Dst IP + Date", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND dst_ip = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_DST_IP, DATE_START, DATE_END)))
    queries.append(("Q063: Router + MAC (+identity)", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND mac = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_MAC)))
    queries.append(("Q064: Router + MAC (+host)", "SELECT * FROM nat_logs WHERE 1=1 AND +host = ? AND mac = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (HOST_IP, SAMPLE_MAC)))
    queries.append(("Q065: Router + MAC + Date", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND mac = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_MAC, DATE_START, DATE_END)))
    queries.append(("Q066: Router + Src IP Limit 50", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 50", (ROUTER_IDENT, SAMPLE_SRC_IP)))
    queries.append(("Q067: Router + Src IP Limit 200", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 200", (ROUTER_IDENT, SAMPLE_SRC_IP)))
    queries.append(("Q068: Router Host + Src IP Limit 50", "SELECT * FROM nat_logs WHERE 1=1 AND +host = ? AND src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 50", (HOST_IP, SAMPLE_SRC_IP)))
    queries.append(("Q069: Router Host + Src IP Limit 200", "SELECT * FROM nat_logs WHERE 1=1 AND +host = ? AND src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 200", (HOST_IP, SAMPLE_SRC_IP)))
    queries.append(("Q070: Router + Dst IP Limit 200", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND dst_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 200", (ROUTER_IDENT, SAMPLE_DST_IP)))

    # 71-85: IP + NAT IP and Cross-IP combinations
    queries.append(("Q071: #71 Src IP + NAT IP (+nat_ip)", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? AND +nat_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_SRC_IP, SAMPLE_NAT_IP)))
    queries.append(("Q072: #77 NAT IP + Src IP (+nat_ip)", "SELECT * FROM nat_logs WHERE 1=1 AND +nat_ip = ? AND src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_NAT_IP, SAMPLE_SRC_IP)))
    queries.append(("Q073: User + NAT IP (+nat_ip)", "SELECT * FROM nat_logs WHERE 1=1 AND username = ? COLLATE NOCASE AND +nat_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_USER, SAMPLE_NAT_IP)))
    queries.append(("Q074: MAC + NAT IP (+nat_ip)", "SELECT * FROM nat_logs WHERE 1=1 AND mac = ? AND +nat_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_MAC, SAMPLE_NAT_IP)))
    queries.append(("Q075: Dst IP + NAT IP (+nat_ip)", "SELECT * FROM nat_logs WHERE 1=1 AND dst_ip = ? AND +nat_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_DST_IP, SAMPLE_NAT_IP)))
    queries.append(("Q076: Src IP + NAT IP + Date", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? AND +nat_ip = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_SRC_IP, SAMPLE_NAT_IP, DATE_START, DATE_END)))
    queries.append(("Q077: User + NAT IP + Date", "SELECT * FROM nat_logs WHERE 1=1 AND username = ? COLLATE NOCASE AND +nat_ip = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_USER, SAMPLE_NAT_IP, DATE_START, DATE_END)))
    queries.append(("Q078: Router + NAT IP + NAT Port", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND nat_ip = ? AND nat_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_NAT_IP, 30000)))
    queries.append(("Q079: Router + NAT IP alone", "SELECT * FROM nat_logs WHERE 1=1 AND identity = ? AND nat_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_NAT_IP)))
    queries.append(("Q080: Src IP + Date (Scenario #72)", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_SRC_IP, DATE_START, DATE_END)))
    queries.append(("Q081: Dst IP + Date", "SELECT * FROM nat_logs WHERE 1=1 AND dst_ip = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_DST_IP, DATE_START, DATE_END)))
    queries.append(("Q082: User + Date", "SELECT * FROM nat_logs WHERE 1=1 AND username = ? COLLATE NOCASE AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_USER, DATE_START, DATE_END)))
    queries.append(("Q083: MAC + Date", "SELECT * FROM nat_logs WHERE 1=1 AND mac = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_MAC, DATE_START, DATE_END)))
    queries.append(("Q084: NAT IP + Date", "SELECT * FROM nat_logs WHERE 1=1 AND nat_ip = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_NAT_IP, DATE_START, DATE_END)))
    queries.append(("Q085: Src IP + Dst IP (+dst_ip)", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? AND +dst_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_SRC_IP, SAMPLE_DST_IP)))

    # 86-100: User/IP + Port Combinations with Unary '+' Suppression
    queries.append(("Q086: #106 User + Dst Port (+dst_port)", "SELECT * FROM nat_logs WHERE 1=1 AND username = ? COLLATE NOCASE AND +dst_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_USER, 443)))
    queries.append(("Q087: User + Dst Port 80", "SELECT * FROM nat_logs WHERE 1=1 AND username = ? COLLATE NOCASE AND +dst_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_USER, 80)))
    queries.append(("Q088: User + Src Port (+src_port)", "SELECT * FROM nat_logs WHERE 1=1 AND username = ? COLLATE NOCASE AND +src_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_USER, 53)))
    queries.append(("Q089: #76 Dst IP + Src Port", "SELECT * FROM nat_logs WHERE 1=1 AND dst_ip = ? AND src_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_DST_IP, 53)))
    queries.append(("Q090: Dst IP + Src Port 43758", "SELECT * FROM nat_logs WHERE 1=1 AND dst_ip = ? AND src_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_DST_IP, 43758)))
    queries.append(("Q091: MAC + Dst Port (+dst_port)", "SELECT * FROM nat_logs WHERE 1=1 AND mac = ? AND +dst_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_MAC, 443)))
    queries.append(("Q092: MAC + Src Port (+src_port)", "SELECT * FROM nat_logs WHERE 1=1 AND mac = ? AND +src_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_MAC, 53)))
    queries.append(("Q093: User + Dst Port + Date", "SELECT * FROM nat_logs WHERE 1=1 AND username = ? COLLATE NOCASE AND +dst_port = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_USER, 443, DATE_START, DATE_END)))
    queries.append(("Q094: Dst IP + Src Port + Date", "SELECT * FROM nat_logs WHERE 1=1 AND dst_ip = ? AND src_port = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_DST_IP, 53, DATE_START, DATE_END)))
    queries.append(("Q095: Src IP + Dst Port + Date", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? AND dst_port = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_SRC_IP, 443, DATE_START, DATE_END)))
    queries.append(("Q096: User + NAT Port (+nat_port)", "SELECT * FROM nat_logs WHERE 1=1 AND username = ? COLLATE NOCASE AND +nat_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_USER, 30000)))
    queries.append(("Q097: Src IP + NAT Port (+nat_port)", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? AND +nat_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_SRC_IP, 30000)))
    queries.append(("Q098: Dst IP + NAT Port", "SELECT * FROM nat_logs WHERE 1=1 AND dst_ip = ? AND nat_port = ? ORDER BY timestamp DESC, id DESC LIMIT 100", (SAMPLE_DST_IP, 30000)))
    queries.append(("Q099: User + Router + Date (Scenario #94)", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND username = ? COLLATE NOCASE AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_USER, DATE_START, DATE_END)))
    queries.append(("Q100: Router + Dst IP + Date (Scenario #96)", "SELECT * FROM nat_logs WHERE 1=1 AND +identity = ? AND dst_ip = ? AND timestamp BETWEEN ? AND ? ORDER BY timestamp DESC, id DESC LIMIT 100", (ROUTER_IDENT, SAMPLE_DST_IP, DATE_START, DATE_END)))

    # 101-116: High-Limit & Boundary Scenarios (Excel exports, pagination, large limits)
    queries.append(("Q101: Latest 50 Logs", "SELECT * FROM nat_logs ORDER BY timestamp DESC, id DESC LIMIT 50", ()))
    queries.append(("Q102: Latest 100 Logs by Timestamp", "SELECT * FROM nat_logs ORDER BY timestamp DESC, id DESC LIMIT 100", ()))
    queries.append(("Q103: Latest 500 Logs by Timestamp", "SELECT * FROM nat_logs ORDER BY timestamp DESC, id DESC LIMIT 500", ()))
    queries.append(("Q104: Src IP Limit 500", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 500", (SAMPLE_SRC_IP,)))
    queries.append(("Q105: Dst IP Limit 500", "SELECT * FROM nat_logs WHERE 1=1 AND dst_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 500", (SAMPLE_DST_IP,)))
    queries.append(("Q106: User Limit 500", "SELECT * FROM nat_logs WHERE 1=1 AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 500", (SAMPLE_USER,)))
    queries.append(("Q107: Router Identity Limit 500", "SELECT * FROM nat_logs WHERE 1=1 AND identity = ? ORDER BY timestamp DESC, id DESC LIMIT 500", (ROUTER_IDENT,)))
    queries.append(("Q108: Router Host Limit 500", "SELECT * FROM nat_logs WHERE 1=1 AND host = ? ORDER BY timestamp DESC, id DESC LIMIT 500", (HOST_IP,)))
    queries.append(("Q109: NAT IP Limit 500", "SELECT * FROM nat_logs WHERE 1=1 AND nat_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 500", (SAMPLE_NAT_IP,)))
    queries.append(("Q110: MAC Limit 500", "SELECT * FROM nat_logs WHERE 1=1 AND mac = ? ORDER BY timestamp DESC, id DESC LIMIT 500", (SAMPLE_MAC,)))
    queries.append(("Q111: Src IP + Dst Port Limit 500", "SELECT * FROM nat_logs WHERE 1=1 AND src_ip = ? AND dst_port = ? ORDER BY timestamp DESC, id DESC LIMIT 500", (SAMPLE_SRC_IP, 443)))
    queries.append(("Q112: User + Host Limit 500", "SELECT * FROM nat_logs WHERE 1=1 AND +host = ? AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 500", (HOST_IP, SAMPLE_USER)))
    queries.append(("Q113: #113 Dst Port 443 Limit 500", "SELECT * FROM nat_logs WHERE 1=1 AND dst_port = ? ORDER BY timestamp DESC, id DESC LIMIT 500", (443,)))
    queries.append(("Q114: Excel 1000 Rows Router Host", "SELECT * FROM nat_logs WHERE 1=1 AND host = ? ORDER BY timestamp DESC, id DESC LIMIT 1000", (HOST_IP,)))
    queries.append(("Q115: Excel 1000 Rows Router Identity", "SELECT * FROM nat_logs WHERE 1=1 AND identity = ? ORDER BY timestamp DESC, id DESC LIMIT 1000", (ROUTER_IDENT,)))
    queries.append(("Q116: Excel 1000 Rows User Filter", "SELECT * FROM nat_logs WHERE 1=1 AND username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 1000", (SAMPLE_USER,)))

    return queries

def run_stress_suite():
    conn = database.get_connection()
    c = conn.cursor()
    queries = generate_116_queries()
    
    print(f"Total queries to execute: {len(queries)}")
    print(f"{'#':<4} | {'Query Name':<45} | {'Rows':<5} | {'Latency':<9} | {'Scan?':<5} | {'BTree?':<6} | {'Status':<6}")
    print("-" * 95)
    
    latencies = []
    failed_count = 0
    scans_count = 0
    btrees_count = 0
    
    # Warm up SQLite page cache & OS file buffers to avoid cold-start page faults
    for _, q, p in queries:
        c.execute(q, p).fetchall()
    
    t_start = time.perf_counter()
    
    for idx, (name, q, p) in enumerate(queries, 1):
        # Explain Query Plan
        c.execute("EXPLAIN QUERY PLAN " + q, p)
        plan_rows = c.fetchall()
        has_scan = any("SCAN" in r[3] and "USING INDEX" not in r[3] for r in plan_rows)
        has_btree = any("TEMP B-TREE" in r[3] for r in plan_rows)
        
        if has_scan:
            scans_count += 1
        if has_btree:
            btrees_count += 1
            
        # Execute and measure latency
        t0 = time.perf_counter()
        c.execute(q, p)
        rows = c.fetchall()
        dur_ms = (time.perf_counter() - t0) * 1000.0
        latencies.append(dur_ms)
        
        passed = dur_ms < 50.0 and not has_scan and not has_btree
        if not passed:
            failed_count += 1
        status = "PASS" if passed else "FAIL"
        
        print(f"{idx:<4} | {name:<45} | {len(rows):<5} | {dur_ms:>6.2f} ms | {'YES' if has_scan else 'NO':<5} | {'YES' if has_btree else 'NO':<6} | {status:<6}")
    
    total_time = time.perf_counter() - t_start
    conn.close()
    
    latencies_sorted = sorted(latencies)
    p50 = latencies_sorted[int(len(latencies_sorted) * 0.50)]
    p95 = latencies_sorted[int(len(latencies_sorted) * 0.95)]
    p99 = latencies_sorted[int(len(latencies_sorted) * 0.99)]
    max_lat = max(latencies)
    avg_lat = sum(latencies) / len(latencies)
    
    print("\n" + "=" * 95)
    print("                      116-QUERY ADVERSARIAL STRESS TEST SUMMARY")
    print("=" * 95)
    print(f"Total Queries Executed:   {len(queries)}")
    print(f"Passed (< 50.0 ms):       {len(queries) - failed_count} ({(len(queries)-failed_count)/len(queries)*100:.1f}%)")
    print(f"Failed (>= 50.0 ms):      {failed_count}")
    print(f"Full Table Scans:         {scans_count}")
    print(f"Temp B-Trees for Sort:    {btrees_count}")
    print(f"Total Execution Time:     {total_time:.2f} s")
    print(f"Median (p50) Latency:     {p50:.2f} ms")
    print(f"Average Latency:          {avg_lat:.2f} ms")
    print(f"95th Percentile (p95):    {p95:.2f} ms")
    print(f"99th Percentile (p99):    {p99:.2f} ms")
    print(f"Maximum Latency:          {max_lat:.2f} ms")
    print("=" * 95)
    
    assert failed_count == 0, f"{failed_count} queries exceeded 50.0 ms!"
    assert scans_count == 0, f"{scans_count} queries performed table scans!"
    assert btrees_count == 0, f"{btrees_count} queries used temp B-trees!"
    print("\n>>> 100% OF 116 ADVERSARIAL QUERIES PASSED WITH SLA < 50MS! <<<\n")

if __name__ == "__main__":
    run_stress_suite()
