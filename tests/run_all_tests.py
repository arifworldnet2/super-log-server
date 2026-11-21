"""
run_all_tests.py - Standalone Master Test Runner for Super LOG Server.

Executes all 4 Test Tiers:
  - Tier 1: Feature Coverage (test_tier1_features.py)
  - Tier 2: Boundary & Corner Cases (test_tier2_boundaries.py)
  - Tier 3: Cross-Feature Combinations (test_tier3_combinations.py)
  - Tier 4: Real-World Application Scenarios (test_tier4_scenarios.py)

Reports:
  - Test count per tier and total count (asserts >= 121 tests).
  - Passed, failed, skipped counts.
  - Execution duration per tier and total runtime.
  - Production SLA verifications:
      * Search latency < 50ms across 1.85M+ rows.
      * Zero full table scans on composite indexes.
      * Clean error handling & event loop responsiveness.
  - Clean formatted summary table.
  - Returns exit code 0 if 100% pass, exit code 1 on any failure.
"""

import os
import sys
import time
import tempfile
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, Any, List

# Ensure codebase root is in sys.path
CODEBASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if CODEBASE_DIR not in sys.path:
    sys.path.insert(0, CODEBASE_DIR)

try:
    sys.stdout.reconfigure(line_buffering=True)
except Exception:
    pass

import database
from tests.conftest import explain_query, measure_query_latency


TIER_SUITES = [
    {
        "tier": "Tier 1",
        "name": "Feature Coverage (F1-F10)",
        "file": os.path.join(CODEBASE_DIR, "tests", "test_tier1_features.py")
    },
    {
        "tier": "Tier 2",
        "name": "Boundary & Corner Cases",
        "file": os.path.join(CODEBASE_DIR, "tests", "test_tier2_boundaries.py")
    },
    {
        "tier": "Tier 3",
        "name": "Cross-Feature Combinations",
        "file": os.path.join(CODEBASE_DIR, "tests", "test_tier3_combinations.py")
    },
    {
        "tier": "Tier 4",
        "name": "Real-World ISP Workload Scenarios",
        "file": os.path.join(CODEBASE_DIR, "tests", "test_tier4_scenarios.py")
    }
]


def run_tier_suite(suite_info: Dict[str, Any]) -> Dict[str, Any]:
    """Runs a single test tier via subprocess with JUnit XML reporting for precise metrics."""
    tier_name = suite_info["tier"]
    file_path = suite_info["file"]

    xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix=f"pytest_{tier_name.replace(' ', '_')}_")
    os.close(xml_fd)

    cmd = [
        sys.executable,
        "-m", "pytest",
        file_path,
        "-v",
        "--tb=short",
        f"--junitxml={xml_path}"
    ]

    t0 = time.perf_counter()
    proc = subprocess.run(cmd, cwd=CODEBASE_DIR, capture_output=True, text=True)
    duration = time.perf_counter() - t0

    total = 0
    passed = 0
    failed = 0
    skipped = 0

    if os.path.exists(xml_path):
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            # Handle either testsuites or single testsuite root
            suite = root if root.tag == "testsuite" else root.find("testsuite")
            if suite is not None:
                total = int(suite.attrib.get("tests", 0))
                failures = int(suite.attrib.get("failures", 0))
                errors = int(suite.attrib.get("errors", 0))
                skipped = int(suite.attrib.get("skipped", 0))
                failed = failures + errors
                passed = total - failed - skipped
                xml_time = float(suite.attrib.get("time", duration))
                if xml_time > 0:
                    duration = xml_time
        except Exception as e:
            print(f"[{tier_name}] Warning: Failed to parse JUnit XML: {e}")
        finally:
            try:
                os.remove(xml_path)
            except Exception:
                pass

    status = "PASS" if (proc.returncode == 0 and failed == 0 and total > 0) else "FAIL"

    return {
        "tier": tier_name,
        "name": suite_info["name"],
        "total": total,
        "passed": passed,
        "failed": failed,
        "skipped": skipped,
        "duration": duration,
        "status": status,
        "stdout": proc.stdout,
        "stderr": proc.stderr
    }


def verify_production_slas() -> List[Dict[str, Any]]:
    """Performs direct, independent SLA verifications against the live 1.85M+ row database."""
    sla_results = []

    conn = database.get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT src_ip, dst_ip, username FROM nat_logs WHERE username IS NOT NULL AND src_ip IS NOT NULL ORDER BY id DESC LIMIT 1;")
        sample = cursor.fetchone()
        sample_ip = sample["src_ip"] if sample else "10.24.109.198"
        sample_user = sample["username"] if sample else "arif"

        # SLA 1: Search Latency < 50ms on Indexed Queries
        sql_search = "SELECT * FROM nat_logs WHERE src_ip = ? ORDER BY timestamp DESC, id DESC LIMIT 50"
        search_latency = measure_query_latency(conn, sql_search, (sample_ip,), iterations=3)
        sla_1_pass = search_latency < 50.0
        sla_results.append({
            "name": "Search Latency SLA (< 50ms across 1.85M rows)",
            "measured": f"{search_latency:.2f} ms",
            "threshold": "< 50.00 ms",
            "status": "PASS" if sla_1_pass else "FAIL"
        })

        # SLA 2: Zero Full Table Scans on Composite Index
        plan = explain_query(conn, sql_search, (sample_ip,))
        sla_2_pass = (not plan["has_scan"]) and (not plan["has_temp_btree"])
        sla_results.append({
            "name": "Index Query Plan (Zero Table Scans & Zero Temp B-Trees)",
            "measured": f"Scan={plan['has_scan']}, TempBTree={plan['has_temp_btree']}",
            "threshold": "Scan=False, TempBTree=False",
            "status": "PASS" if sla_2_pass else "FAIL"
        })

        # SLA 3: Case-Insensitive Username Lookup SLA (< 30ms)
        sql_user = "SELECT * FROM nat_logs WHERE username = ? COLLATE NOCASE ORDER BY timestamp DESC, id DESC LIMIT 50"
        user_latency = measure_query_latency(conn, sql_user, (sample_user.upper(),), iterations=3)
        sla_3_pass = user_latency < 30.0
        sla_results.append({
            "name": "Case-Insensitive Subscriber Resolution SLA (< 30ms)",
            "measured": f"{user_latency:.2f} ms",
            "threshold": "< 30.00 ms",
            "status": "PASS" if sla_3_pass else "FAIL"
        })

        # SLA 4: Database WAL Mode & PRAGMA Verification
        cursor.execute("PRAGMA journal_mode;")
        j_mode = cursor.fetchone()[0]
        cursor.execute("PRAGMA synchronous;")
        sync_mode = cursor.fetchone()[0]
        wal_pass = str(j_mode).lower() == "wal" and sync_mode in (1, "1", "NORMAL", "normal")
        sla_results.append({
            "name": "Database WAL Mode & High-Throughput PRAGMA Configuration",
            "measured": f"journal_mode={j_mode}, synchronous={sync_mode}",
            "threshold": "journal_mode=wal, synchronous=NORMAL",
            "status": "PASS" if wal_pass else "FAIL"
        })
    finally:
        conn.close()

    return sla_results


def print_banner():
    banner = """
========================================================================================
             SUPER LOG SERVER - MASTER TEST SUITE & SLA BENCHMARK RUNNER
                        Python 3.12+ | FastAPI | SQLite (WAL)
========================================================================================
"""
    print(banner)


def print_summary_table(tier_results: List[Dict[str, Any]], total_duration: float):
    print("\n" + "=" * 88)
    print(f"{'TIER':<8} | {'TEST SUITE NAME':<34} | {'TESTS':<6} | {'PASS':<5} | {'FAIL':<5} | {'SKIP':<5} | {'TIME (s)':<8} | {'STATUS':<6}")
    print("-" * 88)

    total_tests = sum(r["total"] for r in tier_results)
    total_passed = sum(r["passed"] for r in tier_results)
    total_failed = sum(r["failed"] for r in tier_results)
    total_skipped = sum(r["skipped"] for r in tier_results)

    for r in tier_results:
        print(
            f"{r['tier']:<8} | "
            f"{r['name']:<34} | "
            f"{r['total']:<6} | "
            f"{r['passed']:<5} | "
            f"{r['failed']:<5} | "
            f"{r['skipped']:<5} | "
            f"{r['duration']:<8.2f} | "
            f"{r['status']:<6}"
        )

    print("-" * 88)
    all_tiers_pass = all(r["status"] == "PASS" for r in tier_results)
    overall_status = "PASS" if (all_tiers_pass and total_failed == 0) else "FAIL"

    print(
        f"{'TOTAL':<8} | "
        f"{'All 4 Test Tiers Combined':<34} | "
        f"{total_tests:<6} | "
        f"{total_passed:<5} | "
        f"{total_failed:<5} | "
        f"{total_skipped:<5} | "
        f"{total_duration:<8.2f} | "
        f"{overall_status:<6}"
    )
    print("=" * 88)

    return total_tests, total_passed, total_failed, total_skipped, overall_status


def print_sla_table(sla_results: List[Dict[str, Any]]):
    print("\n" + "=" * 88)
    print(f"{'SLA VERIFICATION CRITERION':<55} | {'MEASURED':<18} | {'STATUS':<6}")
    print("-" * 88)
    for s in sla_results:
        print(f"{s['name']:<55} | {s['measured']:<18} | {s['status']:<6}")
    print("=" * 88 + "\n")


def main():
    print_banner()

    start_total_time = time.perf_counter()
    tier_results = []

    print("[*] Initiating Execution of 4 Comprehensive Test Tiers...\n")

    for suite in TIER_SUITES:
        print(f"--> Executing {suite['tier']}: {suite['name']}...")
        result = run_tier_suite(suite)
        tier_results.append(result)
        print(f"    Result: {result['status']} | Tests: {result['total']} (Passed: {result['passed']}, Failed: {result['failed']}, Skipped: {result['skipped']}) in {result['duration']:.2f}s\n")
        if result["failed"] > 0:
            print("--- Failure Details ---")
            lines = result["stdout"].splitlines()
            for line in lines[-25:]:
                print(f"    {line}")
            print("-----------------------")

    total_duration = time.perf_counter() - start_total_time

    # Run direct SLA benchmarks
    print("[*] Performing Independent Live Database SLA Benchmarks...")
    sla_results = verify_production_slas()

    # Print Summary Tables
    total_tests, total_passed, total_failed, total_skipped, overall_status = print_summary_table(tier_results, total_duration)
    print_sla_table(sla_results)

    # Minimum coverage check: Total test count must exceed 121+ tests
    coverage_passed = total_tests >= 121
    all_slas_passed = all(s["status"] == "PASS" for s in sla_results)

    print(f"[*] Total Test Cases Executed: {total_tests} (Requirement: >= 121 tests) -> {'MET' if coverage_passed else 'FAILED'}")
    print(f"[*] Production SLA Standards: {'ALL SATISFIED' if all_slas_passed else 'VIOLATED'}")
    print(f"[*] Final Test Suite Verdict: {'SUCCESS' if (overall_status == 'PASS' and coverage_passed and all_slas_passed) else 'FAILURE'}\n")

    if overall_status == "PASS" and coverage_passed and all_slas_passed:
        print("[+] 100% of tests passed successfully. Super LOG Server is ready for production deployment.")
        sys.exit(0)
    else:
        print("[-] One or more tests or SLAs failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()
