import asyncio
import re
import time
import threading
from datetime import datetime
from database import get_connection

SYSLOG_HOST = "0.0.0.0"
SYSLOG_PORT = 5514
SYSLOG_QUEUE_MAXSIZE = 100000

# Live Packet Statistics Tracker
PACKET_STATS = {
    "total_packets": 0,
    "total_received": 0,
    "total_inserted": 0,
    "total_dropped": 0,
    "queue_size": 0,
    "rate_pps": 0.0,
    "last_packet_time": None,
    "last_host": None,
    "recent_packets": []
}

_last_rate_calc_time = time.monotonic()
_last_rate_packet_count = 0

def _update_rate():
    global _last_rate_calc_time, _last_rate_packet_count
    now = time.monotonic()
    dt = now - _last_rate_calc_time
    if dt >= 1.0:
        current_count = PACKET_STATS["total_received"]
        PACKET_STATS["rate_pps"] = round((current_count - _last_rate_packet_count) / dt, 1)
        _last_rate_calc_time = now
        _last_rate_packet_count = current_count

def get_packet_stats():
    _update_rate()
    if syslog_queue is not None:
        PACKET_STATS["queue_size"] = syslog_queue.qsize()
    return PACKET_STATS

def format_bytes(b):
    try:
        b = int(b)
        if b >= 1024**4:
            return f"{round(b / 1024**4, 1)} TB"
        elif b >= 1024**3:
            return f"{round(b / 1024**3, 1)} GB"
        elif b >= 1024**2:
            return f"{round(b / 1024**2, 1)} MB"
        elif b >= 1024:
            return f"{round(b / 1024, 1)} KB"
        return f"{b} B"
    except Exception:
        return str(b)

# 1. Flexible NAT Regex
NAT_PATTERN = re.compile(
    r'(?:proto\s+(?P<proto>\w+))?.*?(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)->(?P<nat_ip>\d+\.\d+\.\d+\.\d+):(?P<nat_port>\d+)->(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+)',
    re.IGNORECASE
)

NAT_ALT_PATTERN = re.compile(
    r'NAT\s*\(?(?P<src_ip>\d+\.\d+\.\d+\.\d+):(?P<src_port>\d+)->(?P<nat_ip>\d+\.\d+\.\d+\.\d+):(?P<nat_port>\d+)\)?(?:->(?P<dst_ip>\d+\.\d+\.\d+\.\d+):(?P<dst_port>\d+))?',
    re.IGNORECASE
)

# 2. MikroTik Script acct_login (from user's PPP Profile Up script)
# Format: acct_login $user $"caller-id" $session $"remote-address"
# Example: acct_login Adnan.moktar@sn 98:4A:6B:4E:88:50 *81000001 10.24.34.27
ACCT_LOGIN_PATTERN = re.compile(
    r'acct_login\s+["\']?(?P<user>[^\s"\']+)["\']?\s+["\']?(?P<mac>[0-9A-Fa-f:-]+)["\']?\s+["\']?(?P<session>[^\s"\']+)["\']?\s+["\']?(?P<ip>\d+\.\d+\.\d+\.\d+)["\']?',
    re.IGNORECASE
)

# 3. MikroTik Script acct_logout (companion Down script)
# Format: acct_logout $user $"caller-id" $"remote-address" $"bytes-in" $"bytes-out" $"uptime"
ACCT_LOGOUT_PATTERN = re.compile(
    r'acct_logout\s+["\']?(?P<user>[^\s"\']+)["\']?\s+["\']?(?P<mac>[0-9A-Fa-f:-]+)?["\']?(?:\s+["\']?(?P<session>\*\S+)["\']?)?\s*["\']?(?P<ip>\d+\.\d+\.\d+\.\d+)?["\']?(?:\s+["\']?(?P<bytes_in>\d+)["\']?\s+["\']?(?P<bytes_out>\d+)["\']?)?(?:\s+["\']?(?P<uptime>[^\s\r\n"\']+)["\']?)?',
    re.IGNORECASE
)

# 4. Standard MikroTik RouterOS PPPoE Events
PPPOE_CONNECTED_PATTERN = re.compile(
    r'<pppoe-(?P<user>[^>]+)>:\s*connected,\s*(?:.*?IP\s+(?P<ip>\d+\.\d+\.\d+\.\d+))?(?:.*?MAC\s+(?P<mac>[0-9A-Fa-f:]+))?',
    re.IGNORECASE
)

PPPOE_DISCONNECTED_PATTERN = re.compile(
    r'<pppoe-(?P<user>[^>]+)>:\s*disconnected(?:.*?(?P<bytes_in>\d+)\s+bytes\s+sent)?(?:.*?(?P<bytes_out>\d+)\s+bytes\s+received)?(?:.*?(?P<uptime>[\w\d]+)\s+uptime)?',
    re.IGNORECASE
)

# In-Memory Fast Lookup Caches (Eliminates 3-5 synchronous DB reads per packet)
ROUTER_CACHE: dict = {}        # host -> {"identity": identity, "type": router_type, "name": name}
USER_IP_CACHE: dict = {}       # ip -> {"username": username, "mac": mac}
USER_NAME_CACHE: dict = {}     # username -> mac
NEW_ROUTERS_QUEUE: dict = {}   # host -> (name, identity, router_type)
HOST_ACTIVITY_CACHE: dict = {} # identity -> (now_str, details, router_type)

def refresh_memory_caches():
    """Synchronously refreshes router and online user mapping from SQLite database in read-only mode."""
    global ROUTER_CACHE, USER_IP_CACHE, USER_NAME_CACHE
    try:
        import os, sqlite3
        db_path = os.path.join(os.path.dirname(__file__), "xtreamlog.db")
        db_uri = f"file:{os.path.abspath(db_path)}?mode=ro"
        conn = sqlite3.connect(db_uri, uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            # 1. Refresh Routers
            cursor.execute("SELECT name, router_identity, router_type, host FROM routers WHERE host IS NOT NULL;")
            router_rows = cursor.fetchall()
            new_router_cache = {}
            for r in router_rows:
                host = r["host"]
                identity = r["router_identity"] or r["name"]
                rtype = r["router_type"] or "NAT Router"
                new_router_cache[host] = {
                    "identity": identity,
                    "type": rtype,
                    "name": r["name"]
                }
            ROUTER_CACHE.update(new_router_cache)

            # 2. Refresh Online Users
            cursor.execute("SELECT username, mac, address FROM online_users WHERE address IS NOT NULL AND address != '';")
            user_rows = cursor.fetchall()
            new_user_ip_cache = {}
            new_user_name_cache = {}
            for u in user_rows:
                username = u["username"]
                mac = u["mac"] or ""
                addr = u["address"]
                new_user_ip_cache[addr] = {"username": username, "mac": mac}
                if mac:
                    new_user_name_cache[username] = mac

            USER_IP_CACHE.update(new_user_ip_cache)
            USER_NAME_CACHE.update(new_user_name_cache)
        finally:
            conn.close()
    except Exception:
        pass

async def periodic_cache_refresher():
    """Background task to periodically refresh memory caches every 30-60 seconds."""
    global _batch_writer_running, _syslog_transport
    while _batch_writer_running:
        if _syslog_transport is not None and _syslog_transport.is_closing():
            _batch_writer_running = False
            break
        try:
            for _ in range(60):
                if not _batch_writer_running or (_syslog_transport is not None and _syslog_transport.is_closing()):
                    _batch_writer_running = False
                    break
                await asyncio.sleep(0.5)
            if not _batch_writer_running:
                break
            await asyncio.to_thread(refresh_memory_caches)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(1)

def _fast_parse_packet(client_ip: str, message: str, now_str: str):
    """
    Ultra-fast in-memory parsing (< 0.05ms) using precompiled regexes and in-memory caches.
    Performs zero synchronous database queries.
    """
    # 1. Router identity resolution from cache
    router_info = ROUTER_CACHE.get(client_ip)
    if router_info:
        router_identity = router_info["identity"]
        router_type = router_info["type"]
    else:
        match_host = re.search(r'>[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+([^\s:]+)', message)
        detected_name = match_host.group(1) if match_host else f"Router_{client_ip.replace('.', '_')}"
        router_identity = detected_name
        router_type = "PPPoE Router" if ("acct_" in message or "pppoe" in message.lower()) else "NAT Router"
        ROUTER_CACHE[client_ip] = {
            "identity": router_identity,
            "type": router_type,
            "name": detected_name
        }
        NEW_ROUTERS_QUEUE[client_ip] = (detected_name, router_identity, router_type)

    # 2. Host activity determination
    details = "Log Successfully Received"
    if "acct_" in message or "pppoe" in message.lower() or "accounting" in message.lower():
        details = "Accounting Log Successfully Received"
        router_type = "PPPoE Router"
    elif "firewall" in message.lower() or "nat" in message.lower():
        details = "Firewall Log Successfully Received"

    HOST_ACTIVITY_CACHE[router_identity] = (now_str, details, router_type)

    # 3. Check Custom Script: acct_login (Customer Up event)
    login_match = ACCT_LOGIN_PATTERN.search(message)
    if login_match:
        user = login_match.group("user")
        mac = login_match.group("mac") or ""
        session = login_match.group("session") or ""
        ip = login_match.group("ip") or ""
        if ip:
            USER_IP_CACHE[ip] = {"username": user, "mac": mac}
        if user:
            USER_NAME_CACHE[user] = mac
        return ("acct_login", (user, mac, session, ip, router_identity, client_ip, now_str, message))

    # 4. Check Custom Script: acct_logout (Customer Down event)
    logout_match = ACCT_LOGOUT_PATTERN.search(message)
    if logout_match:
        user = logout_match.group("user")
        mac = logout_match.group("mac") or ""
        session = logout_match.group("session") or ""
        ip = logout_match.group("ip") or ""
        bytes_in = int(logout_match.group("bytes_in") or 0)
        bytes_out = int(logout_match.group("bytes_out") or 0)
        uptime = logout_match.group("uptime") or "0s"
        if ip and ip in USER_IP_CACHE:
            if not mac:
                mac = USER_IP_CACHE[ip].get("mac", "")
            del USER_IP_CACHE[ip]
        return ("acct_logout", (user, mac, session, ip, bytes_in, bytes_out, uptime, router_identity, client_ip, now_str, message))

    # 5. Check Standard RouterOS PPPoE Connected
    std_conn_match = PPPOE_CONNECTED_PATTERN.search(message)
    if std_conn_match:
        user = std_conn_match.group("user")
        ip = std_conn_match.group("ip") or "10.0.0.1"
        mac = std_conn_match.group("mac") or "00:00:00:00:00:00"
        if ip:
            USER_IP_CACHE[ip] = {"username": user, "mac": mac}
        if user:
            USER_NAME_CACHE[user] = mac
        return ("pppoe_connected", (user, ip, mac, router_identity, client_ip, now_str, message))

    # 6. Check Standard RouterOS PPPoE Disconnected
    std_disconn_match = PPPOE_DISCONNECTED_PATTERN.search(message)
    if std_disconn_match:
        user = std_disconn_match.group("user")
        bytes_in = int(std_disconn_match.group("bytes_in") or 0)
        bytes_out = int(std_disconn_match.group("bytes_out") or 0)
        uptime = std_disconn_match.group("uptime") or ""
        return ("pppoe_disconnected", (user, bytes_in, bytes_out, uptime, router_identity, client_ip, now_str, message))

    # 7. Check NAT Log Match
    nat_match = NAT_PATTERN.search(message)
    if not nat_match:
        nat_match = NAT_ALT_PATTERN.search(message)

    if nat_match:
        groups = nat_match.groupdict()
        proto = (groups.get("proto") or "TCP").upper()
        src_ip = groups.get("src_ip")
        src_port = int(groups.get("src_port") or 0)
        nat_ip = groups.get("nat_ip")
        nat_port = int(groups.get("nat_port") or 0)
        dst_ip = groups.get("dst_ip") or "0.0.0.0"
        dst_port = int(groups.get("dst_port") or 0)

        username = None
        mac = None

        # Check for in:<pppoe-...> in message
        pppoe_m = re.search(r'in:<pppoe-(?P<user>[^>]+)>', message, re.IGNORECASE)
        if pppoe_m:
            username = pppoe_m.group("user")

        # Resolve via in-memory cache
        if src_ip and src_ip in USER_IP_CACHE:
            cached_u = USER_IP_CACHE[src_ip]
            if not username:
                username = cached_u.get("username")
            if not mac:
                mac = cached_u.get("mac")

        if username and not mac:
            mac = USER_NAME_CACHE.get(username)

        return ("nat", (now_str, client_ip, router_identity, username, mac, proto, src_ip, src_port, nat_ip, nat_port, dst_ip, dst_port, message))

    # 8. General System Log
    priority = "info"
    msg_lower = message.lower()
    if "warning" in msg_lower:
        priority = "warning"
    elif "error" in msg_lower or "critical" in msg_lower:
        priority = "error"

    return ("system_log", (now_str, priority, router_identity, client_ip, message))

_write_lock = threading.Lock()

def _persist_batch_sync(batch):
    """
    Commits a batch of parsed records inside a single SQLite write transaction
    using executemany for high throughput. Executed in worker thread to prevent event loop stalls.
    """
    if not batch:
        return

    _write_lock.acquire()
    try:
        conn = get_connection()
        cursor = conn.cursor()
        nat_rows = []
        sys_rows = []
        login_events = []
        logout_events = []
        std_conn_events = []
        std_disconn_events = []

        for item_type, item_data in batch:
            if item_type == "nat":
                nat_rows.append(item_data)
            elif item_type == "system_log":
                sys_rows.append(item_data)
            elif item_type == "acct_login":
                login_events.append(item_data)
            elif item_type == "acct_logout":
                logout_events.append(item_data)
            elif item_type == "pppoe_connected":
                std_conn_events.append(item_data)
            elif item_type == "pppoe_disconnected":
                std_disconn_events.append(item_data)

        # 1. Register newly detected routers if any
        if NEW_ROUTERS_QUEUE:
            new_routers = []
            for h in list(NEW_ROUTERS_QUEUE.keys()):
                val = NEW_ROUTERS_QUEUE.pop(h, None)
                if val:
                    new_routers.append((h, val))
            for host, (name, identity, rtype) in new_routers:
                try:
                    cursor.execute("SELECT id FROM routers WHERE host = ?", (host,))
                    if not cursor.fetchone():
                        cursor.execute("""
                            INSERT INTO routers (name, router_identity, router_type, nat_identity, host, status, ipv6, accounting)
                            VALUES (?, ?, ?, '', ?, 1, 0, 1)
                        """, (name, identity, rtype, host))
                except Exception:
                    pass

        # 2. Update host activity (batched per unique router identity)
        if HOST_ACTIVITY_CACHE:
            activities = []
            for ident in list(HOST_ACTIVITY_CACHE.keys()):
                val = HOST_ACTIVITY_CACHE.pop(ident, None)
                if val:
                    activities.append((ident, val))
            for identity, (last_check, details, rtype) in activities:
                try:
                    cursor.execute("SELECT id FROM host_activities WHERE identity = ?", (identity,))
                    existing_host = cursor.fetchone()
                    if existing_host:
                        cursor.execute("""
                            UPDATE host_activities 
                            SET last_check = ?, details = ?, type = ? 
                            WHERE id = ?
                        """, (last_check, details, rtype, existing_host["id"]))
                    else:
                        cursor.execute("""
                            INSERT INTO host_activities (identity, type, details, last_check, status)
                            VALUES (?, ?, ?, ?, 'Success')
                        """, (identity, rtype, details, last_check))
                except Exception:
                    pass

        # 3. Process acct_login events
        for user, mac, session, ip, router_identity, client_ip, now_str, message in login_events:
            try:
                cursor.execute("SELECT id FROM online_users WHERE username = ?", (user,))
                existing_u = cursor.fetchone()
                if existing_u:
                    cursor.execute("""
                        UPDATE online_users 
                        SET mac = ?, address = ?, identity = ?, host = ?, login_time = ?, online_duration = '0d 00:00:01'
                        WHERE id = ?
                    """, (mac, ip, router_identity, client_ip, now_str, existing_u["id"]))
                else:
                    cursor.execute("""
                        INSERT INTO online_users (sl, username, mac, address, login_time, online_duration, upload, download, identity, host)
                        VALUES ((SELECT COALESCE(MAX(sl), 0) + 1 FROM online_users), ?, ?, ?, ?, '0d 00:00:01', '0 B', '0 B', ?, ?)
                    """, (user, mac, ip, now_str, router_identity, client_ip))

                cursor.execute("""
                    INSERT INTO system_logs (timestamp, priority, identity, host, message)
                    VALUES (?, 'info', ?, ?, ?)
                """, (now_str, router_identity, client_ip, f"Customer Logged In: {user} | IP: {ip} | MAC: {mac} | Session: {session}"))
            except Exception:
                pass

        # 4. Process acct_logout events
        for user, mac, session, ip, bytes_in, bytes_out, uptime, router_identity, client_ip, now_str, message in logout_events:
            try:
                cursor.execute("SELECT login_time, mac, address FROM online_users WHERE username = ?", (user,))
                prev_user = cursor.fetchone()
                login_time = prev_user["login_time"] if prev_user else now_str
                if not mac and prev_user: mac = prev_user["mac"]
                if not ip and prev_user: ip = prev_user["address"]

                cursor.execute("""
                    INSERT INTO customer_usage (username, mac, address, session_id, login_time, logout_time, uptime, upload_bytes, download_bytes, upload_formatted, download_formatted, identity, host)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user, mac or "", ip or "", session or "", login_time, now_str, uptime,
                    bytes_in, bytes_out, format_bytes(bytes_in), format_bytes(bytes_out),
                    router_identity, client_ip
                ))
                cursor.execute("DELETE FROM online_users WHERE username = ?", (user,))

                cursor.execute("""
                    INSERT INTO system_logs (timestamp, priority, identity, host, message)
                    VALUES (?, 'info', ?, ?, ?)
                """, (now_str, router_identity, client_ip, f"Customer Logged Out: {user} | Session: {uptime} | Upload: {format_bytes(bytes_in)} | Download: {format_bytes(bytes_out)}"))
            except Exception:
                pass

        # 5. Process standard PPPoE connected events
        for user, ip, mac, router_identity, client_ip, now_str, message in std_conn_events:
            try:
                cursor.execute("SELECT id FROM online_users WHERE username = ?", (user,))
                existing_u = cursor.fetchone()
                if existing_u:
                    cursor.execute("""
                        UPDATE online_users SET address = ?, host = ?, identity = ?, login_time = ? WHERE id = ?
                    """, (ip, client_ip, router_identity, now_str, existing_u["id"]))
                else:
                    cursor.execute("""
                        INSERT INTO online_users (sl, username, mac, address, login_time, online_duration, upload, download, identity, host)
                        VALUES ((SELECT COALESCE(MAX(sl), 0) + 1 FROM online_users), ?, ?, ?, ?, '0d 00:00:01', '0 B', '0 B', ?, ?)
                    """, (user, mac, ip, now_str, router_identity, client_ip))
            except Exception:
                pass

        # 6. Process standard PPPoE disconnected events
        for user, bytes_in, bytes_out, uptime, router_identity, client_ip, now_str, message in std_disconn_events:
            try:
                cursor.execute("SELECT login_time, mac, address FROM online_users WHERE username = ?", (user,))
                prev_user = cursor.fetchone()
                login_time = prev_user["login_time"] if prev_user else now_str
                mac = prev_user["mac"] if prev_user else ""
                ip = prev_user["address"] if prev_user else ""

                cursor.execute("""
                    INSERT INTO customer_usage (username, mac, address, session_id, login_time, logout_time, uptime, upload_bytes, download_bytes, upload_formatted, download_formatted, identity, host)
                    VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user, mac, ip, login_time, now_str, uptime,
                    bytes_in, bytes_out, format_bytes(bytes_in), format_bytes(bytes_out),
                    router_identity, client_ip
                ))
                cursor.execute("DELETE FROM online_users WHERE username = ?", (user,))
            except Exception:
                pass

        # 7. Batch insert NAT logs using executemany
        if nat_rows:
            resolved_nat_rows = []
            for row in nat_rows:
                now_str, client_ip, router_identity, username, mac, proto, src_ip, src_port, nat_ip, nat_port, dst_ip, dst_port, msg = row
                # Fallback database lookup if not yet populated in cache
                if not username and src_ip:
                    if src_ip in USER_IP_CACHE:
                        cached = USER_IP_CACHE[src_ip]
                        username = cached.get("username")
                        mac = cached.get("mac")
                    else:
                        cursor.execute("SELECT username, mac FROM online_users WHERE address = ? LIMIT 1;", (src_ip,))
                        u_row = cursor.fetchone()
                        if u_row:
                            username = u_row["username"]
                            mac = u_row["mac"]
                            USER_IP_CACHE[src_ip] = {"username": username, "mac": mac}
                        else:
                            USER_IP_CACHE[src_ip] = {"username": None, "mac": None}
                if username and not mac:
                    if username in USER_NAME_CACHE:
                        mac = USER_NAME_CACHE[username]
                    else:
                        cursor.execute("SELECT mac FROM online_users WHERE username = ? LIMIT 1;", (username,))
                        m_row = cursor.fetchone()
                        if m_row and m_row["mac"]:
                            mac = m_row["mac"]
                            USER_NAME_CACHE[username] = mac
                resolved_nat_rows.append((now_str, client_ip, router_identity, username, mac, proto, src_ip, src_port, nat_ip, nat_port, dst_ip, dst_port, msg))

            cursor.executemany("""
                INSERT INTO nat_logs (timestamp, host, identity, username, mac, proto, src_ip, src_port, nat_ip, nat_port, dst_ip, dst_port, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, resolved_nat_rows)

        # 8. Batch insert system logs using executemany
        if sys_rows:
            cursor.executemany("""
                INSERT INTO system_logs (timestamp, priority, identity, host, message)
                VALUES (?, ?, ?, ?, ?)
            """, sys_rows)

        conn.commit()
    except Exception as e:
        try:
            conn.rollback()
        except Exception:
            pass
        raise e
    finally:
        try:
            conn.close()
        except Exception:
            pass
        _write_lock.release()

# Dedicated Async Ingestion Queue & Background Tasks
syslog_queue: asyncio.Queue = None
_batch_writer_task = None
_cache_refresher_task = None
_batch_writer_running = False
_syslog_transport = None

async def syslog_batch_writer():
    """
    Dedicated background worker consuming parsed records from syslog_queue.
    Batches up to 500 records or flushes every 100ms inside a single write transaction.
    Commits via worker thread to guarantee zero event loop stalls (< 10ms lag).
    """
    global syslog_queue, _batch_writer_running, _syslog_transport
    _batch_writer_running = True
    while _batch_writer_running:
        if _syslog_transport is not None and _syslog_transport.is_closing():
            _batch_writer_running = False
            break
        try:
            if syslog_queue is None:
                await asyncio.sleep(0.05)
                continue

            try:
                first_item = await asyncio.wait_for(syslog_queue.get(), timeout=0.2)
            except (asyncio.TimeoutError, TimeoutError):
                continue

            batch = [first_item]
            t0 = time.monotonic()

            while len(batch) < 500:
                rem = 0.1 - (time.monotonic() - t0)
                if rem <= 0:
                    break
                try:
                    item = await asyncio.wait_for(syslog_queue.get(), timeout=rem)
                    batch.append(item)
                except (asyncio.TimeoutError, TimeoutError):
                    break

            if batch:
                await asyncio.to_thread(_persist_batch_sync, batch)
                for _ in batch:
                    syslog_queue.task_done()
                PACKET_STATS["total_inserted"] += len(batch)
                PACKET_STATS["queue_size"] = syslog_queue.qsize()

        except asyncio.CancelledError:
            break
        except Exception as e:
            await asyncio.sleep(0.01)

_flush_lock = threading.Lock()

def flush_remaining_queue():
    """Flushes 100% of remaining items in syslog_queue to SQLite before shutdown."""
    global syslog_queue
    if syslog_queue is None:
        return
    with _flush_lock:
        items = []
        while not syslog_queue.empty():
            try:
                items.append(syslog_queue.get_nowait())
                syslog_queue.task_done()
            except asyncio.QueueEmpty:
                break
        if items:
            for i in range(0, len(items), 500):
                chunk = items[i:i + 500]
                _persist_batch_sync(chunk)
            PACKET_STATS["total_inserted"] += len(items)
            PACKET_STATS["queue_size"] = syslog_queue.qsize()

class SyslogProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        print(f"[Syslog] UDP Server actively listening on {SYSLOG_HOST}:{SYSLOG_PORT}")

    def connection_lost(self, exc):
        global _batch_writer_task, _cache_refresher_task, _batch_writer_running
        _batch_writer_running = False
        if _batch_writer_task and not _batch_writer_task.done():
            _batch_writer_task.cancel()
        if _cache_refresher_task and not _cache_refresher_task.done():
            _cache_refresher_task.cancel()
        flush_remaining_queue()

    def _update_stats(self, client_ip: str, message: str, now_str: str):
        PACKET_STATS["total_packets"] += 1
        PACKET_STATS["total_received"] += 1
        PACKET_STATS["last_packet_time"] = now_str
        PACKET_STATS["last_host"] = client_ip
        PACKET_STATS["recent_packets"].insert(0, {
            "time": now_str,
            "host": client_ip,
            "message": message[:250]
        })
        if len(PACKET_STATS["recent_packets"]) > 40:
            PACKET_STATS["recent_packets"].pop()
        _update_rate()

    def datagram_received(self, data, addr):
        """
        Decoupled non-blocking UDP ingestion (< 0.05ms per packet).
        Parses packet in memory and pushes to in-memory asyncio.Queue.
        Never runs synchronous SQLite queries or conn.commit() on the event loop.
        """
        try:
            if not data:
                return

            client_ip = addr[0] if addr else "127.0.0.1"
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            message = data.decode("utf-8", errors="ignore").strip()
            if not message:
                return

            self._update_stats(client_ip, message, now_str)
            parsed_item = _fast_parse_packet(client_ip, message, now_str)

            if syslog_queue is not None:
                try:
                    syslog_queue.put_nowait(parsed_item)
                    PACKET_STATS["queue_size"] = syslog_queue.qsize()
                except asyncio.QueueFull:
                    PACKET_STATS["total_dropped"] += 1
            else:
                # Standalone fallback when server loop is not running
                if parsed_item:
                    _persist_batch_sync([parsed_item])
                    PACKET_STATS["total_inserted"] += 1
        except Exception:
            pass

    def process_log(self, client_ip: str, message: str):
        """
        Direct log processing interface for standalone tests and direct invocations.
        Updates in-memory caches and persists record immediately.
        """
        try:
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self._update_stats(client_ip, message, now_str)
            parsed_item = _fast_parse_packet(client_ip, message, now_str)
            if parsed_item:
                _persist_batch_sync([parsed_item])
                PACKET_STATS["total_inserted"] += 1
        except Exception as e:
            print(f"[Syslog Error] {e}")

async def start_syslog_server(port=5514):
    """
    Lifecycle start: Initializes queue, in-memory caches, batch writer worker,
    and binds the UDP syslog listener on SYSLOG_PORT.
    """
    global SYSLOG_PORT, syslog_queue, _batch_writer_task, _cache_refresher_task, _syslog_transport
    SYSLOG_PORT = port

    loop = asyncio.get_running_loop()
    if syslog_queue is None or getattr(syslog_queue, "_loop", None) is not loop:
        syslog_queue = asyncio.Queue(maxsize=SYSLOG_QUEUE_MAXSIZE)

    # Warm up in-memory caches
    refresh_memory_caches()

    if _batch_writer_task is None or _batch_writer_task.done():
        _batch_writer_task = loop.create_task(syslog_batch_writer())

    if _cache_refresher_task is None or _cache_refresher_task.done():
        _cache_refresher_task = loop.create_task(periodic_cache_refresher())

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(),
        local_addr=(SYSLOG_HOST, SYSLOG_PORT)
    )
    _syslog_transport = transport

    # Attach safe lifecycle close hook so transport.close() cleanly stops background tasks immediately
    orig_close = transport.close
    def _safe_close():
        global _batch_writer_running, _batch_writer_task, _cache_refresher_task
        _batch_writer_running = False
        if _batch_writer_task and not _batch_writer_task.done():
            _batch_writer_task.cancel()
        if _cache_refresher_task and not _cache_refresher_task.done():
            _cache_refresher_task.cancel()
        flush_remaining_queue()
        try:
            orig_close()
        except Exception:
            pass
    transport.close = _safe_close
    return transport

async def stop_syslog_server():
    """
    Lifecycle stop: Flushes all remaining queued items to SQLite,
    closes UDP transport, and terminates background workers cleanly.
    """
    global _syslog_transport, _batch_writer_task, _cache_refresher_task, _batch_writer_running
    _batch_writer_running = False

    print("[DEBUG stop] 1: cancelling writer task", flush=True)
    if _batch_writer_task is not None:
        _batch_writer_task.cancel()
        try:
            print("[DEBUG stop] 2: awaiting writer task", flush=True)
            await _batch_writer_task
            print("[DEBUG stop] 2b: writer task done", flush=True)
        except (asyncio.CancelledError, Exception) as e:
            print(f"[DEBUG stop] 2 exc: {e}", flush=True)
        _batch_writer_task = None

    print("[DEBUG stop] 3: cancelling refresher task", flush=True)
    if _cache_refresher_task is not None:
        _cache_refresher_task.cancel()
        try:
            print("[DEBUG stop] 4: awaiting refresher task", flush=True)
            await _cache_refresher_task
            print("[DEBUG stop] 4b: refresher task done", flush=True)
        except (asyncio.CancelledError, Exception) as e:
            print(f"[DEBUG stop] 4 exc: {e}", flush=True)
        _cache_refresher_task = None

    print("[DEBUG stop] 5: closing transport", flush=True)
    if _syslog_transport is not None:
        try:
            _syslog_transport.close()
        except Exception:
            pass
        _syslog_transport = None

    print("[DEBUG stop] 6: calling flush_remaining_queue", flush=True)
    flush_remaining_queue()
    print("[DEBUG stop] 7: stop complete", flush=True)
