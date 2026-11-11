import asyncio
import re
from datetime import datetime
from database import get_connection

SYSLOG_HOST = "0.0.0.0"
SYSLOG_PORT = 5514

# Live Packet Statistics Tracker
PACKET_STATS = {
    "total_packets": 0,
    "last_packet_time": None,
    "last_host": None,
    "recent_packets": []
}

def get_packet_stats():
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

class SyslogProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
        print(f"[Syslog] UDP Server actively listening on {SYSLOG_HOST}:{SYSLOG_PORT}")

    def datagram_received(self, data, addr):
        try:
            message = data.decode("utf-8", errors="ignore").strip()
            client_ip = addr[0]
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Track in live stats
            PACKET_STATS["total_packets"] += 1
            PACKET_STATS["last_packet_time"] = now_str
            PACKET_STATS["last_host"] = client_ip
            PACKET_STATS["recent_packets"].insert(0, {
                "time": now_str,
                "host": client_ip,
                "message": message[:250]
            })
            if len(PACKET_STATS["recent_packets"]) > 40:
                PACKET_STATS["recent_packets"].pop()

            self.process_log(client_ip, message)
        except Exception as e:
            print(f"[Syslog Error] {e}")

    def process_log(self, client_ip, message):
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_connection()
        cursor = conn.cursor()

        # Look up router in database
        cursor.execute("SELECT name, router_identity, router_type FROM routers WHERE host = ?", (client_ip,))
        router_row = cursor.fetchone()

        if router_row:
            router_identity = router_row["router_identity"] or router_row["name"]
            router_type = router_row["router_type"] or "NAT Router"
        else:
            match_host = re.search(r'>[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+([^\s:]+)', message)
            detected_name = match_host.group(1) if match_host else f"Router_{client_ip.replace('.', '_')}"
            router_identity = detected_name
            router_type = "PPPoE Router" if ("acct_" in message or "pppoe" in message.lower()) else "NAT Router"

            try:
                cursor.execute("""
                    INSERT OR IGNORE INTO routers (name, router_identity, router_type, nat_identity, host, status, ipv6, accounting)
                    VALUES (?, ?, ?, '', ?, 1, 0, 1)
                """, (detected_name, detected_name, router_type, client_ip))
            except Exception:
                pass

        # Update or Insert into Host Activity
        details = "Log Successfully Received"
        if "acct_" in message or "pppoe" in message.lower() or "accounting" in message.lower():
            details = "Accounting Log Successfully Received"
            router_type = "PPPoE Router"
        elif "firewall" in message.lower() or "nat" in message.lower():
            details = "Firewall Log Successfully Received"

        cursor.execute("SELECT id FROM host_activities WHERE identity = ?", (router_identity,))
        existing_host = cursor.fetchone()
        if existing_host:
            cursor.execute("""
                UPDATE host_activities 
                SET last_check = ?, details = ?, type = ? 
                WHERE id = ?
            """, (now_str, details, router_type, existing_host["id"]))
        else:
            cursor.execute("""
                INSERT INTO host_activities (identity, type, details, last_check, status)
                VALUES (?, ?, ?, ?, 'Success')
            """, (router_identity, router_type, details, now_str))

        # ----------------------------------------------------
        # 1. Check Custom Script: acct_login (Customer Up event)
        # ----------------------------------------------------
        login_match = ACCT_LOGIN_PATTERN.search(message)
        if login_match:
            user = login_match.group("user")
            mac = login_match.group("mac")
            session = login_match.group("session")
            ip = login_match.group("ip")

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

        # ----------------------------------------------------
        # 2. Check Custom Script: acct_logout (Customer Down event)
        # ----------------------------------------------------
        logout_match = ACCT_LOGOUT_PATTERN.search(message)
        if logout_match:
            user = logout_match.group("user")
            mac = logout_match.group("mac") or ""
            session = logout_match.group("session") or ""
            ip = logout_match.group("ip") or ""
            bytes_in = int(logout_match.group("bytes_in") or 0)
            bytes_out = int(logout_match.group("bytes_out") or 0)
            uptime = logout_match.group("uptime") or "0s"

            # Look up previous login time from online_users before removing
            cursor.execute("SELECT login_time, mac, address FROM online_users WHERE username = ?", (user,))
            prev_user = cursor.fetchone()
            login_time = prev_user["login_time"] if prev_user else now_str
            if not mac and prev_user: mac = prev_user["mac"]
            if not ip and prev_user: ip = prev_user["address"]

            # Save historical customer usage record!
            cursor.execute("""
                INSERT INTO customer_usage (username, mac, address, session_id, login_time, logout_time, uptime, upload_bytes, download_bytes, upload_formatted, download_formatted, identity, host)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                user, mac, ip, session, login_time, now_str, uptime,
                bytes_in, bytes_out, format_bytes(bytes_in), format_bytes(bytes_out),
                router_identity, client_ip
            ))

            # Remove from online users
            cursor.execute("DELETE FROM online_users WHERE username = ?", (user,))

            cursor.execute("""
                INSERT INTO system_logs (timestamp, priority, identity, host, message)
                VALUES (?, 'info', ?, ?, ?)
            """, (now_str, router_identity, client_ip, f"Customer Logged Out: {user} | Session: {uptime} | Upload: {format_bytes(bytes_in)} | Download: {format_bytes(bytes_out)}"))

        # ----------------------------------------------------
        # 3. Check Standard RouterOS PPPoE Connected
        # ----------------------------------------------------
        std_conn_match = PPPOE_CONNECTED_PATTERN.search(message)
        if std_conn_match and not login_match:
            user = std_conn_match.group("user")
            ip = std_conn_match.group("ip") or "10.0.0.1"
            mac = std_conn_match.group("mac") or "00:00:00:00:00:00"

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

        # ----------------------------------------------------
        # 4. Check Standard RouterOS PPPoE Disconnected
        # ----------------------------------------------------
        std_disconn_match = PPPOE_DISCONNECTED_PATTERN.search(message)
        if std_disconn_match and not logout_match:
            user = std_disconn_match.group("user")
            bytes_in = int(std_disconn_match.group("bytes_in") or 0)
            bytes_out = int(std_disconn_match.group("bytes_out") or 0)
            uptime = std_disconn_match.group("uptime") or ""

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

        # ----------------------------------------------------
        # 5. Check NAT Log Match
        # ----------------------------------------------------
        nat_match = NAT_PATTERN.search(message)
        if not nat_match:
            nat_match = NAT_ALT_PATTERN.search(message)

        if nat_match:
            groups = nat_match.groupdict()
            proto = groups.get("proto") or "TCP"
            src_ip = groups.get("src_ip")
            src_port = int(groups.get("src_port") or 0)
            nat_ip = groups.get("nat_ip")
            nat_port = int(groups.get("nat_port") or 0)
            dst_ip = groups.get("dst_ip") or "0.0.0.0"
            dst_port = int(groups.get("dst_port") or 0)

            # 1. Check if username is embedded in message (e.g. in:<pppoe-mc@cmh032>)
            username = None
            mac = None
            pppoe_m = re.search(r'in:<pppoe-(?P<user>[^>]+)>', message, re.IGNORECASE)
            if pppoe_m:
                username = pppoe_m.group("user")

            # 2. Check online_users for src_ip
            if src_ip:
                cursor.execute("SELECT username, mac FROM online_users WHERE address = ?", (src_ip,))
                user_row = cursor.fetchone()
                if user_row:
                    if not username:
                        username = user_row["username"]
                    mac = user_row["mac"]

            # 3. If username found from in:<pppoe-xxx> but mac is still None, look up mac
            if username and not mac:
                cursor.execute("SELECT mac FROM online_users WHERE username = ?", (username,))
                m_row = cursor.fetchone()
                if m_row and m_row["mac"]:
                    mac = m_row["mac"]
                else:
                    cursor.execute("SELECT mac FROM customer_usage WHERE username = ? AND mac != '' ORDER BY id DESC LIMIT 1", (username,))
                    m_row2 = cursor.fetchone()
                    if m_row2 and m_row2["mac"]:
                        mac = m_row2["mac"]

            # 4. Fallback to customer_usage if username is still None
            if not username and src_ip:
                cursor.execute("SELECT username, mac FROM customer_usage WHERE address = ? ORDER BY id DESC LIMIT 1", (src_ip,))
                c_row = cursor.fetchone()
                if c_row:
                    username = c_row["username"]
                    if not mac:
                        mac = c_row["mac"]

            cursor.execute("""
                INSERT INTO nat_logs (timestamp, host, identity, username, mac, proto, src_ip, src_port, nat_ip, nat_port, dst_ip, dst_port, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (now_str, client_ip, router_identity, username, mac, proto.upper(), src_ip, src_port, nat_ip, nat_port, dst_ip, dst_port, message))

        # ----------------------------------------------------
        # 6. General System Log
        # ----------------------------------------------------
        if not login_match and not logout_match and not nat_match:
            priority = "info"
            if "warning" in message.lower(): priority = "warning"
            elif "error" in message.lower() or "critical" in message.lower(): priority = "error"

            cursor.execute("""
                INSERT INTO system_logs (timestamp, priority, identity, host, message)
                VALUES (?, ?, ?, ?, ?)
            """, (now_str, priority, router_identity, client_ip, message))

        conn.commit()
        conn.close()

async def start_syslog_server(port=5514):
    global SYSLOG_PORT
    SYSLOG_PORT = port
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogProtocol(),
        local_addr=(SYSLOG_HOST, SYSLOG_PORT)
    )
    return transport
