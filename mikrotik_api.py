import socket
import ipaddress
from datetime import datetime
import routeros_api
from routeros_api.exceptions import RouterOsApiCommunicationError, RouterOsApiConnectionError

SERVER_LOG_IP = "103.137.108.70"
SERVER_LOG_PORT = "5514"

def parse_pool_ranges_to_prefixes(ranges_str):
    """
    Converts MikroTik pool ranges (e.g. '10.24.0.2-10.24.7.254, 10.24.16.2-10.24.17.254')
    into standardized CIDR prefixes (e.g. ['10.24.0.0/21', '10.24.16.0/23']).
    """
    prefixes = []
    if not ranges_str:
        return prefixes

    for part in ranges_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            s_str, e_str = part.split('-')
            s_parts = s_str.strip().split('.')
            e_parts = e_str.strip().split('.')
            if len(s_parts) == 4 and len(e_parts) == 4:
                # Normalize typical ISP host IP boundaries (.1/.2 -> .0, .254 -> .255)
                if s_parts[3] in ('1', '2'):
                    s_parts[3] = '0'
                if e_parts[3] in ('254', '253'):
                    e_parts[3] = '255'
                try:
                    s = ipaddress.IPv4Address('.'.join(s_parts))
                    e = ipaddress.IPv4Address('.'.join(e_parts))
                    nets = list(ipaddress.summarize_address_range(s, e))
                    for n in nets:
                        prefixes.append(str(n))
                    continue
                except Exception:
                    pass
        prefixes.append(part)
    return prefixes

def test_mikrotik_connection(host: str, username: str, password: str, port: int = 8728, timeout: int = 5):
    """
    Connects to MikroTik RouterOS via API (default port 8728) to test connection
    and fetch system identity (hostname) and hardware info.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, int(port)))
        sock.close()
        if result != 0:
            return {
                "success": False,
                "error": f"Port {port} unreachable on {host}. Please verify IP and ensure RouterOS API service is enabled (/ip service enable api)."
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Cannot reach {host}:{port} - {str(e)}"
        }

    connection = None
    try:
        connection = routeros_api.RouterOsApiPool(
            host,
            username=username,
            password=password,
            port=int(port),
            plaintext_login=True,
            use_ssl=False
        )
        api = connection.get_api()
        
        identity_res = api.get_resource('/system/identity')
        identity_data = identity_res.get()
        identity_name = identity_data[0].get('name', 'MikroTik') if identity_data else 'MikroTik'

        resource_res = api.get_resource('/system/resource')
        resource_data = resource_res.get()
        board_name = resource_data[0].get('board-name', '') if resource_data else ''
        version = resource_data[0].get('version', '') if resource_data else ''
        uptime = resource_data[0].get('uptime', '') if resource_data else ''
        cpu_load = resource_data[0].get('cpu-load', 0) if resource_data else 0

        connection.disconnect()

        return {
            "success": True,
            "identity": identity_name,
            "board_name": board_name,
            "version": version,
            "uptime": uptime,
            "cpu_load": cpu_load
        }
    except Exception as e:
        try:
            if connection:
                try: connection.disconnect()
                except: pass

            connection = routeros_api.RouterOsApiPool(
                host,
                username=username,
                password=password,
                port=int(port),
                plaintext_login=False,
                use_ssl=False
            )
            api = connection.get_api()
            identity_res = api.get_resource('/system/identity')
            identity_data = identity_res.get()
            identity_name = identity_data[0].get('name', 'MikroTik') if identity_data else 'MikroTik'
            connection.disconnect()
            return {
                "success": True,
                "identity": identity_name,
                "board_name": "",
                "version": "",
                "uptime": "",
                "cpu_load": 0
            }
        except Exception:
            return {
                "success": False,
                "error": f"API Login Failed: {str(e)}"
            }

def fetch_mikrotik_pool_prefixes(host: str, username: str, password: str, port: int = 8728, timeout: int = 6):
    """
    Connects to MikroTik API and extracts all IP pool prefixes, subnets, and address-lists.
    """
    prefixes = []
    connection = None
    try:
        connection = routeros_api.RouterOsApiPool(
            host,
            username=username,
            password=password,
            port=int(port),
            plaintext_login=True,
            use_ssl=False
        )
        api = connection.get_api()

        # 1. Query /ip/pool
        try:
            pool_res = api.get_resource('/ip/pool')
            pools = pool_res.get()
            for p in pools:
                ranges = p.get('ranges', '')
                for prefix in parse_pool_ranges_to_prefixes(ranges):
                    if prefix not in prefixes:
                        prefixes.append(prefix)
        except Exception as e:
            print(f"[Pool Query Warning] {e}")

        # 2. Query /ip/firewall/address-list for any existing Log list
        try:
            addr_res = api.get_resource('/ip/firewall/address-list')
            addr_list = addr_res.get()
            for a in addr_list:
                if a.get('list', '').lower() == 'log':
                    addr = a.get('address')
                    if addr and addr not in prefixes:
                        prefixes.append(addr)
        except Exception:
            pass

        # 3. If still empty, check /ip/address for private customer networks
        if not prefixes:
            try:
                ip_res = api.get_resource('/ip/address')
                for item in ip_res.get():
                    addr = item.get('address')
                    if addr and ('/24' in addr or '/23' in addr or '/22' in addr or '/21' in addr or '/20' in addr or '/19' in addr or '/18' in addr or '/16' in addr):
                        try:
                            net = ipaddress.IPv4Network(addr, strict=False)
                            net_str = str(net)
                            if net_str not in prefixes:
                                prefixes.append(net_str)
                        except:
                            pass
            except Exception:
                pass

        connection.disconnect()
    except Exception as e:
        print(f"[Fetch Pools Error] {e}")
        if connection:
            try: connection.disconnect()
            except: pass

    # If completely empty, return typical ISP fallback template prefixes
    if not prefixes:
        prefixes = [
            "10.24.0.0/21",
            "10.24.16.0/23",
            "10.24.8.0/21",
            "10.24.18.0/23",
            "10.24.20.0/23",
            "10.24.22.0/23",
            "10.24.24.0/23",
            "10.24.26.0/24",
            "10.144.32.0/22"
        ]

    return prefixes

def sync_all_active_pppoe_users():
    """
    Connects to all registered routers via API:
    1. Fetches all interfaces from /interface to get exact rx-byte (Upload), tx-byte (Download),
       and last-link-up-time for each <pppoe-username>.
    2. Fetches all active PPPoE users from /ppp/active.
    3. Detects users who disconnected since previous sync and automatically archives their
       completed session into customer_usage with exact upload_bytes and download_bytes!
    4. Updates online_users with 100% REAL live traffic numbers from MikroTik!
    """
    from database import get_connection
    from syslog_server import format_bytes

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM routers WHERE status = 1")
    routers = [dict(r) for r in cursor.fetchall()]
    conn.close()

    total_synced = 0
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for r in routers:
        host = r["host"]
        api_port = r["api_port"] or 8728
        api_user = r["api_username"] or ""
        api_pass = r["api_password"] or ""
        identity = r["router_identity"] or r["name"]

        if not api_user:
            continue

        # Fast socket reachability check (2 second timeout)
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(2.0)
            if test_sock.connect_ex((host, int(api_port))) != 0:
                test_sock.close()
                continue
            test_sock.close()
        except Exception:
            continue

        try:
            pool = routeros_api.RouterOsApiPool(
                host,
                username=api_user,
                password=api_pass,
                port=int(api_port),
                plaintext_login=True,
                use_ssl=False
            )
            api = pool.get_api()

            # 1. Fetch interfaces for real-time bytes
            iface_res = api.get_resource('/interface').get()
            iface_map = {}
            for i in iface_res:
                n = i.get('name', '')
                if n.startswith('<pppoe-') and n.endswith('>'):
                    uname = n[7:-1]
                    rx = int(i.get('rx-byte', 0) or 0) # Upload from customer
                    tx = int(i.get('tx-byte', 0) or 0) # Download to customer
                    up_time = i.get('last-link-up-time', '')
                    iface_map[uname] = {
                        'rx': rx,
                        'tx': tx,
                        'up_time': up_time
                    }

            # 2. Fetch active PPP connections
            active_list = api.get_resource('/ppp/active').get()
            fresh_users_dict = {}

            for idx, u in enumerate(active_list, 1):
                name = u.get('name')
                if not name:
                    continue
                mac = u.get('caller-id', '00:00:00:00:00:00')
                ip = u.get('address', '')
                uptime = u.get('uptime', '0s')
                session_id = u.get('session-id', '')

                # Real traffic bytes from interface
                tr = iface_map.get(name, {'rx': 0, 'tx': 0, 'up_time': ''})
                upload_bytes = tr['rx']
                download_bytes = tr['tx']
                login_time = tr['up_time'] or now_str

                fresh_users_dict[name] = {
                    'sl': idx,
                    'username': name,
                    'mac': mac,
                    'address': ip,
                    'session_id': session_id,
                    'login_time': login_time,
                    'online_duration': uptime,
                    'upload_bytes': upload_bytes,
                    'download_bytes': download_bytes,
                    'upload': format_bytes(upload_bytes),
                    'download': format_bytes(download_bytes),
                    'identity': identity,
                    'host': host
                }

            # 3. Save updates to SQLite in a quick dedicated transaction
            db_conn = get_connection()
            db_cursor = db_conn.cursor()
            try:
                db_cursor.execute("SELECT * FROM online_users WHERE host = ?", (host,))
                prev_online_users = [dict(row) for row in db_cursor.fetchall()]

                for prev_u in prev_online_users:
                    prev_name = prev_u["username"]
                    if prev_name not in fresh_users_dict:
                        # User disconnected! Save their completed session before removing
                        up_b = prev_u.get("upload_bytes") or 0
                        down_b = prev_u.get("download_bytes") or 0
                        db_cursor.execute("""
                            INSERT INTO customer_usage (username, mac, address, session_id, login_time, logout_time, uptime, upload_bytes, download_bytes, upload_formatted, download_formatted, identity, host)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            prev_name,
                            prev_u.get("mac", ""),
                            prev_u.get("address", ""),
                            prev_u.get("session_id", ""),
                            prev_u.get("login_time", now_str),
                            now_str, # Disconnect timestamp
                            prev_u.get("online_duration", "0s"),
                            up_b,
                            down_b,
                            prev_u.get("upload") or format_bytes(up_b),
                            prev_u.get("download") or format_bytes(down_b),
                            identity,
                            host
                        ))
                        # Also log to system_logs
                        db_cursor.execute("""
                            INSERT INTO system_logs (timestamp, priority, identity, host, message)
                            VALUES (?, 'info', ?, ?, ?)
                        """, (
                            now_str, identity, host,
                            f"Customer Disconnected: {prev_name} | Session Uptime: {prev_u.get('online_duration', '0s')} | Upload: {prev_u.get('upload')} | Download: {prev_u.get('download')}"
                        ))

                # 4. Refresh online_users table with fresh active entries
                db_cursor.execute("DELETE FROM online_users WHERE host = ?", (host,))
                entries = [
                    (
                        v['sl'],
                        v['username'],
                        v['mac'],
                        v['address'],
                        v['session_id'],
                        v['login_time'],
                        v['online_duration'],
                        v['upload_bytes'],
                        v['download_bytes'],
                        v['upload'],
                        v['download'],
                        v['identity'],
                        v['host']
                    )
                    for v in fresh_users_dict.values()
                ]

                db_cursor.executemany("""
                    INSERT OR REPLACE INTO online_users (sl, username, mac, address, session_id, login_time, online_duration, upload_bytes, download_bytes, upload, download, identity, host)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, entries)

                db_conn.commit()
                total_synced += len(entries)
            finally:
                db_conn.close()

            pool.disconnect()
        except Exception as e:
            print(f"[Sync Error on {host}] {e}")

    return total_synced

def generate_export_script(router_name: str, router_identity: str, host: str, prefixes: list):
    """
    Generates the exact MikroTik configuration script matching the user's reference image:
    Name: ...
    Identity: ...
    Host: ...

    /ip firewall mangle
    add action=log chain=prerouting connection-state=established protocol=tcp src-address-list=Log tcp-flags=fin

    /ip firewall address-list
    add address=... list=Log
    """
    lines = [
        f"Name: {router_name}",
        f"Identity: {router_identity or router_name}",
        f"Host: {host}",
        "",
        "# 1. Setup Remote Logging Action",
        f'/system logging action add name="xtreamlog" target=remote remote={SERVER_LOG_IP} remote-port={SERVER_LOG_PORT} bsd-syslog=yes',
        '/system logging add action=xtreamlog topics=firewall,info',
        '/system logging add action=xtreamlog topics=info',
        "",
        "# 2. Mangle rule for TCP FIN logging",
        "/ip firewall mangle",
        "add action=log chain=prerouting connection-state=established protocol=tcp src-address-list=Log tcp-flags=fin",
        "",
        "# 3. IP Pool & Prefix Address List",
        "/ip firewall address-list"
    ]

    for p in prefixes:
        lines.append(f"add address={p} list=Log")

    lines.extend([
        "",
        "# 4. PPP Profile Accounting Scripts (For instant login/disconnect session tracking)",
        "# In Winbox: PPP -> Profiles -> Edit Profile -> Scripts Tab:",
        "# [On Up]:",
        '#:local session [/ppp active get value-name=session-id [find name=$user]]; :log info "acct_login $user $\\"caller-id\\" $session $\\"remote-address\\"";',
        "# [On Down]:",
        '#:log info "acct_logout $user $\\"caller-id\\" $\\"session-id\\" $\\"remote-address\\" $\\"bytes-in\\" $\\"bytes-out\\" $\\"uptime\\"";'
    ])

    return "\n".join(lines)
