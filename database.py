import sqlite3
import os
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "xtreamlog.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA cache_size = -64000;")
    conn.execute("PRAGMA mmap_size = 2147483648;")
    conn.execute("PRAGMA temp_store = MEMORY;")
    conn.execute("PRAGMA wal_autocheckpoint = 1000;")
    return conn

@contextmanager
def get_db():
    conn = get_connection()
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        login_enabled INTEGER DEFAULT 1,
        mobile TEXT
    )
    """)

    # Routers Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS routers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        router_identity TEXT NOT NULL,
        router_type TEXT NOT NULL,
        nat_identity TEXT,
        host TEXT NOT NULL UNIQUE,
        api_port INTEGER DEFAULT 8728,
        api_username TEXT,
        api_password TEXT,
        status INTEGER DEFAULT 1,
        ipv6 INTEGER DEFAULT 0,
        accounting INTEGER DEFAULT 0
    )
    """)

    # Ensure columns exist if table was created previously
    cursor.execute("PRAGMA table_info(routers)")
    existing_cols = [row[1] for row in cursor.fetchall()]
    if "api_port" not in existing_cols:
        cursor.execute("ALTER TABLE routers ADD COLUMN api_port INTEGER DEFAULT 8728")
    if "api_username" not in existing_cols:
        cursor.execute("ALTER TABLE routers ADD COLUMN api_username TEXT")
    if "api_password" not in existing_cols:
        cursor.execute("ALTER TABLE routers ADD COLUMN api_password TEXT")

    # Ensure online_users has byte columns
    cursor.execute("PRAGMA table_info(online_users)")
    online_cols = [row[1] for row in cursor.fetchall()]
    if "upload_bytes" not in online_cols:
        cursor.execute("ALTER TABLE online_users ADD COLUMN upload_bytes INTEGER DEFAULT 0")
    if "download_bytes" not in online_cols:
        cursor.execute("ALTER TABLE online_users ADD COLUMN download_bytes INTEGER DEFAULT 0")
    if "session_id" not in online_cols:
        cursor.execute("ALTER TABLE online_users ADD COLUMN session_id TEXT")

    # Host Activity Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS host_activities (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        identity TEXT NOT NULL UNIQUE,
        type TEXT NOT NULL,
        details TEXT NOT NULL,
        size TEXT DEFAULT '-',
        last_check TEXT NOT NULL,
        status TEXT DEFAULT 'Success'
    )
    """)

    cursor.execute("PRAGMA table_info(host_activities)")
    host_cols = [row[1] for row in cursor.fetchall()]
    if "size" not in host_cols:
        cursor.execute("ALTER TABLE host_activities ADD COLUMN size TEXT DEFAULT '-'")

    # Online Users Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS online_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sl INTEGER,
        username TEXT NOT NULL UNIQUE,
        mac TEXT NOT NULL,
        address TEXT NOT NULL,
        login_time TEXT NOT NULL,
        online_duration TEXT NOT NULL,
        upload TEXT NOT NULL,
        download TEXT NOT NULL,
        identity TEXT NOT NULL,
        host TEXT NOT NULL
    )
    """)

    # NAT Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS nat_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        host TEXT NOT NULL,
        identity TEXT,
        username TEXT,
        mac TEXT,
        proto TEXT DEFAULT 'TCP',
        src_ip TEXT NOT NULL,
        src_port INTEGER,
        nat_ip TEXT NOT NULL,
        nat_port INTEGER,
        dst_ip TEXT NOT NULL,
        dst_port INTEGER,
        details TEXT
    )
    """)

    # System Logs Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS system_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        priority TEXT NOT NULL,
        identity TEXT NOT NULL,
        host TEXT NOT NULL,
        message TEXT NOT NULL
    )
    """)

    # Customer Usage & Accounting History Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS customer_usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        mac TEXT,
        address TEXT,
        session_id TEXT,
        login_time TEXT,
        logout_time TEXT,
        uptime TEXT,
        upload_bytes INTEGER DEFAULT 0,
        download_bytes INTEGER DEFAULT 0,
        upload_formatted TEXT,
        download_formatted TEXT,
        identity TEXT,
        host TEXT
    )
    """)

    # AS Info Cache Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS as_cache (
        subnet TEXT PRIMARY KEY,
        as_info TEXT NOT NULL,
        org TEXT,
        updated_at TEXT
    )
    """)

    # User Feature Permissions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        permission_key TEXT NOT NULL,
        is_allowed INTEGER DEFAULT 1,
        UNIQUE(user_id, permission_key)
    )
    """)

    # User Specific Router Permissions Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS user_router_permissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        router_id INTEGER NOT NULL,
        is_allowed INTEGER DEFAULT 1,
        UNIQUE(user_id, router_id)
    )
    """)

    # Create Indexes for high-speed queries
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_timestamp ON nat_logs(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_host ON nat_logs(host);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_user ON nat_logs(username);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_src_ip ON nat_logs(src_ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_dst_ip ON nat_logs(dst_ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_nat_ip ON nat_logs(nat_ip);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_as_subnet ON as_cache(subnet);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sys_timestamp ON system_logs(timestamp);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sys_priority ON system_logs(priority);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_sys_identity ON system_logs(identity);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cust_user ON customer_usage(username);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cust_ip ON customer_usage(address);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cust_mac ON customer_usage(mac);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_cust_date ON customer_usage(logout_time);")

    # Composite Indexes on nat_logs for zero-table-scan, zero-temp-btree searches
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_ts_id ON nat_logs(timestamp DESC, id DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_user_ts_id ON nat_logs(username COLLATE NOCASE, timestamp DESC, id DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_src_ip_ts_id ON nat_logs(src_ip, timestamp DESC, id DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_dst_ip_ts_id ON nat_logs(dst_ip, timestamp DESC, id DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_nat_ip_ts_id ON nat_logs(nat_ip, timestamp DESC, id DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_host_ts_id ON nat_logs(host, timestamp DESC, id DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_identity_ts_id ON nat_logs(identity, timestamp DESC, id DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_src_ip_port_ts ON nat_logs(src_ip, src_port, timestamp DESC, id DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_dst_ip_port_ts ON nat_logs(dst_ip, dst_port, timestamp DESC, id DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_nat_ip_port_ts ON nat_logs(nat_ip, nat_port, timestamp DESC, id DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_src_port_ts ON nat_logs(src_port, timestamp DESC, id DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_dst_port_ts ON nat_logs(dst_port, timestamp DESC, id DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_nat_port_ts ON nat_logs(nat_port, timestamp DESC, id DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_nat_mac_ts_id ON nat_logs(mac, timestamp DESC, id DESC);")

    # Ensure default Admin account exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'arif'")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO users (username, name, email, password, role, login_enabled, mobile)
        VALUES ('arif', 'System Admin', 'arifworldnet2@gmail.com', 'admin123', 'Admin', 1, '01877755536')
        """)

    conn.commit()
    conn.close()

def get_user_permissions(user_id: int):
    """Returns a dictionary of permission_key -> bool for the specified user."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT permission_key, is_allowed FROM user_permissions WHERE user_id = ?", (user_id,))
        rows = cursor.fetchall()
        return {row["permission_key"]: bool(row["is_allowed"]) for row in rows}

def set_user_permission(user_id: int, permission_key: str, is_allowed: bool):
    """Sets a specific permission for a user."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_permissions (user_id, permission_key, is_allowed)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, permission_key) DO UPDATE SET is_allowed = excluded.is_allowed
        """, (user_id, permission_key, 1 if is_allowed else 0))
        conn.commit()

def get_user_router_permissions(user_id: int):
    """Returns all routers with an indicator of whether user has permission to access them."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.id, r.name, r.router_identity, r.router_type, r.host, r.status,
                   COALESCE(urp.is_allowed, 1) as is_allowed
            FROM routers r
            LEFT JOIN user_router_permissions urp 
                   ON urp.router_id = r.id AND urp.user_id = ?
            ORDER BY r.id ASC
        """, (user_id,))
        return [dict(row) for row in cursor.fetchall()]

def set_user_router_permission(user_id: int, router_id: int, is_allowed: bool):
    """Sets router access permission for a user."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_router_permissions (user_id, router_id, is_allowed)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id, router_id) DO UPDATE SET is_allowed = excluded.is_allowed
        """, (user_id, router_id, 1 if is_allowed else 0))
        conn.commit()

def clear_all_data():
    """Wipes all dummy/historical data, keeping only the Admin user account."""
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM routers")
        cursor.execute("DELETE FROM host_activities")
        cursor.execute("DELETE FROM online_users")
        cursor.execute("DELETE FROM nat_logs")
        cursor.execute("DELETE FROM system_logs")
        # Reset sqlite sequence counters
        cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('routers', 'host_activities', 'online_users', 'nat_logs', 'system_logs')")
        conn.commit()
        print("[Database] All old data has been deleted. Ready for real MikroTik logs.")

if __name__ == "__main__":
    init_db()
    # clear_all_data() removed for data safety
