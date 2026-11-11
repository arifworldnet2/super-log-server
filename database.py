import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "xtreamlog.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

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
        last_check TEXT NOT NULL,
        status TEXT DEFAULT 'Success'
    )
    """)

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

    # Ensure default Admin account exists
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = 'arif'")
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
        INSERT INTO users (username, name, email, password, role, login_enabled, mobile)
        VALUES ('arif', 'System Admin', 'arifworldnet2@gmail.com', 'admin123', 'Admin', 1, '01877755536')
        """)

    conn.commit()
    conn.close()

def clear_all_data():
    """Wipes all dummy/historical data, keeping only the Admin user account."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM routers")
    cursor.execute("DELETE FROM host_activities")
    cursor.execute("DELETE FROM online_users")
    cursor.execute("DELETE FROM nat_logs")
    cursor.execute("DELETE FROM system_logs")
    # Reset sqlite sequence counters
    cursor.execute("DELETE FROM sqlite_sequence WHERE name IN ('routers', 'host_activities', 'online_users', 'nat_logs', 'system_logs')")
    conn.commit()
    conn.close()
    print("[Database] All old data has been deleted. Ready for real MikroTik logs.")

if __name__ == "__main__":
    init_db()
    clear_all_data()
