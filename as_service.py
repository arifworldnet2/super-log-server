import ipaddress
import urllib.request
import json
from datetime import datetime
from database import get_connection

# In-memory fast cache: subnet -> as_info string
AS_MEMORY_CACHE = {}

# Known public DNS & major tech ASNs for instant offline resolution
WELL_KNOWN_AS = {
    "8.8.8.0/24": "AS15169 Google LLC",
    "8.8.4.0/24": "AS15169 Google LLC",
    "1.1.1.0/24": "AS13335 Cloudflare, Inc.",
    "1.0.0.0/24": "AS13335 Cloudflare, Inc.",
    "9.9.9.0/24": "AS19281 Quad9",
    "208.67.222.0/24": "AS36692 OpenDNS (Cisco)",
    "208.67.220.0/24": "AS36692 OpenDNS (Cisco)",
}

def get_subnet_key(ip_str: str) -> str:
    """Returns /24 subnet string for IPv4 or original IP."""
    try:
        parts = ip_str.strip().split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        pass
    return ip_str

def is_private_or_special(ip_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except Exception:
        return False

def init_as_cache():
    """Initializes the as_cache database table and loads existing records into memory."""
    global AS_MEMORY_CACHE
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS as_cache (
                subnet TEXT PRIMARY KEY,
                as_info TEXT NOT NULL,
                org TEXT,
                updated_at TEXT
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_as_cache_subnet ON as_cache(subnet)")
        cursor.execute("SELECT subnet, as_info FROM as_cache")
        for row in cursor.fetchall():
            AS_MEMORY_CACHE[row["subnet"]] = row["as_info"]
        conn.close()
    except Exception as e:
        print(f"[AS Service Init Error] {e}")

# Pre-load cache from DB
init_as_cache()

def get_as_info(ip: str) -> str:
    """Lookup AS Info for a single IP address."""
    if not ip or ip in ("0.0.0.0", "127.0.0.1", ""):
        return ""
    if is_private_or_special(ip):
        return "Private / Local IP"

    subnet = get_subnet_key(ip)
    if subnet in AS_MEMORY_CACHE:
        return AS_MEMORY_CACHE[subnet]
    if subnet in WELL_KNOWN_AS:
        info = WELL_KNOWN_AS[subnet]
        AS_MEMORY_CACHE[subnet] = info
        save_as_to_db(subnet, info)
        return info

    # Fallback to single lookup
    res = batch_get_as_info([ip])
    return res.get(ip, "")

def batch_get_as_info(ip_list: list) -> dict:
    """
    Given a list of IP addresses, resolves their AS Info efficiently.
    Uses memory cache first, then database cache, and batches un-cached public IPs in a single HTTP call.
    """
    result = {}
    missing_subnets = {}  # subnet -> representative ip

    for raw_ip in ip_list:
        if not raw_ip:
            continue
        ip = raw_ip.strip()
        if not ip or ip in ("0.0.0.0", "127.0.0.1"):
            result[raw_ip] = ""
            continue

        if is_private_or_special(ip):
            result[raw_ip] = "Private / Local IP"
            continue

        subnet = get_subnet_key(ip)
        if subnet in AS_MEMORY_CACHE:
            result[raw_ip] = AS_MEMORY_CACHE[subnet]
        elif subnet in WELL_KNOWN_AS:
            result[raw_ip] = WELL_KNOWN_AS[subnet]
            AS_MEMORY_CACHE[subnet] = WELL_KNOWN_AS[subnet]
        else:
            missing_subnets[subnet] = ip

    # If there are missing public IPs, batch fetch up to 100 in 1 HTTP call
    if missing_subnets:
        unique_ips = list(missing_subnets.values())[:100]
        try:
            url = "http://ip-api.com/batch?fields=query,status,as,asname,org,isp"
            req_data = json.dumps(unique_ips).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=req_data,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "SuperLOG/1.0"
                }
            )
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                db_updates = []
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                for item in data:
                    q_ip = item.get("query")
                    if q_ip and item.get("status") == "success":
                        as_str = item.get("as") or item.get("asname") or item.get("isp") or ""
                        # If AS name is just AS number, append org/isp
                        if as_str and not any(c.isalpha() for c in as_str.replace("AS", "")):
                            extra = item.get("org") or item.get("isp") or ""
                            if extra:
                                as_str = f"{as_str} {extra}"
                        sub = get_subnet_key(q_ip)
                        if as_str:
                            AS_MEMORY_CACHE[sub] = as_str
                            db_updates.append((sub, as_str, item.get("org", ""), now_str))

                if db_updates:
                    try:
                        conn = get_connection()
                        conn.executemany("""
                            INSERT OR REPLACE INTO as_cache (subnet, as_info, org, updated_at)
                            VALUES (?, ?, ?, ?)
                        """, db_updates)
                        conn.commit()
                        conn.close()
                    except Exception as e:
                        print(f"[AS Cache DB Save Error] {e}")
        except Exception as e:
            # Network failure or timeout: graceful fallback
            pass

        # Populate results for the requested IPs
        for raw_ip in ip_list:
            if raw_ip not in result:
                sub = get_subnet_key(raw_ip)
                result[raw_ip] = AS_MEMORY_CACHE.get(sub, "")

    return result

def save_as_to_db(subnet: str, as_info: str, org: str = ""):
    try:
        conn = get_connection()
        conn.execute("""
            INSERT OR REPLACE INTO as_cache (subnet, as_info, org, updated_at)
            VALUES (?, ?, ?, ?)
        """, (subnet, as_info, org, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()
    except Exception:
        pass
