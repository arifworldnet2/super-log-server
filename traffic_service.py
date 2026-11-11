from datetime import datetime
from database import get_connection

def format_bytes_human(b):
    if b is None:
        return "0 B"
    try:
        # If it's already a string like '45.2 GB', return as is
        if isinstance(b, str) and any(unit in b for unit in ["GB", "MB", "KB", "TB", "B"]):
            return b
        b = float(b)
        if b <= 0:
            return "0 B"
        if b >= 1024**4:
            return f"{round(b / 1024**4, 1)} TB"
        elif b >= 1024**3:
            return f"{round(b / 1024**3, 1)} GB"
        elif b >= 1024**2:
            return f"{round(b / 1024**2, 1)} MB"
        elif b >= 1024:
            return f"{round(b / 1024, 1)} KB"
        return f"{int(b)} B"
    except Exception:
        return "0 B"

def parse_bytes_from_str(s):
    if not s:
        return 0
    try:
        s = str(s).strip()
        parts = s.split()
        if len(parts) == 2:
            val = float(parts[0])
            unit = parts[1].upper()
            if unit == "TB": return int(val * 1024**4)
            if unit == "GB": return int(val * 1024**3)
            if unit == "MB": return int(val * 1024**2)
            if unit == "KB": return int(val * 1024)
            return int(val)
        return int(float(s))
    except Exception:
        return 0

def get_traffic_drilldown(username: str, year: str = None, month: str = None, date: str = None):
    """
    Returns drilldown data from REAL data only:
    - Active sessions from `online_users` (synced from MikroTik API or syslog)
    - Closed historical sessions from `customer_usage` (recorded upon acct_logout)
    No sample or synthetic data is generated.
    """
    conn = get_connection()
    c = conn.cursor()

    # Check if user is currently active
    c.execute("SELECT * FROM online_users WHERE username = ? LIMIT 1", (username,))
    online_user = c.fetchone()
    online_dict = dict(online_user) if online_user else None

    # Determine login date/month/year for active session
    active_year = None
    active_month = None
    active_date = None
    if online_dict and online_dict.get("login_time"):
        try:
            dt = datetime.strptime(online_dict["login_time"][:10], "%Y-%m-%d")
            active_year = dt.strftime("%Y")
            active_month = dt.strftime("%Y-%m")
            active_date = dt.strftime("%Y-%m-%d")
        except Exception:
            now_dt = datetime.now()
            active_year = now_dt.strftime("%Y")
            active_month = now_dt.strftime("%Y-%m")
            active_date = now_dt.strftime("%Y-%m-%d")

    active_up_bytes = (online_dict.get("upload_bytes") or parse_bytes_from_str(online_dict.get("upload"))) if online_dict else 0
    active_down_bytes = (online_dict.get("download_bytes") or parse_bytes_from_str(online_dict.get("download"))) if online_dict else 0

    # ==========================================================
    # Level 4: PPPoE Sessions View for a specific date
    # ==========================================================
    if date:
        c.execute("""
            SELECT * FROM customer_usage 
            WHERE username = ? AND (strftime('%Y-%m-%d', login_time) = ? OR strftime('%Y-%m-%d', logout_time) = ?)
            ORDER BY login_time ASC
        """, (username, date, date))
        rows = [dict(r) for r in c.fetchall()]

        sessions = []
        sl = 1
        for r in rows:
            up_b = r.get("upload_bytes") or 0
            down_b = r.get("download_bytes") or 0
            tot_b = up_b + down_b
            sessions.append({
                "sl": sl,
                "user": r["username"],
                "mac": r.get("mac") or "-",
                "ip": r.get("address") or "-",
                "start_time": r.get("login_time") or "-",
                "end_time": r.get("logout_time") or "-",
                "is_connected": False,
                "online_time": r.get("uptime") or "-",
                "upload": format_bytes_human(up_b),
                "download": format_bytes_human(down_b),
                "total": format_bytes_human(tot_b),
                "identity": r.get("identity") or "-",
                "host": r.get("host") or "-"
            })
            sl += 1

        # If user is currently online and date matches their active session date
        today_str = datetime.now().strftime("%Y-%m-%d")
        if online_dict and (date == active_date or date == today_str):
            tot_b = active_up_bytes + active_down_bytes
            sessions.append({
                "sl": sl,
                "user": username,
                "mac": online_dict.get("mac") or "-",
                "ip": online_dict.get("address") or "-",
                "start_time": online_dict.get("login_time") or f"{date} 00:00:00",
                "end_time": "Connected",
                "is_connected": True,
                "online_time": online_dict.get("online_duration") or "-",
                "upload": format_bytes_human(active_up_bytes),
                "download": format_bytes_human(active_down_bytes),
                "total": format_bytes_human(active_up_bytes + active_down_bytes),
                "identity": online_dict.get("identity") or "-",
                "host": online_dict.get("host") or "-"
            })

        conn.close()
        return {
            "level": 4,
            "level_name": "sessions",
            "user": username,
            "date": date,
            "sessions": sessions
        }

    # ==========================================================
    # Level 3: Daily View for a specific month
    # ==========================================================
    if year and month:
        ym = month if "-" in month else f"{year}-{month.zfill(2)}"

        c.execute("""
            SELECT strftime('%Y-%m-%d', login_time) as period, username, 
                   SUM(upload_bytes) as total_up, 
                   SUM(download_bytes) as total_down
            FROM customer_usage 
            WHERE username = ? AND strftime('%Y-%m', login_time) = ?
            GROUP BY period 
            ORDER BY period ASC
        """, (username, ym))
        rows = [dict(r) for r in c.fetchall()]

        daily_dict = {}
        for r in rows:
            p = r["period"]
            daily_dict[p] = {
                "date": p,
                "user": username,
                "up_b": r["total_up"] or 0,
                "down_b": r["total_down"] or 0
            }

        # Include real active session if within this month
        if online_dict and active_month == ym and active_date:
            if active_date in daily_dict:
                daily_dict[active_date]["up_b"] += active_up_bytes
                daily_dict[active_date]["down_b"] += active_down_bytes
            else:
                daily_dict[active_date] = {
                    "date": active_date,
                    "user": username,
                    "up_b": active_up_bytes,
                    "down_b": active_down_bytes
                }

        daily_data = []
        for p in sorted(daily_dict.keys()):
            entry = daily_dict[p]
            tot_b = entry["up_b"] + entry["down_b"]
            daily_data.append({
                "date": entry["date"],
                "user": entry["user"],
                "upload": format_bytes_human(entry["up_b"]),
                "download": format_bytes_human(entry["down_b"]),
                "total": format_bytes_human(tot_b),
                "link": f"/traffic/report?user={username}&date={entry['date']}"
            })

        conn.close()
        return {
            "level": 3,
            "level_name": "daily",
            "user": username,
            "year": year,
            "month": ym,
            "rows": daily_data
        }

    # ==========================================================
    # Level 2: Monthly View for a specific year
    # ==========================================================
    if year:
        c.execute("""
            SELECT strftime('%Y-%m', login_time) as period, username, 
                   SUM(upload_bytes) as total_up, 
                   SUM(download_bytes) as total_down
            FROM customer_usage 
            WHERE username = ? AND strftime('%Y', login_time) = ?
            GROUP BY period 
            ORDER BY period ASC
        """, (username, str(year)))
        rows = [dict(r) for r in c.fetchall()]

        monthly_dict = {}
        for r in rows:
            p = r["period"]
            monthly_dict[p] = {
                "date": p,
                "user": username,
                "up_b": r["total_up"] or 0,
                "down_b": r["total_down"] or 0
            }

        # Include real active session if within this year
        if online_dict and active_year == str(year) and active_month:
            if active_month in monthly_dict:
                monthly_dict[active_month]["up_b"] += active_up_bytes
                monthly_dict[active_month]["down_b"] += active_down_bytes
            else:
                monthly_dict[active_month] = {
                    "date": active_month,
                    "user": username,
                    "up_b": active_up_bytes,
                    "down_b": active_down_bytes
                }

        monthly_data = []
        for p in sorted(monthly_dict.keys()):
            entry = monthly_dict[p]
            tot_b = entry["up_b"] + entry["down_b"]
            monthly_data.append({
                "date": entry["date"],
                "user": entry["user"],
                "upload": format_bytes_human(entry["up_b"]),
                "download": format_bytes_human(entry["down_b"]),
                "total": format_bytes_human(tot_b),
                "link": f"/traffic/report?user={username}&year={year}&month={entry['date']}"
            })

        conn.close()
        return {
            "level": 2,
            "level_name": "monthly",
            "user": username,
            "year": year,
            "rows": monthly_data
        }

    # ==========================================================
    # Level 1: Yearly View
    # ==========================================================
    c.execute("""
        SELECT strftime('%Y', login_time) as period, username, 
               SUM(upload_bytes) as total_up, 
               SUM(download_bytes) as total_down
        FROM customer_usage 
        WHERE username = ?
        GROUP BY period 
        ORDER BY period ASC
    """, (username,))
    rows = [dict(r) for r in c.fetchall()]

    yearly_dict = {}
    for r in rows:
        p = r["period"]
        yearly_dict[p] = {
            "date": p,
            "user": username,
            "up_b": r["total_up"] or 0,
            "down_b": r["total_down"] or 0
        }

    # Include real active session if user is currently online
    if online_dict and active_year:
        if active_year in yearly_dict:
            yearly_dict[active_year]["up_b"] += active_up_bytes
            yearly_dict[active_year]["down_b"] += active_down_bytes
        else:
            yearly_dict[active_year] = {
                "date": active_year,
                "user": username,
                "up_b": active_up_bytes,
                "down_b": active_down_bytes
            }

    yearly_data = []
    for p in sorted(yearly_dict.keys()):
        entry = yearly_dict[p]
        tot_b = entry["up_b"] + entry["down_b"]
        yearly_data.append({
            "date": entry["date"],
            "user": entry["user"],
            "upload": format_bytes_human(entry["up_b"]),
            "download": format_bytes_human(entry["down_b"]),
            "total": format_bytes_human(tot_b),
            "link": f"/traffic/report?user={username}&year={entry['date']}"
        })

    conn.close()
    return {
        "level": 1,
        "level_name": "yearly",
        "user": username,
        "rows": yearly_data
    }
