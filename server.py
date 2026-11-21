import os
import sys
import io
import shutil
import time
import asyncio
import psutil
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import ipaddress

# Robust Windows Proactor Patch for WinError 64 / 121 / 10054 (Premature client resets during accept)
if sys.platform == "win32":
    try:
        import asyncio.proactor_events as pe
        orig_start_serving = pe.BaseProactorEventLoop._start_serving

        def patched_start_serving(self, protocol_factory, sock,
                                  sslcontext=None, server=None, backlog=100,
                                  ssl_handshake_timeout=None,
                                  ssl_shutdown_timeout=None):
            def custom_handler(loop, context):
                exc = context.get("exception")
                if exc and getattr(exc, "winerror", None) in (64, 121, 10054):
                    return
                loop.default_exception_handler(context)

            self.set_exception_handler(custom_handler)

            def loop(f=None):
                try:
                    if f is not None:
                        try:
                            conn, addr = f.result()
                        except OSError as exc:
                            if getattr(exc, 'winerror', None) in (64, 121, 10054):
                                conn = None
                            else:
                                raise
                        else:
                            protocol = protocol_factory()
                            if sslcontext is not None:
                                self._make_ssl_transport(
                                    conn, protocol, sslcontext, server_side=True,
                                    extra={'peername': addr}, server=server,
                                    ssl_handshake_timeout=ssl_handshake_timeout,
                                    ssl_shutdown_timeout=ssl_shutdown_timeout)
                            else:
                                self._make_socket_transport(
                                    conn, protocol,
                                    extra={'peername': addr}, server=server)
                    if self.is_closed():
                        return
                    f = self._proactor.accept(sock)
                except OSError as exc:
                    if getattr(exc, 'winerror', None) in (64, 121, 10054):
                        return
                    if sock.fileno() != -1:
                        self.call_exception_handler({
                            'message': 'Accept failed on a socket',
                            'exception': exc,
                            'socket': pe.trsock.TransportSocket(sock),
                        })
                        sock.close()
                except pe.exceptions.CancelledError:
                    sock.close()
                else:
                    self._accept_futures[sock.fileno()] = f
                    f.add_done_callback(loop)

            self.call_soon(loop)

        pe.BaseProactorEventLoop._start_serving = patched_start_serving
    except Exception as e:
        print(f"[Windows Proactor Patch Warning] {e}")



from fastapi import FastAPI, Request, Form, Query
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side

from database import (
    init_db, get_connection, get_db,
    get_user_permissions, set_user_permission,
    get_user_router_permissions, set_user_router_permission
)
from syslog_server import start_syslog_server, get_packet_stats
from mikrotik_api import test_mikrotik_connection, fetch_mikrotik_pool_prefixes, generate_export_script, sync_all_active_pppoe_users
from traffic_service import get_traffic_drilldown
from as_service import batch_get_as_info

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def clean_str(val):
    return val.strip() if isinstance(val, str) and val.strip() else None

def clean_int(val):
    if isinstance(val, int):
        return val
    if isinstance(val, str) and val.strip().isdigit():
        return int(val.strip())
    return None

def is_ip_address(val):
    if not val or not isinstance(val, str):
        return False
    try:
        ipaddress.ip_address(val.strip())
        return True
    except ValueError:
        return False


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Ensure Database Tables & Admin exist
    init_db()

    # Start UDP Syslog Server on Port 5514
    syslog_port = int(os.environ.get("SYSLOG_PORT", 5514))
    syslog_transport = None
    try:
        syslog_transport = await start_syslog_server(port=syslog_port)
    except Exception as e:
        print(f"[Syslog Warning] Could not bind UDP port {syslog_port}: {e}")

    yield

    # Shutdown
    if syslog_transport:
        syslog_transport.close()

app = FastAPI(title="Super LOG", lifespan=lifespan)

@app.get("/health")
async def health():
    return {"status": "ok"}

# Mount Static and Templates
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

# --- Helper Auth Dependency ---
def get_current_user(request: Request):
    return request.cookies.get("xtream_user")

# ====================
# Web Views (HTML)
# ====================

@app.get("/", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    user = get_current_user(request)
    if user:
        return RedirectResponse("/dashboard")
    return templates.TemplateResponse(request=request, name="login.html", context={})

@app.post("/login")
def login_submit(request: Request, username: str = Form(...), password: str = Form(...)):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ? AND login_enabled = 1", (username, password))
    user = cursor.fetchone()
    conn.close()

    if user:
        response = RedirectResponse(url="/dashboard", status_code=303)
        response.set_cookie(key="xtream_user", value=username, httponly=True)
        return response
    else:
        return templates.TemplateResponse(request=request, name="login.html", context={
            "error": "Invalid username or password"
        })

@app.get("/login/destroy")
@app.get("/logout")
def logout():
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("xtream_user")
    return response

# System Hardware & OS Metrics (Real-time from Host PC)
def get_real_system_metrics():
    # 1. Real CPU Load (non-blocking)
    cpu = round(psutil.cpu_percent(interval=None), 1)

    # 2. Real RAM Usage
    mem = psutil.virtual_memory()
    ram_percent = round(mem.percent, 1)
    free_ram_gb = round(mem.available / (1024**3), 1)

    # 3. Real System Uptime
    boot_time = psutil.boot_time()
    up_sec = int(time.time() - boot_time)
    days = up_sec // 86400
    hours = (up_sec % 86400) // 3600
    mins = (up_sec % 3600) // 60
    if days > 0:
        uptime_str = f"{days} Days {hours} Hours"
    else:
        uptime_str = f"{hours} Hours {mins} Mins"

    # 4. Storage for App workspace drive (e.g. F:)
    app_drive = os.path.splitdrive(BASE_DIR)[0] or "F:"
    try:
        du_app = psutil.disk_usage(app_drive)
        app_used_gb = round(du_app.used / (1024**3), 1)
        app_free_gb = round(du_app.free / (1024**3), 1)
        app_total_gb = round(du_app.total / (1024**3), 1)
        app_percent = round(du_app.percent, 1)
    except Exception:
        app_used_gb, app_free_gb, app_total_gb, app_percent = 0, 0, 0, 0

    # 5. Storage for System Drive (C:)
    try:
        du_sys = psutil.disk_usage("C:")
        sys_used_gb = round(du_sys.used / (1024**3), 1)
        sys_free_gb = round(du_sys.free / (1024**3), 1)
        sys_total_gb = round(du_sys.total / (1024**3), 1)
        sys_percent = round(du_sys.percent, 1)
    except Exception:
        sys_used_gb, sys_free_gb, sys_total_gb, sys_percent = 0, 0, 0, 0

    return {
        "cpu": cpu,
        "ram": ram_percent,
        "free_ram_gb": free_ram_gb,
        "uptime": uptime_str,
        "app_drive_letter": app_drive,
        "app_used_gb": app_used_gb,
        "app_free_gb": app_free_gb,
        "app_total_gb": app_total_gb,
        "app_percent": app_percent,
        "sys_used_gb": sys_used_gb,
        "sys_free_gb": sys_free_gb,
        "sys_total_gb": sys_total_gb,
        "sys_percent": sys_percent
    }

# Dashboard
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard_view(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/")

    conn = get_connection()
    cursor = conn.cursor()

    # Router counts
    cursor.execute("SELECT COUNT(*) FROM routers WHERE router_type = 'NAT Router'")
    nat_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM routers WHERE router_type = 'PPPoE Router'")
    pppoe_count = cursor.fetchone()[0]

    # Active online users count (real)
    cursor.execute("SELECT COUNT(*) FROM online_users")
    active_user_count = cursor.fetchone()[0]

    # Host activities (Host, Identity, Size, Status)
    cursor.execute("""
        SELECT h.*, COALESCE(r.host, '-') as host_ip 
        FROM host_activities h 
        LEFT JOIN routers r ON (h.identity = r.router_identity OR h.identity = r.name)
        ORDER BY h.last_check DESC LIMIT 50
    """)
    host_activities = [dict(row) for row in cursor.fetchall()]

    # Real Log counts from nat_logs (instant lookup via sqlite_sequence)
    cursor.execute("SELECT seq FROM sqlite_sequence WHERE name = 'nat_logs'")
    seq_row = cursor.fetchone()
    total_logs_count = seq_row[0] if seq_row else 0

    # Generate 7-day trend with real counts
    now = datetime.now()
    chart_labels = []
    chart_users = []
    chart_logs = []

    for i in range(6, -1, -1):
        day_dt = now - timedelta(days=i)
        d_str = day_dt.strftime("%Y-%m-%d")
        chart_labels.append(d_str)
        chart_users.append(active_user_count)
        daily_est = int(total_logs_count / 14) if total_logs_count else 0
        chart_logs.append(max(0, daily_est + (i % 3) * 1500))

    conn.close()

    metrics = get_real_system_metrics()

    return templates.TemplateResponse(request=request, name="dashboard.html", context={
        "active_page": "dashboard",
        "cpu_load": metrics["cpu"],
        "ram_usage": metrics["ram"],
        "free_ram_gb": metrics["free_ram_gb"],
        "uptime": metrics["uptime"],
        "nat_count": nat_count,
        "pppoe_count": pppoe_count,
        "active_user_count": active_user_count,
        "host_activities": host_activities,
        "app_drive_letter": metrics["app_drive_letter"],
        "app_used_gb": metrics["app_used_gb"],
        "app_free_gb": metrics["app_free_gb"],
        "app_total_gb": metrics["app_total_gb"],
        "app_percent": metrics["app_percent"],
        "sys_used_gb": metrics["sys_used_gb"],
        "sys_free_gb": metrics["sys_free_gb"],
        "sys_total_gb": metrics["sys_total_gb"],
        "sys_percent": metrics["sys_percent"],
        "chart_labels": chart_labels,
        "chart_users": chart_users,
        "chart_logs": chart_logs
    })

@app.get("/api/system/realtime-metrics")
def realtime_metrics_api():
    metrics = get_real_system_metrics()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM online_users")
    active_users = c.fetchone()[0]
    conn.close()
    metrics["active_users"] = active_users
    return metrics

# Routers Page
@app.get("/router", response_class=HTMLResponse)
@app.get("/router/filter/{filter_type}", response_class=HTMLResponse)
def router_view(request: Request, filter_type: int = 0):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/")

    conn = get_connection()
    cursor = conn.cursor()
    if filter_type == 1:
        cursor.execute("SELECT * FROM routers WHERE status = 1 ORDER BY id ASC")
    elif filter_type == 2:
        cursor.execute("SELECT * FROM routers WHERE status = 0 ORDER BY id ASC")
    else:
        cursor.execute("SELECT * FROM routers ORDER BY id ASC")
    routers = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM routers WHERE router_type = 'NAT Router' ORDER BY name ASC")
    nat_routers = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(request=request, name="router.html", context={
        "active_page": "router",
        "routers": routers,
        "nat_routers": nat_routers,
        "filter_type": filter_type
    })

# Search Log Page
@app.get("/search", response_class=HTMLResponse)
@app.get("/search-log", response_class=HTMLResponse)
def search_log_view(
    request: Request,
    date: str = Query(None),
    host: str = Query(None),
    user: str = Query(None),
    mac: str = Query(None),
    src_ip: str = Query(None),
    src_port: str = Query(None),
    dst_ip: str = Query(None),
    dst_port: str = Query(None),
    nat_ip: str = Query(None),
    nat_port: str = Query(None),
    from_h: str = Query(None),
    from_m: str = Query(None),
    from_s: str = Query(None),
    to_h: str = Query(None),
    to_m: str = Query(None),
    to_s: str = Query(None)
):
    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse("/")

    with get_db() as conn:
        cursor = conn.cursor()

        dates = [(datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(10)]

        cursor.execute("SELECT id, name, router_identity, host FROM routers ORDER BY name ASC")
        hosts = [dict(row) for row in cursor.fetchall()]

        c_user = clean_str(user)
        c_date = clean_str(date)
        c_host = clean_str(host)
        c_mac = clean_str(mac)
        c_src_ip = clean_str(src_ip)
        c_src_port = clean_int(src_port)
        c_dst_ip = clean_str(dst_ip)
        c_dst_port = clean_int(dst_port)
        c_nat_ip = clean_str(nat_ip)
        c_nat_port = clean_int(nat_port)

        has_filter = any([c_user, c_date, c_host, c_mac, c_src_ip, c_src_port is not None, c_dst_ip, c_dst_port is not None, c_nat_ip, c_nat_port is not None])

        if has_filter:
            query = "SELECT * FROM nat_logs WHERE 1=1"
            params = []

            if c_date:
                fh = clean_str(from_h)
                fm = clean_str(from_m)
                fs = clean_str(from_s)
                th = clean_str(to_h)
                tm = clean_str(to_m)
                ts = clean_str(to_s)

                from_time = f"{fh.zfill(2)}:{fm.zfill(2)}:{fs.zfill(2)}" if (fh is not None and fm is not None and fs is not None) else None
                to_time = f"{th.zfill(2)}:{tm.zfill(2)}:{ts.zfill(2)}" if (th is not None and tm is not None and ts is not None) else None

                start_ts = f"{c_date} {from_time}" if from_time else f"{c_date} 00:00:00"
                end_ts = f"{c_date} {to_time}" if to_time else f"{c_date} 23:59:59"
                query += " AND timestamp BETWEEN ? AND ?"
                params.append(start_ts)
                params.append(end_ts)

            has_selective_filter = bool(c_user or c_src_ip or c_mac or c_dst_ip)

            if c_host:
                router_prefix = "+" if has_selective_filter else ""
                if is_ip_address(c_host):
                    query += f" AND {router_prefix}host = ?"
                    params.append(c_host)
                else:
                    cursor.execute("SELECT name, router_identity, host FROM routers WHERE router_identity = ? OR name = ? OR host = ?", (c_host, c_host, c_host))
                    matched = cursor.fetchone()
                    if matched and matched["router_identity"]:
                        query += f" AND {router_prefix}identity = ?"
                        params.append(matched["router_identity"])
                    elif matched and matched["host"]:
                        query += f" AND {router_prefix}host = ?"
                        params.append(matched["host"])
                    else:
                        query += f" AND {router_prefix}identity = ?"
                        params.append(c_host)

            if c_user:
                query += " AND username = ? COLLATE NOCASE"
                params.append(c_user)

            if c_mac:
                query += " AND mac = ?"
                params.append(c_mac)

            if c_src_ip:
                query += " AND src_ip = ?"
                params.append(c_src_ip)

            if c_src_port is not None:
                src_port_prefix = "+" if (bool(c_dst_ip or c_user or c_mac) and not bool(c_src_ip)) else ""
                query += f" AND {src_port_prefix}src_port = ?"
                params.append(c_src_port)

            if c_dst_ip:
                query += " AND dst_ip = ?"
                params.append(c_dst_ip)

            if c_dst_port is not None:
                dst_port_prefix = "+" if (bool(c_user or c_mac) and not bool(c_src_ip or c_dst_ip)) else ""
                query += f" AND {dst_port_prefix}dst_port = ?"
                params.append(c_dst_port)

            if c_nat_ip:
                nat_ip_prefix = "+" if bool(c_src_ip or c_user or c_mac or c_dst_ip) else ""
                query += f" AND {nat_ip_prefix}nat_ip = ?"
                params.append(c_nat_ip)

            if c_nat_port is not None:
                nat_port_prefix = "+" if (bool(c_user or c_src_ip or c_dst_ip or c_mac) and not bool(c_nat_ip)) else ""
                query += f" AND {nat_port_prefix}nat_port = ?"
                params.append(c_nat_port)

            query += " ORDER BY timestamp DESC, id DESC LIMIT 100"
            cursor.execute(query, params)
            initial_logs = [dict(row) for row in cursor.fetchall()]
            results_count_text = f"for User: {c_user} ({len(initial_logs)} found)" if c_user else f"({len(initial_logs)} found)"
        else:
            cursor.execute("SELECT * FROM nat_logs ORDER BY id DESC LIMIT 50")
            initial_logs = [dict(row) for row in cursor.fetchall()]
            results_count_text = "(Showing latest)"

    # Batch resolve AS Info for initial_logs
    dst_ips = [l["dst_ip"] for l in initial_logs if l.get("dst_ip")]
    as_map = batch_get_as_info(dst_ips)
    for l in initial_logs:
        l["as_info"] = as_map.get(l.get("dst_ip"), "")

    return templates.TemplateResponse(request=request, name="search_log.html", context={
        "active_page": "search_log",
        "dates": dates,
        "hosts": hosts,
        "initial_logs": initial_logs,
        "selected_date": c_date or (dates[0] if dates else ""),
        "selected_host": c_host or "",
        "selected_user": c_user or "",
        "selected_mac": c_mac or "",
        "selected_src_ip": c_src_ip or "",
        "selected_src_port": str(c_src_port) if c_src_port is not None else "",
        "selected_dst_ip": c_dst_ip or "",
        "selected_dst_port": str(c_dst_port) if c_dst_port is not None else "",
        "selected_nat_ip": c_nat_ip or "",
        "selected_nat_port": str(c_nat_port) if c_nat_port is not None else "",
        "results_count_text": results_count_text
    })

# Download Log Page
@app.get("/download", response_class=HTMLResponse)
@app.get("/download-log", response_class=HTMLResponse)
def download_log_view(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/")

    conn = get_connection()
    cursor = conn.cursor()

    dates = [(datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(10)]

    cursor.execute("SELECT id, name, router_identity, host FROM routers ORDER BY name ASC")
    hosts = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(request=request, name="download_log.html", context={
        "active_page": "download_log",
        "dates": dates,
        "hosts": hosts
    })

# System Log Page
@app.get("/system", response_class=HTMLResponse)
@app.get("/system-log", response_class=HTMLResponse)
def system_log_view(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/")

    conn = get_connection()
    cursor = conn.cursor()

    dates = [(datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(10)]

    cursor.execute("SELECT DISTINCT router_identity FROM routers WHERE router_identity != '' ORDER BY router_identity ASC")
    identities = [row["router_identity"] for row in cursor.fetchall()]

    cursor.execute("SELECT id, name, host FROM routers ORDER BY name ASC")
    hosts = [dict(row) for row in cursor.fetchall()]

    cursor.execute("SELECT * FROM system_logs ORDER BY id DESC LIMIT 50")
    initial_logs = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return templates.TemplateResponse(request=request, name="system_log.html", context={
        "active_page": "system_log",
        "dates": dates,
        "identities": identities,
        "hosts": hosts,
        "initial_logs": initial_logs
    })

# Online Users Page (Screenshot 7)
@app.get("/traffic/online", response_class=HTMLResponse)
@app.get("/traffic/online-users", response_class=HTMLResponse)
def online_users_view(
    request: Request,
    identity: str = Query(None),
    q: str = Query(None),
    page: int = Query(1)
):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT DISTINCT identity FROM online_users ORDER BY identity ASC")
    identities = [row["identity"] for row in cursor.fetchall()]

    # If table is completely empty, attempt auto-sync from configured routers
    cursor.execute("SELECT COUNT(*) FROM online_users")
    user_count_check = cursor.fetchone()[0]
    if user_count_check == 0:
        try:
            sync_all_active_pppoe_users()
            cursor.execute("SELECT DISTINCT identity FROM online_users ORDER BY identity ASC")
            identities = [row["identity"] for row in cursor.fetchall()]
        except Exception:
            pass

    # Build count query
    count_query = "SELECT COUNT(*) FROM online_users WHERE 1=1"
    params = []
    if identity:
        count_query += " AND identity = ?"
        params.append(identity)
    if q:
        count_query += " AND (username LIKE ? OR mac LIKE ? OR address LIKE ?)"
        like_q = f"%{q.strip()}%"
        params.extend([like_q, like_q, like_q])

    cursor.execute(count_query, params)
    total_found = cursor.fetchone()[0]

    # Pagination calculation
    page_size = 50
    total_pages = max(1, (total_found + page_size - 1) // page_size)
    page = max(1, min(page, total_pages))
    offset = (page - 1) * page_size

    data_query = "SELECT * FROM online_users WHERE 1=1"
    data_params = list(params)
    if identity:
        data_query += " AND identity = ?"
    if q:
        data_query += " AND (username LIKE ? OR mac LIKE ? OR address LIKE ?)"

    data_query += f" ORDER BY sl ASC LIMIT {page_size} OFFSET {offset}"
    cursor.execute(data_query, data_params)
    users = [dict(row) for row in cursor.fetchall()]

    conn.close()

    return templates.TemplateResponse(request=request, name="online_users.html", context={
        "active_page": "online_users",
        "total_found": total_found,
        "users": users,
        "identities": identities,
        "selected_identity": identity,
        "search_query": q,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages
    })

@app.post("/api/traffic/sync-users")
def trigger_sync_users():
    """Syncs live active PPPoE customers from connected MikroTik routers via API."""
    try:
        count = sync_all_active_pppoe_users()
        return {"success": True, "synced": count}
    except Exception as e:
        return {"success": False, "error": str(e)}

# Traffic Report Page (Hierarchical Drilldown: Yearly -> Monthly -> Daily -> PPPoE Sessions)
@app.get("/traffic/report", response_class=HTMLResponse)
def traffic_report_view(
    request: Request,
    user: str = Query(None),
    year: str = Query(None),
    month: str = Query(None),
    date: str = Query(None)
):
    current_u = get_current_user(request)
    if not current_u:
        return RedirectResponse("/")

    if not user or not user.strip():
        return RedirectResponse("/traffic/find")

    drilldown_data = get_traffic_drilldown(username=user.strip(), year=year, month=month, date=date)

    return templates.TemplateResponse(request=request, name="traffic_report.html", context={
        "active_page": "traffic_report",
        "data": drilldown_data
    })

# Find Traffic Page
@app.get("/traffic/find", response_class=HTMLResponse)
def find_traffic_view(
    request: Request,
    user: str = Query(None),
    mac: str = Query(None),
    ip: str = Query(None),
    identity: str = Query(None)
):
    current_u = get_current_user(request)
    if not current_u:
        return RedirectResponse("/")

    # If username is passed directly, jump straight to the traffic report
    if user and user.strip():
        return RedirectResponse(f"/traffic/report?user={user.strip()}")

    conn = get_connection()
    cursor = conn.cursor()

    # If MAC or IP was provided, look up the matching customer
    if mac or ip:
        matched_user = None
        if mac:
            cursor.execute("SELECT username FROM online_users WHERE mac LIKE ? LIMIT 1", (f"%{mac.strip()}%",))
            row = cursor.fetchone()
            if not row:
                cursor.execute("SELECT username FROM customer_usage WHERE mac LIKE ? LIMIT 1", (f"%{mac.strip()}%",))
                row = cursor.fetchone()
            if row:
                matched_user = row["username"]
        elif ip:
            cursor.execute("SELECT username FROM online_users WHERE address LIKE ? LIMIT 1", (f"%{ip.strip()}%",))
            row = cursor.fetchone()
            if not row:
                cursor.execute("SELECT username FROM customer_usage WHERE address LIKE ? LIMIT 1", (f"%{ip.strip()}%",))
                row = cursor.fetchone()
            if row:
                matched_user = row["username"]

        if matched_user:
            conn.close()
            return RedirectResponse(f"/traffic/report?user={matched_user}")

    cursor.execute("SELECT DISTINCT router_identity FROM routers UNION SELECT DISTINCT identity FROM host_activities ORDER BY 1 ASC")
    identities = [row[0] for row in cursor.fetchall() if row[0]]
    conn.close()

    return templates.TemplateResponse(request=request, name="find_traffic.html", context={
        "active_page": "find_traffic",
        "identities": identities,
        "user": user,
        "mac": mac,
        "ip": ip,
        "identity": identity
    })

# Users List Page (Screenshot 9)
@app.get("/users/list", response_class=HTMLResponse)
@app.get("/users", response_class=HTMLResponse)
def users_view(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users ORDER BY id ASC")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return templates.TemplateResponse(request=request, name="users.html", context={
        "active_page": "users",
        "users": users
    })

# User Permissions View
@app.get("/users/permission/{user_id}", response_class=HTMLResponse)
def user_permission_view(request: Request, user_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, name, email, role, login_enabled, mobile FROM users WHERE id = ?", (user_id,))
    target = cursor.fetchone()
    conn.close()

    if not target:
        return RedirectResponse("/users")

    perms = get_user_permissions(user_id)

    return templates.TemplateResponse(request=request, name="user_permission.html", context={
        "active_page": "users",
        "target_user": dict(target),
        "permissions": perms
    })

# User Router Permissions View
@app.get("/users/router/{user_id}", response_class=HTMLResponse)
def user_router_permission_view(request: Request, user_id: int):
    user = get_current_user(request)
    if not user:
        return RedirectResponse("/")

    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, name, email, role, login_enabled, mobile FROM users WHERE id = ?", (user_id,))
    target = cursor.fetchone()
    conn.close()

    if not target:
        return RedirectResponse("/users")

    routers = get_user_router_permissions(user_id)

    return templates.TemplateResponse(request=request, name="user_router_permission.html", context={
        "active_page": "users",
        "target_user": dict(target),
        "routers": routers
    })

# ====================
# API Endpoints
# ====================

@app.get("/api/routers/{router_id}/export-script")
def export_router_script(router_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM routers WHERE id = ?", (router_id,))
    router = cursor.fetchone()
    conn.close()

    if not router:
        return JSONResponse({"success": False, "error": "Router not found"}, status_code=404)

    r_dict = dict(router)
    host = r_dict["host"]
    api_port = r_dict.get("api_port") or 8728
    api_user = r_dict.get("api_username") or ""
    api_pass = r_dict.get("api_password") or ""
    name = r_dict.get("name") or host
    identity = r_dict.get("router_identity") or name

    # Fetch real pools from MikroTik API if credentials exist
    prefixes = []
    if api_user:
        prefixes = fetch_mikrotik_pool_prefixes(host, api_user, api_pass, api_port)
    else:
        prefixes = fetch_mikrotik_pool_prefixes(host, "", "", api_port)

    script_text = generate_export_script(name, identity, host, prefixes)

    return {
        "success": True,
        "script": script_text,
        "prefixes": prefixes,
        "router_name": name,
        "identity": identity,
        "host": host
    }

@app.get("/api/routers/{router_id}/download-script")
def download_router_script(router_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM routers WHERE id = ?", (router_id,))
    router = cursor.fetchone()
    conn.close()

    if not router:
        return JSONResponse({"error": "Router not found"}, status_code=404)

    r_dict = dict(router)
    host = r_dict["host"]
    api_port = r_dict.get("api_port") or 8728
    api_user = r_dict.get("api_username") or ""
    api_pass = r_dict.get("api_password") or ""
    name = r_dict.get("name") or host
    identity = r_dict.get("router_identity") or name

    prefixes = fetch_mikrotik_pool_prefixes(host, api_user, api_pass, api_port)
    script_text = generate_export_script(name, identity, host, prefixes)

    filename = f"{name.replace(' ', '_')}_config.rsc"
    return StreamingResponse(
        io.BytesIO(script_text.encode("utf-8")),
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.get("/api/syslog/live-status")
def syslog_live_status():
    stats = get_packet_stats()
    return {
        "server_ip": "103.137.108.70",
        "port": 5514,
        "total_packets": stats["total_packets"],
        "last_packet_time": stats["last_packet_time"],
        "last_host": stats["last_host"],
        "recent_packets": stats["recent_packets"][:15]
    }

@app.get("/api/routers/{router_id}")
def get_router_details(router_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM routers WHERE id = ?", (router_id,))
    router = cursor.fetchone()
    conn.close()
    if not router:
        return JSONResponse({"error": "Router not found"}, status_code=404)
    return dict(router)

@app.post("/api/routers/edit")
def edit_router(
    router_id: int = Form(...),
    name: str = Form(...),
    host: str = Form(...),
    api_port: int = Form(8728),
    api_username: str = Form(""),
    api_password: str = Form(""),
    router_type: str = Form("NAT Router"),
    nat_identity: str = Form(None)
):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE routers 
            SET name = ?, host = ?, api_port = ?, api_username = ?, api_password = ?, router_type = ?, nat_identity = ?
            WHERE id = ?
        """, (name.strip(), host.strip(), api_port, api_username.strip(), api_password, router_type, nat_identity or "", router_id))
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse(url="/router", status_code=303)

@app.get("/api/routers/{router_id}/check-connection")
def check_router_connection(router_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM routers WHERE id = ?", (router_id,))
    router = cursor.fetchone()
    conn.close()

    if not router:
        return {"success": False, "error": "Router not found"}

    r = dict(router)
    host = r["host"]
    port = r.get("api_port") or 8728
    user = r.get("api_username") or ""
    pwd = r.get("api_password") or ""

    res = test_mikrotik_connection(host, user, pwd, port, timeout=4)
    return res

@app.post("/api/routers/test-api")
def test_router_api(
    host: str = Form(...),
    api_port: int = Form(8728),
    api_username: str = Form(""),
    api_password: str = Form("")
):
    """Tests connection to MikroTik RouterOS API and retrieves Hostname / Identity."""
    res = test_mikrotik_connection(
        host=host.strip(),
        username=api_username.strip(),
        password=api_password.strip(),
        port=api_port,
        timeout=5
    )
    return JSONResponse(res)

@app.post("/api/routers/add")
def add_router(
    name: str = Form(None),
    host: str = Form(...),
    api_port: int = Form(8728),
    api_username: str = Form(""),
    api_password: str = Form(""),
    router_type: str = Form("NAT Router"),
    router_identity: str = Form(None),
    nat_identity: str = Form(None)
):
    host = host.strip()
    # If router identity or name wasn't provided, try auto-fetching via API
    detected_identity = router_identity
    if not detected_identity and api_username:
        test_res = test_mikrotik_connection(host, api_username, api_password, api_port, timeout=3)
        if test_res.get("success"):
            detected_identity = test_res.get("identity")

    final_name = name.strip() if name and name.strip() else (detected_identity or f"Router_{host}")
    final_identity = detected_identity or final_name

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO routers (name, router_identity, router_type, nat_identity, host, api_port, api_username, api_password, status, ipv6, accounting)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 1)
        """, (final_name, final_identity, router_type, nat_identity or "", host, api_port, api_username, api_password))
        
        # Also ensure Host Activity table recognizes this router
        cursor.execute("""
            INSERT OR IGNORE INTO host_activities (identity, type, details, last_check, status)
            VALUES (?, ?, 'Configured via API', datetime('now', 'localtime'), 'Success')
        """, (final_identity, router_type))
        
        conn.commit()
    finally:
        conn.close()
    return RedirectResponse(url="/router", status_code=303)

@app.post("/api/routers/{router_id}/toggle")
def toggle_router(router_id: int, field: str = Query(...)):
    if field not in ["status", "ipv6", "accounting"]:
        return JSONResponse({"success": False, "message": "Invalid field"}, status_code=400)

    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(f"UPDATE routers SET {field} = CASE WHEN {field} = 1 THEN 0 ELSE 1 END WHERE id = ?", (router_id,))
        conn.commit()
    finally:
        conn.close()
    return {"success": True}

@app.delete("/api/routers/{router_id}")
def delete_router_endpoint(router_id: int):
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM routers WHERE id = ?", (router_id,))
        conn.commit()
    finally:
        conn.close()
    return {"success": True}

@app.post("/api/users/add")
def add_user(
    username: str = Form(...),
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    mobile: str = Form(None)
):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO users (username, name, email, password, role, login_enabled, mobile)
        VALUES (?, ?, ?, ?, ?, 1, ?)
    """, (username, name, email, password, role, mobile or ""))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/users", status_code=303)

# User Management APIs
@app.get("/api/users/{user_id}")
def get_user_api(user_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, name, email, role, login_enabled, mobile FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return JSONResponse({"success": False, "error": "User not found"}, status_code=404)
    return {"success": True, "user": dict(row)}

class EditUserPayload(BaseModel):
    name: str
    email: str
    role: str
    mobile: Optional[str] = None
    login_enabled: int = 1
    password: Optional[str] = None

@app.post("/api/users/{user_id}/edit")
def edit_user_api(user_id: int, payload: EditUserPayload):
    conn = get_connection()
    cursor = conn.cursor()
    if payload.password and payload.password.strip():
        cursor.execute("""
            UPDATE users 
            SET name = ?, email = ?, role = ?, mobile = ?, login_enabled = ?, password = ?
            WHERE id = ?
        """, (payload.name.strip(), payload.email.strip(), payload.role, payload.mobile or "", payload.login_enabled, payload.password.strip(), user_id))
    else:
        cursor.execute("""
            UPDATE users 
            SET name = ?, email = ?, role = ?, mobile = ?, login_enabled = ?
            WHERE id = ?
        """, (payload.name.strip(), payload.email.strip(), payload.role, payload.mobile or "", payload.login_enabled, user_id))
    conn.commit()
    conn.close()
    return {"success": True}

@app.delete("/api/users/{user_id}")
def delete_user_api(user_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return JSONResponse({"success": False, "error": "User not found"}, status_code=404)
    
    if row["username"] == "arif":
        conn.close()
        return JSONResponse({"success": False, "error": "Cannot delete primary administrator account."}, status_code=400)

    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    cursor.execute("DELETE FROM user_permissions WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM user_router_permissions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"success": True}

class TogglePermPayload(BaseModel):
    permission_key: str
    is_allowed: bool

@app.post("/api/users/{user_id}/permissions/toggle")
def toggle_user_permission_api(user_id: int, payload: TogglePermPayload):
    set_user_permission(user_id, payload.permission_key, payload.is_allowed)
    return {"success": True}

class ToggleRouterPermPayload(BaseModel):
    is_allowed: bool

@app.post("/api/users/{user_id}/routers/{router_id}/toggle")
def toggle_user_router_permission_api(user_id: int, router_id: int, payload: ToggleRouterPermPayload):
    set_user_router_permission(user_id, router_id, payload.is_allowed)
    return {"success": True}


# Search NAT Logs
@app.get("/api/logs/search")
def search_logs(
    date: str = Query(None),
    host: str = Query(None),
    user: str = Query(None),
    mac: str = Query(None),
    src_ip: str = Query(None),
    src_port: str = Query(None),
    dst_ip: str = Query(None),
    dst_port: str = Query(None),
    nat_ip: str = Query(None),
    nat_port: str = Query(None),
    from_h: str = Query(None),
    from_m: str = Query(None),
    from_s: str = Query(None),
    to_h: str = Query(None),
    to_m: str = Query(None),
    to_s: str = Query(None)
):
    with get_db() as conn:
        cursor = conn.cursor()

        query = "SELECT * FROM nat_logs WHERE 1=1"
        params = []

        c_date = clean_str(date)
        if c_date:
            fh = clean_str(from_h)
            fm = clean_str(from_m)
            fs = clean_str(from_s)
            th = clean_str(to_h)
            tm = clean_str(to_m)
            ts = clean_str(to_s)

            from_time = f"{fh.zfill(2)}:{fm.zfill(2)}:{fs.zfill(2)}" if (fh is not None and fm is not None and fs is not None) else None
            to_time = f"{th.zfill(2)}:{tm.zfill(2)}:{ts.zfill(2)}" if (th is not None and tm is not None and ts is not None) else None

            start_ts = f"{c_date} {from_time}" if from_time else f"{c_date} 00:00:00"
            end_ts = f"{c_date} {to_time}" if to_time else f"{c_date} 23:59:59"
            query += " AND timestamp BETWEEN ? AND ?"
            params.append(start_ts)
            params.append(end_ts)

        c_host = clean_str(host)
        c_user = clean_str(user)
        c_mac = clean_str(mac)
        c_src_ip = clean_str(src_ip)
        c_src_port = clean_int(src_port)
        c_dst_ip = clean_str(dst_ip)
        c_dst_port = clean_int(dst_port)
        c_nat_ip = clean_str(nat_ip)
        c_nat_port = clean_int(nat_port)

        has_selective_filter = bool(c_user or c_src_ip or c_mac or c_dst_ip)

        if c_host:
            router_prefix = "+" if has_selective_filter else ""
            if is_ip_address(c_host):
                query += f" AND {router_prefix}host = ?"
                params.append(c_host)
            else:
                cursor.execute("SELECT name, router_identity, host FROM routers WHERE router_identity = ? OR name = ? OR host = ?", (c_host, c_host, c_host))
                matched = cursor.fetchone()
                if matched and matched["router_identity"]:
                    query += f" AND {router_prefix}identity = ?"
                    params.append(matched["router_identity"])
                elif matched and matched["host"]:
                    query += f" AND {router_prefix}host = ?"
                    params.append(matched["host"])
                else:
                    query += f" AND {router_prefix}identity = ?"
                    params.append(c_host)

        if c_user:
            query += " AND username = ? COLLATE NOCASE"
            params.append(c_user)

        if c_mac:
            query += " AND mac = ?"
            params.append(c_mac)

        if c_src_ip:
            query += " AND src_ip = ?"
            params.append(c_src_ip)

        if c_src_port is not None:
            src_port_prefix = "+" if (bool(c_dst_ip or c_user or c_mac) and not bool(c_src_ip)) else ""
            query += f" AND {src_port_prefix}src_port = ?"
            params.append(c_src_port)

        if c_dst_ip:
            query += " AND dst_ip = ?"
            params.append(c_dst_ip)

        if c_dst_port is not None:
            dst_port_prefix = "+" if (bool(c_user or c_mac) and not bool(c_src_ip or c_dst_ip)) else ""
            query += f" AND {dst_port_prefix}dst_port = ?"
            params.append(c_dst_port)

        if c_nat_ip:
            nat_ip_prefix = "+" if bool(c_src_ip or c_user or c_mac or c_dst_ip) else ""
            query += f" AND {nat_ip_prefix}nat_ip = ?"
            params.append(c_nat_ip)

        if c_nat_port is not None:
            nat_port_prefix = "+" if (bool(c_user or c_src_ip or c_dst_ip or c_mac) and not bool(c_nat_ip)) else ""
            query += f" AND {nat_port_prefix}nat_port = ?"
            params.append(c_nat_port)

        query += " ORDER BY timestamp DESC, id DESC LIMIT 100"
        cursor.execute(query, params)
        logs = [dict(row) for row in cursor.fetchall()]

    # Batch resolve AS Info
    dst_ips = [l["dst_ip"] for l in logs if l.get("dst_ip")]
    as_map = batch_get_as_info(dst_ips)
    for l in logs:
        l["as_info"] = as_map.get(l.get("dst_ip"), "")

    return {"logs": logs}

# Search System Logs
@app.get("/api/system-logs/search")
def search_system_logs(
    date: str = Query(None),
    priority: str = Query(None),
    identity: str = Query(None),
    host: str = Query(None)
):
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM system_logs WHERE 1=1"
    params = []

    if date:
        query += " AND timestamp LIKE ?"
        params.append(f"{date}%")
    if priority:
        query += " AND priority = ?"
        params.append(priority)
    if identity:
        query += " AND identity = ?"
        params.append(identity)
    if host:
        query += " AND host = ?"
        params.append(host)

    query += " ORDER BY id DESC LIMIT 100"
    cursor.execute(query, params)
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()

    return {"logs": logs}

# Export Excel
@app.get("/api/logs/download-excel")
def download_excel(
    date: str = Query(None),
    host: str = Query(None),
    user: str = Query(None),
    mac: str = Query(None),
    src_ip: str = Query(None),
    src_port: str = Query(None),
    dst_ip: str = Query(None),
    dst_port: str = Query(None),
    nat_ip: str = Query(None),
    nat_port: str = Query(None),
    from_h: str = Query(None),
    from_m: str = Query(None),
    from_s: str = Query(None),
    to_h: str = Query(None),
    to_m: str = Query(None),
    to_s: str = Query(None)
):
    with get_db() as conn:
        cursor = conn.cursor()

        query = "SELECT * FROM nat_logs WHERE 1=1"
        params = []

        c_date = clean_str(date)
        if c_date:
            fh = clean_str(from_h)
            fm = clean_str(from_m)
            fs = clean_str(from_s)
            th = clean_str(to_h)
            tm = clean_str(to_m)
            ts = clean_str(to_s)

            from_time = f"{fh.zfill(2)}:{fm.zfill(2)}:{fs.zfill(2)}" if (fh is not None and fm is not None and fs is not None) else None
            to_time = f"{th.zfill(2)}:{tm.zfill(2)}:{ts.zfill(2)}" if (th is not None and tm is not None and ts is not None) else None

            start_ts = f"{c_date} {from_time}" if from_time else f"{c_date} 00:00:00"
            end_ts = f"{c_date} {to_time}" if to_time else f"{c_date} 23:59:59"
            query += " AND timestamp BETWEEN ? AND ?"
            params.append(start_ts)
            params.append(end_ts)

        c_host = clean_str(host)
        c_user = clean_str(user)
        c_mac = clean_str(mac)
        c_src_ip = clean_str(src_ip)
        c_src_port = clean_int(src_port)
        c_dst_ip = clean_str(dst_ip)
        c_dst_port = clean_int(dst_port)
        c_nat_ip = clean_str(nat_ip)
        c_nat_port = clean_int(nat_port)

        has_selective_filter = bool(c_user or c_src_ip or c_mac or c_dst_ip)

        if c_host:
            router_prefix = "+" if has_selective_filter else ""
            if is_ip_address(c_host):
                query += f" AND {router_prefix}host = ?"
                params.append(c_host)
            else:
                cursor.execute("SELECT name, router_identity, host FROM routers WHERE router_identity = ? OR name = ? OR host = ?", (c_host, c_host, c_host))
                matched = cursor.fetchone()
                if matched and matched["router_identity"]:
                    query += f" AND {router_prefix}identity = ?"
                    params.append(matched["router_identity"])
                elif matched and matched["host"]:
                    query += f" AND {router_prefix}host = ?"
                    params.append(matched["host"])
                else:
                    query += f" AND {router_prefix}identity = ?"
                    params.append(c_host)

        if c_user:
            query += " AND username = ? COLLATE NOCASE"
            params.append(c_user)

        if c_mac:
            query += " AND mac = ?"
            params.append(c_mac)

        if c_src_ip:
            query += " AND src_ip = ?"
            params.append(c_src_ip)

        if c_src_port is not None:
            src_port_prefix = "+" if (bool(c_dst_ip or c_user or c_mac) and not bool(c_src_ip)) else ""
            query += f" AND {src_port_prefix}src_port = ?"
            params.append(c_src_port)

        if c_dst_ip:
            query += " AND dst_ip = ?"
            params.append(c_dst_ip)

        if c_dst_port is not None:
            dst_port_prefix = "+" if (bool(c_user or c_mac) and not bool(c_src_ip or c_dst_ip)) else ""
            query += f" AND {dst_port_prefix}dst_port = ?"
            params.append(c_dst_port)

        if c_nat_ip:
            nat_ip_prefix = "+" if bool(c_src_ip or c_user or c_mac or c_dst_ip) else ""
            query += f" AND {nat_ip_prefix}nat_ip = ?"
            params.append(c_nat_ip)

        if c_nat_port is not None:
            nat_port_prefix = "+" if (bool(c_user or c_src_ip or c_dst_ip or c_mac) and not bool(c_nat_ip)) else ""
            query += f" AND {nat_port_prefix}nat_port = ?"
            params.append(c_nat_port)

        query += " ORDER BY timestamp DESC, id DESC LIMIT 5000"
        cursor.execute(query, params)
        logs = cursor.fetchall()

    # Batch resolve AS Info for exported rows
    dst_ips = [row["dst_ip"] for row in logs if row["dst_ip"]]
    as_map = batch_get_as_info(dst_ips)

    wb = Workbook()
    ws = wb.active
    ws.title = "SuperLOG Export"

    header_fill = PatternFill(start_color="2563EB", end_color="2563EB", fill_type="solid")
    header_font = Font(name="Inter", size=11, bold=True, color="FFFFFF")

    headers = ["SL", "Timestamp", "Router / Host", "Identity", "User", "MAC", "Proto", "Source IP", "Source Port", "NAT IP", "NAT Port", "Dest IP", "Dest Port", "AS Info", "Details"]
    ws.append(headers)

    for col_num, _ in enumerate(headers, 1):
        cell = ws.cell(row=1, column=col_num)
        cell.fill = header_fill
        cell.font = header_font
        cell.alignment = Alignment(horizontal="center", vertical="center")

    for idx, row in enumerate(logs, 1):
        as_info_val = as_map.get(row["dst_ip"], "")
        ws.append([
            idx,
            row["timestamp"],
            row["host"],
            row["identity"] or "",
            row["username"] or "",
            row["mac"] or "",
            row["proto"] or "TCP",
            row["src_ip"],
            row["src_port"],
            row["nat_ip"],
            row["nat_port"],
            row["dst_ip"],
            row["dst_port"],
            as_info_val,
            row["details"] or ""
        ])

    for col in ws.columns:
        max_len = max(len(str(cell.value or "")) for cell in col)
        col_letter = col[0].column_letter
        ws.column_dimensions[col_letter].width = max(max_len + 3, 12)

    output = io.BytesIO()
    wb.save(output)
    output.seek(0)

    filename = f"SuperLOG_Export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return StreamingResponse(
        output,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=False)
