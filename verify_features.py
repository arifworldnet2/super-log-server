import requests
import sys
import os

sys.path.insert(0, r"F:\Antigravity\xtream_log_server")
import database

BASE_URL = "http://127.0.0.1:8000"
s = requests.Session()

# 1. Login
login_res = s.post(f"{BASE_URL}/login", data={"username": "arif", "password": "admin123"}, allow_redirects=True)
print(f"[Auth] Login status: {login_res.status_code}")
assert login_res.status_code == 200, "Login failed!"

# 2. Test Route Aliases
routes = [
    "/dashboard",
    "/search",
    "/search-log",
    "/download",
    "/download-log",
    "/system",
    "/system-log",
    "/traffic/online",
    "/traffic/online-users",
    "/users/list",
    "/users",
    "/router/filter/0",
    "/router/filter/1",
    "/router/filter/2"
]

for r in routes:
    res = s.get(f"{BASE_URL}{r}", timeout=30)
    assert res.status_code == 200, f"Route {r} returned {res.status_code}"
    print(f"[Route] {r} -> OK (200)")

# 3. Test Realtime Metrics
res = s.get(f"{BASE_URL}/api/system/realtime-metrics", timeout=30)
assert res.status_code == 200
metrics = res.json()
print(f"[Metrics] RAM: {metrics.get('free_ram_gb')} GB free, Active Users: {metrics.get('active_users')}")
assert "free_ram_gb" in metrics

# 4. Test Single User API
res = s.get(f"{BASE_URL}/api/users/1", timeout=30)
assert res.status_code == 200
u_data = res.json()
print(f"[User API] User 1: {u_data['user']['username']} ({u_data['user']['role']})")

# 5. Clean up any previous test_operator and add fresh
conn = database.get_connection()
conn.execute("DELETE FROM users WHERE username = 'test_operator'")
conn.commit()
conn.close()

add_res = s.post(f"{BASE_URL}/api/users/add", data={
    "username": "test_operator",
    "name": "Test Operator",
    "email": "test@example.com",
    "password": "password123",
    "role": "Operator",
    "mobile": "01700000000"
}, allow_redirects=True, timeout=30)
print(f"[User Add] Status: {add_res.status_code}")
assert add_res.status_code == 200

# Get test_operator ID via DB
conn = database.get_connection()
row = conn.execute("SELECT id FROM users WHERE username = 'test_operator'").fetchone()
conn.close()
assert row is not None, "Failed to find test_operator in database"
test_user_id = row["id"]
print(f"[User] Created test_operator with ID: {test_user_id}")

# 6. Test User Permission Page & Toggle
perm_page = s.get(f"{BASE_URL}/users/permission/{test_user_id}", timeout=30)
assert perm_page.status_code == 200
print(f"[User Perm Page] /users/permission/{test_user_id} -> OK (200)")

toggle_res = s.post(f"{BASE_URL}/api/users/{test_user_id}/permissions/toggle", json={
    "permission_key": "router_delete",
    "is_allowed": False
}, timeout=30)
assert toggle_res.status_code == 200
print(f"[User Perm Toggle] router_delete=False -> {toggle_res.json()}")

perms = database.get_user_permissions(test_user_id)
assert perms.get("router_delete") is False, "Permission router_delete was not updated in DB"
print("[User Perm Verified in DB] router_delete is False!")

# 7. Test User Router Permission Page & Toggle
router_perm_page = s.get(f"{BASE_URL}/users/router/{test_user_id}", timeout=30)
assert router_perm_page.status_code == 200
print(f"[User Router Perm Page] /users/router/{test_user_id} -> OK (200)")

toggle_r_res = s.post(f"{BASE_URL}/api/users/{test_user_id}/routers/2/toggle", json={
    "is_allowed": False
}, timeout=30)
assert toggle_r_res.status_code == 200
print(f"[User Router Toggle] router_2=False -> {toggle_r_res.json()}")

# 8. Test Edit User
edit_res = s.post(f"{BASE_URL}/api/users/{test_user_id}/edit", json={
    "name": "Updated Test Operator",
    "email": "updated@example.com",
    "role": "Manager",
    "mobile": "01999999999",
    "login_enabled": 1
}, timeout=30)
assert edit_res.status_code == 200
print(f"[User Edit API] -> {edit_res.json()}")

# 9. Test Delete User
del_res = s.delete(f"{BASE_URL}/api/users/{test_user_id}", timeout=30)
assert del_res.status_code == 200
print(f"[User Delete API] -> {del_res.json()}")

conn = database.get_connection()
row_del = conn.execute("SELECT id FROM users WHERE username = 'test_operator'").fetchone()
conn.close()
assert row_del is None, "User test_operator should have been deleted!"
print("[User Delete Verified in DB] User was deleted successfully!")

print("\n>>> ALL AUTOMATED VERIFICATION TESTS PASSED SUCCESSFULLY! <<<")
