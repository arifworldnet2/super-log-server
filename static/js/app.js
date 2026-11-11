// Xtream Log Server - Front-end JavaScript

document.addEventListener("DOMContentLoaded", function () {
    // 1. Sidebar Toggle
    const toggleBtn = document.querySelector(".toggle-sidebar-btn");
    const sidebar = document.querySelector(".sidebar");
    if (toggleBtn && sidebar) {
        toggleBtn.addEventListener("click", function () {
            sidebar.classList.toggle("collapsed");
        });
    }

    // Dropdown Menus in Sidebar
    const dropdownTriggers = document.querySelectorAll(".has-dropdown > a");
    dropdownTriggers.forEach(function (trigger) {
        trigger.addEventListener("click", function (e) {
            e.preventDefault();
            e.stopPropagation();
            const parent = this.closest(".has-dropdown");
            if (parent) {
                parent.classList.toggle("open");
                const submenu = parent.querySelector(".submenu");
                if (submenu) {
                    submenu.classList.toggle("open");
                }
            }
        });
    });

    // 3. Initialize Dashboard Charts if on Dashboard page
    initDashboardCharts();

    // 4. Start Real-time live polling for CPU, RAM, Uptime
    startDashboardRealtimeUpdates();
});

// Real-time metric updater for Dashboard
function startDashboardRealtimeUpdates() {
    const cpuEl = document.getElementById("statCpuVal");
    const ramEl = document.getElementById("statRamVal");
    const uptimeEl = document.getElementById("statUptimeVal");
    const usersEl = document.getElementById("statActiveUsersVal");
    
    if (!cpuEl && !ramEl) return;

    setInterval(async () => {
        try {
            const res = await fetch("/api/system/realtime-metrics");
            if (res.ok) {
                const data = await res.json();
                if (cpuEl && data.cpu !== undefined) cpuEl.innerText = data.cpu;
                if (ramEl && data.ram !== undefined) ramEl.innerText = data.ram;
                if (uptimeEl && data.uptime) uptimeEl.innerText = data.uptime;
                if (usersEl && data.active_users !== undefined) usersEl.innerText = data.active_users;
            }
        } catch (e) {
            // Ignore polling errors
        }
    }, 2500);
}

// Chart.js initialization for Dashboard
function initDashboardCharts() {
    // Active User vs Log Size Bar Chart
    const barCanvas = document.getElementById("trafficBarChart");
    if (barCanvas && window.Chart) {
        let labels = ["2026-11-05", "2026-11-06", "2026-11-07", "2026-11-08", "2026-11-09", "2026-11-10", "2026-11-11"];
        let users = [1538, 1538, 1538, 1538, 1538, 1538, 1538];
        let logs = [1000, 2500, 4200, 6000, 8500, 10000, 11949];

        try {
            if (barCanvas.getAttribute("data-labels")) labels = JSON.parse(barCanvas.getAttribute("data-labels"));
            if (barCanvas.getAttribute("data-users")) users = JSON.parse(barCanvas.getAttribute("data-users"));
            if (barCanvas.getAttribute("data-logs")) logs = JSON.parse(barCanvas.getAttribute("data-logs"));
        } catch (e) {}

        const maxVal = Math.max(...users, ...logs, 1000) * 1.25;

        new Chart(barCanvas, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [
                    {
                        label: "Active Users (PPPoE)",
                        data: users,
                        backgroundColor: "rgba(37, 99, 235, 0.6)",
                        borderColor: "rgba(37, 99, 235, 1)",
                        borderWidth: 1.5,
                        borderRadius: 4,
                        barPercentage: 0.65,
                    },
                    {
                        label: "Log Count (Syslog)",
                        data: logs,
                        backgroundColor: "rgba(239, 68, 68, 0.45)",
                        borderColor: "rgba(239, 68, 68, 1)",
                        borderWidth: 1.5,
                        borderRadius: 4,
                        barPercentage: 0.65,
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        max: Math.ceil(maxVal),
                        ticks: {
                            callback: function(value) { return value.toLocaleString(); }
                        },
                        grid: { color: "#f1f5f9" }
                    },
                    x: {
                        grid: { display: false }
                    }
                },
                plugins: {
                    legend: {
                        position: "top",
                        labels: { boxWidth: 16, font: { size: 12, family: "'Inter', sans-serif" } }
                    }
                }
            }
        });
    }

    // Pie Chart 1 - Workspace Drive (e.g. Drive F:)
    const pieCanvas1 = document.getElementById("storagePie1");
    if (pieCanvas1 && window.Chart) {
        const used = parseFloat(pieCanvas1.getAttribute("data-used") || "135");
        const free = parseFloat(pieCanvas1.getAttribute("data-free") || "62");
        new Chart(pieCanvas1, {
            type: "doughnut",
            data: {
                labels: ["Used Space", "Free Space"],
                datasets: [{
                    data: [used, free],
                    backgroundColor: ["#3b82f6", "#e2e8f0"],
                    borderColor: ["#2563eb", "#cbd5e1"],
                    borderWidth: 1.5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } },
                    tooltip: {
                        callbacks: {
                            label: function(ctx) { return `${ctx.label}: ${ctx.raw} GB`; }
                        }
                    }
                }
            }
        });
    }

    // Pie Chart 2 - System Drive (Drive C:)
    const pieCanvas2 = document.getElementById("storagePie2");
    if (pieCanvas2 && window.Chart) {
        const used = parseFloat(pieCanvas2.getAttribute("data-used") || "102");
        const free = parseFloat(pieCanvas2.getAttribute("data-free") || "16");
        new Chart(pieCanvas2, {
            type: "doughnut",
            data: {
                labels: ["Used Space", "Free Space"],
                datasets: [{
                    data: [used, free],
                    backgroundColor: ["#10b981", "#e2e8f0"],
                    borderColor: ["#059669", "#cbd5e1"],
                    borderWidth: 1.5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } },
                    tooltip: {
                        callbacks: {
                            label: function(ctx) { return `${ctx.label}: ${ctx.raw} GB`; }
                        }
                    }
                }
            }
        });
    }
}

// Router Toggle Function
async function toggleRouterSetting(routerId, field) {
    try {
        const response = await fetch(`/api/routers/${routerId}/toggle?field=${field}`, {
            method: "POST"
        });
        const data = await response.json();
        if (data.success) {
            window.location.reload();
        } else {
            alert("Error: " + (data.message || "Could not toggle setting"));
        }
    } catch (e) {
        alert("Request failed: " + e.message);
    }
}

// Delete Router
async function deleteRouter(routerId) {
    if (confirm("Are you sure you want to delete this router?")) {
        const res = await fetch(`/api/routers/${routerId}`, { method: "DELETE" });
        if (res.ok) {
            window.location.reload();
        }
    }
}

function escapeHtml(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Search NAT Log
async function performSearchLog(e) {
    if (e) {
        e.preventDefault();
        e.stopPropagation();
    }
    const form = document.getElementById("searchLogForm");
    if (!form) return false;

    const formData = new FormData(form);
    const userVal = form.elements["user"] ? form.elements["user"].value.trim() : "";
    const params = new URLSearchParams(formData).toString();

    const tbody = document.getElementById("logResultsBody");
    const countEl = document.getElementById("resultsCount");
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 25px;"><i class="fas fa-spinner fa-spin"></i> Searching logs & resolving AS Info...</td></tr>`;

    try {
        const response = await fetch(`/api/logs/search?${params}`);
        const data = await response.json();

        if (!data.logs || data.logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 25px; color: #888;"><i class="fas fa-info-circle"></i> No matching logs found. Try adjusting your date, router, or username filters.</td></tr>`;
            if (countEl) {
                countEl.innerHTML = userVal 
                    ? `for User: <span style="color: #2563eb; font-weight: 600;">${escapeHtml(userVal)}</span> (0 found)` 
                    : `(0 found)`;
            }
            return false;
        }

        if (countEl) {
            countEl.innerHTML = userVal 
                ? `for User: <span style="color: #2563eb; font-weight: 600;">${escapeHtml(userVal)}</span> (${data.logs.length} found)` 
                : `(${data.logs.length} found)`;
        }

        let html = "";
        data.logs.forEach(log => {
            const dstPort = log.dst_port ? `:${log.dst_port}` : '';
            const asInfoAttr = log.as_info ? ` title="${escapeHtml(log.as_info)}"` : '';
            const infoIcon = log.as_info ? ` <i class="fas fa-info-circle" style="color: #2563eb; font-size: 11px; margin-left: 4px;" title="${escapeHtml(log.as_info)}"></i>` : '';

            html += `
                <tr>
                    <td style="white-space: nowrap;">${escapeHtml(log.timestamp)}</td>
                    <td><b>${escapeHtml(log.identity || log.host)}</b></td>
                    <td><span class="badge ${log.proto === 'TCP' ? 'badge-info' : 'badge-warning'}">${escapeHtml(log.proto)}</span></td>
                    <td style="white-space: nowrap;">${escapeHtml(log.src_ip)}:${log.src_port || ''}</td>
                    <td style="white-space: nowrap;">${escapeHtml(log.nat_ip)}:${log.nat_port || ''}</td>
                    <td style="white-space: nowrap;">
                        <span class="dst-ip-tooltip"${asInfoAttr}>
                            ${escapeHtml(log.dst_ip)}${dstPort}${infoIcon}
                        </span>
                    </td>
                    <td><small><b>${escapeHtml(log.username || '-')}</b></small></td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color: red; padding: 20px;">Error searching logs: ${err.message}</td></tr>`;
    }
    return false;
}

function resetSearchForm() {
    const form = document.getElementById("searchLogForm");
    if (form) {
        form.reset();
        window.location.href = "/search-log";
    }
}

// System Log Search
async function performSystemLogSearch(e) {
    if (e) e.preventDefault();
    const form = document.getElementById("systemLogForm");
    const formData = new FormData(form);
    const params = new URLSearchParams(formData).toString();

    const tbody = document.getElementById("systemLogResultsBody");
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 20px;">Searching system logs...</td></tr>`;

    try {
        const response = await fetch(`/api/system-logs/search?${params}`);
        const data = await response.json();

        if (data.logs.length === 0) {
            tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding: 20px; color: #888;">No system logs found.</td></tr>`;
            return;
        }

        let html = "";
        data.logs.forEach(log => {
            let badgeClass = "badge-info";
            if (log.priority === 'warning') badgeClass = "badge-warning";
            if (log.priority === 'error' || log.priority === 'critical') badgeClass = "badge-danger";

            html += `
                <tr>
                    <td>${log.timestamp}</td>
                    <td><span class="badge ${badgeClass}">${log.priority.toUpperCase()}</span></td>
                    <td><b>${log.identity}</b></td>
                    <td>${log.host}</td>
                    <td>${log.message}</td>
                </tr>
            `;
        });
        tbody.innerHTML = html;
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color: red;">Error: ${err.message}</td></tr>`;
    }
}

// Modal handling
function openModal(id) {
    const m = document.getElementById(id);
    if (m) m.classList.add("show");
}

function closeModal(id) {
    const m = document.getElementById(id);
    if (m) m.classList.remove("show");
}
