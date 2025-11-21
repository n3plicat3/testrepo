let metricsChart = null;
let logBarChart = null;
let __logsData = [];
let __insights = null;

function animateCounter(el, from, to, duration = 450) {
    from = Number(from) || 0;
    to = Number(to) || 0;
    const diff = to - from;
    if (diff === 0) {
        el.textContent = to.toLocaleString();
        el.dataset.value = String(to);
        return;
    }

    const start = performance.now();
    function frame(now) {
        const t = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - t, 3); // ease-out cubic
        const value = Math.round(from + diff * eased);
        el.textContent = value.toLocaleString();
        if (t < 1) {
            requestAnimationFrame(frame);
        } else {
            el.dataset.value = String(to);
        }
    }
    requestAnimationFrame(frame);
}

function formatPct(value) {
    return (value * 100).toFixed(1) + "%";
}

function updateMetricCards(data) {
    const totalEl = document.getElementById("totalEvents");
    const errorEl = document.getElementById("errorEvents");
    const logsEl = document.getElementById("logsMonitored");
    const lastUpdatedEl = document.getElementById("lastUpdated");
    const errorRateEl = document.getElementById("errorRate");
    const trendEl = document.getElementById("totalEventsTrend");
    const topLogNameEl = document.getElementById("topLogName");

    const prevTotal = Number(totalEl.dataset.value || "0");
    animateCounter(totalEl, prevTotal, data.total_events);

    const prevErr = Number(errorEl.dataset.value || "0");
    animateCounter(errorEl, prevErr, data.error_events);

    const prevLogs = Number(logsEl.dataset.value || "0");
    animateCounter(logsEl, prevLogs, data.log_count);

    if (lastUpdatedEl && data.generated_at) {
        lastUpdatedEl.textContent = data.generated_at;
    }

    const rate = data.error_rate || 0;
    errorRateEl.textContent = `Error rate: ${formatPct(rate)}`;
    errorRateEl.classList.toggle("danger", rate > 0.05);
    errorRateEl.classList.toggle("neutral", rate <= 0.05);

    // Simple directional trend vs previous snapshot in history
    if (data.history && data.history.length >= 2) {
        const prev = data.history[data.history.length - 2].total_events;
        const curr = data.history[data.history.length - 1].total_events;
        const delta = curr - prev;
        if (delta > 0) {
            trendEl.textContent = `Trend: +${delta.toLocaleString()} vs prev`;
            trendEl.classList.remove("neutral");
        } else if (delta < 0) {
            trendEl.textContent = `Trend: ${delta.toLocaleString()} vs prev`;
            trendEl.classList.remove("neutral");
        } else {
            trendEl.textContent = "Trend: flat vs prev";
            trendEl.classList.add("neutral");
        }
    }

    // Top log by events
    const byLog = data.by_log || {};
    const logsArray = Object.values(byLog);
    if (logsArray.length > 0) {
        logsArray.sort((a, b) => (b.events || 0) - (a.events || 0));
        topLogNameEl.textContent = `Top source: ${logsArray[0].name} (${logsArray[0].events || 0} events)`;
    } else {
        topLogNameEl.textContent = "Top source: —";
    }
}

function buildMetricsChart(ctx, history) {
    const labels = history.map(h => h.timestamp);
    const totalSeries = history.map(h => h.total_events);
    const errorSeries = history.map(h => h.error_events);

    return new Chart(ctx, {
        type: "line",
        data: {
            labels,
            datasets: [
                {
                    label: "Total Events",
                    data: totalSeries,
                    tension: 0.35,
                    borderWidth: 2,
                    pointRadius: 2,
                },
                {
                    label: "Error Events",
                    data: errorSeries,
                    tension: 0.35,
                    borderWidth: 2,
                    pointRadius: 2,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: "index", intersect: false },
            plugins: {
                legend: {
                    display: true,
                    labels: {
                        boxWidth: 12,
                        font: { size: 11 }
                    }
                },
                tooltip: {
                    mode: "index",
                    intersect: false
                }
            },
            scales: {
                x: {
                    ticks: { maxRotation: 0, autoSkip: true, font: { size: 10 } },
                    grid: { display: false }
                },
                y: {
                    beginAtZero: true,
                    ticks: { stepSize: 1, font: { size: 10 } },
                    grid: { color: "rgba(55,65,81,0.4)" }
                }
            },
            animation: {
                duration: 400
            }
        }
    });
}

function buildLogBarChart(ctx, byLog) {
    const logsArray = Object.values(byLog);
    const labels = logsArray.map(l => l.name);
    const values = logsArray.map(l => l.events || 0);

    return new Chart(ctx, {
        type: "bar",
        data: {
            labels,
            datasets: [
                {
                    label: "Events",
                    data: values,
                    borderWidth: 1
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { enabled: true }
            },
            scales: {
                x: {
                    ticks: { font: { size: 10 } },
                    grid: { display: false }
                },
                y: {
                    beginAtZero: true,
                    ticks: { stepSize: 1, font: { size: 10 } },
                    grid: { color: "rgba(55,65,81,0.4)" }
                }
            },
            animation: {
                duration: 350
            }
        }
    });
}

function updateCharts(data) {
    const history = data.history || [];
    const byLog = data.by_log || {};

    const metricsCtx = document.getElementById("eventsOverTime").getContext("2d");
    const barCtx = document.getElementById("eventsByLog").getContext("2d");

    if (!metricsChart) {
        metricsChart = buildMetricsChart(metricsCtx, history);
    } else {
        metricsChart.data.labels = history.map(h => h.timestamp);
        metricsChart.data.datasets[0].data = history.map(h => h.total_events);
        metricsChart.data.datasets[1].data = history.map(h => h.error_events);
        metricsChart.update();
    }

    const logsArray = Object.values(byLog);
    const labels = logsArray.map(l => l.name);
    const values = logsArray.map(l => l.events || 0);

    if (!logBarChart) {
        logBarChart = buildLogBarChart(barCtx, byLog);
    } else {
        logBarChart.data.labels = labels;
        logBarChart.data.datasets[0].data = values;
        logBarChart.update();
    }
}

function levelClass(level) {
    if (!level) return "level-default";
    const lvl = String(level).toLowerCase();
    if (["critical", "crit", "fatal"].includes(lvl)) return "level-critical";
    if (["error", "err"].includes(lvl)) return "level-error";
    if (["warn", "warning"].includes(lvl)) return "level-warning";
    if (["info", "information"].includes(lvl)) return "level-info";
    return "level-default";
}

function applyLogFilters(logs) {
    const src = (document.getElementById("filterSource")?.value || "").trim();
    const lvl = (document.getElementById("filterLevel")?.value || "").trim().toLowerCase();
    const q = (document.getElementById("filterSearch")?.value || "").trim().toLowerCase();

    const filtered = [];
    (logs || []).forEach(log => {
        if (src && (log.id !== src)) return;
        const events = (log.events || []).filter(ev => {
            const evLevel = (ev.level || "").toLowerCase();
            if (lvl && evLevel !== lvl) return false;
            if (q) {
                const hay = `${ev.timestamp || ''} ${ev.process || ''} ${ev.message || ev.raw || ''}`.toLowerCase();
                if (hay.indexOf(q) === -1) return false;
            }
            return true;
        });
        filtered.push({...log, events});
    });
    return filtered;
}

function updateLogsTable(logs) {
    const tbody = document.getElementById("logsTableBody");
    tbody.innerHTML = "";

    const list = applyLogFilters(logs);

    if (!list || list.length === 0 || list.every(l => (l.events || []).length === 0)) {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td colspan="5" class="placeholder-row">No log data available.</td>`;
        tbody.appendChild(tr);
        return;
    }

    list.forEach(log => {
        const logName = log.name || log.id || "Unknown";
        (log.events || []).slice().reverse().forEach(ev => {
            const tr = document.createElement("tr");

            const ts = ev.timestamp || "—";
            const proc = ev.process || "—";
            const msg = ev.message || ev.raw || "";

            const lvl = ev.level || "info";
            const lvlClass = levelClass(lvl);

            tr.innerHTML = `
                <td><span class="log-pill">${logName}</span></td>
                <td>${ts}</td>
                <td><span class="level-badge ${lvlClass}">${lvl.toUpperCase()}</span></td>
                <td>${proc}</td>
                <td>${msg}</td>
            `;
            tbody.appendChild(tr);
        });
    });
}

function fetchMetrics() {
    fetch("/api/metrics")
        .then(r => r.json())
        .then(data => {
            updateMetricCards(data);
            updateCharts(data);
        })
        .catch(err => {
            console.error("Failed to fetch metrics", err);
        });
}

function fetchLogs() {
    fetch("/api/logs")
        .then(r => r.json())
        .then(data => {
            __logsData = data || [];
            // Populate source filter options once
            const srcSel = document.getElementById("filterSource");
            if (srcSel && srcSel.options.length <= 1) {
                (__logsData || []).forEach(l => {
                    const opt = document.createElement("option");
                    opt.value = l.id;
                    opt.textContent = l.name || l.id;
                    srcSel.appendChild(opt);
                });
            }
            updateLogsTable(__logsData);
        })
        .catch(err => {
            console.error("Failed to fetch logs", err);
        });
}

function renderInsights(ins) {
    const riskEl = document.getElementById("insightsRiskList");
    if (riskEl) {
        const items = (ins.risks || []).slice(0, 6).map(r => `
            <div class="insight-item">
                <div>
                    <div class="insight-title">${r.name} <span class="badge badge-risk">Risk ${r.risk}</span></div>
                    <div class="insight-sub">Errors: ${r.error_events} • Error rate: ${(r.error_rate*100).toFixed(1)}%</div>
                </div>
                <div class="insight-sub">Events: ${r.events}</div>
            </div>
        `).join("");
        riskEl.innerHTML = items || '<div class="insight-sub">No risk signals.</div>';
        riskEl.classList.remove('placeholder');
    }

    const patEl = document.getElementById("insightsPatterns");
    if (patEl) {
        const items = (ins.top_error_patterns || []).slice(0, 8).map(p => `
            <div class="insight-item">
                <div>
                    <div class="insight-title">${p.name || p.log_id || 'Unknown'}</div>
                    <div class="insight-sub">${p.signature}</div>
                </div>
                <div class="insight-sub">x${p.count}</div>
            </div>
        `).join("");
        patEl.innerHTML = items || '<div class="insight-sub">No error patterns.</div>';
        patEl.classList.remove('placeholder');
    }

    const procEl = document.getElementById("insightsProcesses");
    if (procEl) {
        const items = (ins.noisy_processes || []).slice(0, 8).map(p => `
            <div class="insight-item">
                <div class="insight-title">${p.process}</div>
                <div class="insight-sub">${p.events} events</div>
            </div>
        `).join("");
        procEl.innerHTML = items || '<div class="insight-sub">No process data.</div>';
        procEl.classList.remove('placeholder');
    }

    const rareEl = document.getElementById("insightsRare");
    if (rareEl) {
        const items = (ins.rare_events || []).slice(0, 8).map(p => `
            <div class="insight-item">
                <div>
                    <div class="insight-title">${p.name || 'Unknown source'}</div>
                    <div class="insight-sub">${p.signature}</div>
                </div>
                <div class="insight-sub">unique</div>
            </div>
        `).join("");
        rareEl.innerHTML = items || '<div class="insight-sub">No rare events now.</div>';
        rareEl.classList.remove('placeholder');
    }
}

function fetchInsights() {
    fetch("/api/insights")
        .then(r => r.json())
        .then(ins => {
            __insights = ins;
            renderInsights(ins);
        })
        .catch(err => console.error("Failed to fetch insights", err));
}

document.addEventListener("DOMContentLoaded", () => {
    const refreshInterval = Number(document.body.dataset.refreshInterval || "4000");

    fetchMetrics();
    fetchLogs();
    fetchInsights();

    setInterval(fetchMetrics, refreshInterval);
    setInterval(fetchLogs, refreshInterval * 2);
    setInterval(fetchInsights, refreshInterval * 2);

    // Load pipeline config
    fetch("/api/config/pipeline")
        .then(r => r.json())
        .then(p => {
            const w = document.getElementById("inpWorkers");
            const m = document.getElementById("inpMps");
            if (w && typeof p.workers !== "undefined") w.value = p.workers;
            if (m && typeof p.mps_limit !== "undefined") m.value = p.mps_limit;
        })
        .catch(() => {});

    // Load archive config
    fetch("/api/config/archive")
        .then(r => r.json())
        .then(a => {
            const en = document.getElementById("archEnabled");
            const rd = document.getElementById("archRetention");
            const dir = document.getElementById("archDir");
            if (en) en.checked = !!a.enabled;
            if (rd && typeof a.retention_days !== "undefined") rd.value = a.retention_days;
            if (dir && typeof a.dir === "string") dir.value = a.dir;
        })
        .catch(() => {});

    // Save handler
    const btn = document.getElementById("btnSavePipeline");
    if (btn) {
        btn.addEventListener("click", () => {
            const w = Number(document.getElementById("inpWorkers").value || 4);
            const m = Number(document.getElementById("inpMps").value || 0);
            const msgEl = document.getElementById("pipelineSaveMsg");
            fetch("/api/config/pipeline", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({workers: w, mps_limit: m})
            })
                .then(r => r.json().then(j => ({ok: r.ok, j})))
                .then(({ok, j}) => {
                    msgEl.textContent = ok ? "Saved" : (j.warning || j.error || "Error");
                    setTimeout(() => { msgEl.textContent = ""; }, 2000);
                })
                .catch(() => {
                    msgEl.textContent = "Error";
                    setTimeout(() => { msgEl.textContent = ""; }, 2000);
                });
        });
    }

    // Save archive settings
    const btnArch = document.getElementById("btnSaveArchive");
    if (btnArch) {
        btnArch.addEventListener("click", () => {
            const en = !!document.getElementById("archEnabled").checked;
            const rd = Number(document.getElementById("archRetention").value || 2);
            const dir = String(document.getElementById("archDir").value || "");
            const msgEl = document.getElementById("archiveSaveMsg");
            fetch("/api/config/archive", {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify({enabled: en, retention_days: rd, dir})
            })
                .then(r => r.json().then(j => ({ok: r.ok, j})))
                .then(({ok, j}) => {
                    msgEl.textContent = ok ? "Saved" : (j.warning || j.error || "Error");
                    setTimeout(() => { msgEl.textContent = ""; }, 2000);
                })
                .catch(() => {
                    msgEl.textContent = "Error";
                    setTimeout(() => { msgEl.textContent = ""; }, 2000);
                });
        });
    }

    // Filters
    const srcSel = document.getElementById("filterSource");
    const lvlSel = document.getElementById("filterLevel");
    const qInp = document.getElementById("filterSearch");
    [srcSel, lvlSel].forEach(el => el && el.addEventListener("change", () => updateLogsTable(__logsData)));
    qInp && qInp.addEventListener("input", () => updateLogsTable(__logsData));
});
