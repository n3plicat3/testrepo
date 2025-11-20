let metricsChart = null;
let logBarChart = null;

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

function updateLogsTable(logs) {
    const tbody = document.getElementById("logsTableBody");
    tbody.innerHTML = "";

    if (!logs || logs.length === 0) {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td colspan="5" class="placeholder-row">No log data available.</td>`;
        tbody.appendChild(tr);
        return;
    }

    logs.forEach(log => {
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
            updateLogsTable(data);
        })
        .catch(err => {
            console.error("Failed to fetch logs", err);
        });
}

document.addEventListener("DOMContentLoaded", () => {
    const refreshInterval = Number(document.body.dataset.refreshInterval || "4000");

    fetchMetrics();
    fetchLogs();

    setInterval(fetchMetrics, refreshInterval);
    setInterval(fetchLogs, refreshInterval * 2);
});
