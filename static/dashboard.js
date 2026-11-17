// ==========================================
// SURICATA IDS - REAL-TIME SOC DASHBOARD
// ==========================================

let timelineChart = null;
let distributionChart = null;

// Convert Suricata severity to readable labels
function getSeverity(severity) {
    if (severity === 1) {
        return { label: "HIGH", className: "severity-high" };
    }

    if (severity === 2) {
        return { label: "MEDIUM", className: "severity-medium" };
    }

    return { label: "LOW", className: "severity-low" };
}

// Read real alerts from Flask
async function updateDashboard() {
    try {
        const response = await fetch("/api/alerts", {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error("Failed to fetch alerts");
        }

        const data = await response.json();
        const alerts = data.alerts || [];

        updateStatistics(alerts);
        updateAlertTable(alerts);
        updateCharts(alerts);

    } catch (error) {
        console.error("Dashboard update error:", error);
    }
}

// Update statistics cards
function updateStatistics(alerts) {
    const total = alerts.length;

    const high = alerts.filter(
        alert => Number(alert.severity) === 1
    ).length;

    const uniqueIPs = new Set(
        alerts.map(alert => alert.source_ip).filter(Boolean)
    );

    const attackTypes = new Set(
        alerts.map(alert => alert.attack).filter(Boolean)
    );

    document.getElementById("totalAlerts").textContent = total;
    document.getElementById("highAlerts").textContent = high;
    document.getElementById("sourceIPs").textContent = uniqueIPs.size;
    document.getElementById("attackTypes").textContent = attackTypes.size;
}

// Display latest alerts
function updateAlertTable(alerts) {
    const table = document.getElementById("alertTable");

    table.innerHTML = "";

    const recentAlerts = alerts.slice(-30).reverse();

    recentAlerts.forEach(alert => {
        const row = document.createElement("tr");

        const severity = getSeverity(Number(alert.severity));

        const values = [
            alert.timestamp || "N/A",
            alert.attack || "Unknown",
            alert.source_ip || "N/A",
            alert.destination_ip || "N/A"
        ];

        values.forEach(value => {
            const cell = document.createElement("td");
            cell.textContent = value;
            row.appendChild(cell);
        });

        const severityCell = document.createElement("td");
        severityCell.textContent = severity.label;
        severityCell.className = severity.className;

        row.appendChild(severityCell);
        table.appendChild(row);
    });
}

// Generate chart data
function updateCharts(alerts) {

    if (typeof Chart === "undefined") {
        console.warn("Chart.js is not loaded");
        return;
    }

    // Group alerts by minute
    const timelineData = {};

    alerts.forEach(alert => {
        if (!alert.timestamp) return;

        const minute = alert.timestamp.substring(0, 16);

        timelineData[minute] =
            (timelineData[minute] || 0) + 1;
    });

    const timelineLabels =
        Object.keys(timelineData).sort().slice(-15);

    const timelineValues =
        timelineLabels.map(key => timelineData[key]);

    // Group alerts by signature
    const attackData = {};

    alerts.forEach(alert => {
        const attack = alert.attack || "Unknown";

        attackData[attack] =
            (attackData[attack] || 0) + 1;
    });

    const topAttacks = Object.entries(attackData)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 6);

    const attackLabels = topAttacks.map(item => item[0]);
    const attackValues = topAttacks.map(item => item[1]);

    // Create or update timeline chart
    if (!timelineChart) {
        const ctx = document.getElementById("attackTimeline");

        timelineChart = new Chart(ctx, {
            type: "line",
            data: {
                labels: timelineLabels,
                datasets: [{
                    label: "Detected Alerts",
                    data: timelineValues,
                    borderColor: "#00d4ff",
                    backgroundColor: "rgba(0,212,255,0.15)",
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: "#e2e8f0" }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: "#94a3b8" }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: "#94a3b8",
                            precision: 0
                        }
                    }
                }
            }
        });
    } else {
        timelineChart.data.labels = timelineLabels;
        timelineChart.data.datasets[0].data = timelineValues;
        timelineChart.update();
    }

    // Create or update distribution chart
    if (!distributionChart) {
        const ctx = document.getElementById("attackDistribution");

        distributionChart = new Chart(ctx, {
            type: "doughnut",
            data: {
                labels: attackLabels,
                datasets: [{
                    data: attackValues,
                    backgroundColor: [
                        "#00d4ff",
                        "#ff4d4d",
                        "#ffb020",
                        "#00d084",
                        "#8b5cf6",
                        "#f472b6"
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            color: "#e2e8f0"
                        }
                    }
                }
            }
        });
    } else {
        distributionChart.data.labels = attackLabels;
        distributionChart.data.datasets[0].data = attackValues;
        distributionChart.update();
    }
}

// Initial dashboard load
updateDashboard();

// Refresh every 3 seconds
setInterval(updateDashboard, 3000);
