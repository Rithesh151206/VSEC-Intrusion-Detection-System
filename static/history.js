// ==========================================
// VSEC SECURITY OPERATIONS
// ATTACK HISTORY
// ==========================================

let allHistoryAlerts = [];


// Convert severity to readable text
function getSeverity(severity) {

    severity = Number(severity);

    if (severity === 1) {
        return {
            label: "HIGH",
            className: "severity-high"
        };
    }

    if (severity === 2) {
        return {
            label: "MEDIUM",
            className: "severity-medium"
        };
    }

    return {
        label: "LOW",
        className: "severity-low"
    };
}


// Fetch historical alerts from Flask
async function loadHistory() {

    try {

        const response = await fetch("/api/history", {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error("Unable to retrieve attack history");
        }

        const data = await response.json();

        allHistoryAlerts = data.alerts || [];

        updateHistoryStatistics();
        filterHistory();

        document.getElementById("historyStatus").textContent =
            "Historical attack records loaded successfully.";

    } catch (error) {

        console.error("History error:", error);

        document.getElementById("historyStatus").textContent =
            "Unable to load attack history.";
    }
}


// Update historical statistics
function updateHistoryStatistics() {

    const total = allHistoryAlerts.length;

    const high = allHistoryAlerts.filter(
        alert => Number(alert.severity) === 1
    ).length;

    const medium = allHistoryAlerts.filter(
        alert => Number(alert.severity) === 2
    ).length;

    const low = allHistoryAlerts.filter(
        alert => Number(alert.severity) >= 3
    ).length;

    document.getElementById("historyTotal").textContent = total;
    document.getElementById("historyHigh").textContent = high;
    document.getElementById("historyMedium").textContent = medium;
    document.getElementById("historyLow").textContent = low;
}


// Search and filter historical alerts
function filterHistory() {

    const search = document.getElementById("historySearch")
        .value.toLowerCase().trim();

    const severityFilter =
        document.getElementById("severityFilter").value;

    const filtered = allHistoryAlerts.filter(alert => {

        const searchableText = [
            alert.timestamp,
            alert.attack,
            alert.source_ip,
            alert.destination_ip,
            alert.protocol,
            alert.destination_port,
            alert.category
        ].join(" ").toLowerCase();

        const matchesSearch = searchableText.includes(search);

        let matchesSeverity = true;

        if (severityFilter === "1") {
            matchesSeverity = Number(alert.severity) === 1;
        } else if (severityFilter === "2") {
            matchesSeverity = Number(alert.severity) === 2;
        } else if (severityFilter === "3") {
            matchesSeverity = Number(alert.severity) >= 3;
        }

        return matchesSearch && matchesSeverity;
    });

    renderHistoryTable(filtered);

    document.getElementById("historyCount").textContent =
        `Showing ${filtered.length} of ${allHistoryAlerts.length} alerts`;
}


// Display historical alerts
function renderHistoryTable(alerts) {

    const table = document.getElementById("historyTable");

    table.innerHTML = "";

    // Show newest alerts first
    const sortedAlerts = [...alerts].reverse();

    sortedAlerts.forEach(alert => {

        const row = document.createElement("tr");

        const values = [
            alert.timestamp || "N/A",
            alert.attack || "Unknown",
            alert.source_ip || "N/A",
            alert.destination_ip || "N/A",
            alert.protocol || "N/A",
            alert.destination_port ?? "N/A"
        ];

        values.forEach(value => {

            const cell = document.createElement("td");

            // textContent prevents HTML injection
            cell.textContent = value;

            row.appendChild(cell);
        });

        const severity = getSeverity(alert.severity);

        const severityCell = document.createElement("td");

        severityCell.textContent = severity.label;
        severityCell.className = severity.className;

        row.appendChild(severityCell);

        table.appendChild(row);
    });

    if (alerts.length === 0) {

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 7;
        cell.textContent = "No matching attack records found.";

        row.appendChild(cell);
        table.appendChild(row);
    }
}


// Search input
document.getElementById("historySearch")
    .addEventListener("input", filterHistory);


// Severity dropdown
document.getElementById("severityFilter")
    .addEventListener("change", filterHistory);


// Load records when page opens
loadHistory();

// Refresh historical records every 10 seconds
setInterval(loadHistory, 10000);

