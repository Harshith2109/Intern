let severityChart = null;
let trendChart = null;

document.addEventListener("DOMContentLoaded", () => {
    initDropzone();
    initGithubForm();
    loadAnalytics();
    loadScanHistory();
});

// Drag and drop setup
function initDropzone() {
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("fileInput");

    dropzone.addEventListener("click", () => fileInput.click());

    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        dropzone.classList.add("dragover");
    });

    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));

    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (e.dataTransfer.files.length > 0) {
            uploadFile(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener("change", (e) => {
        if (e.target.files.length > 0) {
            uploadFile(e.target.files[0]);
        }
    });
}

function uploadFile(file) {
    showLoading(true, "Scanning dependency manifest file...");
    const formData = new FormData();
    formData.append("file", file);

    fetch("/api/scan/file", {
        method: "POST",
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        showLoading(false);
        if (data.detail) {
            alert("Error: " + data.detail);
        } else {
            renderScanResult(data);
            loadAnalytics();
            loadScanHistory();
        }
    })
    .catch(err => {
        showLoading(false);
        alert("Scan failed: " + err);
    });
}

function initGithubForm() {
    const btn = document.getElementById("btnGithubScan");
    btn.addEventListener("click", () => {
        const url = document.getElementById("githubUrl").value.trim();
        const branch = document.getElementById("githubBranch").value.trim() || "main";
        if (!url) {
            alert("Please enter a valid GitHub repository URL.");
            return;
        }

        showLoading(true, "Fetching & scanning remote GitHub repository...");

        fetch("/api/scan/github", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url, branch })
        })
        .then(res => res.json())
        .then(data => {
            showLoading(false);
            if (data.detail) {
                alert("Error: " + data.detail);
            } else {
                renderScanResult(data);
                loadAnalytics();
                loadScanHistory();
            }
        })
        .catch(err => {
            showLoading(false);
            alert("GitHub scan failed: " + err);
        });
    });
}

function showLoading(show, message = "Processing...") {
    const overlay = document.getElementById("loadingOverlay");
    const statusText = document.getElementById("loadingText");
    if (show) {
        statusText.innerText = message;
        overlay.style.display = "flex";
    } else {
        overlay.style.display = "none";
    }
}

function renderScanResult(data) {
    document.getElementById("targetName").innerText = data.target_path;
    document.getElementById("riskScoreValue").innerText = `${data.overall_risk_score} / 100`;

    const scoreElem = document.getElementById("riskScoreValue");
    if (data.overall_risk_score >= 80) scoreElem.style.color = "#f43f5e";
    else if (data.overall_risk_score >= 50) scoreElem.style.color = "#fb923c";
    else scoreElem.style.color = "#4ade80";

    const gateBadge = document.getElementById("qualityGateBadge");
    if (data.quality_gate_passed) {
        gateBadge.innerText = "PASSED";
        gateBadge.className = "badge badge-passed";
    } else {
        gateBadge.innerText = "FAILED (QUALITY GATE BREACHED)";
        gateBadge.className = "badge badge-failed";
    }

    document.getElementById("totalDepsCount").innerText = data.total_dependencies;
    document.getElementById("vulnDepsCount").innerText = data.vulnerable_dependencies_count;

    // Export links
    if (data.scan_id) {
        document.getElementById("btnExportHtml").href = `/api/scans/${data.scan_id}/export/html`;
        document.getElementById("btnExportJson").href = `/api/scans/${data.scan_id}/export/json`;
        document.getElementById("btnExportSarif").href = `/api/scans/${data.scan_id}/export/sarif`;
        document.getElementById("btnExportCycloneDx").href = `/api/scans/${data.scan_id}/export/cyclonedx`;
        document.getElementById("exportGroup").style.display = "flex";
    }


    // Render Vulnerability Table
    const tbody = document.getElementById("vulnTableBody");
    tbody.innerHTML = "";

    let hasVulns = false;
    data.dependencies.forEach(dep_analysis => {
        const dep = dep_analysis.dependency;
        dep_analysis.vulnerabilities.forEach(vuln => {
            hasVulns = true;
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><strong>${dep.name}</strong></td>
                <td>${dep.version}</td>
                <td>${dep.ecosystem}</td>
                <td><code>${vuln.vuln_id}</code></td>
                <td><span class="badge badge-${vuln.severity}">${vuln.severity}</span></td>
                <td>${vuln.cvss_score ? vuln.cvss_score.toFixed(1) : "N/A"}</td>
                <td>${vuln.fixed_version ? `<span style="color:#4ade80">${vuln.fixed_version}</span>` : "N/A"}</td>
                <td style="color:#94a3b8; font-size:0.85rem">${vuln.summary}</td>
            `;
            tbody.appendChild(tr);
        });
    });

    if (!hasVulns) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#4ade80; padding:2rem">✨ No security vulnerabilities detected in dependencies!</td></tr>`;
    }

    // Render Severity Donut Chart
    updateSeverityChart(data.severity_counts);
}

function updateSeverityChart(counts) {
    const ctx = document.getElementById("severityChart").getContext("2d");
    if (severityChart) severityChart.destroy();

    severityChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [
                    counts.CRITICAL || 0,
                    counts.HIGH || 0,
                    counts.MEDIUM || 0,
                    counts.LOW || 0
                ],
                backgroundColor: ['#f43f5e', '#fb923c', '#facc15', '#4ade80'],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8' } }
            }
        }
    });
}

function loadAnalytics() {
    fetch("/api/analytics")
        .then(res => res.json())
        .then(data => {
            const trendData = data.trend || [];
            const labels = trendData.map((t, idx) => `Scan #${t.id}`);
            const scores = trendData.map(t => t.overall_risk_score);

            const ctx = document.getElementById("trendChart").getContext("2d");
            if (trendChart) trendChart.destroy();

            trendChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Composite Risk Score (0-100)',
                        data: scores,
                        borderColor: '#38bdf8',
                        backgroundColor: 'rgba(56, 189, 248, 0.1)',
                        fill: true,
                        tension: 0.3
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: { min: 0, max: 100, grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8' } },
                        x: { grid: { color: 'rgba(255, 255, 255, 0.05)' }, ticks: { color: '#94a3b8' } }
                    },
                    plugins: {
                        legend: { labels: { color: '#94a3b8' } }
                    }
                }
            });
        });
}

function loadScanHistory() {
    fetch("/api/scans")
        .then(res => res.json())
        .then(scans => {
            const historyBody = document.getElementById("historyTableBody");
            if (!historyBody) return;
            historyBody.innerHTML = "";

            scans.forEach(s => {
                const tr = document.createElement("tr");
                tr.style.cursor = "pointer";
                tr.onclick = () => loadScanById(s.id);
                tr.innerHTML = `
                    <td>#${s.id}</td>
                    <td><strong>${s.target_name}</strong></td>
                    <td>${s.overall_risk_score}</td>
                    <td><span class="badge badge-${s.risk_level}">${s.risk_level}</span></td>
                    <td>${s.quality_gate_passed ? '<span class="badge badge-passed">PASSED</span>' : '<span class="badge badge-failed">FAILED</span>'}</td>
                    <td style="color:#94a3b8; font-size:0.8rem">${new Date(s.scan_timestamp).toLocaleString()}</td>
                `;
                historyBody.appendChild(tr);
            });
        });
}

function loadScanById(id) {
    showLoading(true, "Loading scan record...");
    fetch(`/api/scans/${id}`)
        .then(res => res.json())
        .then(data => {
            showLoading(false);
            renderScanResult(data.report);
        });
}
