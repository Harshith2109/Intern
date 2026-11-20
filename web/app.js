let severityChart = null;
let trendChart = null;
let astNetwork = null;
let dagNetwork = null;
let currentScanData = null;
let currentTheme = localStorage.getItem("devsecops_theme") || "dark";
let currentDagLayout = "tree"; // Default to Hierarchical Tree: 100% collision-free
let lastScanReport = null;
let lastASTGraphData = null;
let lastDAGGraphData = null;

document.addEventListener("DOMContentLoaded", () => {
    applyTheme(currentTheme);
    initDropzone();
    initGithubForm();
    initWorkbenchTabs();
    initClickableCards();
    initSimulator();
    loadAnalytics();
    loadScanHistory();
});

// Theme Management (Light / Dark Mode)
function applyTheme(theme) {
    currentTheme = theme;
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("devsecops_theme", theme);

    const btn = document.getElementById("themeToggleBtn");
    const icon = document.getElementById("themeIcon");
    const label = document.getElementById("themeLabel");
    if (btn && icon && label) {
        if (theme === "light") {
            icon.innerHTML = `<svg class="ui-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg>`;
            label.innerText = "Dark Mode";
            btn.title = "Switch to Dark Mode";
        } else {
            icon.innerHTML = `<svg class="ui-icon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>`;
            label.innerText = "Light Mode";
            btn.title = "Switch to Light Mode";
        }
    }

    updateChartsTheme(theme);

    if (lastASTGraphData) renderASTGraph(lastASTGraphData);
    if (lastDAGGraphData) renderSupplyChainDAG(lastDAGGraphData);
}

function toggleTheme() {
    const nextTheme = currentTheme === "dark" ? "light" : "dark";
    applyTheme(nextTheme);
}

function updateChartsTheme(theme) {
    const isLight = theme === "light";
    const textColor = isLight ? "#475569" : "#94a3b8";
    const gridColor = isLight ? "rgba(0, 0, 0, 0.06)" : "rgba(255, 255, 255, 0.05)";

    if (trendChart && trendChart.options) {
        if (trendChart.options.scales && trendChart.options.scales.x) {
            trendChart.options.scales.x.ticks.color = textColor;
            trendChart.options.scales.x.grid.color = gridColor;
            trendChart.options.scales.y.ticks.color = textColor;
            trendChart.options.scales.y.grid.color = gridColor;
        }
        if (trendChart.options.plugins && trendChart.options.plugins.legend) {
            trendChart.options.plugins.legend.labels.color = textColor;
        }
        trendChart.update();
    }

    if (severityChart && severityChart.options) {
        if (severityChart.options.plugins && severityChart.options.plugins.legend) {
            severityChart.options.plugins.legend.labels.color = textColor;
        }
        severityChart.update();
    }
}

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
    currentScanData = data;
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

    // Academic Research Metrics
    if (data.research_metrics) {
        document.getElementById("resFalsePositives").innerText = data.research_metrics.false_positives_eliminated || 0;
        document.getElementById("resBlastRadius").innerText = (data.research_metrics.average_blast_radius || 0.0).toFixed(1);
        document.getElementById("resZeroDays").innerText = data.research_metrics.predicted_zero_day_threats || 0;
        document.getElementById("resBreakingChanges").innerText = data.research_metrics.breaking_changes_prevented || 0;
    }

    // Render Research Metrics & Visualizers
    lastScanReport = data;
    const scoreData = data.score_breakdown || data.research_metrics?.score_breakdown;
    if (scoreData) {
        renderScoreMath(scoreData);
    }
    if (data.research_metrics?.reachability_graph) {
        lastASTGraphData = data.research_metrics.reachability_graph;
        renderASTGraph(data.research_metrics.reachability_graph);
    }
    if (data.research_metrics?.supply_chain_dag) {
        lastDAGGraphData = data.research_metrics.supply_chain_dag;
        renderSupplyChainDAG(data.research_metrics.supply_chain_dag);
    }
    if (data.research_metrics?.ml_feature_breakdown) {
        renderMLFeatureTable(data.research_metrics.ml_feature_breakdown);
    }
    if (data.research_metrics?.breaking_change_details) {
        renderBreakingChangeTable(data.research_metrics.breaking_change_details);
    }


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
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#4ade80; padding:2rem">All dependencies are clean. No security vulnerabilities detected.</td></tr>`;
    }

    // Render Severity Donut Chart
    updateSeverityChart(data.severity_counts);
}

function updateSeverityChart(counts) {
    const ctx = document.getElementById("severityChart").getContext("2d");
    if (severityChart) severityChart.destroy();

    const totalVulns = (counts.CRITICAL || 0) + (counts.HIGH || 0) + (counts.MEDIUM || 0) + (counts.LOW || 0);
    const isLight = currentTheme === 'light';

    const centerTextPlugin = {
        id: 'centerText',
        beforeDraw: function(chart) {
            const width = chart.width;
            const height = chart.height;
            const ctx = chart.ctx;
            ctx.restore();
            ctx.font = '700 1.6rem Inter, sans-serif';
            ctx.textBaseline = 'middle';
            ctx.textAlign = 'center';
            ctx.fillStyle = totalVulns > 0 ? '#f43f5e' : '#4ade80';
            ctx.fillText(totalVulns, width / 2, height / 2 - 10);

            ctx.font = '600 0.72rem Inter, sans-serif';
            ctx.fillStyle = currentTheme === 'light' ? '#475569' : '#94a3b8';
            ctx.fillText(totalVulns === 1 ? 'VULNERABILITY' : 'TOTAL VULNS', width / 2, height / 2 + 15);
            ctx.save();
        }
    };

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
                borderColor: isLight ? '#ffffff' : '#0f172a',
                borderWidth: 3,
                hoverOffset: 6,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            cutout: '74%',
            plugins: {
                legend: { position: 'bottom', labels: { color: isLight ? '#475569' : '#94a3b8', font: { family: 'Inter', size: 12 }, padding: 15 } }
            }
        },
        plugins: [centerTextPlugin]
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

            const gradient = ctx.createLinearGradient(0, 0, 0, 200);
            gradient.addColorStop(0, 'rgba(56, 189, 248, 0.35)');
            gradient.addColorStop(1, 'rgba(99, 102, 241, 0.0)');

            const isLight = currentTheme === 'light';
            const textColor = isLight ? '#475569' : '#94a3b8';
            const gridColor = isLight ? 'rgba(0, 0, 0, 0.06)' : 'rgba(255, 255, 255, 0.05)';

            trendChart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: labels,
                    datasets: [{
                        label: 'Composite Risk Score (0-100)',
                        data: scores,
                        borderColor: '#38bdf8',
                        borderWidth: 2.5,
                        backgroundColor: gradient,
                        fill: true,
                        tension: 0.35,
                        pointBackgroundColor: '#38bdf8',
                        pointBorderColor: '#ffffff',
                        pointBorderWidth: 1.5,
                        pointRadius: 5,
                        pointHoverRadius: 8
                    }]
                },
                options: {
                    responsive: true,
                    scales: {
                        y: { min: 0, max: 100, grid: { color: gridColor }, ticks: { color: textColor } },
                        x: { grid: { color: gridColor }, ticks: { color: textColor } }
                    },
                    plugins: {
                        legend: { labels: { color: textColor } }
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

// ---------------------------------------------------------------------
// Interactive Research Workbench & Visualizer Engines
// ---------------------------------------------------------------------

function initWorkbenchTabs() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetTabId = btn.getAttribute("data-tab");
            switchTab(targetTabId);
        });
    });
}

function switchTab(tabId) {
    document.querySelectorAll(".tab-btn").forEach(b => {
        if (b.getAttribute("data-tab") === tabId) {
            b.classList.add("active");
        } else {
            b.classList.remove("active");
        }
    });

    document.querySelectorAll(".tab-content").forEach(c => {
        if (c.id === tabId) {
            c.classList.add("active");
        } else {
            c.classList.remove("active");
        }
    });

    // Auto-fit network canvases when revealed
    if (tabId === "tabAST" && astNetwork) {
        setTimeout(() => astNetwork.fit({ animation: { duration: 500 } }), 100);
    }
    if (tabId === "tabDAG" && dagNetwork) {
        setTimeout(() => dagNetwork.fit({ animation: { duration: 500 } }), 100);
    }
}

function initClickableCards() {
    const cardMap = {
        "cardScore": "tabMath",
        "cardReachability": "tabAST",
        "cardBlastRadius": "tabDAG",
        "cardZeroDay": "tabML",
        "cardBreakingChange": "tabDiff"
    };

    Object.keys(cardMap).forEach(cardId => {
        const cardElem = document.getElementById(cardId);
        if (cardElem) {
            cardElem.addEventListener("click", () => {
                switchTab(cardMap[cardId]);
                const wb = document.getElementById("interactiveWorkbench");
                if (wb) {
                    wb.scrollIntoView({ behavior: "smooth", block: "start" });
                }
            });
        }
    });
}

// Live What-If Risk Simulator
function initSimulator() {
    const cvssSlider = document.getElementById("simCvss");
    const epssSlider = document.getElementById("simEpss");
    const scopeSelect = document.getElementById("simScope");
    const reachCheck = document.getElementById("simReachable");

    if (!cvssSlider || !epssSlider || !scopeSelect || !reachCheck) return;

    const updateSimulator = () => {
        const cvss = parseFloat(cvssSlider.value) || 0;
        const epss = parseFloat(epssSlider.value) || 0;
        const scopeWeight = parseFloat(scopeSelect.value) || 1.0;
        const isReachable = reachCheck.checked;

        document.getElementById("simCvssVal").innerText = cvss.toFixed(1);
        document.getElementById("simEpssVal").innerText = `${Math.round(epss * 100)}%`;

        let scopeText = "Direct (1.0x)";
        if (scopeWeight === 0.50) scopeText = "Transitive (0.50x)";
        if (scopeWeight === 0.05) scopeText = "DevDep (0.05x)";
        document.getElementById("simScopeVal").innerText = scopeText;

        if (!isReachable) {
            document.getElementById("simResultValue").innerText = "0.0 pts";
            document.getElementById("simResultValue").style.color = "#4ade80";
            document.getElementById("simFormulaTag").innerText = "UNREACHABLE in AST -> Threat Discounted to 0.0 pts (0 False-Positive impact)";
        } else {
            const threatScore = cvss * (1.0 + epss * 0.5) * scopeWeight;
            const resElem = document.getElementById("simResultValue");
            resElem.innerText = `${threatScore.toFixed(1)} pts`;

            if (threatScore >= 8.0) resElem.style.color = "#f43f5e";
            else if (threatScore >= 4.0) resElem.style.color = "#fb923c";
            else resElem.style.color = "#4ade80";

            document.getElementById("simFormulaTag").innerText =
                `${cvss.toFixed(1)} CVSS × (1 + ${(epss * 0.5).toFixed(2)} EPSS factor) × ${scopeWeight} weight = ${threatScore.toFixed(1)} pts`;
        }
    };

    cvssSlider.addEventListener("input", updateSimulator);
    epssSlider.addEventListener("input", updateSimulator);
    scopeSelect.addEventListener("change", updateSimulator);
    reachCheck.addEventListener("change", updateSimulator);
    updateSimulator();
}

// Render Score Math Breakdown
function renderScoreMath(scoreData) {
    if (!scoreData) return;

    if (scoreData.formula) {
        document.getElementById("mathFormulaText").innerText = scoreData.formula;
    }
    document.getElementById("mathBaseScore").innerText = (scoreData.base_score || 0.0).toFixed(1);
    document.getElementById("mathCritBonus").innerText = `+${(scoreData.crit_bonus || 0.0).toFixed(1)}`;
    document.getElementById("mathHighBonus").innerText = `+${(scoreData.high_bonus || 0.0).toFixed(1)}`;
    document.getElementById("mathMedBonus").innerText = `+${(scoreData.med_bonus || 0.0).toFixed(1)}`;

    const reachDisc = scoreData.reachability_discount_points || 0.0;
    document.getElementById("mathReachDiscount").innerText =
        `-${reachDisc.toFixed(1)} pts saved (false-positives eliminated via AST analysis)`;

    const devDisc = scoreData.dev_discount_points || 0.0;
    document.getElementById("mathDevDiscount").innerText =
        `-${devDisc.toFixed(1)} pts saved (build-time devDependencies down-weighted by 95%)`;

    // Package Contributions Table
    const tbody = document.getElementById("packageContributionBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    const contributions = scoreData.package_contributions || [];
    if (contributions.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-secondary)">No vulnerable packages contributing to risk score.</td></tr>`;
        return;
    }

    contributions.forEach(c => {
        const tr = document.createElement("tr");
        const scopeBadge = c.is_dev
            ? `<span class="badge" style="background:rgba(168,85,247,0.2); color:#c084fc; border:1px solid #c084fc;">DEV</span>`
            : (c.is_direct
                ? `<span class="badge" style="background:rgba(56,189,248,0.2); color:#38bdf8; border:1px solid #38bdf8;">PROD DIRECT</span>`
                : `<span class="badge" style="background:rgba(148,163,184,0.2); color:#cbd5e1; border:1px solid #cbd5e1;">TRANSITIVE</span>`);

        const reachBadge = c.is_reachable
            ? `<span class="badge badge-HIGH">REACHABLE</span>`
            : `<span class="badge badge-LOW">UNREACHABLE</span>`;

        tr.innerHTML = `
            <td><strong>${c.package}</strong> <span style="font-size:0.75rem; color:#94a3b8">v${c.version}</span></td>
            <td>${scopeBadge}</td>
            <td>${reachBadge}</td>
            <td>${c.weighted_cvss ? c.weighted_cvss.toFixed(1) : "0.0"}</td>
            <td>${c.dep_weight}x</td>
            <td><strong style="color:${c.contribution >= 5 ? '#f43f5e' : (c.contribution > 0 ? '#fb923c' : '#4ade80')}">${c.contribution.toFixed(1)} pts</strong></td>
        `;
        tbody.appendChild(tr);
    });
}

// ---------------------------------------------------------------------
// Standard Vector Favicons / Icons (Clean, Professional, Zero Emojis)
// ---------------------------------------------------------------------
const ICONS = {
    // Shield Alert Icon for Reachable Threats
    shieldAlert: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="rgba(244,63,94,0.2)" stroke="#f43f5e" stroke-width="2"/><path d="M12 8v5M12 16h.01" stroke="#f43f5e" stroke-width="2.2" stroke-linecap="round"/></svg>`,

    // Shield Check Icon for Filtered False Positives / Clean
    shieldCheck: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 2L3 7v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" fill="rgba(16,185,129,0.2)" stroke="#10b981" stroke-width="2"/><path d="M9 12l2 2 4-4" stroke="#10b981" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,

    // Code File Favicon for Source Code Entrypoint
    codeFile: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8l-6-6z" fill="rgba(56,189,248,0.2)" stroke="#38bdf8" stroke-width="2"/><path d="M14 2v6h6M10 13l-2 2 2 2M14 13l2 2-2 2" stroke="#38bdf8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,

    // Package Box Favicon for Imported Modules
    packageBox: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M21 16.5l-9 5.2-9-5.2V7.5L12 2.3l9 5.2v9z" fill="rgba(129,140,248,0.2)" stroke="#818cf8" stroke-width="2"/><path d="M12 12l8.5-4.9M12 12v9.5M12 12L3.5 7.1" stroke="#818cf8" stroke-width="1.8"/></svg>`,

    // Architecture Server Stack Favicon for DAG Root
    serverStack: `<svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" stroke="#38bdf8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>`,

    // High Blast Threat Favicon
    blastThreat: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="rgba(244,63,94,0.2)" stroke="#f43f5e" stroke-width="2"/><circle cx="12" cy="12" r="3" fill="#f43f5e"/></svg>`,

    // Moderate Blast Radar Favicon
    blastModerate: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" fill="rgba(251,146,60,0.2)" stroke="#fb923c" stroke-width="2" stroke-linejoin="round"/></svg>`
};

function createNodeCardSVG({
    iconSvg,
    title,
    subtitleLeft = '',
    subtitleRight = '',
    borderColor = '#38bdf8',
    glowColor = 'rgba(56,189,248,0.4)',
    badge1 = null,
    badge2 = null
}) {
    const isLight = currentTheme === "light";
    const width = 270;
    const height = 86;

    const cardBg = isLight ? '#ffffff' : '#0b1329';
    const titleColor = isLight ? '#0f172a' : '#f8fafc';
    const subLeftColor = isLight ? '#475569' : '#64748b';
    const subRightColor = isLight ? '#64748b' : '#94a3b8';
    const filterId = isLight ? 'cardShadowLight' : 'cardGlowDark';

    let badgesSvg = '';
    let currentX = 14;

    if (badge1) {
        const bWidth = Math.max(badge1.text.length * 6.6 + 14, 65);
        badgesSvg += `
            <rect x="${currentX}" y="54" width="${bWidth}" height="20" rx="4" fill="${badge1.bg}" stroke="${badge1.border || 'none'}" stroke-width="1"/>
            <text x="${currentX + bWidth / 2}" y="68" font-family="Inter, system-ui, -apple-system, sans-serif" font-size="9.5" font-weight="700" fill="${badge1.color}" text-anchor="middle" letter-spacing="0.04em">${escapeXml(badge1.text)}</text>
        `;
        currentX += bWidth + 6;
    }

    if (badge2) {
        const bWidth = Math.max(badge2.text.length * 6.6 + 14, 55);
        badgesSvg += `
            <rect x="${currentX}" y="54" width="${bWidth}" height="20" rx="4" fill="${badge2.bg}" stroke="${badge2.border || 'none'}" stroke-width="1"/>
            <text x="${currentX + bWidth / 2}" y="68" font-family="Inter, system-ui, -apple-system, sans-serif" font-size="9.5" font-weight="700" fill="${badge2.color}" text-anchor="middle" letter-spacing="0.04em">${escapeXml(badge2.text)}</text>
        `;
    }

    const cleanTitle = title.length > 20 ? title.substring(0, 18) + '...' : title;

    const shadowDef = isLight
        ? `<filter id="cardShadowLight" x="-20%" y="-20%" width="140%" height="140%">
               <feDropShadow dx="0" dy="2" stdDeviation="4" flood-color="rgba(15,23,42,0.12)"/>
           </filter>`
        : `<filter id="cardGlowDark" x="-20%" y="-20%" width="140%" height="140%">
               <feDropShadow dx="0" dy="3" stdDeviation="5" flood-color="${glowColor}" flood-opacity="0.5"/>
           </filter>`;

    const svg = `
        <svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
            <defs>
                ${shadowDef}
            </defs>
            <rect x="3" y="3" width="${width - 6}" height="${height - 6}" rx="10" fill="${cardBg}" stroke="${borderColor}" stroke-width="${isLight ? '1.5' : '1.8'}" filter="url(#${filterId})"/>
            <g transform="translate(14, 14)">
                ${iconSvg}
            </g>
            <text x="42" y="27" font-family="Inter, system-ui, -apple-system, sans-serif" font-size="13.5" font-weight="700" fill="${titleColor}">${escapeXml(cleanTitle)}</text>
            <text x="${width - 14}" y="26" font-family="Inter, system-ui, -apple-system, sans-serif" font-size="11" font-weight="600" fill="${subRightColor}" text-anchor="end">${escapeXml(subtitleRight)}</text>
            <text x="42" y="42" font-family="Inter, system-ui, -apple-system, sans-serif" font-size="10.5" font-weight="500" fill="${subLeftColor}">${escapeXml(subtitleLeft)}</text>
            ${badgesSvg}
        </svg>
    `;

    return "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg.trim());
}

function escapeXml(unsafe) {
    if (!unsafe) return "";
    return String(unsafe).replace(/[<>&'"]/g, c => {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
        }
    });
}

// Render AST Reachability Network Graph (Hierarchical Pipeline with Vector SVG Cards)
function renderASTGraph(graphData) {
    lastASTGraphData = graphData;
    const container = document.getElementById("astGraphContainer");
    if (!container || !window.vis || !graphData || !graphData.nodes || graphData.nodes.length === 0) {
        if (container) {
            container.innerHTML = `<div style="display:flex; justify-content:center; align-items:center; height:100%; color:var(--text-secondary)">No AST graph data available. Run a workspace scan.</div>`;
        }
        return;
    }

    // Pre-calculate clean column coordinates for Left-to-Right layout,
    // then leave hierarchical locking disabled so nodes can be pulled freely in any 360° direction!
    const levelGroups = { 0: [], 1: [], 2: [] };
    (graphData.nodes || []).forEach(n => {
        const lvl = n.type === "file" ? 0 : (n.type === "module" ? 1 : 2);
        levelGroups[lvl].push(n);
    });

    const levelSlots = { 0: 0, 1: 0, 2: 0 };
    const styledNodes = (graphData.nodes || []).map(n => {
        let nodeCopy = { ...n };
        const isReach = n.is_reachable;
        const hasVulns = (n.vuln_count || 0) > 0;
        let svgUrl = "";

        nodeCopy.rawLabel = n.label || n.id;
        nodeCopy.label = ""; // Clear canvas text label to prevent duplicate ghost labels!

        const lvl = n.type === "file" ? 0 : (n.type === "module" ? 1 : 2);
        nodeCopy.level = lvl;

        const slot = levelSlots[lvl]++;
        const countInLvl = levelGroups[lvl].length || 1;
        const yPos = (slot - (countInLvl - 1) / 2) * 125;
        const xPos = (lvl - 1) * 360; // Level 0: -360, Level 1: 0, Level 2: +360

        nodeCopy.x = xPos;
        nodeCopy.y = yPos;
        nodeCopy.fixed = { x: false, y: false }; // 100% unlocked for 360° dragging in any direction

        if (n.type === "dependency") {
            const parts = (nodeCopy.rawLabel || '').split('@');
            const pkgName = parts[0] || nodeCopy.rawLabel;
            const pkgVer = parts[1] ? `v${parts[1]}` : '';

            if (!isReach) {
                svgUrl = createNodeCardSVG({
                    iconSvg: ICONS.shieldCheck,
                    title: pkgName,
                    subtitleLeft: 'Dependency • Direct/Transitive',
                    subtitleRight: pkgVer,
                    borderColor: '#10b981',
                    glowColor: 'rgba(16,185,129,0.5)',
                    badge1: { text: "FALSE POSITIVE FILTERED", bg: "rgba(16,185,129,0.22)", color: "#10b981", border: "rgba(16,185,129,0.5)" },
                    badge2: { text: "0 CODE CALLS", bg: "rgba(16,185,129,0.12)", color: currentTheme === 'light' ? '#16a34a' : '#6ee7b7' }
                });
            } else if (hasVulns) {
                svgUrl = createNodeCardSVG({
                    iconSvg: ICONS.shieldAlert,
                    title: pkgName,
                    subtitleLeft: 'Active Dependency Threat',
                    subtitleRight: pkgVer,
                    borderColor: '#f43f5e',
                    glowColor: 'rgba(244,63,94,0.6)',
                    badge1: { text: "ACTIVE THREAT", bg: "rgba(244,63,94,0.25)", color: "#f43f5e", border: "rgba(244,63,94,0.6)" },
                    badge2: { text: `${n.vuln_count} CVEs`, bg: "rgba(244,63,94,0.15)", color: currentTheme === 'light' ? '#e11d48' : '#fda4af' }
                });
            } else {
                svgUrl = createNodeCardSVG({
                    iconSvg: ICONS.shieldCheck,
                    title: pkgName,
                    subtitleLeft: 'Verified Safe Dependency',
                    subtitleRight: pkgVer,
                    borderColor: '#38bdf8',
                    glowColor: 'rgba(56,189,248,0.4)',
                    badge1: { text: "CLEAN PACKAGE", bg: "rgba(56,189,248,0.2)", color: "#38bdf8", border: "rgba(56,189,248,0.5)" },
                    badge2: { text: "0 VULNS", bg: "rgba(56,189,248,0.12)", color: currentTheme === 'light' ? '#0284c7' : '#7dd3fc' }
                });
            }
            nodeCopy.title = `${pkgName} ${pkgVer}`;
        } else if (n.type === "file") {
            svgUrl = createNodeCardSVG({
                iconSvg: ICONS.codeFile,
                title: nodeCopy.rawLabel,
                subtitleLeft: 'Application Codebase File',
                subtitleRight: 'SOURCE',
                borderColor: '#0284c7',
                glowColor: 'rgba(56,189,248,0.6)',
                badge1: { text: "CODE ENTRYPOINT", bg: "rgba(56,189,248,0.22)", color: "#38bdf8", border: "rgba(56,189,248,0.5)" }
            });
            nodeCopy.title = `Source File: ${nodeCopy.rawLabel}`;
        } else if (n.type === "module") {
            svgUrl = createNodeCardSVG({
                iconSvg: ICONS.packageBox,
                title: nodeCopy.rawLabel.replace(/^import\s+/, ''),
                subtitleLeft: 'Static AST Import Statement',
                subtitleRight: 'MODULE',
                borderColor: '#818cf8',
                glowColor: 'rgba(129,140,248,0.5)',
                badge1: { text: "IMPORTED MODULE", bg: "rgba(129,140,248,0.22)", color: "#818cf8", border: "rgba(129,140,248,0.5)" }
            });
            nodeCopy.title = `Imported Module: ${nodeCopy.rawLabel}`;
        }

        nodeCopy.shape = 'image';
        nodeCopy.image = svgUrl;
        nodeCopy.size = 65;
        return nodeCopy;
    });

    const isLight = currentTheme === 'light';
    const styledEdges = (graphData.edges || []).map(e => {
        let edgeCopy = { ...e };
        edgeCopy.width = 2.6;
        edgeCopy.arrows = { to: { enabled: true, scaleFactor: 0.85 } };
        edgeCopy.smooth = { type: 'cubicBezier', forceDirection: 'horizontal', roundness: 0.38 };
        if (e.dashes) {
            edgeCopy.color = {
                color: isLight ? 'rgba(100, 116, 139, 0.6)' : 'rgba(148, 163, 184, 0.45)',
                highlight: isLight ? '#475569' : '#94a3b8'
            };
            edgeCopy.width = 2.0;
        } else {
            edgeCopy.color = {
                color: isLight ? 'rgba(2, 132, 199, 0.85)' : 'rgba(56, 189, 248, 0.85)',
                highlight: isLight ? '#0284c7' : '#38bdf8'
            };
            edgeCopy.shadow = {
                enabled: !isLight,
                color: 'rgba(56, 189, 248, 0.35)',
                size: 6,
                x: 0,
                y: 0
            };
        }
        return edgeCopy;
    });

    const data = {
        nodes: new vis.DataSet(styledNodes),
        edges: new vis.DataSet(styledEdges)
    };

    const options = {
        layout: {
            hierarchical: { enabled: false } // Disabled so nodes can be pulled in any direction freely
        },
        physics: false,
        interaction: {
            dragNodes: true,
            dragView: true,
            hover: true,
            tooltipDelay: 100,
            navigationButtons: false,
            keyboard: true,
            zoomView: true
        }
    };

    if (astNetwork) astNetwork.destroy();
    astNetwork = new vis.Network(container, data, options);

    // Zoom constraint: Clamp to prevent disappearing
    astNetwork.on("zoom", function(params) {
        if (params.scale < 0.45) {
            astNetwork.moveTo({ scale: 0.45 });
        } else if (params.scale > 2.2) {
            astNetwork.moveTo({ scale: 2.2 });
        }
    });

    // Ensure dragged node coordinates persist and stay unlocked
    astNetwork.on("dragEnd", function(params) {
        if (params.nodes && params.nodes.length > 0) {
            params.nodes.forEach(id => {
                data.nodes.update({ id: id, fixed: { x: false, y: false } });
            });
        }
    });

    astNetwork.on("click", function(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = data.nodes.get(nodeId);
            renderASTNodeDetails(node);
        }
    });
}

function renderASTNodeDetails(node) {
    const panel = document.getElementById("astInspectorContent");
    if (!panel || !node) return;

    const nodeTitle = node.rawLabel || node.label || node.id;
    let content = `
        <div style="margin-bottom:0.75rem;">
            <div style="font-size:0.75rem; color:var(--text-secondary); text-transform:uppercase;">Selected Node</div>
            <div style="font-size:1.15rem; font-weight:700; color:var(--text-primary)">${nodeTitle}</div>
            <div style="font-size:0.8rem; color:var(--accent-blue); margin-top:0.25rem;">Type: ${node.type || 'Node'}</div>
        </div>
    `;

    if (node.type === "dependency") {
        const isReach = node.is_reachable;
        content += `
            <div style="background:rgba(255,255,255,0.03); border:1px solid var(--card-border); border-radius:8px; padding:0.75rem; margin-bottom:0.75rem;">
                <div style="font-size:0.75rem; color:var(--text-secondary)">Reachability Verdict</div>
                <div style="font-weight:700; color:${isReach ? '#f43f5e' : '#4ade80'}; margin-top:0.25rem;">
                    ${isReach ? 'ACTIVE THREAT (Reachable via Application AST)' : 'FALSE POSITIVE (Filtered - 0 Code Calls)'}
                </div>
                <div style="font-size:0.75rem; color:var(--text-secondary); margin-top:0.5rem">
                    ${isReach
                        ? 'Static AST inspection found active import statements matching this library. Vulnerabilities pose active exposure.'
                        : 'Package is declared in manifest but AST analysis proves no code imports or invokes this module. False-positive threat eliminated.'}
                </div>
            </div>
            <div style="display:flex; justify-content:space-between; font-size:0.85rem; padding:0.5rem 0; border-bottom:1px solid rgba(255,255,255,0.05)">
                <span>Known Vulnerabilities:</span>
                <strong style="color:${node.vuln_count > 0 ? '#f43f5e' : '#4ade80'}">${node.vuln_count || 0} CVEs</strong>
            </div>
        `;
    } else if (node.type === "file") {
        content += `
            <div style="background:rgba(56,189,248,0.1); border:1px solid rgba(56,189,248,0.3); border-radius:8px; padding:0.75rem;">
                <div style="font-size:0.75rem; color:var(--accent-blue)">Application Source Entrypoint</div>
                <div style="font-size:0.85rem; color:var(--text-primary); margin-top:0.25rem;">
                    Scanned source code file in workspace. AST parser walks syntax tree of this file to resolve third-party imports and symbol invocations.
                </div>
            </div>
        `;
    } else if (node.type === "module") {
        content += `
            <div style="background:rgba(129,140,248,0.1); border:1px solid rgba(129,140,248,0.3); border-radius:8px; padding:0.75rem;">
                <div style="font-size:0.75rem; color:var(--accent-indigo)">Imported Module Node</div>
                <div style="font-size:0.85rem; color:var(--text-primary); margin-top:0.25rem;">
                    Static <code>ast.Import</code> or <code>ast.ImportFrom</code> statement identified during codebase parsing.
                </div>
            </div>
        `;
    }

    panel.innerHTML = content;
}

// Render Supply-Chain DAG Blast Radius Graph (Radial Force-Directed or Hierarchical Tree with Vector SVG Cards)
function renderSupplyChainDAG(dagData) {
    lastDAGGraphData = dagData;
    const container = document.getElementById("dagGraphContainer");
    if (!container || !window.vis || !dagData || !dagData.nodes || dagData.nodes.length === 0) {
        if (container) {
            container.innerHTML = `<div style="display:flex; justify-content:center; align-items:center; height:100%; color:var(--text-secondary)">No DAG graph data available.</div>`;
        }
        return;
    }

    // For Tree layout: pre-calculate clean Left-to-Right column positions,
    // then leave hierarchical locking disabled so nodes can be pulled freely in any 360° direction!
    const dagLevels = { 0: [], 1: [], 2: [] };
    (dagData.nodes || []).forEach(n => {
        const lvl = n.group === "root" ? 0 : (n.is_direct ? 1 : 2);
        dagLevels[lvl].push(n);
    });

    const dagSlots = { 0: 0, 1: 0, 2: 0 };
    const styledDagNodes = (dagData.nodes || []).map(n => {
        let nodeCopy = { ...n };
        const blast = n.blast_radius || 0.0;
        let svgUrl = "";

        nodeCopy.rawLabel = n.label || n.id;
        nodeCopy.label = ""; // Clear canvas text label to prevent duplicate ghost labels!

        const lvl = n.group === "root" ? 0 : (n.is_direct ? 1 : 2);
        nodeCopy.level = lvl;

        if (currentDagLayout === 'tree') {
            const slot = dagSlots[lvl]++;
            const countInLvl = dagLevels[lvl].length || 1;
            nodeCopy.x = (lvl - 1) * 380;
            nodeCopy.y = (slot - (countInLvl - 1) / 2) * 130;
            nodeCopy.fixed = { x: false, y: false };
        } else {
            nodeCopy.fixed = { x: false, y: false };
        }

        if (n.group === "root") {
            svgUrl = createNodeCardSVG({
                iconSvg: ICONS.serverStack,
                title: 'Application Root',
                subtitleLeft: 'Workspace Dependency Root',
                subtitleRight: 'CORE',
                borderColor: '#0284c7',
                glowColor: 'rgba(56,189,248,0.7)',
                badge1: { text: "SUPPLY CHAIN ROOT", bg: "rgba(56,189,248,0.25)", color: "#38bdf8", border: "rgba(56,189,248,0.6)" }
            });
            nodeCopy.title = "Application Root (Dependency Core)";
        } else {
            const parts = (nodeCopy.rawLabel || '').split('\n')[0].split('@');
            const pkgName = parts[0] || nodeCopy.rawLabel;
            const pkgVer = parts[1] ? `v${parts[1]}` : (n.version ? `v${n.version}` : '');
            const typeLabel = n.is_direct ? 'Direct Dependency' : 'Transitive Sub-Dep';

            if (blast >= 60.0) {
                svgUrl = createNodeCardSVG({
                    iconSvg: ICONS.blastThreat,
                    title: pkgName,
                    subtitleLeft: typeLabel,
                    subtitleRight: pkgVer,
                    borderColor: '#ff0055',
                    glowColor: 'rgba(255,0,85,0.65)',
                    badge1: { text: "CASCADING BLAST RISK", bg: "rgba(255,0,85,0.22)", color: "#ff0055", border: "rgba(255,0,85,0.6)" },
                    badge2: { text: `SCORE: ${blast.toFixed(1)}`, bg: "rgba(255,0,85,0.12)", color: currentTheme === 'light' ? '#e11d48' : '#fda4af' }
                });
            } else if (blast >= 30.0) {
                svgUrl = createNodeCardSVG({
                    iconSvg: ICONS.blastModerate,
                    title: pkgName,
                    subtitleLeft: typeLabel,
                    subtitleRight: pkgVer,
                    borderColor: '#fb923c',
                    glowColor: 'rgba(251,146,60,0.55)',
                    badge1: { text: "MODERATE BLAST ZONE", bg: "rgba(251,146,60,0.22)", color: "#fb923c", border: "rgba(251,146,60,0.5)" },
                    badge2: { text: `SCORE: ${blast.toFixed(1)}`, bg: "rgba(251,146,60,0.12)", color: currentTheme === 'light' ? '#ea580c' : '#fdba74' }
                });
            } else {
                svgUrl = createNodeCardSVG({
                    iconSvg: ICONS.shieldCheck,
                    title: pkgName,
                    subtitleLeft: typeLabel,
                    subtitleRight: pkgVer,
                    borderColor: '#10b981',
                    glowColor: 'rgba(16,185,129,0.45)',
                    badge1: { text: "CONTAINED BLAST ZONE", bg: "rgba(16,185,129,0.2)", color: "#10b981", border: "rgba(16,185,129,0.5)" },
                    badge2: { text: `SCORE: ${blast.toFixed(1)}`, bg: "rgba(16,185,129,0.12)", color: currentTheme === 'light' ? '#16a34a' : '#6ee7b7' }
                });
            }
            nodeCopy.title = `${pkgName} ${pkgVer} (Blast Radius: ${blast.toFixed(1)})`;
        }

        nodeCopy.shape = 'image';
        nodeCopy.image = svgUrl;
        nodeCopy.size = 65; // Matches physical card collision bounds
        return nodeCopy;
    });

    const isLight = currentTheme === 'light';
    const styledDagEdges = (dagData.edges || []).map(e => {
        let edgeCopy = { ...e };
        edgeCopy.width = 2.4;
        edgeCopy.arrows = { to: { enabled: true, scaleFactor: 0.85 } };
        edgeCopy.smooth = {
            type: currentDagLayout === 'tree' ? 'cubicBezier' : 'continuous',
            forceDirection: 'horizontal',
            roundness: 0.35
        };
        edgeCopy.color = {
            color: isLight ? 'rgba(79, 70, 229, 0.7)' : 'rgba(129, 140, 248, 0.85)',
            highlight: isLight ? '#4f46e5' : '#818cf8'
        };
        edgeCopy.shadow = {
            enabled: !isLight,
            color: 'rgba(129, 140, 248, 0.35)',
            size: 6,
            x: 0,
            y: 0
        };
        return edgeCopy;
    });

    const data = {
        nodes: new vis.DataSet(styledDagNodes),
        edges: new vis.DataSet(styledDagEdges)
    };

    let options = {};
    if (currentDagLayout === 'tree') {
        options = {
            layout: {
                hierarchical: { enabled: false } // Unlocked so nodes can be dragged in any direction!
            },
            physics: false,
            interaction: {
                dragNodes: true,
                dragView: true,
                hover: true,
                tooltipDelay: 100,
                navigationButtons: false,
                keyboard: true,
                zoomView: true
            }
        };
    } else {
        options = {
            layout: {
                hierarchical: { enabled: false }
            },
            physics: {
                enabled: true,
                solver: 'forceAtlas2Based',
                forceAtlas2Based: {
                    gravitationalConstant: -380,
                    centralGravity: 0.015,
                    springLength: 300,
                    springConstant: 0.04,
                    damping: 0.65,
                    avoidOverlap: 1.0
                },
                stabilization: { iterations: 200 }
            },
            interaction: {
                dragNodes: true,
                dragView: true,
                hover: true,
                tooltipDelay: 100,
                navigationButtons: false,
                keyboard: true,
                zoomView: true
            }
        };
    }

    if (dagNetwork) dagNetwork.destroy();
    dagNetwork = new vis.Network(container, data, options);

    // Zoom constraint: Clamp to prevent disappearing
    dagNetwork.on("zoom", function(params) {
        if (params.scale < 0.45) {
            dagNetwork.moveTo({ scale: 0.45 });
        } else if (params.scale > 2.2) {
            dagNetwork.moveTo({ scale: 2.2 });
        }
    });

    // Ensure dragged node coordinates persist and stay unlocked
    dagNetwork.on("dragEnd", function(params) {
        if (params.nodes && params.nodes.length > 0) {
            params.nodes.forEach(id => {
                data.nodes.update({ id: id, fixed: { x: false, y: false } });
            });
        }
    });

    dagNetwork.on("click", function(params) {
        if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            const node = data.nodes.get(nodeId);
            renderDAGNodeDetails(node);
        }
    });
}

// Network HUD Actions with Hard Clamping
let isAstPhysicsRunning = false;
let isDagPhysicsRunning = true;

function toggleDagLayout() {
    currentDagLayout = currentDagLayout === 'tree' ? 'orbit' : 'tree';
    const btn = document.getElementById("dagLayoutBtn");
    if (btn) {
        if (currentDagLayout === 'tree') {
            btn.innerHTML = `<svg class="ui-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><path d="M5 5a14 14 0 0114 14"/></svg> <span>Orbit View</span>`;
            btn.title = 'Switch to Orbit View';
        } else {
            btn.innerHTML = `<svg class="ui-icon" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg> <span>Tree View</span>`;
            btn.title = 'Switch to Tree View';
        }
    }
    if (lastDAGGraphData) {
        renderSupplyChainDAG(lastDAGGraphData);
    }
}

function zoomNetwork(type, factor) {
    const net = type === 'ast' ? astNetwork : dagNetwork;
    if (!net) return;
    const currentScale = net.getScale();
    const nextScale = Math.min(Math.max(currentScale * factor, 0.45), 2.2);
    net.moveTo({ scale: nextScale, animation: { duration: 300 } });
}

function fitNetwork(type) {
    const net = type === 'ast' ? astNetwork : dagNetwork;
    if (!net) return;
    net.fit({ animation: { duration: 400, easingFunction: 'easeInOutQuad' } });
}

function togglePhysics(type) {
    const net = type === 'ast' ? astNetwork : dagNetwork;
    if (!net) return;
    const btn = document.getElementById(`${type}PhysicsBtn`);
    if (type === 'ast') {
        isAstPhysicsRunning = !isAstPhysicsRunning;
        net.setOptions({
            physics: {
                enabled: isAstPhysicsRunning,
                solver: 'forceAtlas2Based',
                forceAtlas2Based: {
                    gravitationalConstant: -250,
                    centralGravity: 0.01,
                    springLength: 260,
                    springConstant: 0.05,
                    damping: 0.6,
                    avoidOverlap: 1.0
                }
            }
        });
        if (btn) {
            btn.innerHTML = isAstPhysicsRunning
                ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>`
                : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>`;
        }
    } else {
        isDagPhysicsRunning = !isDagPhysicsRunning;
        net.setOptions({ physics: { enabled: isDagPhysicsRunning } });
        if (btn) {
            btn.innerHTML = isDagPhysicsRunning
                ? `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></svg>`
                : `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>`;
        }
    }
}

function renderDAGNodeDetails(node) {
    const panel = document.getElementById("dagInspectorContent");
    if (!panel || !node) return;

    const blast = node.blast_radius || 0.0;
    let blastColor = "#4ade80";
    let blastVerdict = "Contained Blast Radius (< 30)";
    if (blast >= 60.0) {
        blastColor = "#f43f5e";
        blastVerdict = "Critical Cascading Blast Radius (≥ 60)";
    } else if (blast >= 30.0) {
        blastColor = "#fb923c";
        blastVerdict = "Moderate Downstream Blast Radius (30 - 59)";
    }

    const nodeTitle = (node.rawLabel || node.label || node.id).split('\n')[0];

    panel.innerHTML = `
        <div style="margin-bottom:0.75rem;">
            <div style="font-size:0.75rem; color:var(--text-secondary); text-transform:uppercase;">Selected DAG Package</div>
            <div style="font-size:1.15rem; font-weight:700; color:var(--text-primary)">${nodeTitle}</div>
            <div style="font-size:0.8rem; color:${blastColor}; margin-top:0.25rem;">${blastVerdict}</div>
        </div>

        <div style="background:rgba(255,255,255,0.03); border:1px solid var(--card-border); border-radius:8px; padding:0.75rem; margin-bottom:0.75rem;">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span style="font-size:0.8rem; color:var(--text-secondary)">Blast-Radius Score:</span>
                <strong style="font-size:1.3rem; color:${blastColor}">${blast.toFixed(1)} / 100</strong>
            </div>
            <div style="font-size:0.75rem; color:var(--text-secondary); margin-top:0.4rem">
                Formula: (Vulns × 8.0 + Max CVSS × 4.0 + Hierarchy Bonus) × (1 / Depth)
            </div>
        </div>

        <div style="display:flex; justify-content:space-between; font-size:0.85rem; padding:0.5rem 0; border-bottom:1px solid rgba(255,255,255,0.05)">
            <span>Hierarchy Depth:</span>
            <strong>Level ${node.depth || 1} (${node.is_direct ? 'Direct' : 'Transitive'})</strong>
        </div>
        <div style="display:flex; justify-content:space-between; font-size:0.85rem; padding:0.5rem 0; border-bottom:1px solid rgba(255,255,255,0.05)">
            <span>Vulnerability Density:</span>
            <strong style="color:${node.vuln_count > 0 ? '#f43f5e' : '#4ade80'}">${node.vuln_count || 0} CVEs</strong>
        </div>
    `;
}

// Render ML Zero-Day Feature Attribution Table
function renderMLFeatureTable(features) {
    const tbody = document.getElementById("mlFeatureTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!features || features.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--text-secondary)">No ML feature breakdowns available.</td></tr>`;
        return;
    }

    features.forEach(f => {
        const tr = document.createElement("tr");
        const signalsHtml = (f.signals || []).map(s => `<span class="badge" style="background:rgba(255,255,255,0.05); color:#94a3b8; font-size:0.7rem; margin-right:4px;">${s}</span>`).join(" ");

        tr.innerHTML = `
            <td><strong>${f.package}</strong></td>
            <td>${f.version}</td>
            <td>${f.staleness_weight.toFixed(1)} pts <span style="font-size:0.7rem; color:#94a3b8">(v${f.major_version})</span></td>
            <td>${(f.max_epss * 100).toFixed(1)}% <span style="font-size:0.7rem; color:#94a3b8">(+${f.epss_weight.toFixed(0)})</span></td>
            <td>${f.transitive_weight.toFixed(1)} pts <span style="font-size:0.7rem; color:#94a3b8">(${f.is_direct ? 'Direct' : 'Transitive'})</span></td>
            <td><strong style="color:${f.zero_day_score >= 45 ? '#f43f5e' : '#4ade80'}">${f.zero_day_score.toFixed(1)} / 100</strong></td>
            <td><span class="badge badge-${f.threat_level}">${f.threat_level}</span></td>
            <td style="font-size:0.8rem">${signalsHtml}</td>
        `;
        tbody.appendChild(tr);
    });
}

// Render SemVer Breaking Change Safety Matrix
function renderBreakingChangeTable(details) {
    const tbody = document.getElementById("diffTableBody");
    if (!tbody) return;
    tbody.innerHTML = "";

    if (!details || details.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:#4ade80; padding:1.5rem">All dependencies are up to date. No security version upgrades required.</td></tr>`;
        return;
    }

    details.forEach(d => {
        const tr = document.createElement("tr");
        let stepBadge = `<span class="badge" style="background:rgba(74,222,128,0.2); color:#4ade80; border:1px solid #4ade80;">PATCH</span>`;
        if (d.bump_type === "MAJOR") {
            stepBadge = `<span class="badge" style="background:rgba(244,63,94,0.2); color:#f43f5e; border:1px solid #f43f5e;">MAJOR BREAKING</span>`;
        } else if (d.bump_type === "MINOR") {
            stepBadge = `<span class="badge" style="background:rgba(251,146,60,0.2); color:#fb923c; border:1px solid #fb923c;">MINOR UPGRADE</span>`;
        }

        const riskPercent = Math.round(d.breaking_risk * 100);
        const cvesHtml = (d.cves_fixed || []).slice(0, 3).map(c => `<code>${c}</code>`).join(", ");

        tr.innerHTML = `
            <td><strong>${d.package}</strong></td>
            <td><code>${d.current_version}</code></td>
            <td><code style="color:#4ade80">${d.fixed_version}</code></td>
            <td>${stepBadge}</td>
            <td><strong style="color:${d.breaking_risk >= 0.7 ? '#f43f5e' : (d.breaking_risk >= 0.3 ? '#fb923c' : '#4ade80')}">${riskPercent}% Risk</strong></td>
            <td><span class="badge badge-${d.breaking_risk >= 0.7 ? 'CRITICAL' : (d.breaking_risk >= 0.3 ? 'HIGH' : 'LOW')}">${d.risk_label}</span></td>
            <td style="font-size:0.8rem">${cvesHtml}</td>
            <td style="font-size:0.85rem; color:#94a3b8">${d.recommendation}</td>
        `;
        tbody.appendChild(tr);
    });
}
