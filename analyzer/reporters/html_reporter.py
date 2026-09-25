from pathlib import Path
from jinja2 import Template
from ..models import RiskReport

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DevSecOps Dependency Risk Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-blue: #38bdf8;
            --critical-red: #ef4444;
            --high-orange: #f97316;
            --medium-yellow: #eab308;
            --low-green: #22c55e;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            margin: 0;
            padding: 2rem;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }

        h1 { margin: 0; color: var(--accent-blue); font-size: 1.8rem; }
        .meta { color: var(--text-muted); font-size: 0.9rem; }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2.5rem;
        }

        .stat-card {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
        }

        .stat-title { color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
        .stat-value { font-size: 2.2rem; font-weight: bold; margin-top: 0.5rem; }

        .gate-passed { color: var(--low-green); }
        .gate-failed { color: var(--critical-red); }

        .chart-section {
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 2.5rem;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }

        th, td {
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }

        th {
            background-color: #0f172a;
            color: var(--text-muted);
            font-size: 0.85rem;
            text-transform: uppercase;
        }

        tr:hover { background-color: #26334d; }

        .badge {
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: bold;
        }

        .badge-CRITICAL { background: rgba(239, 68, 68, 0.2); color: var(--critical-red); border: 1px solid var(--critical-red); }
        .badge-HIGH { background: rgba(249, 115, 22, 0.2); color: var(--high-orange); border: 1px solid var(--high-orange); }
        .badge-MEDIUM { background: rgba(234, 179, 8, 0.2); color: var(--medium-yellow); border: 1px solid var(--medium-yellow); }
        .badge-LOW { background: rgba(34, 197, 94, 0.2); color: var(--low-green); border: 1px solid var(--low-green); }

        .rem-box {
            background: #112233;
            border-left: 4px solid var(--low-green);
            padding: 1rem;
            margin-bottom: 1rem;
            border-radius: 4px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>🛡️ DevSecOps Dependency Risk Analyzer</h1>
                <div class="meta">Target: {{ report.target_path }}</div>
            </div>
            <div class="meta">Generated at: {{ report.scan_timestamp }}</div>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-title">Composite Risk Score</div>
                <div class="stat-value" style="color: {% if report.overall_risk_score > 70 %}var(--critical-red){% elif report.overall_risk_score > 40 %}var(--medium-yellow){% else %}var(--low-green){% endif %}">
                    {{ report.overall_risk_score }} / 100
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Quality Gate</div>
                <div class="stat-value {% if report.quality_gate_passed %}gate-passed{% else %}gate-failed{% endif %}">
                    {% if report.quality_gate_passed %}PASSED{% else %}FAILED{% endif %}
                </div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Dependencies Scanned</div>
                <div class="stat-value">{{ report.total_dependencies }}</div>
            </div>
            <div class="stat-card">
                <div class="stat-title">Vulnerable Dependencies</div>
                <div class="stat-value" style="color: var(--high-orange)">{{ report.vulnerable_dependencies_count }}</div>
            </div>
        </div>

        {% if report.remediation_recommendations %}
        <div style="margin-bottom: 2.5rem;">
            <h2>🔧 Recommended Fixes & Upgrade Paths</h2>
            {% for rem in report.remediation_recommendations %}
            <div class="rem-box">
                <strong>{{ rem.package }}</strong> ({{ rem.current_version }}) &rarr; <span style="color:var(--low-green)">{{ rem.fixed_version }}</span>
                <span class="badge badge-{{ rem.severity }}">{{ rem.severity }}</span>
                <div style="font-size:0.85rem; color:var(--text-muted); margin-top:0.25rem;">Fixes {{ rem.cve }}</div>
            </div>
            {% endfor %}
        </div>
        {% endif %}

        <h2>🚨 Detected Vulnerabilities</h2>
        <table>
            <thead>
                <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Ecosystem</th>
                    <th>Vulnerability ID</th>
                    <th>Severity</th>
                    <th>CVSS</th>
                    <th>Fixed Version</th>
                    <th>Summary</th>
                </tr>
            </thead>
            <tbody>
                {% for dep_analysis in report.dependencies %}
                    {% for vuln in dep_analysis.vulnerabilities %}
                    <tr>
                        <td><strong>{{ dep_analysis.dependency.name }}</strong></td>
                        <td>{{ dep_analysis.dependency.version }}</td>
                        <td>{{ dep_analysis.dependency.ecosystem }}</td>
                        <td><code>{{ vuln.vuln_id }}</code></td>
                        <td><span class="badge badge-{{ vuln.severity.value }}">{{ vuln.severity.value }}</span></td>
                        <td>{{ "%.1f"|format(vuln.cvss_score) }}</td>
                        <td>{% if vuln.fixed_version %}<span style="color:var(--low-green)">{{ vuln.fixed_version }}</span>{% else %}N/A{% endif %}</td>
                        <td style="font-size:0.9rem; color:var(--text-muted)">{{ vuln.summary }}</td>
                    </tr>
                    {% endfor %}
                {% endfor %}
            </tbody>
        </table>
    </div>
</body>
</html>
"""


class HTMLReporter:
    """Generates standalone HTML reports."""

    def export(self, report: RiskReport, output_path: str) -> str:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        template = Template(HTML_TEMPLATE)
        html_content = template.render(report=report)

        with open(path, "w", encoding="utf-8") as f:
            f.write(html_content)

        return str(path)
