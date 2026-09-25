import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from ..models import RiskReport, Severity

console = Console(force_terminal=True, legacy_windows=False)



class TerminalReporter:
    """Renders risk reports in rich interactive CLI tables and panels."""

    def render(self, report: RiskReport):
        console.print()
        # Title Banner
        console.print(Panel.fit(
            "[bold white on blue] DevSecOps Dependency Risk Analyzer [/bold white on blue]\n"
            f"[dim]Target: {report.target_path} | Timestamp: {report.scan_timestamp}[/dim]",
            border_style="blue"
        ))

        # Risk Summary Panel
        level_colors = {
            "CRITICAL": "bold red",
            "HIGH": "bold bright_red",
            "MEDIUM": "bold yellow",
            "LOW": "bold green",
        }
        color = level_colors.get(report.risk_level, "white")

        gate_status = "[bold green]PASSED[/bold green]" if report.quality_gate_passed else "[bold red]FAILED (QUALITY GATE BREACHED)[/bold red]"

        summary_text = (
            f"[bold]Overall Risk Score:[/bold] [{color}]{report.overall_risk_score} / 100.0 ({report.risk_level})[/{color}]\n"
            f"[bold]Total Dependencies Scanned:[/bold] {report.total_dependencies}\n"
            f"[bold]Vulnerable Dependencies:[/bold] {report.vulnerable_dependencies_count}\n"
            f"[bold]Quality Gate Outcome:[/bold] {gate_status}\n\n"
            f"[bold red]Critical:[/bold red] {report.severity_counts['CRITICAL']} | "
            f"[bold bright_red]High:[/bold bright_red] {report.severity_counts['HIGH']} | "
            f"[bold yellow]Medium:[/bold yellow] {report.severity_counts['MEDIUM']} | "
            f"[bold green]Low:[/bold green] {report.severity_counts['LOW']}"
        )
        console.print(Panel(summary_text, title="🛡️ Risk Overview", border_style="cyan"))

        # Vulnerabilities Table
        if report.vulnerable_dependencies_count > 0:
            table = Table(title="🚨 Detected Dependency Vulnerabilities", show_header=True, header_style="bold magenta")
            table.add_column("Ecosystem", style="dim", width=10)
            table.add_column("Package", style="bold cyan")
            table.add_column("Version", width=10)
            table.add_column("CVE / Vuln ID", style="bold yellow", width=18)
            table.add_column("Severity", width=10)
            table.add_column("CVSS", width=6)
            table.add_column("Fixed Version", style="bold green", width=14)
            table.add_column("Summary")

            for dep_analysis in report.dependencies:
                if not dep_analysis.has_vulnerabilities:
                    continue

                dep = dep_analysis.dependency
                for vuln in dep_analysis.vulnerabilities:
                    sev_style = "bold red" if vuln.severity == Severity.CRITICAL else \
                                "bold bright_red" if vuln.severity == Severity.HIGH else \
                                "bold yellow" if vuln.severity == Severity.MEDIUM else "green"

                    table.add_row(
                        dep.ecosystem,
                        dep.name,
                        dep.version,
                        vuln.vuln_id,
                        f"[{sev_style}]{vuln.severity.value}[/{sev_style}]",
                        f"{vuln.cvss_score:.1f}",
                        vuln.fixed_version or "N/A",
                        vuln.summary[:65] + "..." if len(vuln.summary) > 65 else vuln.summary
                    )

            console.print(table)
        else:
            console.print("[bold green]✨ No security vulnerabilities detected in dependencies![/bold green]")

        # Remediation Panel
        if report.remediation_recommendations:
            rem_tree = Tree("[bold cyan]🔧 Recommended Remediation Actions[/bold cyan]")
            for rem in report.remediation_recommendations:
                rem_tree.add(
                    f"[bold yellow]{rem['package']}[/bold yellow] ({rem['current_version']}) ➔ "
                    f"[bold green]{rem['fixed_version']}[/bold green] "
                    f"[dim](Fixes {rem['cve']} - {rem['severity']})[/dim]"
                )
            console.print(Panel(rem_tree, border_style="green"))

        console.print()
