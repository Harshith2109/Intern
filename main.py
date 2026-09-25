import sys
import os
import argparse

# Fix Windows console UTF-8 output encoding for emojis and symbols
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from pathlib import Path
from analyzer.parsers import find_and_parse
from analyzer.scanners import ScanManager
from analyzer.scoring import RiskEngine
from analyzer.reporters import TerminalReporter, JSONReporter, HTMLReporter, SARIFReporter
from analyzer.github import GitHubFetcher


def main():
    parser = argparse.ArgumentParser(
        description="DevSecOps Dependency Risk Analyzer - Dependency analysis, CVE detection, composite risk scoring & reporting."
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # Local scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a local folder or dependency manifest file.")
    scan_parser.add_argument("target", help="Path to project directory or manifest file (e.g. requirements.txt, package.json)")
    scan_parser.add_argument("--json", help="Path to save JSON report")
    scan_parser.add_argument("--html", help="Path to save HTML interactive report")
    scan_parser.add_argument("--sarif", help="Path to save SARIF report for GitHub Code Scanning")
    scan_parser.add_argument("--threshold", type=float, default=70.0, help="Risk score threshold to breach quality gate (Default: 70.0)")
    scan_parser.add_argument("--no-fail-critical", action="store_true", help="Do not fail quality gate solely on critical CVEs")

    # GitHub scan command
    gh_parser = subparsers.add_parser("scan-github", help="Scan a public or private GitHub repository.")
    gh_parser.add_argument("url", help="GitHub repository URL (e.g., https://github.com/owner/repo)")
    gh_parser.add_argument("--branch", default="main", help="Target branch (Default: main)")
    gh_parser.add_argument("--token", help="GitHub Personal Access Token for private repositories")
    gh_parser.add_argument("--json", help="Path to save JSON report")
    gh_parser.add_argument("--html", help="Path to save HTML interactive report")
    gh_parser.add_argument("--sarif", help="Path to save SARIF report")
    gh_parser.add_argument("--threshold", type=float, default=70.0, help="Risk score threshold (Default: 70.0)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    target_path = None
    if args.command == "scan":
        target_path = Path(args.target).resolve()
        if not target_path.exists():
            print(f"[!] Error: Target path '{args.target}' does not exist.")
            sys.exit(1)
    elif args.command == "scan-github":
        print(f"[*] Fetching dependency manifests from GitHub: {args.url}...")
        fetcher = GitHubFetcher()
        try:
            target_path = fetcher.fetch_repo_manifests(args.url, branch=args.branch, token=args.token)
        except Exception as e:
            print(f"[!] Error fetching GitHub repository: {e}")
            sys.exit(1)

    # Step 1: Parse Dependencies
    print(f"[*] Analyzing dependency manifests at: {target_path}")
    dependencies = find_and_parse(target_path)
    if not dependencies:
        print("[!] No supported dependency manifests found (requirements.txt, package.json, pom.xml, pyproject.toml).")
        sys.exit(0)

    print(f"[*] Found {len(dependencies)} unique dependencies. Querying CVE databases...")

    # Step 2: Scan for Vulnerabilities
    scanner = ScanManager()
    analyses = scanner.scan_dependencies(dependencies)

    # Step 3: Risk Engine & Scoring
    fail_on_critical = not getattr(args, "no_fail_critical", False)
    risk_engine = RiskEngine(risk_threshold=args.threshold, fail_on_critical=fail_on_critical)
    report = risk_engine.evaluate(str(target_path), analyses)

    # Step 4: Terminal Display
    terminal_reporter = TerminalReporter()
    terminal_reporter.render(report)

    # Step 5: Export Reports
    if args.json:
        json_path = JSONReporter().export(report, args.json)
        print(f"[+] JSON report saved to: {json_path}")

    if args.html:
        html_path = HTMLReporter().export(report, args.html)
        print(f"[+] Interactive HTML report saved to: {html_path}")

    if args.sarif:
        sarif_path = SARIFReporter().export(report, args.sarif)
        print(f"[+] SARIF GitHub report saved to: {sarif_path}")

    # Return CI/CD Exit Code
    if not report.quality_gate_passed:
        print("[!] Quality Gate Failed: High security risk or Critical CVE detected.")
        sys.exit(1)
    else:
        print("[+] Quality Gate Passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
