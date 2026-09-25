import json
import shutil
import subprocess
from pathlib import Path
from typing import List
from ..models import Vulnerability, Severity, Dependency, DependencyAnalysis


class TrivyScanner:
    """Wrapper for Aqua Security Trivy CLI scanner."""

    def is_available(self) -> bool:
        return shutil.which("trivy") is not None

    def scan_path(self, target_path: Path) -> List[DependencyAnalysis]:
        if not self.is_available():
            return []

        results: List[DependencyAnalysis] = []
        try:
            cmd = ["trivy", "fs", "--format", "json", "--quiet", str(target_path)]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if proc.returncode == 0 and proc.stdout:
                data = json.loads(proc.stdout)
                results = self._parse_trivy_json(data, target_path)
        except Exception as e:
            print(f"[!] Warning: Trivy scan execution failed: {e}")

        return results

    def _parse_trivy_json(self, data: dict, target_path: Path) -> List[DependencyAnalysis]:
        analyses: List[DependencyAnalysis] = []
        raw_results = data.get("Results", [])

        for target_res in raw_results:
            target_file = target_res.get("Target", str(target_path))
            ecosystem = target_res.get("Type", "unknown")
            vulnerabilities_raw = target_res.get("Vulnerabilities", [])

            dep_vuln_map = {}
            for v_raw in vulnerabilities_raw:
                pkg_name = v_raw.get("PkgName", "unknown")
                installed_ver = v_raw.get("InstalledVersion", "unknown")
                cve_id = v_raw.get("VulnerabilityID", "CVE-UNKNOWN")
                title = v_raw.get("Title") or v_raw.get("Description", "No description")
                sev_str = v_raw.get("Severity", "UNKNOWN").upper()
                fixed_ver = v_raw.get("FixedVersion")

                # Map Severity
                sev_enum = getattr(Severity, sev_str, Severity.MEDIUM)
                cvss_score = float(v_raw.get("CVSS", {}).get("nvd", {}).get("V3Score", 0.0))

                vuln = Vulnerability(
                    vuln_id=cve_id,
                    summary=title[:150],
                    severity=sev_enum,
                    cvss_score=cvss_score or sev_enum.score_weight,
                    fixed_version=fixed_ver,
                    source="Trivy Scanner",
                )

                key = (pkg_name, installed_ver)
                if key not in dep_vuln_map:
                    dep_vuln_map[key] = []
                dep_vuln_map[key].append(vuln)

            for (name, ver), vulns in dep_vuln_map.items():
                dep = Dependency(
                    name=name,
                    version=ver,
                    ecosystem=ecosystem,
                    is_direct=True,
                    file_origin=target_file,
                )
                analyses.append(DependencyAnalysis(dependency=dep, vulnerabilities=vulns))

        return analyses
