import requests
from typing import List, Optional, Dict, Any
from ..models import Dependency, Vulnerability, Severity

OSV_API_URL = "https://api.osv.dev/v1/query"
EPSS_API_URL = "https://api.first.org/data/v1/epss"


class OSVScanner:
    """Scanner leveraging Google OSV (Open Source Vulnerability) DB REST API."""

    ECOSYSTEM_MAP = {
        "PyPI": "PyPI",
        "npm": "npm",
        "Maven": "Maven",
        "Go": "Go",
    }

    def __init__(self):
        self._epss_cache: Dict[str, float] = {}

    def scan_dependency(self, dep: Dependency) -> List[Vulnerability]:
        vulnerabilities: List[Vulnerability] = []
        ecosystem = self.ECOSYSTEM_MAP.get(dep.ecosystem, dep.ecosystem)

        # OSV query payload
        payload = {
            "package": {
                "name": dep.name,
                "ecosystem": ecosystem
            }
        }
        if dep.version and dep.version != "latest":
            payload["version"] = dep.version

        try:
            response = requests.post(OSV_API_URL, json=payload, timeout=5)
            if response.status_code == 200:
                data = response.json()
                vulns_raw = data.get("vulns", [])
                seen_ids = set()
                for item in vulns_raw:
                    vuln = self._parse_osv_item(item)
                    if vuln and vuln.vuln_id not in seen_ids:
                        seen_ids.add(vuln.vuln_id)
                        vulnerabilities.append(vuln)

        except Exception as e:
            print(f"[!] Warning: OSV API query failed for {dep.name}@{dep.version}: {e}", flush=True)

        return vulnerabilities


    def _parse_osv_item(self, item: Dict[str, Any]) -> Optional[Vulnerability]:
        vuln_id = item.get("id", "UNKNOWN-VULN")
        summary = item.get("summary") or item.get("details", "No summary provided.")
        # Truncate summary if too long
        if len(summary) > 150:
            summary = summary[:147] + "..."

        # Look for CVE aliases if available
        aliases = item.get("aliases", [])
        cve_id = next((a for a in aliases if a.startswith("CVE-")), vuln_id)

        # Extract Severity and CVSS
        severity, cvss = self._extract_severity_and_cvss(item)

        # Extract Fixed Version
        fixed_ver = self._extract_fixed_version(item)

        # Extract References
        refs = [ref.get("url") for ref in item.get("references", []) if ref.get("url")]

        # Query EPSS score if CVE ID is available
        epss_score = self._fetch_epss_score(cve_id) if cve_id.startswith("CVE-") else 0.05

        return Vulnerability(
            vuln_id=cve_id,
            summary=summary,
            severity=severity,
            cvss_score=cvss,
            epss_score=epss_score,
            fixed_version=fixed_ver,
            references=refs[:3],
            source="OSV.dev DB",
        )

    def _extract_severity_and_cvss(self, item: Dict[str, Any]) -> (Severity, float):
        cvss_score = 0.0
        severity_str = "UNKNOWN"

        # Try to parse CVSS vectors or scores from OSV database
        severities = item.get("severity", [])
        for s in severities:
            score_type = s.get("type")
            score_val = s.get("score")
            if score_type in ["CVSS_V3", "CVSS_V2"] and score_val:
                # Basic CVSS rating extraction from vector or float
                cvss_score = self._parse_cvss_vector_or_score(score_val)
                break

        # Check database-specific severity annotations
        database_specific = item.get("database_specific", {})
        if "severity" in database_specific:
            severity_str = str(database_specific["severity"]).upper()

        # Deduce severity from CVSS score if not explicitly set
        if cvss_score > 0:
            if cvss_score >= 9.0:
                severity = Severity.CRITICAL
            elif cvss_score >= 7.0:
                severity = Severity.HIGH
            elif cvss_score >= 4.0:
                severity = Severity.MEDIUM
            else:
                severity = Severity.LOW
        else:
            # Map string to Enum
            if "CRITICAL" in severity_str:
                severity = Severity.CRITICAL
                cvss_score = 9.5
            elif "HIGH" in severity_str:
                severity = Severity.HIGH
                cvss_score = 7.8
            elif "MODERATE" in severity_str or "MEDIUM" in severity_str:
                severity = Severity.MEDIUM
                cvss_score = 5.5
            elif "LOW" in severity_str:
                severity = Severity.LOW
                cvss_score = 3.0
            else:
                severity = Severity.MEDIUM
                cvss_score = 5.0

        return severity, cvss_score

    def _parse_cvss_vector_or_score(self, cvss_val: Any) -> float:
        try:
            return float(cvss_val)
        except ValueError:
            pass

        # Parse CVSS v3 Vector String (e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
        if isinstance(cvss_val, str) and cvss_val.startswith("CVSS:"):
            # Estimate CVSS based on vector metrics
            score = 5.0
            if "C:H" in cvss_val and "I:H" in cvss_val and "A:H" in cvss_val:
                score = 9.8 if "PR:N" in cvss_val else 8.8
            elif "C:H" in cvss_val or "I:H" in cvss_val:
                score = 7.5
            elif "C:L" in cvss_val or "I:L" in cvss_val:
                score = 4.3
            return score
        return 5.0

    def _extract_fixed_version(self, item: Dict[str, Any]) -> Optional[str]:
        for affected in item.get("affected", []):
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        return str(event["fixed"])
        return None

    def _fetch_epss_score(self, cve_id: str) -> float:
        """Fetches EPSS (Exploit Prediction Scoring System) score from FIRST.org API with local caching."""
        if cve_id in self._epss_cache:
            return self._epss_cache[cve_id]

        score = 0.05
        try:
            resp = requests.get(EPSS_API_URL, params={"cve": cve_id}, timeout=2)
            if resp.status_code == 200:
                data = resp.json().get("data", [])
                if data:
                    score = float(data[0].get("epss", 0.05))
        except Exception:
            pass

        self._epss_cache[cve_id] = score
        return score

