from typing import List, Dict
from ..models import DependencyAnalysis, RiskReport, Severity


class RiskEngine:
    """
    DevSecOps Composite Risk Scoring Engine.
    Calculates overall project security risk (0.0 - 100.0) and generates quality gate pass/fail criteria.
    """

    def __init__(self, risk_threshold: float = 70.0, fail_on_critical: bool = True):
        self.risk_threshold = risk_threshold
        self.fail_on_critical = fail_on_critical

    def evaluate(self, target_path: str, analyses: List[DependencyAnalysis]) -> RiskReport:
        total_deps = len(analyses)
        vulnerable_deps = [a for a in analyses if a.has_vulnerabilities]
        vulnerable_deps_count = len(vulnerable_deps)

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }

        remediations: List[Dict[str, str]] = []
        raw_risk_accumulation = 0.0

        for analysis in analyses:
            dep = analysis.dependency
            dep_weight = 1.0 if dep.is_direct else 0.65

            max_dep_risk = 0.0
            for vuln in analysis.vulnerabilities:
                sev_key = vuln.severity.value
                severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1

                # Vulnerability score calculation
                base_cvss = vuln.cvss_score or vuln.severity.score_weight
                epss_factor = 1.0 + getattr(vuln, "epss_score", 0.05)

                vuln_risk = base_cvss * epss_factor * dep_weight
                if vuln_risk > max_dep_risk:
                    max_dep_risk = vuln_risk

                # Remediation recommendation
                if vuln.fixed_version:
                    remediations.append({
                        "package": dep.name,
                        "current_version": dep.version,
                        "fixed_version": vuln.fixed_version,
                        "cve": vuln.vuln_id,
                        "severity": vuln.severity.value,
                        "action": f"Upgrade {dep.name} from {dep.version} to {vuln.fixed_version} (fixes {vuln.vuln_id})"
                    })

            raw_risk_accumulation += max_dep_risk

        # Composite score normalization (0 - 100)
        if total_deps == 0:
            overall_score = 0.0
        else:
            base_score = (raw_risk_accumulation / max(total_deps, 1)) * 12.0
            critical_penalty = severity_counts["CRITICAL"] * 15.0
            high_penalty = severity_counts["HIGH"] * 5.0
            overall_score = min(100.0, round(base_score + critical_penalty + high_penalty, 1))

        # Risk level categorization
        if overall_score >= 80.0 or severity_counts["CRITICAL"] > 0:
            risk_level = "CRITICAL"
        elif overall_score >= 60.0 or severity_counts["HIGH"] > 1:
            risk_level = "HIGH"
        elif overall_score >= 30.0 or severity_counts["MEDIUM"] > 2:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Quality Gate evaluation
        gate_passed = True
        if self.fail_on_critical and severity_counts["CRITICAL"] > 0:
            gate_passed = False
        elif overall_score > self.risk_threshold:
            gate_passed = False

        # Deduplicate remediation suggestions
        unique_remediations = []
        seen_rem = set()
        for r in remediations:
            rem_key = (r["package"], r["fixed_version"])
            if rem_key not in seen_rem:
                seen_rem.add(rem_key)
                unique_remediations.append(r)

        return RiskReport(
            target_path=str(target_path),
            dependencies=analyses,
            overall_risk_score=overall_score,
            risk_level=risk_level,
            total_dependencies=total_deps,
            vulnerable_dependencies_count=vulnerable_deps_count,
            severity_counts=severity_counts,
            quality_gate_passed=gate_passed,
            remediation_recommendations=unique_remediations,
        )
