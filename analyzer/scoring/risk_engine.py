from pathlib import Path
from typing import List, Dict
from ..models import DependencyAnalysis, RiskReport, Severity, ResearchMetrics, ReachabilityStatus
from ..research import (
    ASTReachabilityAnalyzer,
    DependencyGraphEngine,
    MLZeroDayPredictor,
    ASTDiffBreakingChangeAnalyzer
)


class RiskEngine:
    """
    DevSecOps Composite Risk Scoring Engine with Academic Research Innovations:
    1. AST Call Graph Reachability (False-Positive Elimination)
    2. Supply Chain DAG Graph Centrality & Blast-Radius Engine
    3. Machine Learning Predictive Zero-Day & Maintainer Health Scoring
    4. AST Differential Breaking-Change Risk Prediction
    """

    def __init__(self, risk_threshold: float = 50.0, fail_on_critical: bool = True, fail_on_high: bool = True):
        self.risk_threshold = risk_threshold
        self.fail_on_critical = fail_on_critical
        self.fail_on_high = fail_on_high

        self.reachability_analyzer = ASTReachabilityAnalyzer()
        self.graph_engine = DependencyGraphEngine()
        self.ml_predictor = MLZeroDayPredictor()
        self.ast_diff_analyzer = ASTDiffBreakingChangeAnalyzer()

    def evaluate(self, target_path: str, analyses: List[DependencyAnalysis]) -> RiskReport:
        target_path_obj = Path(target_path).resolve()

        # Step 1: Run Academic Research Engines
        reachability_res = self.reachability_analyzer.analyze_workspace(target_path_obj, analyses)
        graph_res = self.graph_engine.compute_blast_radius(analyses)
        predicted_zero_days = self.ml_predictor.predict_zero_day_risks(analyses)
        breaking_changes = self.ast_diff_analyzer.analyze_breaking_changes(analyses)

        research_metrics = ResearchMetrics(
            total_packages_analyzed=len(analyses),
            false_positives_eliminated=reachability_res.get("false_positives_eliminated", 0),
            graph_node_count=graph_res.get("graph_nodes", 0),
            graph_edge_count=graph_res.get("graph_edges", 0),
            average_blast_radius=graph_res.get("avg_blast_radius", 0.0),
            predicted_zero_day_threats=predicted_zero_days,
            breaking_changes_prevented=breaking_changes
        )

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
        accumulated_dep_score = 0.0

        for analysis in analyses:
            dep = analysis.dependency
            dep_weight = 0.05 if dep.is_dev_dependency else (1.0 if dep.is_direct else 0.50)

            max_dep_cvss = 0.0
            for vuln in analysis.vulnerabilities:
                # Discount unreachable false positives in risk scoring
                if vuln.reachability == ReachabilityStatus.UNREACHABLE:
                    continue

                sev_key = vuln.severity.value
                severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1

                # Base CVSS rating + EPSS weight
                cvss = vuln.cvss_score or vuln.severity.score_weight
                epss = getattr(vuln, "epss_score", 0.05)
                weighted_cvss = cvss * (1.0 + epss * 0.5)

                if weighted_cvss > max_dep_cvss:
                    max_dep_cvss = weighted_cvss

                if vuln.fixed_version:
                    remediations.append({
                        "package": dep.name,
                        "current_version": dep.version,
                        "fixed_version": vuln.fixed_version,
                        "cve": vuln.vuln_id,
                        "severity": vuln.severity.value,
                        "is_dev": dep.is_dev_dependency,
                        "breaking_change_risk": f"{analysis.breaking_change_risk:.2f}",
                        "action": f"Upgrade {dep.name} from {dep.version} to {vuln.fixed_version} (fixes {vuln.vuln_id}, Breaking Risk: {analysis.breaking_change_risk:.2f})"
                    })

            accumulated_dep_score += max_dep_cvss * dep_weight


        # Composite Score Calculation (0.0 - 100.0)
        if total_deps == 0 or vulnerable_deps_count == 0:
            overall_score = 0.0
        else:
            avg_risk = accumulated_dep_score / max(total_deps, 1)
            base_score = min(60.0, avg_risk * 6.0)

            crit_bonus = min(25.0, severity_counts["CRITICAL"] * 10.0)
            high_bonus = min(15.0, severity_counts["HIGH"] * 3.0)
            med_bonus = min(8.0, severity_counts["MEDIUM"] * 1.5)

            overall_score = min(100.0, round(base_score + crit_bonus + high_bonus + med_bonus, 1))

        # Categorization
        if overall_score >= 75.0 or severity_counts["CRITICAL"] > 0:
            risk_level = "CRITICAL"
        elif overall_score >= 50.0 or severity_counts["HIGH"] > 1:
            risk_level = "HIGH"
        elif overall_score >= 25.0 or severity_counts["MEDIUM"] > 1:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Quality Gate evaluation
        gate_passed = True
        if self.fail_on_critical and severity_counts["CRITICAL"] > 0:
            gate_passed = False
        elif self.fail_on_high and severity_counts["HIGH"] > 0:
            gate_passed = False
        elif overall_score >= self.risk_threshold:
            gate_passed = False

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
            research_metrics=research_metrics,
        )
