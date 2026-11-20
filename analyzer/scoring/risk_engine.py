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

        reachability_graph = reachability_res.get("graph", {})
        supply_chain_dag = graph_res.get("dag_graph", {})
        ml_feature_breakdown = getattr(self.ml_predictor, "get_feature_breakdowns", lambda: [])()
        breaking_change_details = getattr(self.ast_diff_analyzer, "get_breaking_details", lambda: [])()

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
        accumulated_dep_score_all = 0.0
        accumulated_dep_score_prod = 0.0
        package_contributions: List[Dict[str, Any]] = []

        for analysis in analyses:
            dep = analysis.dependency
            dep_weight = 0.05 if dep.is_dev_dependency else (1.0 if dep.is_direct else 0.50)

            max_dep_cvss = 0.0
            max_dep_cvss_raw = 0.0
            for vuln in analysis.vulnerabilities:
                cvss = vuln.cvss_score or vuln.severity.score_weight
                epss = getattr(vuln, "epss_score", 0.05)
                weighted_cvss = cvss * (1.0 + epss * 0.5)

                if weighted_cvss > max_dep_cvss_raw:
                    max_dep_cvss_raw = weighted_cvss

                # Discount unreachable false positives in risk scoring
                if vuln.reachability == ReachabilityStatus.UNREACHABLE:
                    continue

                sev_key = vuln.severity.value
                severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1

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

            dep_contrib = max_dep_cvss * dep_weight
            accumulated_dep_score += dep_contrib
            accumulated_dep_score_all += max_dep_cvss_raw * dep_weight
            accumulated_dep_score_prod += max_dep_cvss * (1.0 if dep.is_direct else 0.50)

            package_contributions.append({
                "package": dep.name,
                "version": dep.version,
                "is_direct": dep.is_direct,
                "is_dev": dep.is_dev_dependency,
                "is_reachable": analysis.is_reachable,
                "weighted_cvss": round(max_dep_cvss, 2),
                "dep_weight": dep_weight,
                "contribution": round(dep_contrib, 2),
                "vuln_count": len(analysis.vulnerabilities),
            })

        package_contributions.sort(key=lambda x: x["contribution"], reverse=True)

        # Composite Score Calculation (0.0 - 100.0)
        if total_deps == 0 or vulnerable_deps_count == 0:
            overall_score = 0.0
            base_score = 0.0
            crit_bonus = 0.0
            high_bonus = 0.0
            med_bonus = 0.0
            avg_risk = 0.0
            reachability_discount_points = 0.0
            dev_discount_points = 0.0
        else:
            avg_risk = accumulated_dep_score / max(total_deps, 1)
            base_score = min(60.0, avg_risk * 6.0)

            crit_bonus = min(25.0, severity_counts["CRITICAL"] * 10.0)
            high_bonus = min(15.0, severity_counts["HIGH"] * 3.0)
            med_bonus = min(8.0, severity_counts["MEDIUM"] * 1.5)

            overall_score = min(100.0, round(base_score + crit_bonus + high_bonus + med_bonus, 1))

            raw_avg_risk = accumulated_dep_score_all / max(total_deps, 1)
            raw_base_score = min(60.0, raw_avg_risk * 6.0)
            reachability_discount_points = round(max(0.0, raw_base_score - base_score), 1)

            prod_avg_risk = accumulated_dep_score_prod / max(total_deps, 1)
            prod_base_score = min(60.0, prod_avg_risk * 6.0)
            dev_discount_points = round(max(0.0, prod_base_score - base_score), 1)

        score_breakdown = {
            "base_score": round(base_score, 1),
            "crit_bonus": round(crit_bonus, 1),
            "high_bonus": round(high_bonus, 1),
            "med_bonus": round(med_bonus, 1),
            "overall_score": overall_score,
            "accumulated_dep_score": round(accumulated_dep_score, 1),
            "avg_dep_risk": round(avg_risk, 2),
            "reachability_discount_points": reachability_discount_points,
            "dev_discount_points": dev_discount_points,
            "package_contributions": package_contributions,
            "formula": f"min(100.0, {base_score:.1f} (Base) + {crit_bonus:.1f} (Crit) + {high_bonus:.1f} (High) + {med_bonus:.1f} (Med)) = {overall_score:.1f}"
        }

        research_metrics = ResearchMetrics(
            total_packages_analyzed=len(analyses),
            false_positives_eliminated=reachability_res.get("false_positives_eliminated", 0),
            graph_node_count=graph_res.get("graph_nodes", 0),
            graph_edge_count=graph_res.get("graph_edges", 0),
            average_blast_radius=graph_res.get("avg_blast_radius", 0.0),
            predicted_zero_day_threats=predicted_zero_days,
            breaking_changes_prevented=breaking_changes,
            reachability_graph=reachability_graph,
            supply_chain_dag=supply_chain_dag,
            ml_feature_breakdown=ml_feature_breakdown,
            breaking_change_details=breaking_change_details,
            score_breakdown=score_breakdown
        )

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
            score_breakdown=score_breakdown,
        )
