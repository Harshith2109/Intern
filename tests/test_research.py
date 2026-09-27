from pathlib import Path
from analyzer.models import Dependency, Vulnerability, DependencyAnalysis, Severity
from analyzer.research import (
    ASTReachabilityAnalyzer,
    DependencyGraphEngine,
    MLZeroDayPredictor,
    ASTDiffBreakingChangeAnalyzer
)


def test_reachability_analyzer(tmp_path):
    py_file = tmp_path / "main.py"
    py_file.write_text("import requests\nprint(requests.get('https://example.com'))\n", encoding="utf-8")

    dep_req = Dependency(name="requests", version="2.25.0", ecosystem="PyPI")
    dep_unused = Dependency(name="unused-pkg", version="1.0.0", ecosystem="PyPI")

    vuln = Vulnerability(vuln_id="CVE-2023-1", summary="test", severity=Severity.HIGH)

    analysis_req = DependencyAnalysis(dependency=dep_req, vulnerabilities=[vuln])
    analysis_unused = DependencyAnalysis(dependency=dep_unused, vulnerabilities=[vuln])

    analyzer = ASTReachabilityAnalyzer()
    res = analyzer.analyze_workspace(tmp_path, [analysis_req, analysis_unused])

    assert res["false_positives_eliminated"] >= 1
    assert analysis_req.is_reachable is True
    assert analysis_unused.is_reachable is False


def test_dependency_graph_engine():
    dep1 = Dependency(name="pkg1", version="1.0.0", ecosystem="PyPI", is_direct=True, depth=1)
    dep2 = Dependency(name="pkg2", version="2.0.0", ecosystem="PyPI", is_direct=False, depth=2)

    vuln = Vulnerability(vuln_id="CVE-100", summary="test", severity=Severity.HIGH, cvss_score=8.5)

    a1 = DependencyAnalysis(dependency=dep1, vulnerabilities=[vuln])
    a2 = DependencyAnalysis(dependency=dep2, vulnerabilities=[])

    engine = DependencyGraphEngine()
    res = engine.compute_blast_radius([a1, a2])

    assert res["graph_nodes"] == 2
    assert dep1.blast_radius_score > 0.0


def test_ml_zero_day_predictor():
    dep = Dependency(name="old-pkg", version="0.1.0", ecosystem="PyPI")
    vuln = Vulnerability(vuln_id="CVE-200", summary="test", severity=Severity.HIGH, epss_score=0.45)
    analysis = DependencyAnalysis(dependency=dep, vulnerabilities=[vuln])

    predictor = MLZeroDayPredictor()
    threats = predictor.predict_zero_day_risks([analysis])

    assert dep.zero_day_risk_score > 30.0


def test_ast_diff_breaking_change_analyzer():
    dep = Dependency(name="breaking-pkg", version="1.0.0", ecosystem="PyPI")
    vuln = Vulnerability(vuln_id="CVE-300", summary="test", severity=Severity.HIGH, fixed_version="2.0.0")
    analysis = DependencyAnalysis(dependency=dep, vulnerabilities=[vuln])

    diff_analyzer = ASTDiffBreakingChangeAnalyzer()
    prevented = diff_analyzer.analyze_breaking_changes([analysis])

    assert analysis.breaking_change_risk >= 0.8
    assert prevented == 1
