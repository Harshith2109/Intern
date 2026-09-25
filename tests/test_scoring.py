from analyzer.models import Dependency, Vulnerability, DependencyAnalysis, Severity
from analyzer.scoring import RiskEngine


def test_risk_engine_clean_project():
    dep = Dependency(name="clean-pkg", version="1.0.0", ecosystem="PyPI")
    analysis = DependencyAnalysis(dependency=dep, vulnerabilities=[])

    engine = RiskEngine(risk_threshold=70.0)
    report = engine.evaluate("clean-target", [analysis])

    assert report.overall_risk_score == 0.0
    assert report.risk_level == "LOW"
    assert report.total_dependencies == 1
    assert report.vulnerable_dependencies_count == 0
    assert report.quality_gate_passed is True


def test_risk_engine_critical_vuln():
    dep = Dependency(name="vulnerable-pkg", version="1.0.0", ecosystem="PyPI", is_direct=True)
    vuln = Vulnerability(
        vuln_id="CVE-2023-9999",
        summary="Critical Remote Code Execution",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
        fixed_version="1.0.1"
    )
    analysis = DependencyAnalysis(dependency=dep, vulnerabilities=[vuln])

    engine = RiskEngine(risk_threshold=70.0, fail_on_critical=True)
    report = engine.evaluate("vulnerable-target", [analysis])

    assert report.overall_risk_score >= 80.0
    assert report.risk_level == "CRITICAL"
    assert report.severity_counts["CRITICAL"] == 1
    assert report.quality_gate_passed is False
    assert len(report.remediation_recommendations) == 1
