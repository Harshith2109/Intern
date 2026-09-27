from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @property
    def score_weight(self) -> float:
        weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.5,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.5,
            Severity.UNKNOWN: 1.0,
        }
        return weights.get(self, 1.0)


class ReachabilityStatus(str, Enum):
    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class Vulnerability:
    vuln_id: str                          # e.g. CVE-2023-28155 or GHSA-xxx
    summary: str
    severity: Severity
    cvss_score: float = 0.0              # 0.0 - 10.0
    epss_score: float = 0.0              # 0.0 - 1.0 (Exploit Prediction Score)
    fixed_version: Optional[str] = None
    affected_versions: Optional[str] = None
    references: List[str] = field(default_factory=list)
    source: str = "OSV DB"                # e.g., "OSV DB", "Trivy Scanner"
    reachability: ReachabilityStatus = ReachabilityStatus.UNKNOWN
    reachable_symbols: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_id": self.vuln_id,
            "summary": self.summary,
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "fixed_version": self.fixed_version,
            "affected_versions": self.affected_versions,
            "references": self.references,
            "source": self.source,
            "reachability": self.reachability.value,
            "reachable_symbols": self.reachable_symbols,
        }


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str                       # e.g., "PyPI", "npm", "Maven"
    is_direct: bool = True               # Direct vs Transitive dependency flag
    file_origin: str = ""                # Path to source manifest file
    depth: int = 1                       # Dependency tree depth
    blast_radius_score: float = 0.0      # DAG Graph Centrality score (0 - 100)
    zero_day_risk_score: float = 0.0     # ML Predictive Zero-Day Score (0 - 100)

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version}".lower()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "is_direct": self.is_direct,
            "file_origin": self.file_origin,
            "depth": self.depth,
            "blast_radius_score": self.blast_radius_score,
            "zero_day_risk_score": self.zero_day_risk_score,
        }


@dataclass
class DependencyAnalysis:
    dependency: Dependency
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    breaking_change_risk: float = 0.0    # Breaking Change Index (0.0 - 1.0)
    is_reachable: bool = True

    @property
    def has_vulnerabilities(self) -> bool:
        return len(self.vulnerabilities) > 0

    @property
    def highest_severity(self) -> Severity:
        if not self.vulnerabilities:
            return Severity.LOW
        severities = [v.severity for v in self.vulnerabilities]
        if Severity.CRITICAL in severities:
            return Severity.CRITICAL
        if Severity.HIGH in severities:
            return Severity.HIGH
        if Severity.MEDIUM in severities:
            return Severity.MEDIUM
        return Severity.LOW

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dependency": self.dependency.to_dict(),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "highest_severity": self.highest_severity.value,
            "breaking_change_risk": self.breaking_change_risk,
            "is_reachable": self.is_reachable,
        }


@dataclass
class ResearchMetrics:
    total_packages_analyzed: int = 0
    false_positives_eliminated: int = 0
    graph_node_count: int = 0
    graph_edge_count: int = 0
    average_blast_radius: float = 0.0
    predicted_zero_day_threats: int = 0
    breaking_changes_prevented: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_packages_analyzed": self.total_packages_analyzed,
            "false_positives_eliminated": self.false_positives_eliminated,
            "graph_node_count": self.graph_node_count,
            "graph_edge_count": self.graph_edge_count,
            "average_blast_radius": self.average_blast_radius,
            "predicted_zero_day_threats": self.predicted_zero_day_threats,
            "breaking_changes_prevented": self.breaking_changes_prevented,
        }


@dataclass
class RiskReport:
    target_path: str
    scan_timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    dependencies: List[DependencyAnalysis] = field(default_factory=list)
    overall_risk_score: float = 0.0     # 0.0 - 100.0 scale
    risk_level: str = "LOW"             # CRITICAL, HIGH, MEDIUM, LOW
    total_dependencies: int = 0
    vulnerable_dependencies_count: int = 0
    severity_counts: Dict[str, int] = field(default_factory=lambda: {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0
    })
    quality_gate_passed: bool = True
    remediation_recommendations: List[Dict[str, str]] = field(default_factory=list)
    research_metrics: ResearchMetrics = field(default_factory=ResearchMetrics)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "scan_timestamp": self.scan_timestamp,
            "overall_risk_score": self.overall_risk_score,
            "risk_level": self.risk_level,
            "total_dependencies": self.total_dependencies,
            "vulnerable_dependencies_count": self.vulnerable_dependencies_count,
            "severity_counts": self.severity_counts,
            "quality_gate_passed": self.quality_gate_passed,
            "remediation_recommendations": self.remediation_recommendations,
            "research_metrics": self.research_metrics.to_dict(),
            "dependencies": [dep.to_dict() for dep in self.dependencies],
        }
