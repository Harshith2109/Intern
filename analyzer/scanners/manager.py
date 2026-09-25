from pathlib import Path
from typing import List
from concurrent.futures import ThreadPoolExecutor, as_completed
from .osv_scanner import OSVScanner
from .trivy_scanner import TrivyScanner
from ..models import Dependency, DependencyAnalysis


class ScanManager:
    """Coordinates dependency parsing and vulnerability scanning across engines using thread pools."""

    def __init__(self, max_workers: int = 10):
        self.osv_scanner = OSVScanner()
        self.trivy_scanner = TrivyScanner()
        self.max_workers = max_workers

    def scan_dependencies(self, dependencies: List[Dependency]) -> List[DependencyAnalysis]:
        analyses: List[DependencyAnalysis] = []

        def _scan_dep(dep: Dependency) -> DependencyAnalysis:
            vulns = self.osv_scanner.scan_dependency(dep)
            return DependencyAnalysis(dependency=dep, vulnerabilities=vulns)

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_dep = {executor.submit(_scan_dep, dep): dep for dep in dependencies}
            for future in as_completed(future_to_dep):
                try:
                    analysis = future.result()
                    analyses.append(analysis)
                except Exception as e:
                    dep = future_to_dep[future]
                    print(f"[!] Warning scanning {dep.name}: {e}", flush=True)

        return analyses
