import json
from pathlib import Path
from ..models import RiskReport


class JSONReporter:
    """Exports risk reports to formatted JSON files."""

    def export(self, report: RiskReport, output_path: str):
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)

        return str(path)
