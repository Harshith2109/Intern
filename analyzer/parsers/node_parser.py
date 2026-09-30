import json
from pathlib import Path
from typing import List
from .base import BaseParser
from ..models import Dependency


class NodeParser(BaseParser):
    """Parser for Node.js package.json files."""

    def can_parse(self, file_path: Path) -> bool:
        filename = file_path.name.lower()
        return "package" in filename and filename.endswith(".json")


    def parse(self, file_path: Path) -> List[Dependency]:
        dependencies: List[Dependency] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Direct dependencies
            deps = data.get("dependencies", {})
            for pkg, ver_spec in deps.items():
                version = str(ver_spec).lstrip("^~=>")
                dependencies.append(
                    Dependency(
                        name=pkg,
                        version=version or "latest",
                        ecosystem="npm",
                        is_direct=True,
                        file_origin=str(file_path),
                    )
                )

            # Dev dependencies (marked as dev dependency)
            dev_deps = data.get("devDependencies", {})
            for pkg, ver_spec in dev_deps.items():
                version = str(ver_spec).lstrip("^~=>")
                dependencies.append(
                    Dependency(
                        name=pkg,
                        version=version or "latest",
                        ecosystem="npm",
                        is_direct=False,
                        is_dev_dependency=True,
                        file_origin=str(file_path),
                    )
                )


        except Exception as e:
            print(f"[!] Warning: Error parsing {file_path}: {e}")

        return dependencies
