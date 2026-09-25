import re
from pathlib import Path
from typing import List
from .base import BaseParser
from ..models import Dependency


class GoParser(BaseParser):
    """Parser for Go module manifest files (go.mod)."""

    def can_parse(self, file_path: Path) -> bool:
        return file_path.name.lower() == "go.mod"

    def parse(self, file_path: Path) -> List[Dependency]:
        dependencies: List[Dependency] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            in_require_block = False
            for line in lines:
                line = line.strip()
                if not line or line.startswith("//"):
                    continue

                if line.startswith("require ("):
                    in_require_block = True
                    continue
                elif in_require_block and line == ")":
                    in_require_block = False
                    continue

                if line.startswith("require "):
                    # Single require line: require github.com/gin-gonic/gin v1.7.0
                    parts = line.split()
                    if len(parts) >= 3:
                        name, version = parts[1], parts[2]
                        is_indirect = "// indirect" in line
                        dependencies.append(
                            Dependency(
                                name=name,
                                version=version.lstrip("v"),
                                ecosystem="Go",
                                is_direct=not is_indirect,
                                file_origin=str(file_path)
                            )
                        )
                elif in_require_block:
                    parts = line.split()
                    if len(parts) >= 2:
                        name, version = parts[0], parts[1]
                        is_indirect = "// indirect" in line
                        dependencies.append(
                            Dependency(
                                name=name,
                                version=version.lstrip("v"),
                                ecosystem="Go",
                                is_direct=not is_indirect,
                                file_origin=str(file_path)
                            )
                        )
        except Exception as e:
            print(f"[!] Warning parsing go.mod at {file_path}: {e}")

        return dependencies
