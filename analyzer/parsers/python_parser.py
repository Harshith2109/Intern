import re
from pathlib import Path
from typing import List
from .base import BaseParser
from ..models import Dependency


class PythonParser(BaseParser):
    """Parser for Python dependency files (requirements.txt, pyproject.toml)."""

    def can_parse(self, file_path: Path) -> bool:
        filename = file_path.name.lower()
        return "requirement" in filename or filename.endswith(".req") or filename.endswith(".txt") or filename == "pyproject.toml"


    def parse(self, file_path: Path) -> List[Dependency]:
        filename = file_path.name.lower()
        if filename == "pyproject.toml":
            return self._parse_pyproject(file_path)
        return self._parse_requirements(file_path)

    def _parse_requirements(self, file_path: Path) -> List[Dependency]:
        dependencies: List[Dependency] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            for line in lines:
                line = line.strip()
                # Skip comments and empty lines or options like -r or -e
                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                # Strip inline comments
                if " #" in line:
                    line = line.split(" #")[0].strip()

                # Parse package name and version specification
                # Examples: requests==2.25.1, django>=3.2.0, flask~=2.0.1, urllib3
                match = re.match(r"^([a-zA-Z0-9_\-\.]+)(?:([=><~!]=?)(.+))?$", line)
                if match:
                    pkg_name = match.group(1).strip()
                    operator = match.group(2)
                    version = match.group(3)

                    # Clean up version string
                    if version:
                        # Take the first exact version if multiple constraints exist (e.g. >=1.0,<2.0 -> 1.0)
                        version = re.split(r"[,;]", version)[0].strip()
                        version = re.sub(r"[^0-9a-zA-Z\.\-\_]", "", version)
                    else:
                        version = "latest"

                    dependencies.append(
                        Dependency(
                            name=pkg_name,
                            version=version or "latest",
                            ecosystem="PyPI",
                            is_direct=True,
                            file_origin=str(file_path),
                        )
                    )
        except Exception as e:
            print(f"[!] Warning: Error reading {file_path}: {e}")

        return dependencies

    def _parse_pyproject(self, file_path: Path) -> List[Dependency]:
        dependencies: List[Dependency] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Regex extraction for dependencies section in pyproject.toml
            deps_matches = re.findall(r'([a-zA-Z0-9_\-\.]+)\s*=\s*["\']([^"\']+)["\']', content)
            for pkg, ver_spec in deps_matches:
                if pkg in ["python", "build-backend"]:
                    continue
                version = re.sub(r"[^0-9a-zA-Z\.\-\_]", "", ver_spec) or "latest"
                dependencies.append(
                    Dependency(
                        name=pkg,
                        version=version,
                        ecosystem="PyPI",
                        is_direct=True,
                        file_origin=str(file_path),
                    )
                )
        except Exception as e:
            print(f"[!] Warning: Error parsing pyproject.toml at {file_path}: {e}")

        return dependencies
