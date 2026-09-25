import re
from pathlib import Path
from typing import List
from .base import BaseParser
from ..models import Dependency


class RustParser(BaseParser):
    """Parser for Rust Cargo lockfiles (Cargo.lock)."""

    def can_parse(self, file_path: Path) -> bool:
        return file_path.name.lower() in ["cargo.lock", "cargo.toml"]

    def parse(self, file_path: Path) -> List[Dependency]:
        dependencies: List[Dependency] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse [[package]] blocks in Cargo.lock
            packages = re.findall(r'\[\[package\]\]\s*name\s*=\s*["\']([^"\']+)["\']\s*version\s*=\s*["\']([^"\']+)["\']', content)
            for pkg_name, pkg_version in packages:
                dependencies.append(
                    Dependency(
                        name=pkg_name,
                        version=pkg_version,
                        ecosystem="crates.io",
                        is_direct=True,
                        file_origin=str(file_path)
                    )
                )
        except Exception as e:
            print(f"[!] Warning parsing Cargo lockfile at {file_path}: {e}")

        return dependencies
