from pathlib import Path
from typing import List, Union
from .base import BaseParser
from .python_parser import PythonParser
from .node_parser import NodeParser
from .java_parser import JavaParser
from .go_parser import GoParser
from .rust_parser import RustParser
from ..models import Dependency

ALL_PARSERS: List[BaseParser] = [
    PythonParser(),
    NodeParser(),
    JavaParser(),
    GoParser(),
    RustParser(),
]


def find_and_parse(target_path: Union[str, Path]) -> List[Dependency]:
    """
    Scans a directory or specific file and returns all parsed dependencies.
    """
    path = Path(target_path).resolve()
    all_dependencies: List[Dependency] = []

    files_to_check: List[Path] = []
    if path.is_file():
        files_to_check.append(path)
    elif path.is_dir():
        # Look for standard dependency manifests recursively
        for pattern in ["*requirement*.txt", "*.txt", "*.req", "pyproject.toml", "*package*.json", "pom.xml", "*.xml", "go.mod", "Cargo.lock"]:
            files_to_check.extend(path.rglob(pattern))

    for file in files_to_check:
        for parser in ALL_PARSERS:
            if parser.can_parse(file):
                deps = parser.parse(file)
                all_dependencies.extend(deps)
                break

    # Deduplicate dependencies by ecosystem:name@version
    unique_deps: List[Dependency] = []
    seen = set()
    for dep in all_dependencies:
        if dep.key not in seen:
            seen.add(dep.key)
            unique_deps.append(dep)

    return unique_deps
