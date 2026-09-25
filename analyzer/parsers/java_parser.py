import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List
from .base import BaseParser
from ..models import Dependency


class JavaParser(BaseParser):
    """Parser for Java Maven pom.xml files."""

    def can_parse(self, file_path: Path) -> bool:
        return file_path.name.lower() == "pom.xml"

    def parse(self, file_path: Path) -> List[Dependency]:
        dependencies: List[Dependency] = []
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            # Remove XML namespaces if present
            ns = ""
            if root.tag.startswith("{"):
                ns = root.tag.split("}")[0] + "}"

            for dep_elem in root.findall(f".//{ns}dependency"):
                group_id = dep_elem.findtext(f"{ns}groupId", default="").strip()
                artifact_id = dep_elem.findtext(f"{ns}artifactId", default="").strip()
                version = dep_elem.findtext(f"{ns}version", default="latest").strip()

                if artifact_id:
                    name = f"{group_id}:{artifact_id}" if group_id else artifact_id
                    dependencies.append(
                        Dependency(
                            name=name,
                            version=version,
                            ecosystem="Maven",
                            is_direct=True,
                            file_origin=str(file_path),
                        )
                    )
        except Exception as e:
            print(f"[!] Warning: Error parsing {file_path}: {e}")

        return dependencies
