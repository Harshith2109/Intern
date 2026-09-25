from abc import ABC, abstractmethod
from typing import List
from pathlib import Path
from ..models import Dependency


class BaseParser(ABC):
    """Abstract base class for all dependency manifest parsers."""

    @abstractmethod
    def can_parse(self, file_path: Path) -> bool:
        """Returns True if this parser supports the specified file."""
        pass

    @abstractmethod
    def parse(self, file_path: Path) -> List[Dependency]:
        """Parses the manifest file and returns a list of Dependency objects."""
        pass
