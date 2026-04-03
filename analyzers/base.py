from abc import ABC, abstractmethod
from typing import List, Set
from core.issue import Issue


class BaseAnalyzer(ABC):
    """Base class for all file analyzers."""

    EXTENSIONS: Set[str] = set()

    def can_analyze(self, filepath: str) -> bool:
        from pathlib import Path
        ext = Path(filepath).suffix.lower()
        return ext in self.EXTENSIONS

    @abstractmethod
    def analyze(self, filepath: str, content: str) -> List[Issue]:
        """Analyze a file and return a list of issues."""
        pass

    def _make_issue(self, filepath, line, severity, category, message, suggestion="", rule=""):
        return Issue(
            file=filepath,
            line=line,
            severity=severity,
            category=category,
            message=message,
            suggestion=suggestion,
            rule=rule,
        )
