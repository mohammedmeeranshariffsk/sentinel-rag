from abc import ABC, abstractmethod
from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.manifest.analyzer import ManifestAnalysis
from sentinel.rules.models import SecurityCandidate


class SecurityRule(ABC):
    """Base interface for all SentinelRAG security rules."""

    rule_id: str
    name: str
    description: str
    default_severity: str

    @abstractmethod
    def analyze_file(
        self,
        file_path: Path,
        context: APKContext,
        manifest: ManifestAnalysis | None = None,
    ) -> list[SecurityCandidate]:
        """
        Analyze one source file and return security candidates.
        """
        raise NotImplementedError