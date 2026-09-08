from abc import ABC, abstractmethod
from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.manifest.analyzer import ManifestAnalysis
from sentinel.rules.behaviors.models import BehaviorCandidate


class BehaviorRule(ABC):
    """
    Base contract for Android malware-behavior detectors.

    Behavior rules identify suspicious capabilities or actions.
    They do not directly attribute an APK to a malware family.
    """

    behavior_id: str
    name: str
    description: str
    category: str
    default_severity: str

    @abstractmethod
    def analyze_file(
        self,
        file_path: Path,
        context: APKContext,
        manifest: ManifestAnalysis | None = None,
    ) -> list[BehaviorCandidate]:
        """
        Analyze one decompiled source file and return behavior candidates.
        """
        raise NotImplementedError