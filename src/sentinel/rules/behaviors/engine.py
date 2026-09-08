from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.manifest.analyzer import ManifestAnalysis
from sentinel.rules.behaviors.base import BehaviorRule
from sentinel.rules.behaviors.models import BehaviorCandidate


class BehaviorEngine:
    """
    Executes malware-behavior rules against decompiled APK source code.

    The behavior engine is intentionally separate from the vulnerability
    rule engine because behavior rules produce BehaviorCandidate objects
    rather than SecurityCandidate objects.
    """

    SOURCE_EXTENSIONS = {
        ".java",
        ".kt",
    }

    def __init__(
        self,
        rules: list[BehaviorRule],
    ) -> None:
        self.rules = rules

    def analyze(
        self,
        context: APKContext,
        manifest: ManifestAnalysis | None = None,
    ) -> list[BehaviorCandidate]:
        """
        Run all configured behavior rules against the APK source tree.
        """
        if context.source_path is None:
            return []

        source_root = Path(context.source_path)

        if not source_root.exists():
            return []

        candidates: list[BehaviorCandidate] = []

        for file_path in self._iter_source_files(source_root):
            for rule in self.rules:
                findings = rule.analyze_file(
                    file_path=file_path,
                    context=context,
                    manifest=manifest,
                )

                candidates.extend(findings)

        return self._deduplicate_candidates(candidates)

    def _iter_source_files(
        self,
        source_root: Path,
    ):
        for file_path in source_root.rglob("*"):
            if not file_path.is_file():
                continue

            if file_path.suffix.lower() not in self.SOURCE_EXTENSIONS:
                continue

            yield file_path

    @staticmethod
    def _deduplicate_candidates(
        candidates: list[BehaviorCandidate],
    ) -> list[BehaviorCandidate]:
        """
        Remove duplicate behavior findings produced for the same
        behavior and source location.
        """
        seen: set[tuple[str, str, int]] = set()
        unique: list[BehaviorCandidate] = []

        for candidate in candidates:
            if candidate.primary_location is not None:
                file_name = candidate.primary_location.file
                line_number = candidate.primary_location.line
            else:
                file_name = ""
                line_number = 0

            key = (
                candidate.behavior_id,
                file_name,
                line_number,
            )

            if key in seen:
                continue

            seen.add(key)
            unique.append(candidate)

        return unique