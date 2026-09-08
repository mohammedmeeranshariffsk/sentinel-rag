from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.manifest.analyzer import ManifestAnalysis
from sentinel.rules.behaviors.base import BehaviorRule
from sentinel.rules.behaviors.models import BehaviorCandidate


class BehaviorEngine:
    """
    Executes malware-behavior rules against application-owned
    decompiled source code.

    By default, bundled libraries and framework code are excluded
    when the application's package name is available.
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
        if context.source_path is None:
            return []

        source_root = Path(context.source_path)

        if not source_root.exists():
            return []

        scan_root = self._resolve_application_source_root(
            source_root=source_root,
            manifest=manifest,
        )

        candidates: list[BehaviorCandidate] = []

        for file_path in self._iter_source_files(scan_root):
            for rule in self.rules:
                findings = rule.analyze_file(
                    file_path=file_path,
                    context=context,
                    manifest=manifest,
                )

                candidates.extend(findings)

        return self._deduplicate_candidates(
            candidates
        )

    @staticmethod
    def _resolve_application_source_root(
        source_root: Path,
        manifest: ManifestAnalysis | None,
    ) -> Path:
        """
        Resolve the application's source directory from its package.

        Example:

            package:
                owasp.sat.agoat

            JADX source:
                sources/owasp/sat/agoat

        If the package cannot be resolved to a directory, fall back
        to the full source tree so analysis does not silently fail.
        """
        if manifest is None:
            return source_root

        if not manifest.package_name:
            return source_root

        package_parts = manifest.package_name.split(".")

        application_root = source_root.joinpath(
            *package_parts
        )

        if application_root.exists():
            return application_root

        return source_root

    def _iter_source_files(
        self,
        source_root: Path,
    ):
        for file_path in source_root.rglob("*"):
            if not file_path.is_file():
                continue

            if (
                file_path.suffix.lower()
                not in self.SOURCE_EXTENSIONS
            ):
                continue

            yield file_path

    @staticmethod
    def _deduplicate_candidates(
        candidates: list[BehaviorCandidate],
    ) -> list[BehaviorCandidate]:
        seen: set[tuple[str, str, int]] = set()
        unique: list[BehaviorCandidate] = []

        for candidate in candidates:
            if candidate.primary_location is not None:
                file_name = (
                    candidate.primary_location.file
                )
                line_number = (
                    candidate.primary_location.line
                )
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