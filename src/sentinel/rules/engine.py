from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.manifest.analyzer import ManifestAnalysis
from sentinel.rules.base import SecurityRule
from sentinel.rules.models import SecurityCandidate
from sentinel.rules.scanner import CodeScanner


class RuleEngine:
    """Execute registered security rules against an APK."""

    def __init__(
        self,
        rules: list[SecurityRule],
        scanner: CodeScanner | None = None,
    ) -> None:
        self.rules = rules
        self.scanner = scanner or CodeScanner()

    def run(
        self,
        context: APKContext,
        manifest: ManifestAnalysis | None = None,
    ) -> list[SecurityCandidate]:
        """Run all rules against all supported source files."""

        if context.source_path is None:
            raise ValueError(
                "APKContext.source_path is not set. "
                "Decompile the APK before running code rules."
            )

        all_candidates: list[SecurityCandidate] = []

        for file_path in self.scanner.scan_directory(
            context.source_path
        ):
            for rule in self.rules:
                candidates = rule.analyze_file(
                    file_path=file_path,
                    context=context,
                    manifest=manifest,
                )

                all_candidates.extend(candidates)

        return all_candidates

    @staticmethod
    def deduplicate(
        candidates: list[SecurityCandidate],
    ) -> list[SecurityCandidate]:
        """Remove duplicate candidates."""

        seen: set[tuple[str, str, int]] = set()
        unique: list[SecurityCandidate] = []

        for candidate in candidates:
            key = (
                candidate.rule_id,
                candidate.location.file,
                candidate.location.line,
            )

            if key in seen:
                continue

            seen.add(key)
            unique.append(candidate)

        return unique