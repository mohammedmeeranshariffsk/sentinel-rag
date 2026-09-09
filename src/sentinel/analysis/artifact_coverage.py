"""Deterministic reporting of static-analysis artifact availability."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
import re
from typing import TYPE_CHECKING
import zipfile

from pydantic import BaseModel, Field

from sentinel.apk.context import APKContext

if TYPE_CHECKING:
    from sentinel.decompiler.pipeline import DecompilationResult


class ToolStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class AnalysisMode(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"


class CoverageLimitationCode(str, Enum):
    MANIFEST_UNAVAILABLE = "MANIFEST_UNAVAILABLE"
    APK_ARCHIVE_UNREADABLE = "APK_ARCHIVE_UNREADABLE"
    DEX_NOT_DISCOVERED = "DEX_NOT_DISCOVERED"
    DEX_ENTRY_UNREADABLE = "DEX_ENTRY_UNREADABLE"
    JADX_FAILED = "JADX_FAILED"
    JADX_PARTIAL = "JADX_PARTIAL"
    JADX_SOURCE_UNAVAILABLE = "JADX_SOURCE_UNAVAILABLE"
    APPLICATION_SOURCE_UNAVAILABLE = "APPLICATION_SOURCE_UNAVAILABLE"
    SOURCE_IMPLEMENTATION_UNAVAILABLE = "SOURCE_IMPLEMENTATION_UNAVAILABLE"
    APKTOOL_FAILED = "APKTOOL_FAILED"
    NATIVE_CODE_NOT_ANALYZED = "NATIVE_CODE_NOT_ANALYZED"
    EMBEDDED_ARCHIVE_NOT_ANALYZED = "EMBEDDED_ARCHIVE_NOT_ANALYZED"


class CoverageLimitation(BaseModel):
    code: CoverageLimitationCode
    message: str
    artifact: str | None = None


class DexEntryCoverage(BaseModel):
    path: str
    directly_readable: bool
    issue: str | None = None


class ArtifactCoverage(BaseModel):
    manifest_available: bool = False
    dex_files_discovered: list[str] = Field(default_factory=list)
    dex_readable: bool | None = None
    dex_entries: list[DexEntryCoverage] = Field(default_factory=list)
    jadx_status: ToolStatus = ToolStatus.FAILED
    jadx_class_count: int = 0
    jadx_application_class_count: int = 0
    jadx_application_implementation_class_count: int = 0
    apktool_status: ToolStatus = ToolStatus.FAILED
    native_libraries: list[str] = Field(default_factory=list)
    embedded_archives: list[str] = Field(default_factory=list)
    analysis_mode: AnalysisMode = AnalysisMode.PARTIAL
    limitations: list[CoverageLimitation] = Field(default_factory=list)


class ArtifactCoverageAnalyzer:
    """Describe recovery coverage without changing APK evidence semantics."""

    ARCHIVE_SUFFIXES = (".jar", ".zip", ".apk")
    PACKAGE_PATTERN = re.compile(
        r"^\s*package\s+([A-Za-z_$][\w.$]*)\s*;?", re.MULTILINE
    )
    GENERATED_SOURCE_NAMES = {"R.java", "R.kt", "BuildConfig.java", "BuildConfig.kt"}

    def analyze(
        self, context: APKContext, decompilation: DecompilationResult
    ) -> ArtifactCoverage:
        coverage = ArtifactCoverage(
            manifest_available=bool(
                decompilation.manifest_path
                and decompilation.manifest_path.is_file()
            ),
            jadx_status=self._jadx_status(decompilation),
            apktool_status=(
                ToolStatus.SUCCESS
                if decompilation.apktool_success
                else ToolStatus.FAILED
            ),
        )
        self._inspect_apk_archive(context.apk_path, coverage)
        self._inspect_jadx_sources(context, decompilation, coverage)
        self._derive_limitations(decompilation, coverage)
        coverage.analysis_mode = (
            AnalysisMode.COMPLETE if not coverage.limitations else AnalysisMode.PARTIAL
        )
        return coverage

    @staticmethod
    def _jadx_status(result: DecompilationResult) -> ToolStatus:
        source_path = result.source_path
        useful_output = bool(
            source_path and source_path.is_dir()
            and any(
                item.is_file() and item.suffix.lower() in {".java", ".kt"}
                for item in source_path.rglob("*")
            )
        )
        nonzero = result.jadx_return_code not in (None, 0)
        reported_error = any(
            error.startswith("JADX returned a non-zero exit code")
            for error in result.errors
        )
        if useful_output and (nonzero or reported_error):
            return ToolStatus.PARTIAL
        if result.jadx_success and useful_output:
            return ToolStatus.SUCCESS
        return ToolStatus.FAILED

    def _inspect_apk_archive(
        self, apk_path: Path, coverage: ArtifactCoverage
    ) -> None:
        try:
            with zipfile.ZipFile(apk_path) as archive:
                names = archive.namelist()
                coverage.dex_files_discovered = sorted(
                    name for name in names
                    if Path(name).name.startswith("classes")
                    and name.lower().endswith(".dex")
                )
                coverage.native_libraries = sorted(
                    name for name in names
                    if name.startswith("lib/") and name.lower().endswith(".so")
                )
                coverage.embedded_archives = sorted(
                    name for name in names
                    if name.lower().endswith(self.ARCHIVE_SUFFIXES)
                )
                for dex_file in coverage.dex_files_discovered:
                    coverage.dex_entries.append(
                        self._inspect_dex_entry(archive, dex_file)
                    )
                coverage.dex_readable = (
                    all(item.directly_readable for item in coverage.dex_entries)
                    if coverage.dex_entries else None
                )
        except (OSError, zipfile.BadZipFile):
            coverage.limitations.append(CoverageLimitation(
                code=CoverageLimitationCode.APK_ARCHIVE_UNREADABLE,
                message="APK archive could not be inspected with the standard ZIP reader.",
            ))

    @staticmethod
    def _inspect_dex_entry(
        archive: zipfile.ZipFile, dex_file: str
    ) -> DexEntryCoverage:
        try:
            with archive.open(dex_file) as handle:
                prefix = handle.read(8)
            if not prefix.startswith(b"dex\n"):
                return DexEntryCoverage(
                    path=dex_file, directly_readable=False,
                    issue="Entry does not begin with a DEX header.",
                )
            return DexEntryCoverage(path=dex_file, directly_readable=True)
        except (RuntimeError, OSError, zipfile.BadZipFile) as error:
            message = (
                "Entry is encrypted or inaccessible."
                if isinstance(error, RuntimeError)
                else "Entry could not be read."
            )
            return DexEntryCoverage(
                path=dex_file, directly_readable=False, issue=message
            )

    def _inspect_jadx_sources(
        self, context: APKContext, result: DecompilationResult,
        coverage: ArtifactCoverage,
    ) -> None:
        source_path = result.source_path
        if source_path is None or not source_path.is_dir():
            return
        source_files = sorted(
            file_path for file_path in source_path.rglob("*")
            if file_path.is_file() and file_path.suffix.lower() in {".java", ".kt"}
        )
        coverage.jadx_class_count = len(source_files)
        if not context.package_name:
            return
        for file_path in source_files:
            try:
                source = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            package_match = self.PACKAGE_PATTERN.search(source)
            package_name = package_match.group(1) if package_match else None
            if package_name != context.package_name:
                continue
            coverage.jadx_application_class_count += 1
            if (
                file_path.name not in self.GENERATED_SOURCE_NAMES
                and not file_path.name.startswith("R$")
            ):
                coverage.jadx_application_implementation_class_count += 1

    @staticmethod
    def _add_limitation(
        coverage: ArtifactCoverage, code: CoverageLimitationCode,
        message: str, artifact: str | None = None,
    ) -> None:
        if not any(
            item.code == code and item.artifact == artifact
            for item in coverage.limitations
        ):
            coverage.limitations.append(CoverageLimitation(
                code=code, message=message, artifact=artifact
            ))

    def _derive_limitations(
        self, result: DecompilationResult, coverage: ArtifactCoverage
    ) -> None:
        def add(
            code: CoverageLimitationCode, message: str,
            artifact: str | None = None,
        ) -> None:
            self._add_limitation(coverage, code, message, artifact)

        if not coverage.manifest_available:
            add(CoverageLimitationCode.MANIFEST_UNAVAILABLE, "Android manifest was not recovered.")
        if coverage.apktool_status == ToolStatus.FAILED:
            add(CoverageLimitationCode.APKTOOL_FAILED, "Apktool decompilation was unsuccessful.")
        if coverage.jadx_status == ToolStatus.FAILED:
            add(CoverageLimitationCode.JADX_FAILED, "JADX source decompilation was unsuccessful.")
        elif coverage.jadx_status == ToolStatus.PARTIAL:
            add(CoverageLimitationCode.JADX_PARTIAL, "JADX reported errors; recovered source may be incomplete.")
        if result.source_path is None or not result.source_path.is_dir():
            add(CoverageLimitationCode.JADX_SOURCE_UNAVAILABLE, "No JADX source directory was recovered.")
        if not coverage.dex_files_discovered:
            add(CoverageLimitationCode.DEX_NOT_DISCOVERED, "No DEX entries were discovered in the APK archive.")
        for entry in coverage.dex_entries:
            if not entry.directly_readable:
                add(CoverageLimitationCode.DEX_ENTRY_UNREADABLE,
                    entry.issue or "DEX entry could not be read directly.", entry.path)
        if coverage.jadx_class_count and not coverage.jadx_application_class_count:
            add(CoverageLimitationCode.APPLICATION_SOURCE_UNAVAILABLE,
                "JADX recovered source, but none belongs to the application package.")
        elif coverage.jadx_application_class_count and not coverage.jadx_application_implementation_class_count:
            add(CoverageLimitationCode.SOURCE_IMPLEMENTATION_UNAVAILABLE,
                "Only generated application-package source was recovered; implementation source is unavailable.")
        if coverage.native_libraries:
            add(CoverageLimitationCode.NATIVE_CODE_NOT_ANALYZED,
                "Native libraries were discovered but are outside current static source analysis.")
        if coverage.embedded_archives:
            add(CoverageLimitationCode.EMBEDDED_ARCHIVE_NOT_ANALYZED,
                "Embedded APK/JAR/ZIP artifacts were discovered but were not recursively analyzed.")
