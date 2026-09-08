from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.extraction.api_extractor import APIExtractor
from sentinel.extraction.capability_extractor import CapabilityExtractor
from sentinel.extraction.method_extractor import MethodExtractor
from sentinel.extraction.models import (
    ExtractedPermission,
    ExtractionResult,
)
from sentinel.extraction.string_extractor import StringExtractor
from sentinel.manifest.analyzer import ManifestAnalysis


class ExtractionPipeline:
    SOURCE_EXTENSIONS = {".java", ".kt"}

    def __init__(self) -> None:
        self.api_extractor = APIExtractor()
        self.string_extractor = StringExtractor()
        self.method_extractor = MethodExtractor()
        self.capability_extractor = CapabilityExtractor()

    def run(
        self,
        context: APKContext,
        manifest: ManifestAnalysis | None = None,
    ) -> ExtractionResult:

        if context.source_path is None:
            raise ValueError("APK source path is not available")

        source_root = Path(context.source_path)

        if not source_root.exists():
            raise FileNotFoundError(
                f"Source path does not exist: {source_root}"
            )

        result = ExtractionResult(
            source_root=source_root,
        )

        scan_root = self._resolve_application_source_root(
            source_root,
            manifest,
        )

        for file_path in self._iter_source_files(scan_root):
            result.apis.extend(
                self.api_extractor.extract_file(file_path)
            )

            result.strings.extend(
                self.string_extractor.extract_file(file_path)
            )

            result.methods.extend(
                self.method_extractor.extract_file(file_path)
            )

        if manifest is not None:
            result.permissions = [
                ExtractedPermission(permission=permission)
                for permission in manifest.permissions
            ]

        result.capabilities = self.capability_extractor.extract(
            apis=result.apis,
            strings=result.strings,
            permissions=result.permissions,
        )

        return result

    @staticmethod
    def _resolve_application_source_root(
        source_root: Path,
        manifest: ManifestAnalysis | None,
    ) -> Path:

        if manifest is None or not manifest.package_name:
            return source_root

        package_root = source_root.joinpath(
            *manifest.package_name.split(".")
        )

        if package_root.exists():
            return package_root

        return source_root

    def _iter_source_files(self, source_root: Path):
        for file_path in source_root.rglob("*"):
            if (
                file_path.is_file()
                and file_path.suffix.lower()
                in self.SOURCE_EXTENSIONS
            ):
                yield file_path