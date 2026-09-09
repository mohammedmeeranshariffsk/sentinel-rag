import json
from pathlib import Path
import struct
import zipfile

import pytest

from sentinel.analysis.artifact_coverage import (
    AnalysisMode,
    ArtifactCoverageAnalyzer,
    CoverageLimitationCode,
    ToolStatus,
)
from sentinel.apk.context import APKContext
from sentinel.decompiler.pipeline import DecompilationResult
from sentinel.reporting.models import APKMetadata, AnalysisMetadata, SecurityReport


def context_for(apk: Path, package_name: str = "example.app") -> APKContext:
    return APKContext(
        apk_path=apk, sha256="abc", file_size=apk.stat().st_size,
        workspace=apk.parent / "workspace", package_name=package_name,
    )


def write_apk(path: Path, dex: bytes = b"dex\n035\0payload") -> None:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", dex)


def recovered(tmp_path: Path, source: str, *, jadx_code: int = 0,
              apktool_success: bool = True) -> DecompilationResult:
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text("<manifest />", encoding="utf-8")
    sources = tmp_path / "sources"
    sources.mkdir(exist_ok=True)
    (sources / "Main.java").write_text(source, encoding="utf-8")
    return DecompilationResult(
        apktool_success=apktool_success,
        jadx_success=True,
        manifest_path=manifest,
        source_path=sources,
        apktool_return_code=0 if apktool_success else 1,
        jadx_return_code=jadx_code,
        errors=(
            ["JADX returned a non-zero exit code (1). Partial output may still be usable."]
            if jadx_code else []
        ),
    )


def limitation_codes(coverage) -> set[str]:
    return {item.code.value for item in coverage.limitations}


def test_readable_dex_and_recovered_application_source_is_complete(tmp_path):
    apk = tmp_path / "sample.apk"
    write_apk(apk)
    coverage = ArtifactCoverageAnalyzer().analyze(
        context_for(apk), recovered(tmp_path, "package example.app; class Main {}")
    )
    assert coverage.dex_readable is True
    assert coverage.dex_entries[0].directly_readable is True
    assert coverage.jadx_status == ToolStatus.SUCCESS
    assert coverage.jadx_class_count == 1
    assert coverage.jadx_application_class_count == 1
    assert coverage.jadx_application_implementation_class_count == 1
    assert coverage.analysis_mode == AnalysisMode.COMPLETE


def test_apktool_failure_does_not_hide_useful_jadx_output(tmp_path):
    apk = tmp_path / "sample.apk"
    write_apk(apk)
    coverage = ArtifactCoverageAnalyzer().analyze(
        context_for(apk), recovered(
            tmp_path, "package example.app; class Main {}", apktool_success=False
        )
    )
    assert coverage.jadx_status == ToolStatus.SUCCESS
    assert coverage.apktool_status == ToolStatus.FAILED
    assert coverage.jadx_application_implementation_class_count == 1
    assert coverage.analysis_mode == AnalysisMode.PARTIAL
    assert "APKTOOL_FAILED" in limitation_codes(coverage)


def test_nonzero_jadx_with_useful_sources_is_partial(tmp_path):
    apk = tmp_path / "sample.apk"
    write_apk(apk)
    coverage = ArtifactCoverageAnalyzer().analyze(
        context_for(apk), recovered(
            tmp_path, "package example.app; class Main {}", jadx_code=1
        )
    )
    assert coverage.jadx_status == ToolStatus.PARTIAL
    assert "JADX_PARTIAL" in limitation_codes(coverage)


@pytest.mark.parametrize("encrypted", [False, True])
def test_abnormal_or_encrypted_dex_is_not_directly_readable(tmp_path, encrypted):
    apk = tmp_path / "sample.apk"
    write_apk(apk, b"not-a-dex")
    if encrypted:
        data = bytearray(apk.read_bytes())
        for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            position = data.find(signature)
            flags = struct.unpack_from("<H", data, position + flag_offset)[0]
            struct.pack_into("<H", data, position + flag_offset, flags | 1)
        apk.write_bytes(data)
    coverage = ArtifactCoverageAnalyzer().analyze(
        context_for(apk), recovered(tmp_path, "package example.app; class Main {}")
    )
    assert coverage.dex_readable is False
    assert coverage.dex_entries[0].directly_readable is False
    assert "DEX_ENTRY_UNREADABLE" in limitation_codes(coverage)


def test_recovered_sources_outside_application_package_are_explicit(tmp_path):
    apk = tmp_path / "sample.apk"
    write_apk(apk)
    coverage = ArtifactCoverageAnalyzer().analyze(
        context_for(apk), recovered(tmp_path, "package library.only; class Helper {}")
    )
    assert coverage.jadx_class_count == 1
    assert coverage.jadx_application_class_count == 0
    assert "APPLICATION_SOURCE_UNAVAILABLE" in limitation_codes(coverage)


def test_artifact_coverage_serializes_in_security_report(tmp_path):
    apk = tmp_path / "sample.apk"
    write_apk(apk)
    coverage = ArtifactCoverageAnalyzer().analyze(
        context_for(apk), recovered(tmp_path, "package example.app; class Main {}")
    )
    report = SecurityReport(
        apk_metadata=APKMetadata(path=str(apk), sha256="abc"),
        evidence_summary={}, artifact_coverage=coverage,
        analysis_metadata=AnalysisMetadata(reasoning_model="fake"),
    )
    restored = SecurityReport.model_validate_json(report.model_dump_json())
    assert restored.artifact_coverage == coverage
    assert json.loads(report.model_dump_json())["artifact_coverage"]["dex_readable"] is True


def test_report_without_coverage_remains_compatible():
    report = SecurityReport(
        apk_metadata=APKMetadata(path="old.apk", sha256="abc"),
        evidence_summary={}, analysis_metadata=AnalysisMetadata(reasoning_model="fake"),
    )
    assert report.artifact_coverage is None
