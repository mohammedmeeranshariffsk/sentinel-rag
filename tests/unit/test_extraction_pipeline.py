from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.extraction.pipeline import ExtractionPipeline
from sentinel.manifest.analyzer import ManifestAnalysis


def test_extraction_pipeline(tmp_path):
    source_root = tmp_path / "sources"
    source_root.mkdir()

    source_file = source_root / "Example.java"

    source_file.write_text(
        """
class Example {

    void run() {
        Runtime.getRuntime().exec("id");
        root.getRootInActiveWindow();
        String url = "https://example.com/api";
    }
}
""",
        encoding="utf-8",
    )

    context = APKContext(
        apk_path=Path("example.apk"),
        sha256="test",
        file_size=100,
        workspace=tmp_path,
        source_path=source_root,
    )

    result = ExtractionPipeline().run(context)

    api_names = {
        api.api_name
        for api in result.apis
    }

    strings = {
        item.value
        for item in result.strings
    }

    capability_ids = {
        capability.capability_id
        for capability in result.capabilities
    }

    assert "exec" in api_names
    assert "getRootInActiveWindow" in api_names
    assert "https://example.com/api" in strings

    assert "CAP-PROCESS-EXEC" in capability_ids
    assert "CAP-ACCESSIBILITY" in capability_ids


def test_pipeline_falls_back_when_manifest_package_contains_only_r_file(
    tmp_path,
):
    source_root = tmp_path / "sources"
    package_root = source_root / "example" / "app"
    package_root.mkdir(parents=True)
    (package_root / "R.java").write_text(
        "package example.app; final class R {}", encoding="utf-8"
    )
    (source_root / "payload").mkdir()
    (source_root / "payload" / "Loader.java").write_text(
        'class Loader { void run() { Runtime.getRuntime().exec("id"); } }',
        encoding="utf-8",
    )
    context = APKContext(
        apk_path=Path("example.apk"), sha256="test", file_size=100,
        workspace=tmp_path, source_path=source_root,
    )
    manifest = ManifestAnalysis(
        manifest_path=tmp_path / "AndroidManifest.xml",
        package_name="example.app",
    )

    result = ExtractionPipeline().run(context, manifest)

    assert "exec" in {item.api_name for item in result.apis}
