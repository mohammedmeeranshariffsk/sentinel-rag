from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.extraction.pipeline import ExtractionPipeline


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