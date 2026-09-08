from sentinel.extraction.api_extractor import APIExtractor


def test_extract_api_calls(tmp_path):
    source_file = tmp_path / "Example.java"
    source_file.write_text(
        """
class Example {
    void run() {
        Runtime.getRuntime().exec("id");
        root.getRootInActiveWindow();
    }
}
""",
        encoding="utf-8",
    )

    results = APIExtractor().extract_file(source_file)

    api_names = [item.api_name for item in results]

    assert "getRuntime" in api_names
    assert "exec" in api_names
    assert "getRootInActiveWindow" in api_names