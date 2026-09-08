from sentinel.extraction.string_extractor import StringExtractor


def test_extract_strings(tmp_path):
    source_file = tmp_path / "Example.java"
    source_file.write_text(
        """
class Example {
    String url = "https://example.com/api";
    String command = "/system/bin/sh";
}
""",
        encoding="utf-8",
    )

    results = StringExtractor().extract_file(source_file)

    values = [item.value for item in results]

    assert "https://example.com/api" in values
    assert "/system/bin/sh" in values