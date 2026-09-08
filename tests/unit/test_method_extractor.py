from sentinel.extraction.method_extractor import MethodExtractor


def test_extract_java_methods(tmp_path):
    source_file = tmp_path / "Example.java"
    source_file.write_text(
        """
public class Example {

    public void loadPayload() {
    }

    private String decryptConfig(String input) {
        return input;
    }
}
""",
        encoding="utf-8",
    )

    results = MethodExtractor().extract_file(source_file)

    names = [item.name for item in results]

    assert "loadPayload" in names
    assert "decryptConfig" in names