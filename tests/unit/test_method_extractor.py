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


def test_method_records_include_owner_and_body_bounds(tmp_path):
    source_file = tmp_path / "AccessibilityWorker.java"
    source_file.write_text(
        """
class AccessibilityWorker {
    void onAccessibilityEvent(Object event) {
        helper(event);
    }
}
""",
        encoding="utf-8",
    )

    method = MethodExtractor().extract_file(source_file)[0]

    assert method.class_name == "AccessibilityWorker"
    assert method.line == 3
    assert method.body_start_line == 3
    assert method.body_end_line == 5
    assert method.end_line == 5


def test_method_owner_does_not_leak_to_a_later_class(tmp_path):
    source_file = tmp_path / "TwoClasses.java"
    source_file.write_text(
        """class First {
    void one() {}
}
class Second {
    void two() {}
}
""",
        encoding="utf-8",
    )

    methods = MethodExtractor().extract_file(source_file)

    assert [(item.name, item.class_name) for item in methods] == [
        ("one", "First"),
        ("two", "Second"),
    ]
