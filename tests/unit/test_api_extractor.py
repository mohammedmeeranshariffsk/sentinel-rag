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


def test_api_records_include_enclosing_context_and_arguments(tmp_path):
    source_file = tmp_path / "AccessibilityWorker.java"
    source_file.write_text(
        """
class AccessibilityWorker {
    void onAccessibilityEvent(Object event) {
        service.dispatchGesture(gesture, callback, null);
    }
}
""",
        encoding="utf-8",
    )

    result = next(
        item for item in APIExtractor().extract_file(source_file)
        if item.api_name == "dispatchGesture"
    )

    assert result.location.class_name == "AccessibilityWorker"
    assert result.location.method_name == "onAccessibilityEvent"
    assert result.location.line == 4
    assert result.arguments == ["gesture", "callback", "null"]
    assert result.call_context == "service.dispatchGesture(gesture, callback, null);"
