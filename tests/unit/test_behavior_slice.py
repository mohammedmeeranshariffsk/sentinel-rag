from pathlib import Path

import pytest

from sentinel.extraction.models import (
    EvidenceLocation,
    ExtractedAPI,
)
from sentinel.program_analysis.behavior_slice import (
    BehaviorSliceBuilder,
)


def test_build_behavior_slice(tmp_path: Path):
    source_file = tmp_path / "RootCheck.java"

    source_file.write_text(
        """
public class RootCheck {

    public void checkRoot() {
        String command = "/system/bin/su";
        Runtime.getRuntime().exec(command);
    }
}
""",
        encoding="utf-8",
    )

    api = ExtractedAPI(
        api_name="exec",
        full_reference="exec",
        location=EvidenceLocation(
            file=str(source_file),
            line=6,
        ),
        evidence="Runtime.getRuntime().exec(command);",
    )

    builder = BehaviorSliceBuilder(
        context_lines=3
    )

    result = builder.build_from_api(api)

    assert result is not None
    assert result.seed == "exec"
    assert result.line == 6

    joined_context = "\n".join(
        result.code_context
    )

    assert "Runtime.getRuntime().exec" in joined_context

    assert "/system/bin/su" in result.related_strings


def test_extract_actual_quoted_strings():
    builder = BehaviorSliceBuilder()

    assert builder._extract_related_strings([
        'Runtime.getRuntime().exec(command);',
        'String[] paths = {"/system/bin/su", "/system/xbin/su"};',
        r'String message = "say \"hello\"";',
        r'String path = "C:\\temp";',
        'String incomplete = "unterminated;',
    ]) == ["/system/bin/su", "/system/xbin/su", r'say \"hello\"', r'C:\\temp']


@pytest.mark.parametrize("value", ["", " ", "x", " x "])
def test_ignore_empty_and_short_strings(value: str):
    assert BehaviorSliceBuilder()._extract_related_strings([
        f'String value = "{value}";'
    ]) == []


@pytest.mark.parametrize("value", [
    "debug Runtime.call", "debug process.exec(command)",
    "debug reader.readLine()", "debug object.getRuntime()",
])
def test_ignore_code_like_strings(value: str):
    assert BehaviorSliceBuilder()._extract_related_strings([
        f'String debug = "{value}"; String command = "su";'
    ]) == ["su"]


def test_remove_duplicates_in_original_order():
    assert BehaviorSliceBuilder()._extract_related_strings([
        'String[] values = {"zz", "aa", "zz"};',
        'String[] more = {" aa ", "bb", "zz"};',
    ]) == ["zz", "aa", "bb"]


@pytest.mark.parametrize("line, radius, start, end", [
    (3, 1, 1, 4), (1, 1, 0, 2), (5, 1, 3, 5), (3, 0, 2, 3),
])
def test_source_context_is_bounded(tmp_path: Path, line, radius, start, end):
    source_file = tmp_path / "Example.java"
    lines = [f'String value{i} = "value{i}";' for i in range(5)]
    source_file.write_text("\n".join(lines), encoding="utf-8")
    api = ExtractedAPI(
        api_name="exec",
        full_reference="Runtime.exec",
        location=EvidenceLocation(file=str(source_file), line=line),
    )

    result = BehaviorSliceBuilder(context_lines=radius).build_from_api(api)

    assert result is not None
    assert result.seed == api.full_reference
    assert result.file == str(source_file)
    assert result.line == line
    assert result.code_context == lines[start:end]
    assert result.related_strings == [f"value{i}" for i in range(start, end)]
