from pathlib import Path

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