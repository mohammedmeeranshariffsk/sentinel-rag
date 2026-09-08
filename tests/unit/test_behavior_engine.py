from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.rules.behaviors.accessibility_abuse import (
    AccessibilityAbuseRule,
)
from sentinel.rules.behaviors.engine import BehaviorEngine


def make_context(
    tmp_path: Path,
    source_path: Path | None = None,
) -> APKContext:
    return APKContext(
        apk_path=tmp_path / "sample.apk",
        sha256="abc123",
        file_size=123,
        workspace=tmp_path,
        source_path=source_path,
    )


def test_behavior_engine_scans_source_tree(
    tmp_path: Path,
):
    source_root = tmp_path / "sources"
    source_root.mkdir()

    source_file = source_root / "EvilAccessibilityService.java"

    source_file.write_text(
        """
public class EvilAccessibilityService
        extends AccessibilityService {

    public void onAccessibilityEvent(
        AccessibilityEvent event
    ) {
        AccessibilityNodeInfo root =
            getRootInActiveWindow();

        if (root != null) {
            root.performAction(
                AccessibilityNodeInfo.ACTION_CLICK
            );
        }
    }
}
""",
        encoding="utf-8",
    )

    context = make_context(
        tmp_path,
        source_path=source_root,
    )

    engine = BehaviorEngine(
        rules=[
            AccessibilityAbuseRule(),
        ]
    )

    candidates = engine.analyze(context)

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.behavior_id == "ACCESS-001"
    assert candidate.primary_location is not None


def test_behavior_engine_ignores_non_source_files(
    tmp_path: Path,
):
    source_root = tmp_path / "sources"
    source_root.mkdir()

    text_file = source_root / "notes.txt"

    text_file.write_text(
        """
extends AccessibilityService
AccessibilityNodeInfo
performAction(
""",
        encoding="utf-8",
    )

    context = make_context(
        tmp_path,
        source_path=source_root,
    )

    engine = BehaviorEngine(
        rules=[
            AccessibilityAbuseRule(),
        ]
    )

    candidates = engine.analyze(context)

    assert candidates == []


def test_behavior_engine_returns_empty_without_source_path(
    tmp_path: Path,
):
    context = make_context(
        tmp_path,
        source_path=None,
    )

    engine = BehaviorEngine(
        rules=[
            AccessibilityAbuseRule(),
        ]
    )

    candidates = engine.analyze(context)

    assert candidates == []