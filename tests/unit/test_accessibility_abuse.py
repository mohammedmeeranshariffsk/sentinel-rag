from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.rules.behaviors.accessibility_abuse import (
    AccessibilityAbuseRule,
)
from sentinel.rules.behaviors.models import EvidenceState


def make_context(tmp_path: Path) -> APKContext:
    return APKContext(
        apk_path=tmp_path / "sample.apk",
        sha256="abc123",
        file_size=123,
        workspace=tmp_path,
    )


def test_detects_suspicious_accessibility_behavior(tmp_path):
    source = """
public class EvilAccessibilityService extends AccessibilityService {

    public void onAccessibilityEvent(AccessibilityEvent event) {
        AccessibilityNodeInfo root = getRootInActiveWindow();

        if (root != null) {
            root.performAction(
                AccessibilityNodeInfo.ACTION_CLICK
            );
        }
    }
}
"""

    source_file = tmp_path / "EvilAccessibilityService.java"
    source_file.write_text(source, encoding="utf-8")

    rule = AccessibilityAbuseRule()

    candidates = rule.analyze_file(
        source_file,
        make_context(tmp_path),
    )

    assert len(candidates) == 1

    candidate = candidates[0]

    assert candidate.behavior_id == "ACCESS-001"
    assert candidate.category == "accessibility"
    assert candidate.evidence_state == EvidenceState.INFERRED
    assert candidate.confidence >= 0.75

    signal_ids = {
        signal.signal_id
        for signal in candidate.signals
    }

    assert "ACCESS-SRC-001" in signal_ids
    assert "ACCESS-SRC-002" in signal_ids
    assert "ACCESS-SRC-003" in signal_ids
    assert "ACCESS-SRC-004" in signal_ids
    assert "ACCESS-SRC-007" in signal_ids


def test_does_not_flag_single_accessibility_reference(tmp_path):
    source = """
public class Helper {

    private AccessibilityEvent lastEvent;

}
"""

    source_file = tmp_path / "Helper.java"
    source_file.write_text(source, encoding="utf-8")

    rule = AccessibilityAbuseRule()

    candidates = rule.analyze_file(
        source_file,
        make_context(tmp_path),
    )

    assert candidates == []