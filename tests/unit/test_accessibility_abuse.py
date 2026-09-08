from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.manifest.analyzer import (
    ComponentInfo,
    IntentFilterInfo,
    ManifestAnalysis,
)
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

def test_manifest_and_source_accessibility_correlation(
    tmp_path: Path,
):
    source = """
public class BankingHelper extends AccessibilityService {

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

    source_file = tmp_path / "BankingHelper.java"
    source_file.write_text(
        source,
        encoding="utf-8",
    )

    accessibility_filter = IntentFilterInfo(
        actions=[
            "android.accessibilityservice.AccessibilityService"
        ],
        categories=[],
        data_schemes=[],
        data_hosts=[],
    )

    accessibility_service = ComponentInfo(
        name="com.example.BankingHelper",
        component_type="service",
        declared_exported=False,
        permission=(
            "android.permission.BIND_ACCESSIBILITY_SERVICE"
        ),
        intent_filters=[
            accessibility_filter
        ],
    )

    manifest = ManifestAnalysis(
    manifest_path=tmp_path / "AndroidManifest.xml",
    package_name="com.example",
    services=[
        accessibility_service
    ],
    )

    rule = AccessibilityAbuseRule()

    candidates = rule.analyze_file(
        source_file,
        make_context(tmp_path),
        manifest=manifest,
    )

    assert len(candidates) == 1

    candidate = candidates[0]

    signal_ids = {
        signal.signal_id
        for signal in candidate.signals
    }

    assert "ACCESS-MANIFEST-001" in signal_ids
    assert "ACCESS-MANIFEST-002" in signal_ids
    assert "ACCESS-SRC-001" in signal_ids
    assert "ACCESS-SRC-004" in signal_ids

    assert candidate.confidence == 0.90
    assert candidate.primary_location is not None


def test_manifest_only_accessibility_service_not_flagged(
    tmp_path: Path,
):
    source = """
public class OrdinaryHelper {

    public void doWork() {
        System.out.println("hello");
    }
}
"""

    source_file = tmp_path / "OrdinaryHelper.java"
    source_file.write_text(
        source,
        encoding="utf-8",
    )

    accessibility_filter = IntentFilterInfo(
        actions=[
            "android.accessibilityservice.AccessibilityService"
        ],
        categories=[],
        data_schemes=[],
        data_hosts=[],
    )

    accessibility_service = ComponentInfo(
        name=(
            "com.example."
            "LegitimateAccessibilityService"
        ),
        component_type="service",
        declared_exported=False,
        permission=(
            "android.permission.BIND_ACCESSIBILITY_SERVICE"
        ),
        intent_filters=[
            accessibility_filter
        ],
    )

    manifest = ManifestAnalysis(
    manifest_path=tmp_path / "AndroidManifest.xml",
    package_name="com.example",
    services=[
        accessibility_service
    ],
    )

    rule = AccessibilityAbuseRule()

    candidates = rule.analyze_file(
        source_file,
        make_context(tmp_path),
        manifest=manifest,
    )

    assert candidates == []