from sentinel.rules.behaviors.models import (
    BehaviorCandidate,
    BehaviorSignal,
    EvidenceState,
)
from sentinel.rules.models import CodeLocation


def test_behavior_signal_creation():
    location = CodeLocation(
        file="ExampleAccessibilityService.java",
        line=42,
        class_name="ExampleAccessibilityService",
        method_name="onAccessibilityEvent",
    )

    signal = BehaviorSignal(
        signal_id="ACCESS-SIGNAL-001",
        description="AccessibilityNodeInfo interaction detected",
        evidence_state=EvidenceState.OBSERVED,
        location=location,
        evidence="node.performAction(...)",
        weight=2.0,
    )

    assert signal.signal_id == "ACCESS-SIGNAL-001"
    assert signal.evidence_state == EvidenceState.OBSERVED
    assert signal.weight == 2.0
    assert signal.location.line == 42


def test_behavior_candidate_creation():
    signal = BehaviorSignal(
        signal_id="ACCESS-SIGNAL-001",
        description="AccessibilityService implementation detected",
        evidence_state=EvidenceState.OBSERVED,
        weight=1.0,
    )

    candidate = BehaviorCandidate(
        candidate_id="ACCESS-001:ExampleAccessibilityService",
        behavior_id="ACCESS-001",
        behavior="Suspicious Accessibility Service Behavior",
        category="accessibility",
        severity="HIGH",
        confidence=0.75,
        evidence_state=EvidenceState.INFERRED,
        signals=[signal],
        description=(
            "Multiple accessibility-related signals indicate "
            "potential UI automation behavior."
        ),
        tags=["accessibility", "ui-automation"],
    )

    assert candidate.behavior_id == "ACCESS-001"
    assert candidate.confidence == 0.75
    assert candidate.evidence_state == EvidenceState.INFERRED
    assert len(candidate.signals) == 1
    assert "ui-automation" in candidate.tags