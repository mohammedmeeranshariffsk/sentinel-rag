import re
from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.manifest.analyzer import ManifestAnalysis
from sentinel.rules.behaviors.base import BehaviorRule
from sentinel.rules.behaviors.models import (
    BehaviorCandidate,
    BehaviorSignal,
    EvidenceState,
)
from sentinel.rules.models import CodeLocation


ACCESSIBILITY_PERMISSION = (
    "android.permission.BIND_ACCESSIBILITY_SERVICE"
)

ACCESSIBILITY_ACTION = (
    "android.accessibilityservice.AccessibilityService"
)


class AccessibilityAbuseRule(BehaviorRule):
    behavior_id = "ACCESS-001"
    name = "Suspicious Accessibility Service Behavior"

    description = (
        "Detects combinations of Android Accessibility Service APIs "
        "that may indicate UI inspection or automation."
    )

    category = "accessibility"
    default_severity = "HIGH"

    SIGNALS = [
        (
            "ACCESS-SRC-001",
            re.compile(r"\bextends\s+AccessibilityService\b"),
            "AccessibilityService subclass detected",
            1.5,
        ),
        (
            "ACCESS-SRC-002",
            re.compile(r"\bAccessibilityEvent\b"),
            "AccessibilityEvent handling detected",
            1.0,
        ),
        (
            "ACCESS-SRC-003",
            re.compile(r"\bAccessibilityNodeInfo\b"),
            "AccessibilityNodeInfo interaction detected",
            2.0,
        ),
        (
            "ACCESS-SRC-004",
            re.compile(r"\.performAction\s*\("),
            "Accessibility node performAction() invocation detected",
            3.0,
        ),
        (
            "ACCESS-SRC-005",
            re.compile(r"\bperformGlobalAction\s*\("),
            "performGlobalAction() invocation detected",
            3.0,
        ),
        (
            "ACCESS-SRC-006",
            re.compile(r"\bdispatchGesture\s*\("),
            "dispatchGesture() invocation detected",
            3.0,
        ),
        (
            "ACCESS-SRC-007",
            re.compile(r"\bgetRootInActiveWindow\s*\("),
            "Active accessibility window inspection detected",
            2.0,
        ),
        (
            "ACCESS-SRC-008",
            re.compile(r"\bfindAccessibilityNodeInfosByText\s*\("),
            "Accessibility node search by text detected",
            2.5,
        ),
        (
            "ACCESS-SRC-009",
            re.compile(r"\bfindAccessibilityNodeInfosByViewId\s*\("),
            "Accessibility node search by view ID detected",
            2.5,
        ),
    ]

    def analyze_file(
        self,
        file_path: Path,
        context: APKContext,
        manifest: ManifestAnalysis | None = None,
    ) -> list[BehaviorCandidate]:
        try:
            lines = file_path.read_text(
                encoding="utf-8",
                errors="ignore",
            ).splitlines()
        except OSError:
            return []

        # Start with manifest-level evidence.
        signals: list[BehaviorSignal] = (
            self._collect_manifest_signals(manifest)
        )

        class_name = self._extract_class_name(lines)

        # Collect source-code signals.
        for line_number, line in enumerate(lines, start=1):
            for (
                signal_id,
                pattern,
                description,
                weight,
            ) in self.SIGNALS:
                if not pattern.search(line):
                    continue

                signals.append(
                    BehaviorSignal(
                        signal_id=signal_id,
                        description=description,
                        evidence_state=EvidenceState.OBSERVED,
                        location=CodeLocation(
                            file=str(file_path),
                            line=line_number,
                            class_name=class_name,
                            method_name=self._extract_method_name(
                                lines,
                                line_number,
                            ),
                        ),
                        evidence=line.strip(),
                        weight=weight,
                    )
                )

        if not signals:
            return []

        signals = self._deduplicate_signals(signals)

        # Manifest declarations alone are not sufficient.
        # We require at least one source-code behavior signal.
        has_source_signal = any(
            signal.signal_id.startswith("ACCESS-SRC-")
            for signal in signals
        )

        if not has_source_signal:
            return []

        score = sum(
            signal.weight
            for signal in signals
        )

        if score < 3.0:
            return []

        confidence = self._calculate_confidence(score)

        # Prefer a real source-code location over manifest-only signals.
        primary_location = next(
            (
                signal.location
                for signal in signals
                if signal.location is not None
            ),
            None,
        )

        return [
            BehaviorCandidate(
                candidate_id=(
                    f"{self.behavior_id}:"
                    f"{file_path}:"
                    f"{primary_location.line if primary_location else 0}"
                ),
                behavior_id=self.behavior_id,
                behavior=self.name,
                category=self.category,
                severity=self.default_severity,
                confidence=confidence,
                evidence_state=EvidenceState.INFERRED,
                signals=signals,
                primary_location=primary_location,
                description=(
                    "Multiple Android Accessibility Service signals were "
                    "detected. The combination may indicate UI inspection "
                    "or automated interaction. Accessibility functionality "
                    "alone is not sufficient to classify the application "
                    "as malicious."
                ),
                tags=[
                    "android",
                    "accessibility",
                    "ui-automation",
                ],
            )
        ]

    def _collect_manifest_signals(
        self,
        manifest: ManifestAnalysis | None,
    ) -> list[BehaviorSignal]:
        """
        Collect accessibility-related evidence from AndroidManifest.xml.

        The current ManifestAnalysis model exposes service permissions
        and intent-filter actions. Accessibility metadata can be added
        later when the manifest parser supports component meta-data.
        """
        if manifest is None:
            return []

        signals: list[BehaviorSignal] = []

        for service in manifest.services:
            if service.permission == ACCESSIBILITY_PERMISSION:
                signals.append(
                    BehaviorSignal(
                        signal_id="ACCESS-MANIFEST-001",
                        description=(
                            "Service protected by "
                            "BIND_ACCESSIBILITY_SERVICE"
                        ),
                        evidence_state=EvidenceState.OBSERVED,
                        evidence=(
                            f"{service.name} declares permission "
                            f"{ACCESSIBILITY_PERMISSION}"
                        ),
                        weight=2.0,
                    )
                )

            for intent_filter in service.intent_filters:
                if ACCESSIBILITY_ACTION in intent_filter.actions:
                    signals.append(
                        BehaviorSignal(
                            signal_id="ACCESS-MANIFEST-002",
                            description=(
                                "AccessibilityService intent "
                                "action declared"
                            ),
                            evidence_state=EvidenceState.OBSERVED,
                            evidence=(
                                f"{service.name} declares action "
                                f"{ACCESSIBILITY_ACTION}"
                            ),
                            weight=1.5,
                        )
                    )

        return self._deduplicate_signals(signals)

    @staticmethod
    def _calculate_confidence(
        score: float,
    ) -> float:
        if score >= 8.0:
            return 0.90

        if score >= 5.0:
            return 0.75

        return 0.55

    @staticmethod
    def _deduplicate_signals(
        signals: list[BehaviorSignal],
    ) -> list[BehaviorSignal]:
        """
        Keep only one occurrence of each signal type.

        For the prototype, repeated uses of the same API increase
        evidence quantity but should not automatically inflate the
        behavioral confidence score.
        """
        seen: set[str] = set()
        unique: list[BehaviorSignal] = []

        for signal in signals:
            if signal.signal_id in seen:
                continue

            seen.add(signal.signal_id)
            unique.append(signal)

        return unique

    @staticmethod
    def _extract_class_name(
        lines: list[str],
    ) -> str | None:
        class_pattern = re.compile(
            r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)"
        )

        for line in lines:
            match = class_pattern.search(line)

            if match:
                return match.group(1)

        return None

    @staticmethod
    def _extract_method_name(
        lines: list[str],
        line_number: int,
    ) -> str | None:
        method_pattern = re.compile(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*"
            r"\([^;{}]*\)\s*"
            r"(?:throws\s+[^{]+)?\{"
        )

        start_index = max(
            0,
            line_number - 20,
        )

        for index in range(
            line_number - 1,
            start_index - 1,
            -1,
        ):
            match = method_pattern.search(
                lines[index]
            )

            if not match:
                continue

            candidate = match.group(1)

            if candidate not in {
                "if",
                "for",
                "while",
                "switch",
                "catch",
            }:
                return candidate

        return None