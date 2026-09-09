import hashlib
import json

from sentinel.findings.models import APKEvidence, SecurityFinding, Severity
from sentinel.profiles.models import ProfileAnalysis, ProfileBehaviorAssessment, ProfileOutcome
from sentinel.reasoning.models import SecurityReasoningResult
from sentinel.validation.models import EvidenceState


class ProfileFindingBuilder:
    """Build conservative findings from deterministic profile outcomes."""

    def build(
        self, analysis: ProfileAnalysis, assessment: ProfileBehaviorAssessment,
        reasoning: SecurityReasoningResult | None = None,
    ) -> SecurityFinding | None:
        if assessment.outcome == ProfileOutcome.NO_SEED:
            return None
        matched = [
            item for item in analysis.artifact_matches
            if item.reference in assessment.matched_evidence_refs
        ]
        grouped: dict[str, list[str]] = {}
        for item in matched:
            grouped.setdefault(item.artifact_group, []).append(item.value)
        evidence = [APKEvidence(
            reference=f"apk:profile:{assessment.template_ref}",
            scope="APK", matched_indicators=grouped,
        )]
        if assessment.outcome == ProfileOutcome.INDICATOR_MATCH:
            assessment_text = (
                "One profile seed is present in the APK. The required behavior relationship "
                "has not been established, and malware-family attribution is unsupported."
            )
        else:
            assessment_text = (
                "Multiple profile seeds co-occur in the APK. Their participation in one behavior "
                "flow has not been established, and malware-family attribution is unsupported."
            )
        identity = json.dumps([analysis.family_id, assessment.template_ref, assessment.matched_evidence_refs])
        llm_summary = reasoning.reasoning_summary if reasoning else assessment_text
        return SecurityFinding(
            finding_id="PF-" + hashlib.sha256(identity.encode()).hexdigest()[:16],
            title=f"Profile review: {analysis.family_id} / {assessment.bundle_id}",
            category="MALWARE_PROFILE_CORRELATION",
            severity=Severity.INFO,
            confidence=min(reasoning.confidence, 0.5) if reasoning else (0.4 if len(matched) > 1 else 0.25),
            evidence_state=EvidenceState.CORRELATED,
            hypothesis=f"APK behavior may resemble {analysis.family_id} research context.",
            behavior=assessment_text,
            assessment=assessment_text,
            apk_evidence=evidence,
            knowledge_references=[],
            missing_evidence=assessment.missing_evidence + [
                "Distinctive corroborating evidence and compatible behavior relationships are required for family attribution."
            ],
            remediation="Review the matched locations and verify the required call/data-flow relationship.",
            reasoning_summary=llm_summary,
        )
