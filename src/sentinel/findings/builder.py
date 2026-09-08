import hashlib
import json

from sentinel.findings.models import APKEvidence, KnowledgeReference, SecurityFinding, Severity
from sentinel.program_analysis.behavior_slice import BehaviorSlice
from sentinel.rag.models import RetrievedKnowledge
from sentinel.reasoning.models import SecurityReasoningResult
from sentinel.reasoning.prompt_builder import ReasoningPromptBuilder
from sentinel.threat_intel.models import ThreatMatch
from sentinel.validation.models import EvidenceState, EvidenceValidationResult


class FindingBuilder:
    """Publish provenance-checked observations, not unchecked model prose.

    INFO is the default until a separate impact assessment supports a severity.
    Confidence describes evidence support, not maliciousness or exploitability.
    """

    def build(
        self, threat_match: ThreatMatch, behavior_slice: BehaviorSlice,
        knowledge: list[RetrievedKnowledge], reasoning: SecurityReasoningResult,
        validation: EvidenceValidationResult,
    ) -> SecurityFinding:
        evidence = []
        apk = ReasoningPromptBuilder().apk_evidence(threat_match, behavior_slice)
        for ref in validation.supported_apk_refs:
            if ref == "apk:behavior_slice":
                evidence.append(APKEvidence(
                    reference=ref, scope="LOCAL", file=behavior_slice.file,
                    line=behavior_slice.line, seed=behavior_slice.seed,
                    code_context=behavior_slice.code_context,
                    related_strings=behavior_slice.related_strings,
                    local_data_flows=validation.local_data_flows,
                ))
            elif ref == "apk:matched_indicators":
                evidence.append(APKEvidence(reference=ref, scope="APK", matched_indicators=apk[ref]))
        references = []
        seen = set()
        for item in knowledge:
            ref = f"knowledge:{item.chunk_id}"
            if ref in validation.supported_knowledge_refs and ref not in seen:
                seen.add(ref)
                references.append(KnowledgeReference(
                    reference=ref, chunk_id=item.chunk_id, document_id=item.document_id,
                    title=item.title, source=item.source,
                ))
        state = validation.evidence_state
        summaries = {
            EvidenceState.OBSERVED: "Literal text is observed in the local source slice; execution and intent are unverified.",
            EvidenceState.INFERRED: "Local source context supports investigation only; the proposed behavior remains unverified.",
            EvidenceState.CORRELATED: "Broader APK indicators are correlated with this investigation, but their participation in the local flow is unverified.",
            EvidenceState.SEMANTIC_SUSPECT: "Only external contextual knowledge is cited; no APK behavior is established.",
            EvidenceState.NOT_VERIFIABLE_FROM_APK: "The proposed behavior is not verifiable from the supplied APK evidence; unsupported claims were not promoted to findings.",
        }
        # Unsupported narrative is deliberately not copied into published fields.
        summary = summaries[state]
        observed_flow = bool(validation.local_data_flows)
        if observed_flow:
            flow = validation.local_data_flows[0]
            prefix = (
                f" beginning with {flow.command_prefix!r}" if flow.command_prefix is not None else ""
            )
            summary = (
                f"User-derived text is incorporated into a command string{prefix} and the "
                "resulting value is passed to Runtime.exec(). This establishes "
                "an observed input-to-command-execution flow. Exploitability and command-injection "
                "impact require additional validation."
            )
        missing = list(dict.fromkeys([
            *validation.issues,
            "Runtime reachability, intent and security impact remain unverified." if observed_flow
            else "Runtime reachability, data flow, intent and security impact remain unverified.",
            "Malware-family attribution is not established by this validation.",
        ]))
        identity = json.dumps([threat_match.knowledge_id, behavior_slice.file, behavior_slice.line, behavior_slice.seed])
        return SecurityFinding(
            finding_id="SF-" + hashlib.sha256(identity.encode()).hexdigest()[:16],
            title=f"Investigation: {threat_match.knowledge_name}",
            category="USER_INPUT_TO_COMMAND_EXECUTION" if observed_flow else "THREAT_INVESTIGATION",
            severity=Severity.MEDIUM if observed_flow else Severity.INFO,
            confidence=validation.local_data_flows[0].confidence if observed_flow else (
                0 if state in (EvidenceState.NOT_VERIFIABLE_FROM_APK, EvidenceState.SEMANTIC_SUSPECT)
                else min(reasoning.confidence, 0.5)
            ),
            evidence_state=state, hypothesis=f"Unverified hypothesis: {threat_match.knowledge_name}",
            behavior=summary,
            assessment="Insufficient evidence of malicious intent or confirmed security impact. " + summary,
            apk_evidence=evidence, knowledge_references=references,
            missing_evidence=missing,
            remediation="Review the cited source and verify reachability and impact before remediation." if evidence else None,
            reasoning_summary=summary,
        )
