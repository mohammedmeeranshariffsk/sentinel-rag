from sentinel.program_analysis.behavior_slice import BehaviorSlice
from sentinel.rag.models import RetrievedKnowledge
from sentinel.reasoning.models import SecurityReasoningResult
from sentinel.reasoning.prompt_builder import ReasoningPromptBuilder
from sentinel.threat_intel.models import ThreatMatch
from sentinel.validation.models import EvidenceState, EvidenceValidationResult
from sentinel.validation.local_flow import LocalDataFlowAnalyzer


class EvidenceValidator:
    """Checks literal presence and scope; never proves execution or data flow."""

    def validate(
        self, threat_match: ThreatMatch, behavior_slice: BehaviorSlice,
        knowledge: list[RetrievedKnowledge], reasoning: SecurityReasoningResult,
    ) -> EvidenceValidationResult:
        apk = ReasoningPromptBuilder().apk_evidence(threat_match, behavior_slice)
        # Ambiguous chunk identifiers cannot safely identify a unique source.
        knowledge_map = {}
        ambiguous = set()
        for item in knowledge:
            ref = f"knowledge:{item.chunk_id}"
            if ref in knowledge_map and knowledge_map[ref] != item:
                ambiguous.add(ref)
            knowledge_map[ref] = item
        for ref in ambiguous:
            del knowledge_map[ref]
        result = EvidenceValidationResult(evidence_state=EvidenceState.NOT_VERIFIABLE_FROM_APK)
        result.local_data_flows = LocalDataFlowAnalyzer().analyze(behavior_slice)
        for refs, allowed, supported in (
            (reasoning.apk_evidence_refs, apk, result.supported_apk_refs),
            (reasoning.knowledge_refs, knowledge_map, result.supported_knowledge_refs),
        ):
            for ref in dict.fromkeys(refs):
                if ref in allowed:
                    supported.append(ref)
                else:
                    result.unsupported_references.append(ref)
                    result.issues.append(f"Unsupported or ambiguous reference: {ref}")

        local_values = [behavior_slice.seed, *behavior_slice.code_context, *behavior_slice.related_strings]
        broader_values = [value for values in apk.get("apk:matched_indicators", {}).values() for value in values]
        for claim in reasoning.claims:
            valid = False
            if claim.value.strip() and claim.kind == "PRESENCE":
                if claim.scope == "LOCAL" and claim.reference == "apk:behavior_slice":
                    valid = claim.reference in result.supported_apk_refs and any(
                        claim.value == value or (value in behavior_slice.code_context and claim.value in value)
                        for value in local_values
                    )
                elif claim.scope == "APK" and claim.reference == "apk:matched_indicators":
                    valid = claim.reference in result.supported_apk_refs and claim.value in broader_values
                elif claim.scope == "EXTERNAL" and claim.reference in result.supported_knowledge_refs:
                    valid = claim.value in knowledge_map[claim.reference].content
            if valid:
                result.supported_claims.append(claim)
            else:
                result.issues.append(
                    f"Unsupported {claim.scope} {claim.kind} claim at {claim.reference}: {claim.value}"
                )

        if result.local_data_flows:
            result.evidence_state = EvidenceState.OBSERVED
            if "apk:behavior_slice" not in result.supported_apk_refs:
                result.supported_apk_refs.insert(0, "apk:behavior_slice")
            return result
        if result.issues:
            return result
        local = "apk:behavior_slice" in result.supported_apk_refs
        broader = "apk:matched_indicators" in result.supported_apk_refs
        if broader:
            result.evidence_state = EvidenceState.CORRELATED
        elif local:
            result.evidence_state = (
                EvidenceState.OBSERVED if any(c.scope == "LOCAL" for c in result.supported_claims)
                else EvidenceState.INFERRED
            )
        elif result.supported_knowledge_refs:
            result.evidence_state = EvidenceState.SEMANTIC_SUSPECT
        return result
