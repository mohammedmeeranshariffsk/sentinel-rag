"""Validate structured claims, never hidden reasoning or arbitrary narrative."""
from sentinel.analysis.behavior_models import BehaviorValidation
from sentinel.validation.models import EvidenceState


class BehaviorClaimValidator:
    def validate(self, context, result, knowledge, source_index):
        validation = BehaviorValidation(evidence_state=(
            EvidenceState.OBSERVED if context.local_data_flows else
            EvidenceState.CORRELATED if context.facts else EvidenceState.NOT_VERIFIABLE_FROM_APK))
        validation.issues.extend(context.coverage_limitations)
        validation.issues.extend(context.context_limitations)
        validation.issues.append('Source presence, call expressions and ownership hints do not establish runtime execution, intent or malware-family attribution.')
        if result is None:
            return validation
        if result.behavior_id != context.behavior_id or result.behavior_name != context.behavior_name:
            validation.rejected_claims.append('Behavior identity does not match supplied investigation')
            return validation
        facts = {f.evidence_id:f for f in context.facts}
        edges = {e.evidence_id:e for e in context.relationships}
        documents = {f'knowledge:{k.chunk_id}':k for k in knowledge}
        for claim in result.observed_facts:
            fact = facts.get(claim.evidence_id)
            if not fact or claim.value != fact.value:
                validation.rejected_claims.append(f'Unsupported APK fact: {claim.evidence_id}')
                continue
            if fact.file:
                source = source_index.sources.get(fact.file)
                if source is None or not fact.line or not 1 <= fact.line <= source.count('\n')+1:
                    validation.rejected_claims.append(f'Unavailable source location: {claim.evidence_id}')
                    continue
            validation.accepted_fact_ids.append(claim.evidence_id)
        for claim in result.supported_relationships:
            edge = edges.get(claim.evidence_id)
            if edge and (claim.source,claim.target,claim.relation)==(edge.source,edge.target,edge.relation):
                validation.accepted_relationship_ids.append(claim.evidence_id)
            else:
                validation.rejected_claims.append(f'Unsupported observed relationship: {claim.evidence_id}')
                validation.unresolved_hypotheses.append('Proposed relationship requires additional source/data-flow evidence')
        for claim in result.knowledge_context:
            item = documents.get(claim.evidence_id)
            if item and item.title == claim.value:
                validation.accepted_knowledge_ids.append(claim.evidence_id)
            else:
                validation.rejected_claims.append(f'Unsupported knowledge reference: {claim.evidence_id}')
        # Free-form prose cannot be semantically verified with reference existence.
        # Keep it in the untrusted reasoning record, not the published assessment.
        if result.hypotheses or result.summary or result.contradictions:
            validation.issues.append('LLM narrative, hypotheses and contradictions are unverified suggestions, not published APK facts.')
        if result.contradictions:
            validation.issues.append(f'LLM proposed {len(result.contradictions)} contradiction(s); analyst review required')
        if context.coverage_limitations:
            validation.issues.append('Artifact coverage is incomplete; missing behavior cannot be interpreted as absent.')
        return validation
