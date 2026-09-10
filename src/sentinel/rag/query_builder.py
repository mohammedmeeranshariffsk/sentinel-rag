from sentinel.program_analysis.behavior_slice import BehaviorSlice
from sentinel.threat_intel.models import ThreatMatch


class RetrievalQueryBuilder:
    """
    Builds a semantic retrieval query from APK evidence
    and a threat-informed investigation seed.
    """

    def build_context(self, context) -> str:
        labels = {f.evidence_id:f.value for f in context.facts}
        parts = [f'Behavior investigation: {context.behavior_name}',
                 'Source presence does not imply execution or maliciousness.']
        parts.extend(f'{f.scope} {f.kind}: {f.value}' for f in context.facts[:32])
        parts.extend(f'Source relationship: {labels.get(e.source,e.source)} -> {e.relation} -> {labels.get(e.target,e.target)}'
                     for e in context.relationships[:12])
        parts.extend(f'Unresolved: {r[:200]}' for r in context.unresolved_relationships[:4])
        return '\n'.join(parts)[:6000]

    def build(
        self,
        threat_match: ThreatMatch,
        behavior_slice: BehaviorSlice,
    ) -> str:

        parts = [
            f"Threat hypothesis: {threat_match.knowledge_name}",
            f"Observed API: {behavior_slice.seed}",
        ]

        if threat_match.matched_apis:
            parts.append(
                "Matched APIs: "
                + ", ".join(threat_match.matched_apis)
            )

        if threat_match.matched_permissions:
            parts.append(
                "Matched permissions: "
                + ", ".join(threat_match.matched_permissions)
            )

        if threat_match.matched_strings:
            parts.append(
                "Matched strings: "
                + ", ".join(threat_match.matched_strings)
            )

        if behavior_slice.related_strings:
            parts.append(
                "Related code strings: "
                + ", ".join(
                    behavior_slice.related_strings
                )
            )

        if behavior_slice.code_context:
            parts.append(
                "Code context:\n"
                + "\n".join(
                    behavior_slice.code_context
                )
            )

        return "\n".join(parts)
