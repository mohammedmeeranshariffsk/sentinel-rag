from sentinel.program_analysis.behavior_slice import BehaviorSlice
from sentinel.threat_intel.models import ThreatMatch


class RetrievalQueryBuilder:
    """
    Builds a semantic retrieval query from APK evidence
    and a threat-informed investigation seed.
    """

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