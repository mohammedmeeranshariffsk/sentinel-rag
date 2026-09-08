from sentinel.program_analysis.behavior_slice import BehaviorSlice
from sentinel.rag.models import RetrievedKnowledge
from sentinel.reasoning.models import SecurityReasoningResult
from sentinel.reasoning.prompt_builder import ReasoningPromptBuilder
from sentinel.reasoning.provider import LLMProvider
from sentinel.threat_intel.models import ThreatMatch


class SecurityReasoningAnalyzer:
    """Validate response structure and reference provenance, not claim semantics."""

    def __init__(self, provider: LLMProvider) -> None:
        self.provider = provider
        self.prompt_builder = ReasoningPromptBuilder()

    def analyze(
        self,
        threat_match: ThreatMatch,
        behavior_slice: BehaviorSlice,
        knowledge: list[RetrievedKnowledge],
    ) -> SecurityReasoningResult:
        prompt = self.prompt_builder.build(threat_match, behavior_slice, knowledge)
        response = self.provider.generate_structured(
            prompt, response_schema=SecurityReasoningResult.model_json_schema()
        )
        result = SecurityReasoningResult.model_validate_json(response)
        apk_refs = self.prompt_builder.apk_evidence(threat_match, behavior_slice)
        knowledge_refs = {f"knowledge:{item.chunk_id}" for item in knowledge}
        if not set(result.apk_evidence_refs).issubset(apk_refs):
            raise ValueError("Unknown APK evidence reference")
        if not set(result.knowledge_refs).issubset(knowledge_refs):
            raise ValueError("Unknown external knowledge reference")
        return result
