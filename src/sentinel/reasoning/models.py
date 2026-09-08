from pydantic import BaseModel, ConfigDict, Field


class SecurityReasoningResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hypothesis: str
    behavior: str
    security_assessment: str
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    apk_evidence_refs: list[str]
    knowledge_refs: list[str]
    missing_evidence: list[str]
    remediation: str | None
    reasoning_summary: str
