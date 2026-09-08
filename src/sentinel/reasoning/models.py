from pydantic import BaseModel, ConfigDict, Field
from typing import Literal


class EvidenceClaim(BaseModel):
    """A checkable text-presence claim or an explicitly unverified flow claim."""

    model_config = ConfigDict(extra="forbid")
    scope: Literal["LOCAL", "APK", "EXTERNAL"]
    reference: str
    value: str = Field(min_length=1)
    kind: Literal["PRESENCE", "FLOW"] = "PRESENCE"


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
    claims: list[EvidenceClaim] = Field(default_factory=list)
