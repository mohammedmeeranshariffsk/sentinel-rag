from enum import Enum

from pydantic import BaseModel, Field

from sentinel.reasoning.models import EvidenceClaim


class EvidenceState(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    SEMANTIC_SUSPECT = "SEMANTIC_SUSPECT"
    CORRELATED = "CORRELATED"
    NOT_VERIFIABLE_FROM_APK = "NOT_VERIFIABLE_FROM_APK"


class LocalDataFlow(BaseModel):
    source: str
    transforms: list[str] = Field(default_factory=list)
    sink: str
    file: str
    start_line: int
    end_line: int
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    evidence_lines: list[str] = Field(default_factory=list)
    command_prefix: str | None = None


class EvidenceValidationResult(BaseModel):
    evidence_state: EvidenceState
    supported_apk_refs: list[str] = Field(default_factory=list)
    supported_knowledge_refs: list[str] = Field(default_factory=list)
    supported_claims: list[EvidenceClaim] = Field(default_factory=list)
    unsupported_references: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    local_data_flows: list[LocalDataFlow] = Field(default_factory=list)
