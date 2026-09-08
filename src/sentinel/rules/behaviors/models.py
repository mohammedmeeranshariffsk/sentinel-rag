from enum import Enum

from pydantic import BaseModel, Field

from sentinel.rules.models import CodeLocation


class EvidenceState(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    CORRELATED = "CORRELATED"
    NOT_VERIFIABLE_FROM_APK = "NOT_VERIFIABLE_FROM_APK"


class BehaviorSignal(BaseModel):
    signal_id: str
    description: str
    evidence_state: EvidenceState
    location: CodeLocation | None = None
    evidence: str | None = None
    weight: float = 1.0


class BehaviorCandidate(BaseModel):
    candidate_id: str
    behavior_id: str
    behavior: str
    category: str
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_state: EvidenceState
    signals: list[BehaviorSignal] = Field(default_factory=list)
    primary_location: CodeLocation | None = None
    description: str | None = None
    tags: list[str] = Field(default_factory=list)