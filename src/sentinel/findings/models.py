from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from sentinel.validation.models import EvidenceState, LocalDataFlow


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class APKEvidence(BaseModel):
    reference: str
    scope: Literal["LOCAL", "APK"]
    file: str | None = None
    line: int | None = None
    seed: str | None = None
    code_context: list[str] = Field(default_factory=list)
    related_strings: list[str] = Field(default_factory=list)
    matched_indicators: dict[str, list[str]] = Field(default_factory=dict)
    local_data_flows: list[LocalDataFlow] = Field(default_factory=list)


class KnowledgeReference(BaseModel):
    reference: str
    chunk_id: str
    document_id: str
    title: str
    source: str | None


class SecurityFinding(BaseModel):
    behavior_id: str | None = None
    graph_evidence_refs: list[str] = Field(default_factory=list)
    coverage_limitations: list[str] = Field(default_factory=list)
    unresolved_relationships: list[str] = Field(default_factory=list)
    finding_id: str
    title: str
    category: str
    severity: Severity
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    evidence_state: EvidenceState
    hypothesis: str
    behavior: str
    assessment: str
    apk_evidence: list[APKEvidence]
    knowledge_references: list[KnowledgeReference]
    missing_evidence: list[str]
    remediation: str | None
    reasoning_summary: str
