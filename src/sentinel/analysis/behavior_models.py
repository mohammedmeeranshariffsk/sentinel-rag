"""Behavior-scoped investigation contracts. Model prose is never APK evidence."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field

from sentinel.program_analysis.behavior_graph import BehaviorGraph
from sentinel.program_analysis.investigation_seeds import InvestigationSeed
from sentinel.validation.models import LocalDataFlow, EvidenceState
from sentinel.rag.models import RetrievedKnowledge
from sentinel.threat_intel.models import ThreatMatch
from sentinel.findings.models import SecurityFinding


class ContextFact(BaseModel):
    evidence_id: str
    scope: Literal['LOCAL', 'APK']
    value: str
    file: str | None = None
    line: int | None = None
    references: list[str] = Field(default_factory=list)
    kind: str = 'presence'


class ContextRelationship(BaseModel):
    evidence_id: str
    source: str
    target: str
    relation: str
    references: list[str]


class SourceSinkAnnotation(BaseModel):
    evidence_id: str
    role: Literal['SOURCE', 'SINK']
    category: str
    qualification: str = 'API investigation label only; no data flow or runtime execution established'


class BehaviorContext(BaseModel):
    behavior_id: str
    behavior_name: str
    seeds: list[InvestigationSeed] = Field(default_factory=list)
    facts: list[ContextFact] = Field(default_factory=list)
    relationships: list[ContextRelationship] = Field(default_factory=list)
    local_data_flows: list[LocalDataFlow] = Field(default_factory=list)
    source_sink_annotations: list[SourceSinkAnnotation] = Field(default_factory=list)
    unresolved_relationships: list[str] = Field(default_factory=list)
    coverage_limitations: list[str] = Field(default_factory=list)
    context_limitations: list[str] = Field(default_factory=list)
    expected_relationships: list[str] = Field(default_factory=list)


class ReasonedFact(BaseModel):
    model_config = ConfigDict(extra='forbid')
    evidence_id: str
    value: str


class ReasonedRelationship(BaseModel):
    model_config = ConfigDict(extra='forbid')
    evidence_id: str
    source: str
    target: str
    relation: str


class BehaviorReasoningResult(BaseModel):
    model_config = ConfigDict(extra='forbid')
    behavior_id: str
    behavior_name: str
    summary: str = Field(max_length=1200)
    observed_facts: list[ReasonedFact] = Field(default_factory=list, max_length=64)
    supported_relationships: list[ReasonedRelationship] = Field(default_factory=list, max_length=64)
    hypotheses: list[str] = Field(default_factory=list, max_length=12)
    missing_evidence: list[str] = Field(default_factory=list, max_length=12)
    contradictions: list[str] = Field(default_factory=list, max_length=12)
    coverage_effects: list[str] = Field(default_factory=list, max_length=12)
    knowledge_context: list[ReasonedFact] = Field(default_factory=list, max_length=12)
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    recommended_next_investigation_steps: list[str] = Field(default_factory=list, max_length=12)


class BehaviorValidation(BaseModel):
    accepted_fact_ids: list[str] = Field(default_factory=list)
    accepted_relationship_ids: list[str] = Field(default_factory=list)
    accepted_knowledge_ids: list[str] = Field(default_factory=list)
    rejected_claims: list[str] = Field(default_factory=list)
    unresolved_hypotheses: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)
    evidence_state: EvidenceState = EvidenceState.NOT_VERIFIABLE_FROM_APK


class BehaviorInvestigation(BaseModel):
    reasoning_is_evidence: Literal[False] = False
    behavior_id: str
    behavior_name: str
    matched_indicators: ThreatMatch
    selected_seeds: list[InvestigationSeed] = Field(default_factory=list)
    graph: BehaviorGraph
    context: BehaviorContext
    retrieval_query: str = ''
    retrieved_knowledge: list[RetrievedKnowledge] = Field(default_factory=list)
    # Untrusted model output is retained only for audit, never used as graph facts.
    reasoning_result: BehaviorReasoningResult | None = None
    reasoning_status: Literal['disabled','unavailable','completed'] = 'disabled'
    retrieval_status: Literal['disabled','unavailable','completed'] = 'disabled'
    validation: BehaviorValidation = Field(default_factory=BehaviorValidation)
    validated_findings: list[SecurityFinding] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    stage_timings: dict[str, float] = Field(default_factory=dict)
