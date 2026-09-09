from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class ProfileArtifact(BaseModel):
    model_config = ConfigDict(extra="allow")

    value: str | None = None
    id: str | None = None
    description: str | None = None
    owner: str | None = None
    method: str | None = None
    kind: str | None = None
    declaration_type: str | None = None
    classification: str
    supports: list[str] = Field(default_factory=list)
    source_refs: list[str] = Field(default_factory=list)
    specificity: str | None = None

    @property
    def display_value(self) -> str:
        if self.owner and self.method:
            return f"{self.owner}.{self.method}"
        return self.value or self.id or self.description or "unknown"


class ProfileExtractors(BaseModel):
    manifest: list[ProfileArtifact] = Field(default_factory=list)
    api_calls: list[ProfileArtifact] = Field(default_factory=list)
    exact_strings: list[ProfileArtifact] = Field(default_factory=list)
    components_and_intents: list[ProfileArtifact] = Field(default_factory=list)
    structural_checks: list[ProfileArtifact] = Field(default_factory=list)


class BehaviorBundle(BaseModel):
    id: str
    template_ref: str
    seed_examples: list[str] = Field(default_factory=list)
    required_relationship: str


class ExtractionProfile(BaseModel):
    model_config = ConfigDict(extra="allow")

    schema_version: str
    status: str
    family_id: str
    classification_contract: dict[str, str]
    extractors: ProfileExtractors
    behavior_bundles: list[BehaviorBundle] = Field(default_factory=list)


class ProfileOutcome(str, Enum):
    NO_SEED = "NO_SEED"
    INDICATOR_MATCH = "INDICATOR_MATCH"
    APK_COOCCURRENCE = "APK_COOCCURRENCE"
    PARTIAL_RELATIONSHIP = "PARTIAL_RELATIONSHIP"
    RELATIONSHIP_SUPPORTED = "RELATIONSHIP_SUPPORTED"
    NOT_VERIFIABLE = "NOT_VERIFIABLE"


class ProfileArtifactMatch(BaseModel):
    reference: str
    artifact_group: str
    value: str
    classification: str
    source_refs: list[str] = Field(default_factory=list)
    file: str | None = None
    line: int | None = None


class ProfileBehaviorAssessment(BaseModel):
    bundle_id: str
    template_ref: str
    outcome: ProfileOutcome
    matched_evidence_refs: list[str] = Field(default_factory=list)
    required_relationship: str
    missing_evidence: list[str] = Field(default_factory=list)
    reasoning_summary: str | None = None
    reasoning_error: str | None = None


class ProfileAnalysis(BaseModel):
    profile_path: str
    profile_schema_version: str
    profile_status: str
    family_id: str
    artifact_matches: list[ProfileArtifactMatch] = Field(default_factory=list)
    behavior_assessments: list[ProfileBehaviorAssessment] = Field(default_factory=list)
    conclusion: str
    family_attribution_supported: bool = False
    limitations: list[str] = Field(default_factory=list)
