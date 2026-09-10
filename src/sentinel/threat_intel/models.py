from pydantic import BaseModel, Field


class BehaviorRelationship(BaseModel):
    source: str | None = None
    operation: str
    sink: str | None = None


class ThreatKnowledge(BaseModel):
    schema_version: str = '1.0'
    malware_behavior_category: str = 'INVESTIGATION'
    classes: list[str] = Field(default_factory=list)
    components: list[str] = Field(default_factory=list)
    intents: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    sinks: list[str] = Field(default_factory=list)
    behavior_sequences: list[list[str]] = Field(default_factory=list)
    associated_capabilities: list[str] = Field(default_factory=list)
    known_false_positives: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    provenance: str = 'Local analyst-authored investigation specification; not APK evidence'
    updated_at: str = '2026-09-10'
    knowledge_id: str
    name: str
    description: str

    platform: str = "android"

    families: list[str] = Field(default_factory=list)
    techniques: list[str] = Field(default_factory=list)

    apis: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    strings: list[str] = Field(default_factory=list)
    method_patterns: list[str] = Field(default_factory=list)

    behaviors: list[BehaviorRelationship] = Field(
        default_factory=list
    )

    source: str | None = None
    published_at: str | None = None


class ThreatMatch(BaseModel):
    knowledge_id: str
    knowledge_name: str

    score: float = 0.0

    matched_apis: list[str] = Field(default_factory=list)
    matched_permissions: list[str] = Field(default_factory=list)
    matched_strings: list[str] = Field(default_factory=list)
    matched_methods: list[str] = Field(default_factory=list)
