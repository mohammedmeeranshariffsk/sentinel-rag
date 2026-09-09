from pathlib import Path

from pydantic import BaseModel, Field


class EvidenceLocation(BaseModel):
    file: str
    line: int | None = None
    class_name: str | None = None
    method_name: str | None = None


class ExtractedAPI(BaseModel):
    api_name: str
    full_reference: str
    location: EvidenceLocation
    evidence: str | None = None
    arguments: list[str] = Field(default_factory=list)
    call_context: str | None = None


class ExtractedString(BaseModel):
    value: str
    location: EvidenceLocation
    evidence: str | None = None


class ExtractedMethod(BaseModel):
    name: str
    class_name: str | None = None
    file: str
    line: int | None = None
    end_line: int | None = None
    body_start_line: int | None = None
    body_end_line: int | None = None


class ExtractedPermission(BaseModel):
    permission: str


class SecurityCapability(BaseModel):
    capability_id: str
    name: str
    category: str
    confidence: float = Field(ge=0.0, le=1.0)
    matched_indicators: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class ExtractionResult(BaseModel):
    source_root: Path | None = None

    apis: list[ExtractedAPI] = Field(default_factory=list)
    strings: list[ExtractedString] = Field(default_factory=list)
    methods: list[ExtractedMethod] = Field(default_factory=list)
    permissions: list[ExtractedPermission] = Field(default_factory=list)
    capabilities: list[SecurityCapability] = Field(default_factory=list)
