from pydantic import BaseModel, Field


class CodeLocation(BaseModel):
    """Location of security-relevant code."""

    file: str
    line: int
    class_name: str | None = None
    method_name: str | None = None


class SecurityCandidate(BaseModel):
    """A deterministic security candidate produced by a rule."""

    candidate_id: str
    rule_id: str
    vulnerability: str

    severity: str

    location: CodeLocation

    evidence: list[str] = Field(default_factory=list)

    source: str | None = None
    sink: str | None = None

    description: str | None = None