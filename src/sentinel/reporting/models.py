from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from sentinel.findings.models import SecurityFinding


class APKMetadata(BaseModel):
    path: str
    sha256: str
    file_size: int | None = None
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None


class AnalysisMetadata(BaseModel):
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reasoning_model: str
    status: str = "complete"
    seed_count: int = 0
    errors: list[str] = Field(default_factory=list)
    provenance_limitations: list[str] = Field(default_factory=lambda: [
        "Text presence does not prove execution, data flow, security impact or malware attribution.",
        "Broader APK matches lack source locations and do not establish local participation.",
        "External knowledge provenance identifies supplied documents, not source authenticity.",
        "Free-form LLM assertions are not deterministically verified or published as facts.",
    ])


class SecurityReport(BaseModel):
    apk_metadata: APKMetadata
    evidence_summary: dict[str, int]
    validated_findings: list[SecurityFinding] = Field(default_factory=list)
    analysis_metadata: AnalysisMetadata

    def write_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8")
