from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from sentinel.findings.models import SecurityFinding
from sentinel.analysis.artifact_coverage import ArtifactCoverage
from sentinel.profiles.models import ProfileAnalysis
from sentinel.program_analysis.investigation_seeds import InvestigationSeed
from sentinel.program_analysis.behavior_graph import BehaviorGraph
from sentinel.program_analysis.source_ownership import SourceOwnership
from sentinel.analysis.behavior_models import BehaviorInvestigation
from uuid import uuid4
from sentinel.threat_intel.models import ThreatMatch


class APKMetadata(BaseModel):
    path: str
    sha256: str
    file_size: int | None = None
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None


class AnalysisMetadata(BaseModel):
    analysis_id: str = Field(default_factory=lambda: str(uuid4()))
    stage_timings: dict[str, float] = Field(default_factory=dict)
    configuration: dict = Field(default_factory=dict)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    reasoning_model: str
    status: str = "complete"
    seed_count: int = 0
    profile_count: int = 0
    profile_seed_count: int = 0
    errors: list[str] = Field(default_factory=list)
    provenance_limitations: list[str] = Field(default_factory=lambda: [
        "Text presence does not prove execution, data flow, security impact or malware attribution.",
        "Broader APK matches lack source locations and do not establish local participation.",
        "External knowledge provenance identifies supplied documents, not source authenticity.",
        "Free-form LLM assertions are not deterministically verified or published as facts.",
    ])


class SecurityReport(BaseModel):
    schema_version: str = '1.0-prototype'
    manifest_evidence: dict = Field(default_factory=dict)
    behavior_investigations: list[BehaviorInvestigation] = Field(default_factory=list)
    apk_metadata: APKMetadata
    evidence_summary: dict[str, int]
    artifact_coverage: ArtifactCoverage | None = None
    investigation_seeds: list[InvestigationSeed] = Field(default_factory=list)
    source_ownership: list[SourceOwnership] = Field(default_factory=list)
    behavior_graph: BehaviorGraph | None = None
    matched_indicators: list[ThreatMatch] = Field(default_factory=list)
    validated_findings: list[SecurityFinding] = Field(default_factory=list)
    profile_analyses: list[ProfileAnalysis] = Field(default_factory=list)
    analysis_metadata: AnalysisMetadata

    def write_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2) + "\n", encoding="utf-8")

    def write_markdown(self, path: Path) -> None:
        from sentinel.reporting.markdown import render_markdown
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_markdown(self), encoding='utf-8')
