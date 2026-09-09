from pathlib import Path
from collections.abc import Callable

from dotenv import load_dotenv

# Load project configuration before importing modules that construct settings.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env")

import typer

from sentinel.apk.inspector import APKInspector
from sentinel.analysis.artifact_coverage import ArtifactCoverage, ArtifactCoverageAnalyzer
from sentinel.decompiler.pipeline import DecompilerPipeline
from sentinel.extraction.pipeline import ExtractionPipeline
from sentinel.manifest.analyzer import ManifestAnalyzer
from sentinel.threat_intel import ThreatKnowledgeBase, ThreatMatcher

from sentinel.program_analysis import BehaviorSliceBuilder
from sentinel.rag.document_loader import KnowledgeDocumentLoader
from sentinel.rag.embeddings import GeminiEmbeddingProvider
from sentinel.rag.indexer import KnowledgeIndexer
from sentinel.rag.query_builder import RetrievalQueryBuilder
from sentinel.rag.retriever import ThreatKnowledgeRetriever
from sentinel.rag.vector_store import QdrantVectorStore
from sentinel.reasoning.analyzer import SecurityReasoningAnalyzer
from sentinel.reasoning.gemini import GeminiReasoningProvider
from sentinel.reasoning.errors import safe_reasoning_error
from sentinel.validation.validator import EvidenceValidator
from sentinel.findings.builder import FindingBuilder
from sentinel.reporting.models import APKMetadata, AnalysisMetadata, SecurityReport
from sentinel.profiles.analyzer import ProfileAnalyzer
from sentinel.profiles.finding_builder import ProfileFindingBuilder
from sentinel.profiles.loader import ProfileLoader
from sentinel.profiles.models import ProfileOutcome
from sentinel.profiles.reasoning import ProfileReasoningAnalyzer

app = typer.Typer(
    name="sentinel",
    help="Threat-informed Android security analysis.",
)


def render_validated_finding(finding) -> None:
    typer.echo(f"\n[{finding.severity.value}] {finding.title}")
    typer.echo(f"Confidence: {finding.confidence:.2f}")
    typer.echo(f"Evidence State: {finding.evidence_state.value}")
    typer.echo(f"Assessment: {finding.assessment}")
    typer.echo("\nAPK Evidence:")
    if not finding.apk_evidence:
        typer.echo("- None")
    for item in finding.apk_evidence:
        if item.scope == "LOCAL":
            typer.echo(f"File: {item.file}")
            typer.echo(f"Line: {item.line}")
            for flow in item.local_data_flows:
                typer.echo(f"Source: {flow.source}")
                for transform in flow.transforms:
                    typer.echo(f"Transform: {transform}")
                typer.echo(f"Sink: {flow.sink}")
            if item.related_strings:
                typer.echo("Strings: " + ", ".join(item.related_strings))
        elif item.matched_indicators:
            values = [value for group in item.matched_indicators.values() for value in group]
            typer.echo("Broader APK Indicators: " + ", ".join(values))
    typer.echo("\nKnowledge References:")
    for item in finding.knowledge_references:
        source = f" ({item.source})" if item.source else ""
        typer.echo(f"- {item.title} [{item.reference}]{source}")
    if not finding.knowledge_references:
        typer.echo("- None")
    typer.echo("\nMissing Evidence:")
    for value in finding.missing_evidence or ["None"]:
        typer.echo(f"- {value}")
    typer.echo(f"\nRemediation:\n{finding.remediation or 'None'}")


def render_accessibility_graph(graph: dict[str, object] | None) -> None:
    """Render bounded APK graph facts without treating profile content as evidence."""
    if not graph or not graph.get("nodes"):
        return
    typer.echo("\nAccessibility Behavior Graph (APK evidence)")
    for edge in graph.get("edges", []):
        relation = edge["relation"].replace("_", " ")
        references = ", ".join(edge.get("evidence_refs", []))
        typer.echo(f"- {relation}: {references}")
    for relationship in graph.get("unsupported_relationships", []):
        typer.echo(f"- Not established: {relationship}")
    for limitation in graph.get("analysis_limitations", []):
        typer.echo(f"- Analysis limitation: {limitation}")


def render_artifact_coverage(coverage: ArtifactCoverage) -> None:
    typer.echo("\nArtifact / Decompilation Coverage")
    typer.echo("-" * 40)
    typer.echo(f"Analysis Mode: {coverage.analysis_mode.value.upper()}")
    typer.echo(f"Manifest: {'available' if coverage.manifest_available else 'unavailable'}")
    typer.echo(f"DEX Files: {len(coverage.dex_files_discovered)}")
    for dex in coverage.dex_entries:
        status = "readable" if dex.directly_readable else "unreadable"
        typer.echo(f"  - {dex.path}: {status}")
    typer.echo(f"JADX: {coverage.jadx_status.value}")
    typer.echo(f"JADX Source Classes: {coverage.jadx_class_count}")
    typer.echo(f"Application-Package Classes: {coverage.jadx_application_class_count}")
    typer.echo(
        "Application Implementation Classes: "
        f"{coverage.jadx_application_implementation_class_count}"
    )
    typer.echo(f"Apktool: {coverage.apktool_status.value}")
    typer.echo(f"Native Libraries: {len(coverage.native_libraries)}")
    typer.echo(f"Embedded Archives: {len(coverage.embedded_archives)}")
    typer.echo("Analysis Limitations:")
    if not coverage.limitations:
        typer.echo("  - None")
    for limitation in coverage.limitations:
        artifact = f" ({limitation.artifact})" if limitation.artifact else ""
        typer.echo(f"  - {limitation.code.value}{artifact}: {limitation.message}")


@app.callback()
def main() -> None:
    """SentinelRAG Android security analysis CLI."""
    pass


@app.command("inspect")
def inspect_apk(
    apk: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
) -> None:
    context = APKInspector().inspect(apk)

    typer.echo(f"APK: {context.apk_path}")
    typer.echo(f"SHA256: {context.sha256}")
    typer.echo(f"Size: {context.file_size:,} bytes")
    typer.echo(f"Workspace: {context.workspace}")


@app.command("decompile")
def decompile_apk(
    apk: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
) -> None:
    context = APKInspector().inspect(apk)

    result = DecompilerPipeline().run(context)

    typer.echo(f"APK: {context.apk_path.name}")
    typer.echo(
        f"Apktool: {'SUCCESS' if result.apktool_success else 'FAILED'}"
    )
    typer.echo(
        f"JADX: {'SUCCESS' if result.jadx_success else 'FAILED'}"
    )

    if result.manifest_path:
        typer.echo(f"Manifest: {result.manifest_path}")

    if result.source_path:
        typer.echo(f"Sources: {result.source_path}")

    if result.smali_path:
        typer.echo(f"Smali: {result.smali_path}")


def run_extraction(
    apk: Path,
    progress: Callable[[str], None] | None = None,
    include_decompilation: bool = False,
):
    notify = progress or (lambda _message: None)
    notify("Inspecting and hashing APK")
    context = APKInspector().inspect(apk)

    notify("Running Apktool and JADX decompilation")
    decompilation = DecompilerPipeline().run(context)

    context.manifest_path = decompilation.manifest_path
    context.source_path = decompilation.source_path
    context.smali_path = decompilation.smali_path

    manifest = None

    if context.manifest_path is not None:
        notify("Parsing Android manifest")
        manifest = ManifestAnalyzer().analyze(
            context.manifest_path
        )

        context.package_name = manifest.package_name
        context.version_name = manifest.version_name
        context.version_code = manifest.version_code

    notify("Extracting APIs, methods, strings, permissions and capabilities")
    extraction = ExtractionPipeline().run(
        context=context,
        manifest=manifest,
    )

    if include_decompilation:
        return context, manifest, extraction, decompilation
    return context, manifest, extraction


@app.command("extract")
def extract_apk(
    apk: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
) -> None:
    """
    Extract objective APK evidence and security capabilities.
    """

    context, manifest, extraction, decompilation = run_extraction(
        apk, include_decompilation=True
    )
    coverage = ArtifactCoverageAnalyzer().analyze(context, decompilation)

    typer.echo("")
    typer.echo("SentinelRAG Evidence Extraction")
    typer.echo("=" * 40)

    typer.echo(f"APK: {context.apk_path.name}")
    typer.echo(f"SHA256: {context.sha256}")

    if manifest:
        typer.echo(f"Package: {manifest.package_name}")

    typer.echo("")
    typer.echo("Evidence")
    typer.echo("-" * 40)

    typer.echo(f"APIs:         {len(extraction.apis)}")
    typer.echo(f"Strings:      {len(extraction.strings)}")
    typer.echo(f"Methods:      {len(extraction.methods)}")
    typer.echo(f"Permissions:  {len(extraction.permissions)}")
    typer.echo(f"Capabilities: {len(extraction.capabilities)}")
    render_artifact_coverage(coverage)

    typer.echo("")
    typer.echo("Capabilities")
    typer.echo("-" * 40)

    if not extraction.capabilities:
        typer.echo("No capabilities identified.")
    else:
        for capability in extraction.capabilities:
            typer.echo(
                f"[{capability.capability_id}] "
                f"{capability.name}"
            )

            for indicator in capability.matched_indicators:
                typer.echo(f"  - {indicator}")


@app.command("analyze")
def analyze_apk(
    apk: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    output_json: Path | None = typer.Option(None, '--output-json', dir_okay=False),
    profile: list[Path] = typer.Option(
        [], "--profile", exists=True, file_okay=True, dir_okay=False, readable=True,
        help="Extraction profile JSON. Repeat this option to review multiple profiles.",
    ),
) -> None:
    """
    Investigate APK evidence using retrieved context and security reasoning.
    """

    def show_progress(message: str) -> None:
        typer.echo(f"[progress] {message}")

    context, manifest, extraction, decompilation = run_extraction(
        apk, progress=show_progress, include_decompilation=True
    )
    coverage = ArtifactCoverageAnalyzer().analyze(context, decompilation)

    show_progress("Matching extracted evidence to threat knowledge")
    knowledge_base = ThreatKnowledgeBase()

    knowledge = knowledge_base.load_json(
        Path(
            "data/threat_intel/"
            "android_threat_knowledge.json"
        )
    )

    matches = ThreatMatcher().match(
        extraction=extraction,
        knowledge=knowledge,
    )

    # Build the RAG knowledge index.

    report = SecurityReport(
        apk_metadata=APKMetadata(
            path=str(context.apk_path), sha256=context.sha256,
            file_size=getattr(context, "file_size", None),
            package_name=getattr(context, "package_name", None),
            version_name=getattr(context, "version_name", None),
            version_code=getattr(context, "version_code", None),
        ),
        evidence_summary={name: len(getattr(extraction, name)) for name in (
            "apis", "strings", "methods", "permissions", "capabilities"
        )},
        artifact_coverage=coverage,
        analysis_metadata=AnalysisMetadata(
            reasoning_model=GeminiReasoningProvider.MODEL, seed_count=len(matches)
        ),
    )

    show_progress("Preparing retrieved security knowledge")
    documents = KnowledgeDocumentLoader().load_json(
        Path("data/knowledge/android_security.json")
    )

    retriever = None
    try:
        embedding_provider = GeminiEmbeddingProvider(dimension=768)
        vector_store = QdrantVectorStore(
            collection_name="sentinel_security_analysis",
            dimension=768,
            location=":memory:",
        )
        KnowledgeIndexer(
            embedding_provider=embedding_provider,
            vector_store=vector_store,
        ).index(documents)
        retriever = ThreatKnowledgeRetriever(
            embedding_provider=embedding_provider,
            vector_store=vector_store,
        )
    except Exception:
        typer.echo("Security knowledge retrieval unavailable; continuing with APK evidence.")
        report.analysis_metadata.errors.append("Knowledge index unavailable")

    show_progress("Preparing structured Gemini reasoning")
    reasoning = None
    reasoning_provider = None
    try:
        reasoning_provider = GeminiReasoningProvider()
        reasoning = SecurityReasoningAnalyzer(reasoning_provider)
    except Exception as error:
        detail = safe_reasoning_error(error)
        typer.echo(f"Security reasoning unavailable: {detail}")
        report.analysis_metadata.errors.append(detail)

    query_builder = RetrievalQueryBuilder()

    slice_builder = BehaviorSliceBuilder(
        context_lines=8
    )

    typer.echo("")
    typer.echo("SentinelRAG Threat-Informed Analysis")
    typer.echo("=" * 40)

    typer.echo(f"APK: {context.apk_path.name}")
    typer.echo(f"SHA256: {context.sha256}")

    if manifest:
        typer.echo(f"Package: {manifest.package_name}")

    typer.echo("")
    typer.echo("Evidence Summary")
    typer.echo("-" * 40)

    typer.echo(f"APIs:         {len(extraction.apis)}")
    typer.echo(f"Strings:      {len(extraction.strings)}")
    typer.echo(f"Methods:      {len(extraction.methods)}")
    typer.echo(f"Permissions:  {len(extraction.permissions)}")
    typer.echo(f"Capabilities: {len(extraction.capabilities)}")
    render_artifact_coverage(coverage)

    typer.echo("")
    typer.echo("Threat-Informed Investigation Seeds")
    typer.echo("-" * 40)

    if not matches:
        typer.echo("No investigation seeds identified.")

    for match_index, match in enumerate(matches, start=1):
        try:
            show_progress(
                f"Investigating threat seed {match_index}/{len(matches)}: "
                f"{match.knowledge_name}"
            )
            typer.echo("")
            typer.echo(
                f"[{match.knowledge_id}] "
                f"{match.knowledge_name}"
            )

            typer.echo(f"Score: {match.score}")

            matching_apis = [
                api
                for api in extraction.apis
                if api.api_name in match.matched_apis
            ]

            if not matching_apis:
                typer.echo(
                    "No API evidence available for behavior slicing."
                )
                continue

            # Prototype:
            # use first matching API occurrence.
            api = matching_apis[0]

            behavior_slice = slice_builder.build_from_api(
                api
            )

            if behavior_slice is None:
                typer.echo(
                    "Unable to construct behavior slice."
                )
                continue

            typer.echo("")
            typer.echo("Behavior Slice")
            typer.echo(f"File: {behavior_slice.file}")
            typer.echo(f"Line: {behavior_slice.line}")
            typer.echo(f"Seed: {behavior_slice.seed}")

            if behavior_slice.related_strings:
                typer.echo("Related Strings:")

                for value in behavior_slice.related_strings:
                    typer.echo(f"  - {value}")

            query = query_builder.build(
                threat_match=match,
                behavior_slice=behavior_slice,
            )

            retrieved = []
            if retriever is not None:
                try:
                    retrieved = retriever.retrieve(query=query, limit=3)
                except Exception:
                    typer.echo("Security knowledge retrieval failed for this seed.")
                    report.analysis_metadata.errors.append(f"{match.knowledge_id}: retrieval failed")

            typer.echo("")
            typer.echo("Retrieved Security Knowledge")

            for result in retrieved:
                typer.echo(
                    f"  [{result.score:.4f}] "
                    f"{result.title}"
                )

            if reasoning is not None:
                try:
                    assessment = reasoning.analyze(match, behavior_slice, retrieved)
                    validation = EvidenceValidator().validate(match, behavior_slice, retrieved, assessment)
                    finding = FindingBuilder().build(match, behavior_slice, retrieved, assessment, validation)
                    report.validated_findings.append(finding)
                except Exception as error:
                    # Do not print raw provider errors or unvalidated model output.
                    detail = safe_reasoning_error(error)
                    typer.echo(f"Security reasoning unavailable: {detail}")
                    report.analysis_metadata.errors.append(f"{match.knowledge_id}: {detail}")
                    continue


        except Exception:
            typer.echo("Investigation seed failed; continuing analysis.")
            report.analysis_metadata.errors.append(f"{match.knowledge_id}: seed failed")

    if profile:
        show_progress(f"Reviewing {len(profile)} extraction profile(s)")
        typer.echo("\n# Malware Profile Reviews")
    for profile_index, profile_path in enumerate(profile, start=1):
        try:
            show_progress(
                f"Matching profile {profile_index}/{len(profile)}: "
                f"{profile_path.name}"
            )
            loaded_profile = ProfileLoader().load(profile_path)
            profile_analysis = ProfileAnalyzer().analyze(
                loaded_profile, profile_path, extraction, manifest
            )
            report.profile_analyses.append(profile_analysis)
            report.analysis_metadata.profile_count += 1
            report.analysis_metadata.profile_seed_count += sum(
                item.outcome != ProfileOutcome.NO_SEED
                for item in profile_analysis.behavior_assessments
            )
            typer.echo(f"\nProfile: {loaded_profile.family_id}")
            typer.echo(f"Schema: {loaded_profile.schema_version}")
            typer.echo(f"Status: {loaded_profile.status}")
            typer.echo(f"Matched artifacts: {len(profile_analysis.artifact_matches)}")
            for artifact in profile_analysis.artifact_matches:
                location = (
                    f" ({artifact.file}:{artifact.line})" if artifact.file else ""
                )
                typer.echo(
                    f"- [{artifact.classification}] {artifact.value}{location}"
                )
            render_accessibility_graph(profile_analysis.accessibility_graph)

            for index, assessment in enumerate(profile_analysis.behavior_assessments):
                if assessment.outcome == ProfileOutcome.NO_SEED:
                    continue
                typer.echo(
                    f"- {assessment.bundle_id}: {assessment.outcome.value}"
                )
                model_result = None
                if reasoning_provider is not None:
                    try:
                        model_result = ProfileReasoningAnalyzer(reasoning_provider).analyze(
                            loaded_profile, profile_analysis, index
                        )
                        assessment.reasoning_summary = model_result.reasoning_summary
                    except Exception as error:
                        detail = safe_reasoning_error(error)
                        assessment.reasoning_error = detail
                        report.analysis_metadata.errors.append(
                            f"{loaded_profile.family_id}/{assessment.bundle_id}: {detail}"
                        )
                        typer.echo(f"  Profile reasoning unavailable: {detail}")
                finding = ProfileFindingBuilder().build(
                    profile_analysis, assessment, model_result
                )
                if finding is not None:
                    report.validated_findings.append(finding)
            typer.echo(profile_analysis.conclusion)
        except Exception as error:
            detail = safe_reasoning_error(error)
            typer.echo(f"Profile review unavailable: {detail}")
            report.analysis_metadata.errors.append(
                f"Profile {profile_path}: {detail}"
            )

    typer.echo("\n# Validated Findings")
    if not report.validated_findings:
        typer.echo("No validated findings.")
    for finding in report.validated_findings:
        render_validated_finding(finding)

    if report.analysis_metadata.errors:
        report.analysis_metadata.status = "partial"
    if output_json is not None:
        show_progress("Writing JSON report")
        report.write_json(output_json)
        typer.echo(f"\nJSON report: {output_json}")
    show_progress("Analysis complete")


if __name__ == "__main__":
    app()
