from pathlib import Path
from collections.abc import Callable
from collections import Counter
from dataclasses import asdict
from time import perf_counter
import xml.etree.ElementTree as ET

from dotenv import load_dotenv

# Load project configuration before importing modules that construct settings.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env")

import typer
import logging
from sentinel.config.settings import AnalysisOptions
from sentinel.analysis.investigation import BehaviorInvestigator
from sentinel.threat_intel.starter_catalog import starter_records, catalog_documents, merge_catalog

from sentinel.apk.inspector import APKInspector
from sentinel.analysis.artifact_coverage import ArtifactCoverage, ArtifactCoverageAnalyzer
from sentinel.decompiler.pipeline import DecompilerPipeline
from sentinel.extraction.pipeline import ExtractionPipeline
from sentinel.extraction.models import ExtractionResult, ExtractedPermission
from sentinel.manifest.analyzer import ManifestAnalyzer
from sentinel.threat_intel import ThreatKnowledgeBase, ThreatMatcher

from sentinel.program_analysis import BehaviorSliceBuilder
from sentinel.program_analysis.source_index import SourceIndex
from sentinel.program_analysis.investigation_seeds import InvestigationSeedBuilder
from sentinel.program_analysis.behavior_graph import BehaviorGraphBuilder
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
    decompilation = DecompilerPipeline().run(context, allow_failed=True)

    context.manifest_path = decompilation.manifest_path
    context.source_path = decompilation.source_path
    context.smali_path = decompilation.smali_path

    manifest = None

    if context.manifest_path is not None:
        notify("Parsing Android manifest")
        try:
            manifest = ManifestAnalyzer().analyze(context.manifest_path)
            context.package_name = manifest.package_name
            context.version_name = manifest.version_name
            context.version_code = manifest.version_code
        except (ET.ParseError,OSError,ValueError):
            notify('Manifest parsing unavailable; retaining explicit coverage limitation')
            context.manifest_path = decompilation.manifest_path = None
            decompilation.errors.append('Recovered manifest could not be parsed')

    notify("Extracting APIs, methods, strings, permissions and capabilities")
    pipeline = ExtractionPipeline()
    if context.source_path and context.source_path.is_dir():
        extraction = pipeline.run(context=context,manifest=manifest)
    else:
        extraction = ExtractionResult(permissions=[ExtractedPermission(permission=p)
            for p in (manifest.permissions if manifest else [])])
        extraction.capabilities = pipeline.capability_extractor.extract(
            apis=[],strings=[],permissions=extraction.permissions)

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
    output_markdown: Path | None = typer.Option(None, '--output-markdown', dir_okay=False),
    graph_depth: int | None = typer.Option(None, '--graph-depth', min=0, max=3),
    no_llm: bool = typer.Option(False, '--no-llm'),
    no_rag: bool = typer.Option(False, '--no-rag'),
    verbose: bool = typer.Option(False, '--verbose'),
    profile: list[Path] = typer.Option(
        [], "--profile", exists=True, file_okay=True, dir_okay=False, readable=True,
        help="Extraction profile JSON. Repeat this option to review multiple profiles.",
    ),
) -> None:
    """
    Investigate APK evidence using retrieved context and security reasoning.
    """

    options = AnalysisOptions()
    if graph_depth is not None:
        options.graph_depth = graph_depth
    if no_llm:
        options.reasoning_enabled = False
    if no_rag:
        options.rag_enabled = False
    analysis_started = perf_counter()
    stage_started, stage_name, timings = analysis_started, 'initialization', {}

    def show_progress(message: str) -> None:
        nonlocal stage_started, stage_name
        now = perf_counter()
        timings[stage_name] = timings.get(stage_name,0)+now-stage_started
        stage_started,stage_name = now,message
        logging.getLogger('sentinel.analysis').info('analysis_stage', extra={'stage':message})
        typer.echo(f"[progress] {message}")

    context, manifest, extraction, decompilation = run_extraction(
        apk, progress=show_progress, include_decompilation=True
    )
    show_progress('Assessing artifact coverage')
    coverage = ArtifactCoverageAnalyzer().analyze(context, decompilation)

    show_progress("Matching extracted evidence to threat knowledge")
    knowledge_base = ThreatKnowledgeBase()

    catalog_errors = []
    try:
        knowledge = knowledge_base.load_json(PROJECT_ROOT/'data/threat_intel/android_threat_knowledge.json')
        if isinstance(knowledge_base.errors,list):
            catalog_errors.extend(knowledge_base.errors)
    except (ValueError,OSError,TypeError):
        knowledge = []
        catalog_errors.append('Local threat catalog unavailable; built-in analyst templates retained')

    if isinstance(knowledge, list):
        knowledge = merge_catalog(knowledge)

    matches = ThreatMatcher().match(
        extraction=extraction,
        knowledge=knowledge,
    )

    show_progress("Selecting source-located investigation seeds")
    source_index = SourceIndex.from_extraction(extraction)
    seed_builder = InvestigationSeedBuilder(
        extraction, getattr(context, "package_name", None), source_index, manifest=manifest, max_seeds_per_behavior=options.behavior_seed_budget
    )
    seeds = seed_builder.from_threats(matches)

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
        manifest_evidence=asdict(manifest) if manifest else {},
        investigation_seeds=seeds,
        source_ownership=list(seed_builder.ownership.records.values()),
        matched_indicators=matches,
        analysis_metadata=AnalysisMetadata(
            reasoning_model=GeminiReasoningProvider.MODEL, seed_count=len(matches), configuration=options.model_dump()
        ),
    )

    show_progress("Preparing retrieved security knowledge")
    report.analysis_metadata.errors.extend(catalog_errors)
    retriever = None
    try:
        if not options.rag_enabled:
            raise StopIteration
        documents = KnowledgeDocumentLoader().load_json(
            PROJECT_ROOT / Path("data/knowledge/android_security.json"))
        if isinstance(documents,list) and isinstance(knowledge,list):
            documents += catalog_documents(knowledge)
        embedding_provider = GeminiEmbeddingProvider(dimension=options.embedding_dimensions)
        vector_store = QdrantVectorStore(
            collection_name="sentinel_security_analysis",
            dimension=options.embedding_dimensions,
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
    except StopIteration:
        pass
    except Exception:
        typer.echo("Security knowledge retrieval unavailable; continuing with APK evidence.")
        report.analysis_metadata.errors.append("Knowledge index unavailable")

    show_progress("Preparing structured Gemini reasoning")
    reasoning_provider = None
    try:
        if not options.reasoning_enabled:
            raise StopIteration
        reasoning_provider = GeminiReasoningProvider()
        report.analysis_metadata.reasoning_model = getattr(reasoning_provider,'model',GeminiReasoningProvider.MODEL)
    except StopIteration:
        pass
    except Exception as error:
        detail = safe_reasoning_error(error)
        typer.echo(f"Security reasoning unavailable: {detail}")
        report.analysis_metadata.errors.append(detail)

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
    typer.echo("Threat-Matched Indicators")
    typer.echo("-" * 40)

    if not matches:
        typer.echo("No investigation seeds identified.")

    investigator = BehaviorInvestigator(extraction, source_index, seed_builder.ownership, options, slice_builder)
    records = {r.knowledge_id:r for r in knowledge} if isinstance(knowledge,list) else {}
    for match_index, match in enumerate(matches, start=1):
        try:
            show_progress(f"Building behavior graph {match_index}/{len(matches)}: {match.knowledge_name}")
            typer.echo(f"\n[{match.knowledge_id}] {match.knowledge_name} ? indicator score {match.score}")
            investigation = investigator.investigate(match,seeds,context,coverage,manifest,
                records.get(match.knowledge_id),retriever,reasoning_provider,show_progress)
            report.behavior_investigations.append(investigation)
            report.validated_findings.extend(investigation.validated_findings)
            report.analysis_metadata.errors.extend(investigation.errors)
            typer.echo("Retrieved Security Knowledge")
            for item in investigation.retrieved_knowledge:
                typer.echo(f"  [{item.score:.4f}] {item.title} (KNOWLEDGE context only)")
            for error in investigation.errors:
                typer.echo(error)
            typer.echo(f"Behavior graph: {len(investigation.graph.nodes)} nodes / {len(investigation.graph.edges)} edges; "
                       f"reasoning: {investigation.reasoning_status}; retrieval: {investigation.retrieval_status}")
        except Exception as error:
            detail = safe_reasoning_error(error)
            typer.echo(f"Investigation seed failed; continuing analysis. {detail}")
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
            report.investigation_seeds = seed_builder.select(
                report.investigation_seeds + seed_builder.from_profile(profile_analysis)
            )
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

    show_progress("Building bounded APK behavior graph")
    report.behavior_graph = BehaviorGraphBuilder(max_depth=options.graph_depth,
        max_nodes=options.graph_node_limit,max_methods=options.graph_method_limit).build(
        context, extraction, report.investigation_seeds, coverage, source_index,
        [item.accessibility_graph for item in report.profile_analyses if item.accessibility_graph],
        ownership=seed_builder.ownership,
    )
    selected_seeds = [s for s in report.investigation_seeds if s.selected_for_investigation]
    typer.echo("\n# Investigation Seeds")
    typer.echo(f"Selected: {len(selected_seeds)}; located: {sum(s.located for s in selected_seeds)}; "
               f"unlocated: {sum(not s.located for s in selected_seeds)}")
    typer.echo(f"Matched candidates retained: {len(report.investigation_seeds)}")
    typer.echo(f"Grouped duplicates: {sum(s.duplicate_count for s in selected_seeds)}")
    for provenance in dict.fromkeys(s.source_provenance for s in report.investigation_seeds):
        candidates = [s for s in report.investigation_seeds if s.source_provenance == provenance]
        typer.echo(f"{provenance.value}: {len(candidates)} candidates; "
                   f"{sum(s.selected_for_investigation for s in candidates)} selected")
    for seed in selected_seeds[:10]:
        typer.echo(f"- {seed.source_provenance.value} / {seed.quality.value}: {seed.matched_value}")
        typer.echo(f"  Ownership confidence: {seed.provenance_confidence:.2f}; "
                   + "; ".join(seed.provenance_reasons))
    graph = report.behavior_graph
    typer.echo("\n# Behavior Graph")
    typer.echo(f"Nodes: {len(graph.nodes)}; edges: {len(graph.edges)}; "
               f"unresolved relationships: {len(graph.unresolved_relationships)}")
    typer.echo(f"Expanded methods by provenance: {graph.expanded_methods_by_provenance}")
    typer.echo(f"Nodes by source provenance: {dict(Counter(n.source_provenance.value for n in graph.nodes))}")
    typer.echo(f"Hard graph limit reached: {graph.limit_reached}")
    for limitation in graph.analysis_limitations[:5]:
        typer.echo(f"- Analysis limitation: {limitation}")
    if len(graph.analysis_limitations) > 5:
        typer.echo(f"- {len(graph.analysis_limitations)-5} additional limitations retained in JSON")
    labels = {node.node_id: node.label for node in graph.nodes}
    for edge in graph.edges[:8]:
        typer.echo(f"- {labels[edge.source][:100]} -> {edge.relation.value} -> {labels[edge.target][:100]}")

    typer.echo("\n# Validated Findings")
    if not report.validated_findings:
        typer.echo("No validated findings.")
    for finding in report.validated_findings:
        render_validated_finding(finding)

    if report.analysis_metadata.errors:
        report.analysis_metadata.status = "partial"
    if coverage.analysis_mode == 'partial':
        report.analysis_metadata.status = 'partial'
    show_progress("Writing reports")
    report.analysis_metadata.stage_timings = {**timings,'total_before_reports':perf_counter()-analysis_started}
    output_json = output_json or PROJECT_ROOT/'reports'/f'{context.sha256[:12]}-analysis.json'
    output_markdown = output_markdown or output_json.with_suffix('.md')
    report.write_json(output_json)
    report.write_markdown(output_markdown)
    typer.echo(f"\nJSON report: {output_json}")
    typer.echo(f"Markdown report: {output_markdown}")
    if verbose:
        typer.echo(f"Analysis ID: {report.analysis_metadata.analysis_id}; timings: {report.analysis_metadata.stage_timings}")
    show_progress("Analysis complete")


knowledge_app = typer.Typer(help='Inspect and validate local investigation templates; no network calls.')
app.add_typer(knowledge_app,name='knowledge')


@knowledge_app.command('status')
def knowledge_status():
    typer.echo(f'{len(starter_records())} built-in behavior templates; schema 1.0; analyst-authored, not malware signatures.')


@knowledge_app.command('validate')
def knowledge_validate():
    base = ThreatKnowledgeBase()
    try:
        records = base.load_json(PROJECT_ROOT/'data/threat_intel/android_threat_knowledge.json')
        errors = base.errors
    except (ValueError,OSError,TypeError):
        records,errors = [],['Local threat catalog could not be loaded']
    for error in errors:
        typer.echo(error)
    typer.echo(f'Validated {len(records)} local records and {len(starter_records())} built-in templates.')
    if errors:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
