from pathlib import Path

import typer

from sentinel.apk.inspector import APKInspector
from sentinel.decompiler.pipeline import DecompilerPipeline
from sentinel.extraction.pipeline import ExtractionPipeline
from sentinel.manifest.analyzer import ManifestAnalyzer
from sentinel.threat_intel import ThreatKnowledgeBase, ThreatMatcher

from dotenv import load_dotenv

from sentinel.program_analysis import BehaviorSliceBuilder
from sentinel.rag.document_loader import KnowledgeDocumentLoader
from sentinel.rag.embeddings import GeminiEmbeddingProvider
from sentinel.rag.indexer import KnowledgeIndexer
from sentinel.rag.query_builder import RetrievalQueryBuilder
from sentinel.rag.retriever import ThreatKnowledgeRetriever
from sentinel.rag.vector_store import QdrantVectorStore

load_dotenv()

app = typer.Typer(
    name="sentinel",
    help="Threat-informed Android security analysis.",
)


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


def run_extraction(apk: Path):
    context = APKInspector().inspect(apk)

    decompilation = DecompilerPipeline().run(context)

    context.manifest_path = decompilation.manifest_path
    context.source_path = decompilation.source_path
    context.smali_path = decompilation.smali_path

    manifest = None

    if context.manifest_path is not None:
        manifest = ManifestAnalyzer().analyze(
            context.manifest_path
        )

        context.package_name = manifest.package_name
        context.version_name = manifest.version_name
        context.version_code = manifest.version_code

    extraction = ExtractionPipeline().run(
        context=context,
        manifest=manifest,
    )

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

    context, manifest, extraction = run_extraction(apk)

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
) -> None:
    """
    Generate threat-informed investigation seeds from APK evidence.
    """

    context, manifest, extraction = run_extraction(apk)

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

    documents = KnowledgeDocumentLoader().load_json(
        Path("data/knowledge/android_security.json")
    )

    embedding_provider = GeminiEmbeddingProvider(
        dimension=768
    )

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

    typer.echo("")
    typer.echo("Threat-Informed Investigation Seeds")
    typer.echo("-" * 40)

    if not matches:
        typer.echo("No investigation seeds identified.")
        return

    for match in matches:
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

        retrieved = retriever.retrieve(
            query=query,
            limit=3,
        )

        typer.echo("")
        typer.echo("Retrieved Security Knowledge")

        for result in retrieved:
            typer.echo(
                f"  [{result.score:.4f}] "
                f"{result.title}"
            )


if __name__ == "__main__":
    app()