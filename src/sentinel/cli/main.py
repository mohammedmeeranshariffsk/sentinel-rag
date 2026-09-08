from pathlib import Path

import typer

from sentinel.apk.inspector import APKInspector
from sentinel.decompiler.pipeline import DecompilerPipeline
from sentinel.extraction.pipeline import ExtractionPipeline
from sentinel.manifest.analyzer import ManifestAnalyzer
from sentinel.threat_intel import ThreatKnowledgeBase, ThreatMatcher


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

        if match.matched_apis:
            typer.echo("Matched APIs:")

            for api in match.matched_apis:
                typer.echo(f"  - {api}")

        if match.matched_permissions:
            typer.echo("Matched Permissions:")

            for permission in match.matched_permissions:
                typer.echo(f"  - {permission}")

        if match.matched_strings:
            typer.echo("Matched Strings:")

            for value in match.matched_strings:
                typer.echo(f"  - {value}")

        if match.matched_methods:
            typer.echo("Matched Methods:")

            for method in match.matched_methods:
                typer.echo(f"  - {method}")


if __name__ == "__main__":
    app()