from pathlib import Path


import typer

from sentinel.apk.inspector import APKInspector
from sentinel.decompiler.pipeline import DecompilerPipeline
from sentinel.manifest.analyzer import ManifestAnalyzer
from sentinel.rules import get_default_rules
from sentinel.rules.behaviors import get_default_behavior_rules
from sentinel.rules.behaviors.engine import BehaviorEngine
from sentinel.rules.engine import RuleEngine
from sentinel.extraction.pipeline import ExtractionPipeline
from sentinel.manifest.analyzer import ManifestAnalyzer


app = typer.Typer(
    name="sentinel",
    help="SentinelRAG Android security analysis CLI.",
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
        help="Path to the Android APK to inspect.",
    ),
) -> None:
    """Inspect an APK and display its basic metadata."""

    try:
        inspector = APKInspector()
        context = inspector.inspect(apk)

    except (FileNotFoundError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    typer.echo("")
    typer.echo("SentinelRAG APK Inspection")
    typer.echo("=" * 32)
    typer.echo(f"APK:       {context.apk_path}")
    typer.echo(f"SHA256:    {context.sha256}")
    typer.echo(f"Size:      {context.file_size:,} bytes")
    typer.echo(f"Workspace: {context.workspace}")
    typer.echo("")


@app.command("decompile")
def decompile_apk(
    apk: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to the Android APK to decompile.",
    ),
) -> None:
    """Decompile an APK using Apktool and JADX."""

    try:
        inspector = APKInspector()
        context = inspector.inspect(apk)

        pipeline = DecompilerPipeline()
        result = pipeline.run(context)

    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
    ) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    typer.echo("")
    typer.echo("SentinelRAG APK Decompilation")
    typer.echo("=" * 34)
    typer.echo(f"APK:       {context.apk_path.name}")
    typer.echo(f"Workspace: {context.workspace}")
    typer.echo("")

    typer.echo(
        f"Apktool:   "
        f"{'SUCCESS' if result.apktool_success else 'FAILED'}"
    )

    typer.echo(
        f"JADX:      "
        f"{'SUCCESS' if result.jadx_success else 'FAILED'}"
    )

    if result.manifest_path:
        typer.echo(
            f"Manifest:  {result.manifest_path}"
        )

    if result.source_path:
        typer.echo(
            f"Sources:   {result.source_path}"
        )

    if result.smali_path:
        typer.echo(
            f"Smali:     {result.smali_path}"
        )

    if result.errors:
        typer.echo("")
        typer.echo("Warnings:")

        for error in result.errors:
            typer.echo(
                f"  - {error}"
            )

    typer.echo("")
    typer.echo("Analysis status: READY")
    typer.echo("")


@app.command("analyze")
def analyze_apk(
    apk: Path = typer.Argument(
        ...,
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
        help="Path to the Android APK to analyze.",
    ),
) -> None:
    """
    Run deterministic security and malware-behavior analysis
    against an Android APK.
    """

    try:
        #
        # Stage 1: APK ingestion
        #
        inspector = APKInspector()
        context = inspector.inspect(apk)

        #
        # Stage 2: Decompilation
        #
        pipeline = DecompilerPipeline()
        decompilation = pipeline.run(context)

        #
        # The DecompilerPipeline currently returns these paths
        # rather than mutating APKContext directly.
        #
        context.manifest_path = decompilation.manifest_path
        context.source_path = decompilation.source_path
        context.smali_path = decompilation.smali_path

        #
        # Stage 3: Manifest analysis
        #
        manifest = None

        if context.manifest_path is not None:
            manifest_analyzer = ManifestAnalyzer()

            manifest = manifest_analyzer.analyze(
                context.manifest_path
            )

            context.package_name = (
                manifest.package_name
            )

            context.version_name = (
                manifest.version_name
            )

            context.version_code = (
                manifest.version_code
            )

        #
        # Stage 4: Vulnerability rules
        #
        vulnerability_candidates = []

        if context.source_path is not None:
            rule_engine = RuleEngine(
                rules=get_default_rules()
            )

            vulnerability_candidates = (
                rule_engine.run(
                    context=context,
                    manifest=manifest,
                )
            )

            vulnerability_candidates = (
                rule_engine.deduplicate(
                    vulnerability_candidates
                )
            )

        #
        # Stage 5: Malware-behavior rules
        #
        behavior_engine = BehaviorEngine(
            rules=get_default_behavior_rules()
        )

        behavior_candidates = (
            behavior_engine.analyze(
                context=context,
                manifest=manifest,
            )
        )

    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
    ) as exc:
        typer.echo(
            f"Error: {exc}",
            err=True,
        )

        raise typer.Exit(code=1)

    #
    # Output
    #
    typer.echo("")
    typer.echo("SentinelRAG Android Security Analysis")
    typer.echo("=" * 40)

    typer.echo(
        f"APK:      {context.apk_path.name}"
    )

    typer.echo(
        f"SHA256:   {context.sha256}"
    )

    typer.echo(
        f"Package:  "
        f"{context.package_name or 'Unknown'}"
    )

    typer.echo(
        f"Workspace: {context.workspace}"
    )

    typer.echo("")

    #
    # Decompiler status
    #
    typer.echo("Decompilation")
    typer.echo("-" * 40)

    typer.echo(
        f"Apktool: "
        f"{'SUCCESS' if decompilation.apktool_success else 'FAILED'}"
    )

    typer.echo(
        f"JADX:    "
        f"{'SUCCESS' if decompilation.jadx_success else 'FAILED'}"
    )

    if decompilation.errors:
        typer.echo("")
        typer.echo("Warnings:")

        for error in decompilation.errors:
            typer.echo(
                f"  - {error}"
            )

    #
    # Manifest summary
    #
    typer.echo("")
    typer.echo("Manifest")
    typer.echo("-" * 40)

    if manifest is None:
        typer.echo(
            "Manifest analysis unavailable."
        )

    else:
        typer.echo(
            f"Package:            "
            f"{manifest.package_name or 'Unknown'}"
        )

        typer.echo(
            f"Permissions:        "
            f"{len(manifest.permissions)}"
        )

        typer.echo(
            f"Activities:         "
            f"{len(manifest.activities)}"
        )

        typer.echo(
            f"Services:           "
            f"{len(manifest.services)}"
        )

        typer.echo(
            f"Receivers:          "
            f"{len(manifest.receivers)}"
        )

        typer.echo(
            f"Providers:          "
            f"{len(manifest.providers)}"
        )

        typer.echo(
            f"Debuggable:         "
            f"{manifest.debuggable}"
        )

        typer.echo(
            f"Allow backup:       "
            f"{manifest.allow_backup}"
        )

    #
    # Vulnerability findings
    #
    typer.echo("")
    typer.echo("Vulnerability Findings")
    typer.echo("-" * 40)

    if not vulnerability_candidates:
        typer.echo(
            "No vulnerability candidates detected."
        )

    else:
        typer.echo(
            f"Candidates: "
            f"{len(vulnerability_candidates)}"
        )

        for index, candidate in enumerate(
            vulnerability_candidates,
            start=1,
        ):
            typer.echo("")

            typer.echo(
                f"[{index}] "
                f"{candidate.rule_id} - "
                f"{candidate.vulnerability}"
            )

            typer.echo(
                f"    Severity: "
                f"{candidate.severity}"
            )

            typer.echo(
                f"    File: "
                f"{candidate.location.file}"
            )

            typer.echo(
                f"    Line: "
                f"{candidate.location.line}"
            )

            if candidate.location.class_name:
                typer.echo(
                    f"    Class: "
                    f"{candidate.location.class_name}"
                )

            if candidate.location.method_name:
                typer.echo(
                    f"    Method: "
                    f"{candidate.location.method_name}"
                )

            if candidate.source:
                typer.echo(
                    f"    Source: "
                    f"{candidate.source}"
                )

            if candidate.sink:
                typer.echo(
                    f"    Sink: "
                    f"{candidate.sink}"
                )

            if candidate.description:
                typer.echo(
                    f"    Description: "
                    f"{candidate.description}"
                )

            if candidate.evidence:
                typer.echo(
                    "    Evidence:"
                )

                for evidence in candidate.evidence:
                    typer.echo(
                        f"      - {evidence}"
                    )

    #
    # Malware behavior findings
    #
    typer.echo("")
    typer.echo("Malware Behavior Findings")
    typer.echo("-" * 40)

    if not behavior_candidates:
        typer.echo(
            "No suspicious behavior candidates detected."
        )

    else:
        typer.echo(
            f"Candidates: "
            f"{len(behavior_candidates)}"
        )

        for index, candidate in enumerate(
            behavior_candidates,
            start=1,
        ):
            typer.echo("")

            typer.echo(
                f"[{index}] "
                f"{candidate.behavior_id} - "
                f"{candidate.behavior}"
            )

            typer.echo(
                f"    Category: "
                f"{candidate.category}"
            )

            typer.echo(
                f"    Severity: "
                f"{candidate.severity}"
            )

            typer.echo(
                f"    Confidence: "
                f"{candidate.confidence:.2f}"
            )

            typer.echo(
                f"    Evidence state: "
                f"{candidate.evidence_state.value}"
            )

            if candidate.primary_location:
                typer.echo(
                    f"    File: "
                    f"{candidate.primary_location.file}"
                )

                typer.echo(
                    f"    Line: "
                    f"{candidate.primary_location.line}"
                )

                if (
                    candidate
                    .primary_location
                    .class_name
                ):
                    typer.echo(
                        f"    Class: "
                        f"{candidate.primary_location.class_name}"
                    )

                if (
                    candidate
                    .primary_location
                    .method_name
                ):
                    typer.echo(
                        f"    Method: "
                        f"{candidate.primary_location.method_name}"
                    )

            if candidate.description:
                typer.echo(
                    f"    Description: "
                    f"{candidate.description}"
                )

            if candidate.signals:
                typer.echo(
                    "    Signals:"
                )

                for signal in candidate.signals:
                    typer.echo(
                        f"      - "
                        f"{signal.signal_id}: "
                        f"{signal.description}"
                    )

                    typer.echo(
                        f"        State: "
                        f"{signal.evidence_state.value}"
                    )

                    typer.echo(
                        f"        Weight: "
                        f"{signal.weight}"
                    )

                    if signal.evidence:
                        typer.echo(
                            f"        Evidence: "
                            f"{signal.evidence}"
                        )

    #
    # Summary
    #
    typer.echo("")
    typer.echo("Analysis Summary")
    typer.echo("-" * 40)

    typer.echo(
        f"Vulnerability candidates: "
        f"{len(vulnerability_candidates)}"
    )

    typer.echo(
        f"Behavior candidates:      "
        f"{len(behavior_candidates)}"
    )

    typer.echo("")
    typer.echo(
        "Analysis status: COMPLETE"
    )
    typer.echo("")
@app.command()
def extract(
    apk_path: Path = typer.Argument(
        ...,
        help="Path to the APK file",
    ),
) -> None:
    """
    Extract security-relevant evidence and capabilities from an APK.
    """

    inspector = APKInspector()
    context = inspector.inspect(apk_path)

    decompiler = DecompilerPipeline()
    decompilation = decompiler.run(context)

    context.manifest_path = decompilation.manifest_path
    context.source_path = decompilation.source_path
    context.smali_path = decompilation.smali_path

    manifest = None

    if context.manifest_path is not None:
        manifest = ManifestAnalyzer().analyze(
            context.manifest_path
        )

    result = ExtractionPipeline().run(
        context=context,
        manifest=manifest,
    )

    typer.echo("\n=== SENTINELRAG EVIDENCE EXTRACTION ===")

    typer.echo(f"\nAPK: {context.apk_path}")
    typer.echo(f"SHA256: {context.sha256}")

    if manifest:
        typer.echo(f"Package: {manifest.package_name}")

    typer.echo("\n--- Evidence Summary ---")
    typer.echo(f"APIs: {len(result.apis)}")
    typer.echo(f"Strings: {len(result.strings)}")
    typer.echo(f"Methods: {len(result.methods)}")
    typer.echo(f"Permissions: {len(result.permissions)}")
    typer.echo(f"Capabilities: {len(result.capabilities)}")

    typer.echo("\n--- Security Capabilities ---")

    if not result.capabilities:
        typer.echo("No security capabilities identified.")
        return

    for capability in result.capabilities:
        typer.echo(
            f"\n[{capability.capability_id}] "
            f"{capability.name}"
        )

        typer.echo(
            f"Category: {capability.category}"
        )

        typer.echo(
            "Indicators:"
        )

        for indicator in capability.matched_indicators:
            typer.echo(
                f"  - {indicator}"
            )