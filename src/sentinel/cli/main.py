from pathlib import Path
from sentinel.decompiler.pipeline import DecompilerPipeline

import typer

from sentinel.apk.inspector import APKInspector


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

    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1)

    typer.echo("")
    typer.echo("SentinelRAG APK Decompilation")
    typer.echo("=" * 34)
    typer.echo(f"APK:       {context.apk_path.name}")
    typer.echo(f"Workspace: {context.workspace}")
    typer.echo("")

    typer.echo(
        f"Apktool:   {'SUCCESS' if result.apktool_success else 'FAILED'}"
    )
    typer.echo(
        f"JADX:      {'SUCCESS' if result.jadx_success else 'FAILED'}"
    )

    if result.manifest_path:
        typer.echo(f"Manifest:  {result.manifest_path}")

    if result.source_path:
        typer.echo(f"Sources:   {result.source_path}")

    if result.smali_path:
        typer.echo(f"Smali:     {result.smali_path}")

    if result.errors:
        typer.echo("")
        typer.echo("Warnings:")
        for error in result.errors:
            typer.echo(f"  - {error}")

    typer.echo("")
    typer.echo("Analysis status: READY")
    typer.echo("")