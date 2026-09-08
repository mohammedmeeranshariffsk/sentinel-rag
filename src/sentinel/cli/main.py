from pathlib import Path

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