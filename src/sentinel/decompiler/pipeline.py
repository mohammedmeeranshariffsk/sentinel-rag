import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.config.settings import settings


@dataclass
class DecompilationResult:
    """Result produced by the APK decompilation stage."""

    apktool_success: bool = False
    jadx_success: bool = False

    apktool_output: Path | None = None
    jadx_output: Path | None = None

    manifest_path: Path | None = None
    source_path: Path | None = None
    smali_path: Path | None = None

    errors: list[str] = field(default_factory=list)
    apktool_return_code: int | None = None
    jadx_return_code: int | None = None


class DecompilerPipeline:
    """Run Apktool and JADX against an APK."""

    def __init__(
        self,
        apktool_path: Path | str | None = None,
        jadx_path: Path | str | None = None,
    ) -> None:
        self.apktool_path = Path(
            apktool_path or settings.apktool_path
        )
        self.jadx_path = Path(
            jadx_path or settings.jadx_path
        )

    def _validate_tool(
        self,
        tool_path: Path,
        tool_name: str,
    ) -> None:
        """Verify that an external analysis tool exists."""

        if not tool_path.exists():
            raise FileNotFoundError(
                f"{tool_name} executable not found: {tool_path}"
            )

    def _run_command(
        self,
        command: list[str],
    ) -> subprocess.CompletedProcess[str]:
        """Execute a Windows command and capture its output."""

        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            shell=True,
            check=False,
        )

    def run_apktool(
        self,
        context: APKContext,
        result: DecompilationResult,
    ) -> DecompilationResult:
        """Run Apktool against the APK."""

        try:
            self._validate_tool(
                self.apktool_path,
                "Apktool",
            )

            output_dir = context.workspace / "apktool"

            if output_dir.exists():
                shutil.rmtree(output_dir)

            output_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            command = [
                str(self.apktool_path),
                "d",
                str(context.apk_path),
                "-o",
                str(output_dir),
                "-f",
            ]

            completed = self._run_command(command)
            result.apktool_return_code = completed.returncode

            if completed.returncode != 0:
                result.errors.append(
                    "Apktool failed "
                    f"(exit code {completed.returncode}): "
                    f"{completed.stderr.strip()}"
                )
                return result

            result.apktool_success = True
            result.apktool_output = output_dir

            manifest_path = output_dir / "AndroidManifest.xml"

            if manifest_path.exists():
                result.manifest_path = manifest_path

            smali_candidates = list(
                output_dir.glob("smali*")
            )

            if smali_candidates:
                result.smali_path = smali_candidates[0]

        except Exception as exc:
            result.errors.append(
                f"Apktool error: {exc}"
            )

        return result

    def run_jadx(
        self,
        context: APKContext,
        result: DecompilationResult,
    ) -> DecompilationResult:
        """Run JADX against the APK."""

        try:
            self._validate_tool(
                self.jadx_path,
                "JADX",
            )

            output_dir = context.workspace / "jadx"

            if output_dir.exists():
                shutil.rmtree(output_dir)

            output_dir.mkdir(
                parents=True,
                exist_ok=True,
            )

            command = [
                str(self.jadx_path),
                "-d",
                str(output_dir),
                str(context.apk_path),
            ]

            completed = self._run_command(command)
            result.jadx_return_code = completed.returncode

            # JADX can return a non-zero exit code while still
            # producing useful decompiled sources.
            if completed.returncode != 0:
                result.errors.append(
                    "JADX returned a non-zero exit code "
                    f"({completed.returncode}). "
                    "Partial output may still be usable. "
                    f"stderr: {completed.stderr.strip()}"
                )

            if output_dir.exists():
                result.jadx_output = output_dir

                # Some malformed APKs defeat Apktool while JADX still
                # produces a decoded manifest that is suitable for analysis.
                jadx_manifest = (
                    output_dir / "resources" / "AndroidManifest.xml"
                )
                if (
                    result.manifest_path is None
                    and jadx_manifest.is_file()
                ):
                    result.manifest_path = jadx_manifest

                sources_dir = output_dir / "sources"

                if sources_dir.exists():
                    result.source_path = sources_dir

                    if completed.returncode == 0:
                        result.jadx_success = True
                    else:
                        # Useful source output exists even though
                        # JADX reported some decompilation issues.
                        result.jadx_success = True

        except Exception as exc:
            result.errors.append(
                f"JADX error: {exc}"
            )

        return result

    def run(
        self,
        context: APKContext,
        allow_failed: bool = False,
    ) -> DecompilationResult:
        """Run Apktool and JADX."""

        result = DecompilationResult()

        result = self.run_apktool(
            context,
            result,
        )

        result = self.run_jadx(
            context,
            result,
        )

        if not result.apktool_success and not result.jadx_success and not allow_failed:
            raise RuntimeError(
                "Both Apktool and JADX failed. "
                + " | ".join(result.errors)
            )

        return result
