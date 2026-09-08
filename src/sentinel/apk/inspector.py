import hashlib
from pathlib import Path

from .context import APKContext


class APKInspector:
    """Inspect an APK file and create its initial APKContext."""

    def __init__(self, workspace_root: Path | str = "workspace") -> None:
        self.workspace_root = Path(workspace_root)

    def calculate_sha256(self, apk_path: Path) -> str:
        """Calculate the SHA256 hash of the APK."""

        sha256 = hashlib.sha256()

        with apk_path.open("rb") as apk_file:
            for chunk in iter(lambda: apk_file.read(1024 * 1024), b""):
                sha256.update(chunk)

        return sha256.hexdigest()

    def inspect(self, apk_path: Path | str) -> APKContext:
        """
        Inspect the APK file and return an APKContext.

        This step does not decompile the APK yet.
        """

        apk_path = Path(apk_path).resolve()

        if not apk_path.exists():
            raise FileNotFoundError(
                f"APK file does not exist: {apk_path}"
            )

        if not apk_path.is_file():
            raise ValueError(
                f"APK path is not a file: {apk_path}"
            )

        if apk_path.suffix.lower() != ".apk":
            raise ValueError(
                f"Expected an .apk file, got: {apk_path.suffix}"
            )

        sha256 = self.calculate_sha256(apk_path)

        file_size = apk_path.stat().st_size

        workspace = self.workspace_root / sha256
        workspace.mkdir(parents=True, exist_ok=True)

        return APKContext(
            apk_path=apk_path,
            sha256=sha256,
            file_size=file_size,
            workspace=workspace,
        )