from pathlib import Path
from collections.abc import Iterator


class CodeScanner:
    """Iterate through decompiled Java/Kotlin source files."""

    SUPPORTED_EXTENSIONS = {
        ".java",
        ".kt",
    }

    def scan_directory(
        self,
        source_path: Path,
    ) -> Iterator[Path]:
        """Yield supported source files recursively."""

        if not source_path.exists():
            raise FileNotFoundError(
                f"Source directory not found: {source_path}"
            )

        if not source_path.is_dir():
            raise ValueError(
                f"Source path is not a directory: {source_path}"
            )

        for path in source_path.rglob("*"):
            if (
                path.is_file()
                and path.suffix.lower()
                in self.SUPPORTED_EXTENSIONS
            ):
                yield path