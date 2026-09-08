from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass
class APKContext:
    """
    Represents the state and metadata of an Android APK being analyzed.

    This object is intentionally kept independent of Apktool, JADX,
    RAG, LLMs, or vulnerability rules.
    """

    apk_path: Path
    sha256: str
    file_size: int

    workspace: Path

    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None

    manifest_path: Optional[Path] = None
    decompiled_path: Optional[Path] = None
    source_path: Optional[Path] = None
    smali_path: Optional[Path] = None