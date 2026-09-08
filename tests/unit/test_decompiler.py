from pathlib import Path

import pytest

from sentinel.apk.inspector import APKInspector
from sentinel.decompiler.pipeline import DecompilerPipeline


def test_missing_apktool_is_reported(tmp_path: Path) -> None:
    inspector = APKInspector(tmp_path / "workspace")

    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"fake apk")

    context = inspector.inspect(apk_path)

    pipeline = DecompilerPipeline(
        apktool_path=tmp_path / "missing-apktool.bat",
        jadx_path=tmp_path / "missing-jadx.bat",
    )

    with pytest.raises(RuntimeError):
        pipeline.run(context)