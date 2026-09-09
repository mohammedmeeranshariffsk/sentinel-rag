from pathlib import Path
from subprocess import CompletedProcess

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


def test_jadx_manifest_is_used_when_apktool_manifest_is_unavailable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"fake apk")
    context = APKInspector(tmp_path / "workspace").inspect(apk_path)
    tool = tmp_path / "jadx.bat"
    tool.touch()
    pipeline = DecompilerPipeline(
        apktool_path=tmp_path / "missing-apktool.bat",
        jadx_path=tool,
    )

    def fake_run(command):
        output = Path(command[2])
        (output / "resources").mkdir(parents=True)
        (output / "sources").mkdir()
        (output / "resources" / "AndroidManifest.xml").write_text(
            "<manifest />", encoding="utf-8"
        )
        return CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(pipeline, "_run_command", fake_run)

    result = pipeline.run(context)

    assert result.manifest_path == (
        result.jadx_output / "resources" / "AndroidManifest.xml"
    )
