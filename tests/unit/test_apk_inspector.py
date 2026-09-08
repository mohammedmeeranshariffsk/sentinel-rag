from pathlib import Path

import pytest

from sentinel.apk.inspector import APKInspector


def test_inspector_rejects_missing_apk(tmp_path: Path) -> None:
    inspector = APKInspector(tmp_path / "workspace")

    with pytest.raises(FileNotFoundError):
        inspector.inspect(tmp_path / "missing.apk")


def test_inspector_rejects_non_apk_file(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.txt"
    file_path.write_text("not an apk")

    inspector = APKInspector(tmp_path / "workspace")

    with pytest.raises(ValueError):
        inspector.inspect(file_path)


def test_inspector_creates_context(tmp_path: Path) -> None:
    apk_path = tmp_path / "sample.apk"
    apk_path.write_bytes(b"fake apk content")

    workspace_root = tmp_path / "workspace"

    inspector = APKInspector(workspace_root)
    context = inspector.inspect(apk_path)

    assert context.apk_path == apk_path.resolve()
    assert len(context.sha256) == 64
    assert context.file_size == len(b"fake apk content")
    assert context.workspace.exists()
    assert context.workspace.name == context.sha256