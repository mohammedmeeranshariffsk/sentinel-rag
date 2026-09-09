from pathlib import Path

from sentinel.config.settings import ENV_FILE, PROJECT_ROOT, Settings


def test_project_env_file_does_not_depend_on_current_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert PROJECT_ROOT == Path(__file__).resolve().parents[2]
    assert ENV_FILE == PROJECT_ROOT / ".env"
    assert Path(Settings.model_config["env_file"]) == ENV_FILE
