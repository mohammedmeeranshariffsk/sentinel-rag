from pathlib import Path

from sentinel.profiles.models import ExtractionProfile


class ProfileLoader:
    """Load a versioned extraction profile without changing APK evidence."""

    def load(self, path: Path | str) -> ExtractionProfile:
        profile_path = Path(path)
        if not profile_path.is_file():
            raise FileNotFoundError(f"Profile not found: {profile_path}")
        return ExtractionProfile.model_validate_json(
            profile_path.read_text(encoding="utf-8")
        )
