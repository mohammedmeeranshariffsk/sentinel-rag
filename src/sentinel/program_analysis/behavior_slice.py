from pathlib import Path

from pydantic import BaseModel, Field

from sentinel.extraction.models import ExtractedAPI


class BehaviorSlice(BaseModel):
    seed: str
    file: str
    line: int
    code_context: list[str] = Field(default_factory=list)
    related_strings: list[str] = Field(default_factory=list)


class BehaviorSliceBuilder:
    """
    Builds bounded source-code context around an investigation seed.
    """

    def __init__(self, context_lines: int = 8) -> None:
        self.context_lines = context_lines

    def build_from_api(
        self,
        api: ExtractedAPI,
    ) -> BehaviorSlice | None:

        file_path = Path(api.location.file)

        if not file_path.exists():
            return None

        if api.location.line is None:
            return None

        try:
            lines = file_path.read_text(
                encoding="utf-8",
                errors="ignore",
            ).splitlines()
        except OSError:
            return None

        line_index = api.location.line - 1

        start = max(
            0,
            line_index - self.context_lines,
        )

        end = min(
            len(lines),
            line_index + self.context_lines + 1,
        )

        code_context = lines[start:end]

        related_strings = []

        for line in code_context:
            parts = line.split('"')

            for index in range(1, len(parts), 2):
                value = parts[index].strip()

                if value:
                    related_strings.append(value)

        return BehaviorSlice(
            seed=api.full_reference,
            file=str(file_path),
            line=api.location.line,
            code_context=code_context,
            related_strings=related_strings,
        )