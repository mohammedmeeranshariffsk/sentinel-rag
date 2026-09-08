import re
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

    STRING_PATTERN = re.compile(
        r'"(?P<value>(?:\\.|[^"\\])*)"'
    )

    CODE_LIKE_TOKENS = (
        "Runtime.",
        ".exec(",
        ".readLine(",
        ".getRuntime(",
    )

    def __init__(
        self,
        context_lines: int = 8,
    ) -> None:
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

        if line_index < 0 or line_index >= len(lines):
            return None

        start = max(
            0,
            line_index - self.context_lines,
        )

        end = min(
            len(lines),
            line_index + self.context_lines + 1,
        )

        code_context = lines[start:end]

        related_strings = self._extract_related_strings(
            code_context
        )

        return BehaviorSlice(
            seed=api.full_reference,
            file=str(file_path),
            line=api.location.line,
            code_context=code_context,
            related_strings=related_strings,
        )

    def _extract_related_strings(
        self,
        code_context: list[str],
    ) -> list[str]:

        related_strings: list[str] = []
        seen: set[str] = set()

        for line in code_context:
            for match in self.STRING_PATTERN.finditer(line):

                value = match.group("value").strip()

                # Ignore empty or very small/noisy values such as "n".
                if len(value) < 2:
                    continue

                # Ignore strings that are actually decompiler/debug
                # representations of source-code expressions.
                if any(
                    token in value
                    for token in self.CODE_LIKE_TOKENS
                ):
                    continue

                if value not in seen:
                    seen.add(value)
                    related_strings.append(value)

        # Preserve original order while removing duplicates.
        return related_strings
