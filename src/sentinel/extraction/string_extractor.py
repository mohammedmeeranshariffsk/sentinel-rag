import re
from pathlib import Path

from sentinel.extraction.models import (
    EvidenceLocation,
    ExtractedString,
)


class StringExtractor:
    """
    Extracts string literals from Java/Kotlin source.

    This is intentionally broad. Security relevance is decided
    later by capability/threat-intelligence matching.
    """

    STRING_PATTERN = re.compile(
        r'"(?P<value>(?:\\.|[^"\\])*)"'
    )

    def extract_file(
        self,
        file_path: Path,
    ) -> list[ExtractedString]:
        try:
            source = file_path.read_text(
                encoding="utf-8",
                errors="ignore",
            )
        except OSError:
            return []

        findings: list[ExtractedString] = []

        for line_number, line in enumerate(
            source.splitlines(),
            start=1,
        ):
            for match in self.STRING_PATTERN.finditer(line):
                value = match.group("value")

                if not value:
                    continue

                findings.append(
                    ExtractedString(
                        value=value,
                        location=EvidenceLocation(
                            file=str(file_path),
                            line=line_number,
                        ),
                        evidence=line.strip(),
                    )
                )

        return findings