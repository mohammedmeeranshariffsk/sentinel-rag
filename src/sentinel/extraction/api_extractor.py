import re
from pathlib import Path

from sentinel.extraction.models import (
    EvidenceLocation,
    ExtractedAPI,
)


class APIExtractor:
    """
    Extracts method/API-looking references from Java/Kotlin source.

    This component reports observable API usage only.
    It does not classify the API as malicious.
    """

    CALL_PATTERN = re.compile(
        r"""
        (?P<receiver>
            [A-Za-z_$][A-Za-z0-9_$]*
        )
        \s*
        \.
        \s*
        (?P<method>
            [A-Za-z_$][A-Za-z0-9_$]*
        )
        \s*
        \(
        """,
        re.VERBOSE,
    )

    CHAINED_CALL_PATTERN = re.compile(
        r"""
        \)
        \s*
        \.
        \s*
        (?P<method>
            [A-Za-z_$][A-Za-z0-9_$]*
        )
        \s*
        \(
        """,
        re.VERBOSE,
    )

    def extract_file(
        self,
        file_path: Path,
    ) -> list[ExtractedAPI]:

        try:
            source = file_path.read_text(
                encoding="utf-8",
                errors="ignore",
            )
        except OSError:
            return []

        findings: list[ExtractedAPI] = []

        for line_number, line in enumerate(
            source.splitlines(),
            start=1,
        ):
            stripped = line.strip()

            if not stripped:
                continue

            # Standard calls:
            # Runtime.getRuntime()
            # root.getRootInActiveWindow()
            for match in self.CALL_PATTERN.finditer(line):
                receiver = match.group("receiver")
                method = match.group("method")

                findings.append(
                    ExtractedAPI(
                        api_name=method,
                        full_reference=f"{receiver}.{method}",
                        location=EvidenceLocation(
                            file=str(file_path),
                            line=line_number,
                        ),
                        evidence=stripped,
                    )
                )

            # Chained calls:
            # Runtime.getRuntime().exec()
            for match in self.CHAINED_CALL_PATTERN.finditer(line):
                method = match.group("method")

                findings.append(
                    ExtractedAPI(
                        api_name=method,
                        full_reference=method,
                        location=EvidenceLocation(
                            file=str(file_path),
                            line=line_number,
                        ),
                        evidence=stripped,
                    )
                )

        return findings