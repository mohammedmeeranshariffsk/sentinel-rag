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

    CLASS_PATTERN = re.compile(
        r"\b(?:class|interface|object|enum)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\b"
    )
    METHOD_PATTERN = re.compile(
        r"^\s*(?:public|private|protected|static|final|synchronized|native|abstract|override|\s)*"
        r"(?:fun\s+)?[A-Za-z_$][A-Za-z0-9_$<>\[\].?,\s]*\s+"
        r"(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\s*\("
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
        class_name: str | None = None
        method_name: str | None = None
        method_depth: int | None = None
        brace_depth = 0

        for line_number, line in enumerate(source.splitlines(), start=1):
            stripped = line.strip()

            class_match = self.CLASS_PATTERN.search(line)
            if class_match:
                class_name = class_match.group("name")
            method_match = self.METHOD_PATTERN.search(line)
            if method_match and not class_match:
                method_name = method_match.group("name")
                method_depth = brace_depth + line.count("{") - line.count("}")

            if not stripped:
                brace_depth += line.count("{") - line.count("}")
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
                            class_name=class_name,
                            method_name=method_name,
                        ),
                        evidence=stripped,
                        arguments=self._arguments(line, match.end() - 1),
                        call_context=stripped,
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
                            class_name=class_name,
                            method_name=method_name,
                        ),
                        evidence=stripped,
                        arguments=self._arguments(line, match.end() - 1),
                        call_context=stripped,
                    )
                )

            brace_depth += line.count("{") - line.count("}")
            if method_depth is not None and brace_depth < method_depth:
                method_name, method_depth = None, None

        return findings

    @staticmethod
    def _arguments(line: str, opening_paren: int) -> list[str]:
        """Return top-level same-line arguments; leave complex calls unexpanded."""
        depth = 0
        quote: str | None = None
        escaped = False
        start = opening_paren + 1
        values: list[str] = []
        for index in range(start, len(line)):
            character = line[index]
            if quote:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == quote:
                    quote = None
                continue
            if character in {'"', "'"}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                if depth == 0:
                    value = line[start:index].strip()
                    if value:
                        values.append(value)
                    return values
                depth -= 1
            elif character == "," and depth == 0:
                value = line[start:index].strip()
                if value:
                    values.append(value)
                start = index + 1
        return []
