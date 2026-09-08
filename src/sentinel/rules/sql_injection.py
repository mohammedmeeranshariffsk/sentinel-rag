import re
from pathlib import Path

from sentinel.apk.context import APKContext
from sentinel.manifest.analyzer import ManifestAnalysis
from sentinel.rules.base import SecurityRule
from sentinel.rules.models import (
    CodeLocation,
    SecurityCandidate,
)


class SQLInjectionRule(SecurityRule):
    """Detect potential SQL injection through suspicious SQL construction."""

    rule_id = "SQLI-001"
    name = "SQL Injection"
    description = (
        "Detect SQL queries constructed from potentially untrusted "
        "input and passed to SQLite query sinks."
    )
    default_severity = "HIGH"

    SINK_PATTERNS = (
        re.compile(r"\.rawQuery\s*\("),
        re.compile(r"\.execSQL\s*\("),
    )

    SOURCE_PATTERNS = (
        re.compile(
            r"\b[A-Za-z_][A-Za-z0-9_]*"
            r"\.getText\s*\(\s*\)"
            r"(?:\.toString\s*\(\s*\))?"
        ),
        re.compile(
            r"\b[A-Za-z_][A-Za-z0-9_]*"
            r"\.getStringExtra\s*\("
        ),
        re.compile(
            r"\b[A-Za-z_][A-Za-z0-9_]*"
            r"\.getString\s*\("
        ),
        re.compile(
            r"\b[A-Za-z_][A-Za-z0-9_]*"
            r"\.getQueryParameter\s*\("
        ),
        re.compile(
            r"\b[A-Za-z_][A-Za-z0-9_]*"
            r"\.getData\s*\("
        ),
    )

    STRING_CONCAT_PATTERN = re.compile(
        r'["\'].*["\']\s*\+'
        r"|\+\s*[A-Za-z_][A-Za-z0-9_]*"
    )

    STRING_BUILDER_PATTERN = re.compile(
        r"\bStringBuilder\b"
    )

    APPEND_PATTERN = re.compile(
        r"\.append\s*\("
    )

    def analyze_file(
        self,
        file_path: Path,
        context: APKContext,
        manifest: ManifestAnalysis | None = None,
    ) -> list[SecurityCandidate]:
        """Analyze a source file for SQL injection patterns."""

        lines = file_path.read_text(
            encoding="utf-8",
            errors="ignore",
        ).splitlines()

        candidates: list[SecurityCandidate] = []

        class_name = self._extract_class_name(lines)

        for index, line in enumerate(lines):
            if not self._is_sql_sink(line):
                continue

            # Look backwards from the sink for source and
            # query-construction evidence.
            window_start = max(0, index - 30)
            nearby_lines = lines[window_start : index + 1]

            source = self._find_source(nearby_lines)

            if source is None:
                continue

            has_string_construction = (
                self._has_string_concatenation(nearby_lines)
                or self._has_string_builder_flow(
                    nearby_lines,
                    source,
                )
            )

            if not has_string_construction:
                continue

            sink = self._identify_sink(line)

            method_name = self._extract_method_name(
                lines,
                index,
            )

            evidence = self._build_evidence(
                lines=lines,
                sink_index=index,
                source=source,
            )

            candidate_id = (
                f"{self.rule_id}:"
                f"{file_path}:"
                f"{index + 1}"
            )

            candidates.append(
                SecurityCandidate(
                    candidate_id=candidate_id,
                    rule_id=self.rule_id,
                    vulnerability=self.name,
                    severity=self.default_severity,
                    location=CodeLocation(
                        file=str(file_path),
                        line=index + 1,
                        class_name=class_name,
                        method_name=method_name,
                    ),
                    evidence=evidence,
                    source=source,
                    sink=sink,
                    description=(
                        "Potential SQL injection detected because "
                        "input from an Android UI source appears to "
                        "participate in SQL query construction before "
                        "reaching a SQLite query sink."
                    ),
                )
            )

        return candidates

    def _is_sql_sink(self, line: str) -> bool:
        """Return True when the line contains a known SQL sink."""

        return any(
            pattern.search(line)
            for pattern in self.SINK_PATTERNS
        )

    def _find_source(
        self,
        lines: list[str],
    ) -> str | None:
        """Find the first supported untrusted-input source."""

        for line in lines:
            for pattern in self.SOURCE_PATTERNS:
                match = pattern.search(line)

                if match:
                    return match.group(0)

        return None

    def _has_string_concatenation(
        self,
        lines: list[str],
    ) -> bool:
        """Detect simple string concatenation."""

        return any(
            self.STRING_CONCAT_PATTERN.search(line)
            for line in lines
        )

    def _has_string_builder_flow(
        self,
        lines: list[str],
        source: str,
    ) -> bool:
        """Detect a simple StringBuilder source-to-query flow."""

        text = "\n".join(lines)

        if not self.STRING_BUILDER_PATTERN.search(text):
            return False

        if not self.APPEND_PATTERN.search(text):
            return False

        source_variable = self._extract_source_variable(
            source
        )

        if source_variable is None:
            return False

        source_in_append = re.search(
            rf"\.append\s*\([^;]*"
            rf"{re.escape(source_variable)}"
            rf"[^;]*\)",
            text,
            re.DOTALL,
        )

        return source_in_append is not None

    @staticmethod
    def _extract_source_variable(
        source: str,
    ) -> str | None:
        """Extract the variable used by a source expression."""

        match = re.match(
            r"([A-Za-z_][A-Za-z0-9_]*)\."
            r"(?:getText|getStringExtra|getString|"
            r"getQueryParameter|getData)",
            source,
        )

        if match:
            return match.group(1)

        return None

    def _identify_sink(
        self,
        line: str,
    ) -> str:
        """Identify which SQL sink appears on the line."""

        if ".rawQuery" in line:
            return "SQLiteDatabase.rawQuery()"

        if ".execSQL" in line:
            return "SQLiteDatabase.execSQL()"

        return "Unknown SQL sink"

    def _build_evidence(
        self,
        lines: list[str],
        sink_index: int,
        source: str,
    ) -> list[str]:
        """Build a readable evidence snippet around the sink."""

        start = max(0, sink_index - 12)
        end = min(len(lines), sink_index + 1)

        snippet = "\n".join(
            f"{number + 1}: {lines[number]}"
            for number in range(start, end)
        )

        return [
            f"Source detected: {source}",
            "SQL query construction detected",
            "SQL sink detected",
            f"Code:\n{snippet}",
        ]

    @staticmethod
    def _extract_class_name(
        lines: list[str],
    ) -> str | None:
        """Extract the Java class name from the source."""

        for line in lines:
            match = re.search(
                r"\bpublic\s+"
                r"(?:final\s+)?"
                r"class\s+"
                r"([A-Za-z_][A-Za-z0-9_]*)\b",
                line,
            )

            if match:
                return match.group(1)

        return None

    @staticmethod
    def _extract_method_name(
        lines: list[str],
        sink_index: int,
    ) -> str | None:
        """Find the nearest method declaration above the sink."""

        for index in range(
            sink_index,
            -1,
            -1,
        ):
            line = lines[index]

            match = re.search(
                r"\b(?:public|private|protected)\s+"
                r"(?:static\s+)?"
                r"(?:final\s+)?"
                r"(?:[\w<>\[\]]+\s+)+"
                r"([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                line,
            )

            if match:
                return match.group(1)

        return None