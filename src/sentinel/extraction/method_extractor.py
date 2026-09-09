import re
from pathlib import Path

from sentinel.extraction.models import ExtractedMethod


class MethodExtractor:
    """
    Lightweight Java/Kotlin method declaration extractor.

    This is intentionally simple for the Week-1 prototype.
    """

    JAVA_METHOD_PATTERN = re.compile(
        r"""
        ^\s*
        (?:
            public|
            private|
            protected|
            static|
            final|
            synchronized|
            native|
            abstract|
            strictfp|
            \s
        )*
        [A-Za-z_$][A-Za-z0-9_$<>\[\].?,\s]*
        \s+
        (?P<method>[A-Za-z_$][A-Za-z0-9_$]*)
        \s*
        \(
        """,
        re.VERBOSE,
    )

    KOTLIN_METHOD_PATTERN = re.compile(
        r"""
        ^\s*
        (?:
            public\s+|
            private\s+|
            protected\s+|
            internal\s+|
            suspend\s+|
            override\s+
        )*
        fun\s+
        (?P<method>[A-Za-z_$][A-Za-z0-9_$]*)
        \s*
        \(
        """,
        re.VERBOSE,
    )

    CLASS_PATTERN = re.compile(
        r"\b(?:class|interface|object|enum)\s+(?P<name>[A-Za-z_$][A-Za-z0-9_$]*)\b"
    )

    def extract_file(
        self,
        file_path: Path,
    ) -> list[ExtractedMethod]:
        try:
            source = file_path.read_text(
                encoding="utf-8",
                errors="ignore",
            )
        except OSError:
            return []

        methods: list[ExtractedMethod] = []
        lines = source.splitlines()
        class_stack: list[tuple[str, int]] = []

        for line_number, line in enumerate(lines, start=1):
            class_match = self.CLASS_PATTERN.search(line)
            if class_match:
                class_stack.append((class_match.group("name"), self._depth_before(lines, line_number)))
            match = self.KOTLIN_METHOD_PATTERN.search(line)

            if match is None:
                match = self.JAVA_METHOD_PATTERN.search(line)

            if match is not None:
                body_start, body_end = self._body_bounds(lines, line_number)
                methods.append(
                    ExtractedMethod(
                        name=match.group("method"),
                        class_name=class_stack[-1][0] if class_stack else None,
                        file=str(file_path),
                        line=line_number,
                        end_line=body_end,
                        body_start_line=body_start,
                        body_end_line=body_end,
                    )
                )

            depth_after = self._depth_before(lines, line_number + 1)
            while class_stack and depth_after < class_stack[-1][1] + 1:
                class_stack.pop()

        return methods

    @staticmethod
    def _depth_before(lines: list[str], line_number: int) -> int:
        """Return a lightweight brace depth before the requested one-based line."""
        return sum(line.count("{") - line.count("}") for line in lines[:line_number - 1])

    @staticmethod
    def _body_bounds(lines: list[str], declaration_line: int) -> tuple[int | None, int | None]:
        """Find a declaration's brace-delimited body without claiming full parsing."""
        start_index = declaration_line - 1
        depth = 0
        opened = False
        body_start: int | None = None
        for index in range(start_index, len(lines)):
            for character in lines[index]:
                if character == "{":
                    depth += 1
                    opened = True
                    body_start = body_start or index + 1
                elif character == "}" and opened:
                    depth -= 1
                    if depth == 0:
                        return body_start, index + 1
        return body_start, None
