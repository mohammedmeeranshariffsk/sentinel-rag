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

        for line_number, line in enumerate(
            source.splitlines(),
            start=1,
        ):
            match = self.KOTLIN_METHOD_PATTERN.search(line)

            if match is None:
                match = self.JAVA_METHOD_PATTERN.search(line)

            if match is None:
                continue

            methods.append(
                ExtractedMethod(
                    name=match.group("method"),
                    file=str(file_path),
                    line=line_number,
                )
            )

        return methods