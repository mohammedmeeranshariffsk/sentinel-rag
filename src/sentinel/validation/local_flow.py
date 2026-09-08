import re

from sentinel.program_analysis.behavior_slice import BehaviorSlice
from sentinel.validation.models import LocalDataFlow


class LocalDataFlowAnalyzer:
    """Recognize a small set of intra-slice Java source-to-exec flows."""

    ASSIGNMENT = re.compile(
        r"(?:\b(?:String|CharSequence)\s+)?(?P<target>[A-Za-z_$][\w$]*)\s*=\s*(?P<value>.+?);?$"
    )
    SOURCE = re.compile(
        r"(?P<view>[A-Za-z_$][\w$]*)\.getText\(\)(?:\.toString\(\))?"
    )
    BUILDER_DECLARATION = re.compile(
        r"(?:StringBuilder\s+)?(?P<name>[A-Za-z_$][\w$]*)\s*=\s*new\s+StringBuilder\s*\((?P<initial>[^)]*)"
    )
    APPEND = re.compile(r"(?P<builder>[A-Za-z_$][\w$]*)\.append\((?P<value>.*?)\)")
    BUILDER_RESULT = re.compile(
        r"(?P<builder>[A-Za-z_$][\w$]*)\.toString\(\)"
    )
    SINK = re.compile(
        r"Runtime\.getRuntime\(\)\.exec\s*\(\s*(?P<argument>[A-Za-z_$][\w$]*)"
    )

    def analyze(self, behavior_slice: BehaviorSlice) -> list[LocalDataFlow]:
        tainted: dict[str, tuple[str, int, list[str]]] = {}
        builders: dict[str, tuple[str, int, list[str], str | None]] = {}
        lines = behavior_slice.code_context

        for index, raw_line in enumerate(lines):
            line = raw_line.strip()
            assignment = self.ASSIGNMENT.search(line)
            source = self.SOURCE.search(line)
            if assignment and source:
                target = assignment.group("target")
                description = f"{source.group('view')}.getText().toString()"
                transforms = ["String concatenation / assignment"] if "+" in assignment.group("value") else []
                tainted[target] = (description, index, transforms)

            declaration = self.BUILDER_DECLARATION.search(line)
            if declaration:
                initial = declaration.group("initial").strip()
                literal = re.fullmatch(r'"([^"\\]*(?:\\.[^"\\]*)*)"', initial)
                builders[declaration.group("name")] = (
                    "", index, ["StringBuilder command construction"],
                    literal.group(1) if literal else None,
                )

            for append in self.APPEND.finditer(line):
                builder = append.group("builder")
                value = append.group("value").strip()
                if builder not in builders:
                    continue
                builder_source, start, transforms, prefix = builders[builder]
                literal = re.fullmatch(r'"([^"\\]*(?:\\.[^"\\]*)*)"', value)
                if literal and prefix is None:
                    prefix = literal.group(1)
                dependencies = [name for name in tainted if re.search(rf"\b{re.escape(name)}\b", value)]
                if dependencies:
                    dependency = tainted[dependencies[0]]
                    builder_source = dependency[0]
                    start = min(start, dependency[1])
                direct_source = self.SOURCE.search(line)
                if direct_source:
                    builder_source = f"{direct_source.group('view')}.getText().toString()"
                    start = min(start, index)
                transforms = [*transforms, "StringBuilder command construction"]
                builders[builder] = (builder_source, start, list(dict.fromkeys(transforms)), prefix)

            if assignment:
                target = assignment.group("target")
                value = assignment.group("value")
                builder_result = self.BUILDER_RESULT.search(value)
                if builder_result and builder_result.group("builder") in builders:
                    source_name, start, transforms, prefix = builders[builder_result.group("builder")]
                    if source_name:
                        tainted[target] = (source_name, start, [*transforms, f"command-prefix:{prefix}"] if prefix else transforms)
                else:
                    dependencies = [name for name in tainted if name != target and re.search(rf"\b{re.escape(name)}\b", value)]
                    if dependencies:
                        source_name, start, transforms = tainted[dependencies[0]]
                        transform = "String concatenation / assignment"
                        tainted[target] = (source_name, start, list(dict.fromkeys([*transforms, transform])))

            sink = self.SINK.search(line)
            if sink and sink.group("argument") in tainted:
                source_name, start, transforms = tainted[sink.group("argument")]
                prefix_values = [item.removeprefix("command-prefix:") for item in transforms if item.startswith("command-prefix:")]
                transforms = [item for item in transforms if not item.startswith("command-prefix:")]
                # BehaviorSlice.line identifies the seed API line. Anchor local
                # line numbers to the detected sink rather than the slice length.
                start_line = max(1, behavior_slice.line - (index - start))
                return [LocalDataFlow(
                    source=source_name,
                    transforms=transforms,
                    sink=f"Runtime.getRuntime().exec({sink.group('argument')})",
                    file=behavior_slice.file,
                    start_line=start_line,
                    end_line=behavior_slice.line,
                    confidence=0.9,
                    evidence_lines=[item.strip() for item in lines[start:index + 1]],
                    command_prefix=prefix_values[0] if prefix_values else None,
                )]
        return []
