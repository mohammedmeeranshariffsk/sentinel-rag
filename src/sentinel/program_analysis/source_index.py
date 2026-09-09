"""Small Java source index for bounded, syntactic caller/callee resolution.

This deliberately refuses nested classes, overloads and polymorphic receivers.
It is not a Java parser or a whole-program reachability analysis.
"""

from dataclasses import dataclass
from pathlib import Path
import re


TOKEN = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')


def mask_source(source: str) -> str:
    return TOKEN.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), source)


@dataclass
class SourceMethod:
    key: str
    file: str
    owner: str
    name: str
    line: int
    end_line: int
    start: int
    end: int
    declaration: str


@dataclass
class SourceCall:
    caller: str
    receiver: str
    name: str
    line: int
    offset: int
    target: str | None = None
    issue: str | None = None


class SourceIndex:
    METHOD = re.compile(
        r"^[ \t]*(?:(?:public|private|protected|static|final|synchronized|abstract|native)[ \t]+)*"
        r"[\w$<>\[\].?,]+\s+(?P<name>[\w$]+)\s*\([^;{}]*\)"
        r"\s*(?:throws\s+[\w.,\s]+)?\{", re.MULTILINE
    )
    CALL = re.compile(r"(?:(?<![\w$.])|(?<=\)\.))(?:(?P<receiver>[\w$]+)\s*\.\s*)?(?P<name>[A-Za-z_$][\w$]*)\s*\(")
    CONTROL = {"if", "for", "while", "switch", "catch", "synchronized", "super", "this"}

    def __init__(self, files, max_file_bytes=1_000_000):
        self.sources = {}
        self.masked = {}
        self.packages = {}
        self.classes = {}
        self.methods = {}
        self.calls = {}
        self.issues = []
        for file in sorted({str(Path(f)) for f in files}):
            path = Path(file)
            try:
                if path.stat().st_size > max_file_bytes:
                    self.issues.append(f"SOURCE_SIZE_LIMIT: {file}")
                    continue
                source = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            self.sources[file] = source
            masked = mask_source(source)
            self.masked[file] = masked
            package = re.search(r"\bpackage\s+([\w.]+)", masked)
            self.packages[file] = package[1] if package else None
            if path.suffix != ".java":
                self.issues.append(f"UNSUPPORTED_SOURCE_SYNTAX: {file}")
                continue
            depths, pairs = [], {}
            stack = []
            for i, char in enumerate(masked):
                depths.append(len(stack))
                if char == "{":
                    stack.append(i)
                elif char == "}" and stack:
                    pairs[stack.pop()] = i
            classes = [m for m in re.finditer(r"\bclass\s+([\w$]+)[^{;]*\{", masked) if depths[m.start()] == 0]
            if len(classes) != 1:
                self.issues.append(f"AMBIGUOUS_CLASS_LAYOUT: {file}")
                continue
            cls = classes[0]
            owner = f"{package[1]}.{cls[1]}" if package else cls[1]
            self.classes[file] = (owner, cls.start(), cls.end() - 1, pairs.get(cls.end()-1, len(masked)))
            anonymous = [(m.end()-1,pairs[m.end()-1]) for m in re.finditer(
                r"\bnew\s+[\w.$]+\s*\([^{};]*\)\s*\{",masked) if m.end()-1 in pairs]
            for m in self.METHOD.finditer(masked):
                opening = m.end()-1
                containers = [(a,b) for a,b in anonymous if a < opening < b and depths[opening] == depths[a]+1]
                if (depths[opening] != 1 and not containers) or opening not in pairs:
                    continue
                start = m.start() + len(m[0]) - len(m[0].lstrip())
                line = source.count("\n", 0, start)+1
                key = f"method:{file}:{line}:{m['name']}"
                method_owner = owner if not containers else f"{owner}$anonymous@{containers[-1][0]}"
                self.methods[key] = SourceMethod(key, file, method_owner, m['name'], line,
                    source.count("\n", 0, pairs[opening])+1, opening+1, pairs[opening], m[0])
        self.by_owner_name = {}
        self.by_file = {}
        for method in self.methods.values():
            self.by_owner_name.setdefault((method.owner, method.name), []).append(method)
            self.by_file.setdefault(method.file, []).append(method)
        for method in self.methods.values():
            calls = []
            masked = self.masked[method.file]
            for m in self.CALL.finditer(masked, method.start, method.end):
                if m['name'] in self.CONTROL or re.search(r"\bnew\s*$", masked[max(0,m.start()-10):m.start()]):
                    continue
                # Anonymous classes/lambdas introduce another execution context.
                preceding = masked[method.start:m.start()]
                nested = [other for other in self.by_file[method.file]
                          if method.start < other.start <= m.start() < other.end < method.end]
                if "->" in preceding or nested:
                    continue
                call = SourceCall(method.key, m['receiver'] or "", m['name'],
                    masked.count("\n",0,m.start())+1, m.start())
                if m.start() and masked[m.start()-1] == '.':
                    call.issue = "CHAINED_RECEIVER_UNRESOLVED"
                else:
                    self._resolve(method, call)
                calls.append(call)
            self.calls[method.key] = calls

    @classmethod
    def from_extraction(cls, extraction):
        files = {m.file for m in extraction.methods} | {a.location.file for a in extraction.apis}
        if extraction.source_root and extraction.source_root.is_dir():
            files.update(str(p) for p in extraction.source_root.rglob("*") if p.suffix in {".java", ".kt"})
        return cls(files)

    def containing(self, file, line):
        matches = [m for m in self.by_file.get(str(Path(file)), []) if line and m.line <= line <= m.end_line]
        matches.sort(key=lambda m: m.end-m.start)
        if matches and all(other.start <= matches[0].start and matches[0].end <= other.end for other in matches[1:]):
            return matches[0]
        return None

    def _resolve(self, method, call):
        owner = method.owner
        exact_receiver = call.receiver in {"", "this"}
        if not exact_receiver:
            if call.receiver == owner.rsplit('.',1)[-1]:
                exact_receiver = True  # only static targets accepted below
            else:
                # Only a local, freshly allocated receiver, with no reassignment.
                before = self.masked[method.file][method.start:call.offset]
                pattern = rf"\b([\w.$]+)\s+{re.escape(call.receiver)}\s*=\s*new\s+([\w.$]+)\s*\([^;{{}}]*\)\s*;"
                declarations = list(re.finditer(pattern, before))
                if len(declarations) != 1 or declarations[0][1] != declarations[0][2]:
                    call.issue = "RECEIVER_UNRESOLVED"
                    return
                scope_depth = 0
                for character in before[declarations[0].end():]:
                    scope_depth += (character == '{') - (character == '}')
                    if scope_depth < 0:
                        call.issue = "RECEIVER_OUT_OF_SCOPE"
                        return
                if re.search(rf"\b{re.escape(call.receiver)}\s*=", before[declarations[0].end():]):
                    call.issue = "RECEIVER_REASSIGNED"
                    return
                type_name = declarations[0][1]
                package = self.packages[method.file]
                imports = re.findall(rf"\bimport\s+([\w.]+\.{re.escape(type_name)})\s*;", self.masked[method.file])
                owner = type_name if '.' in type_name else (imports[0] if len(imports)==1 else f"{package}.{type_name}" if package else type_name)
        candidates = self.by_owner_name.get((owner, call.name), [])
        if len(candidates) != 1:
            call.issue = "AMBIGUOUS_OR_UNAVAILABLE_TARGET"
            return
        target = candidates[0]
        if exact_receiver and not re.search(r"\b(private|static|final)\b", target.declaration):
            call.issue = "VIRTUAL_DISPATCH_UNRESOLVED"
            return
        if call.receiver == method.owner.rsplit('.',1)[-1] and not re.search(r"\bstatic\b", target.declaration):
            call.issue = "NONSTATIC_CLASS_RECEIVER"
            return
        call.target = target.key
