"""Convert existing matches into prioritized APK investigation candidates."""

from enum import Enum
import hashlib
from pathlib import Path
import re
from typing import Literal

from pydantic import BaseModel, Field

from sentinel.program_analysis.source_index import SourceIndex


class SourceProvenance(str, Enum):
    APPLICATION = "APPLICATION"
    UNKNOWN = "UNKNOWN"
    THIRD_PARTY = "THIRD_PARTY"
    FRAMEWORK = "FRAMEWORK"
    GENERATED = "GENERATED"


class IndicatorType(str, Enum):
    API = "api"
    METHOD = "method"
    STRING = "string"
    PERMISSION = "permission"
    COMPONENT = "component"
    CAPABILITY = "capability"


class SeedQuality(str, Enum):
    STRONG = "STRONG"
    CONTEXTUAL = "CONTEXTUAL"
    WEAK = "WEAK"
    BROADER = "BROADER"
    GENERATED = "GENERATED"


class SelectionReason(str, Enum):
    LOCAL_CONTEXT = "LOCAL_CONTEXT_CORROBORATED"
    DISTINCTIVE = "DISTINCTIVE_INDICATOR"
    LIBRARY = "LIBRARY_CONTEXT_ONLY"
    GENERIC = "UNCORROBORATED_GENERIC_INDICATOR"
    BROADER = "BROADER_APK_CORRELATION"
    GENERATED = "GENERATED_CODE_EXCLUDED"
    UNVERIFIED = "UNVERIFIED_PROFILE_CANDIDATE"
    NONCODE = "NOT_IN_SOURCE_CODE"


class InvestigationSeed(BaseModel):
    seed_id: str
    behavior_id: str
    origin: Literal["THREAT_MATCH", "PROFILE_MATCH"]
    indicator_type: IndicatorType
    matched_value: str
    file: str | None = None
    class_name: str | None = None
    containing_method: str | None = None
    line: int | None = None
    located: bool = False
    evidence_scope: Literal["LOCAL", "APK"] = "APK"
    evidence_refs: list[str] = Field(default_factory=list)
    source_provenance: SourceProvenance = SourceProvenance.UNKNOWN
    quality: SeedQuality = SeedQuality.WEAK
    corroborating_evidence_refs: list[str] = Field(default_factory=list)
    selected_for_investigation: bool = False
    selection_reason: SelectionReason = SelectionReason.GENERIC
    match_strength: float = Field(default=0, ge=0, le=1)


class InvestigationSeedBuilder:
    # Examples augment a context/specificity policy; unqualified one-word names
    # are weak by default, rather than all other names being automatically strong.
    GENERIC = {"performAction", "onReceive", "run", "start", "execute", "handle", "process", "send", "read", "write", "getText", "exec", "loadClass"}
    FRAMEWORK_PREFIXES = ("android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.")

    def __init__(self, extraction, application_package=None, source_index=None):
        self.extraction = extraction
        self.package = application_package
        self.index = source_index or SourceIndex.from_extraction(extraction)

    def provenance(self, file):
        if not file:
            return SourceProvenance.UNKNOWN
        name = Path(file).name
        if name in {"R.java", "R.kt", "BuildConfig.java", "BuildConfig.kt"} or name.startswith("R$"):
            return SourceProvenance.GENERATED
        package = self.index.packages.get(str(Path(file)))
        if not package:
            return SourceProvenance.UNKNOWN
        if self.package and (package == self.package or package.startswith(self.package + '.')):
            return SourceProvenance.APPLICATION
        if package.startswith(self.FRAMEWORK_PREFIXES):
            return SourceProvenance.FRAMEWORK
        # Different namespace is a third-party candidate, not proof of authorship.
        return SourceProvenance.THIRD_PARTY if self.package else SourceProvenance.UNKNOWN

    def _seed(self, behavior, origin, kind, value, file=None, line=None,
              class_name=None, method=None, ref=None, eligible=True):
        located = bool(file and line and str(Path(file)) in self.index.sources
                       and 0 < line <= len(self.index.sources[str(Path(file))].splitlines()))
        containing = self.index.containing(file, line) if located else None
        provenance = self.provenance(file)
        refs = [ref or (f"apk:source:{file}:{line}" if located else f"apk:{kind}:{value}")]
        seed = InvestigationSeed(
            seed_id="seed:" + hashlib.sha256(str((behavior, origin, kind, value, file, line)).encode()).hexdigest()[:20],
            behavior_id=behavior, origin=origin, indicator_type=kind, matched_value=value,
            file=file, line=line, located=located, evidence_scope="LOCAL" if located else "APK",
            class_name=containing.owner if containing else class_name,
            containing_method=containing.name if containing else method,
            evidence_refs=refs, source_provenance=provenance,
        )
        terminal = value.rsplit('.',1)[-1]
        distinctive = kind in {"string", "component", "permission", "capability"} or (
            terminal not in self.GENERIC and len(re.findall(r"[A-Z][a-z]+|^[a-z]+", terminal)) >= 2
        )
        corroborated = False
        context_refs = []
        if located and kind in {"api", "method"}:
            masked = self.index.masked[str(Path(file))]
            lines = masked.splitlines()
            local = lines[line-1]
            if not re.search(rf"\b{re.escape(terminal)}\s*\(",local):
                seed.selection_reason = SelectionReason.NONCODE
                return seed
            # Receiver-specific type evidence in the containing method, never
            # a permission elsewhere in the APK or an unrelated nearby API.
            receiver = value.rsplit('.',1)[0] if '.' in value else ""
            body = masked[containing.start:containing.end] if containing else local
            owner_patterns = {
                "performAction": "AccessibilityNodeInfo",
                "getText": "AccessibilityNodeInfo",
                "dispatchGesture": "AccessibilityService",
                "performGlobalAction": "AccessibilityService",
                "exec": "Runtime",
                "loadClass": "DexClassLoader|PathClassLoader",
            }
            expected = owner_patterns.get(terminal)
            if expected:
                corroborated = bool(re.search(rf"\b(?:{expected})\s*\.\s*{re.escape(terminal)}\s*\(", local))
                if terminal == "exec":
                    corroborated |= bool(re.search(r"\bRuntime\.getRuntime\(\)\.exec\s*\(", local))
                if receiver and re.fullmatch(r"[\w$]+", receiver):
                    declarations = list(re.finditer(rf"\b(?:{expected})\s+{re.escape(receiver)}\b", body))
                    corroborated |= len(declarations) == 1
                    if len(declarations) == 1 and containing:
                        declaration_line = masked.count('\n',0,containing.start+declarations[0].start())+1
                        context_refs.append(f"apk:source:{file}:{declaration_line}")
                # Accessibility callback/type is useful local context, not an
                # assertion that the call is reached at runtime.
                if containing and terminal in {"dispatchGesture", "performGlobalAction"}:
                    corroborated |= bool(re.search(r"\bextends\s+AccessibilityService\b", masked) and containing.name == "onAccessibilityEvent")
            if terminal == "onAccessibilityEvent":
                corroborated = bool(re.search(r"\bextends\s+AccessibilityService\b", masked))
            if corroborated:
                for declaration in re.finditer(r"\bextends\s+AccessibilityService\b",masked):
                    context_refs.append(f"apk:source:{file}:{masked.count(chr(10),0,declaration.start())+1}")
                seed.corroborating_evidence_refs = list(dict.fromkeys(refs + context_refs))
        if provenance == SourceProvenance.GENERATED:
            seed.quality, seed.selection_reason = SeedQuality.GENERATED, SelectionReason.GENERATED
        elif not eligible:
            seed.selection_reason = SelectionReason.UNVERIFIED
        elif not located:
            seed.quality, seed.selection_reason = SeedQuality.BROADER, SelectionReason.BROADER
            seed.selected_for_investigation, seed.match_strength = True, 0.2
        elif corroborated or distinctive:
            library = provenance in {SourceProvenance.THIRD_PARTY, SourceProvenance.FRAMEWORK}
            seed.quality = SeedQuality.CONTEXTUAL if library else SeedQuality.STRONG
            seed.selection_reason = SelectionReason.LIBRARY if library else SelectionReason.LOCAL_CONTEXT if corroborated else SelectionReason.DISTINCTIVE
            seed.selected_for_investigation, seed.match_strength = True, 0.4 if library else 0.8
        return seed

    def from_threats(self, matches):
        seeds = []
        for match in matches:
            for kind, values, items in (
                ("api", match.matched_apis, self.extraction.apis),
                ("method", match.matched_methods, self.extraction.methods),
                ("string", match.matched_strings, self.extraction.strings),
            ):
                for value in values:
                    found = []
                    for item in items:
                        name = item.api_name if kind == "api" else item.name if kind == "method" else item.value
                        if name.lower() != value.lower():
                            continue
                        loc = item if kind == "method" else item.location
                        found.append(self._seed(match.knowledge_id, "THREAT_MATCH", kind,
                            item.full_reference if kind == "api" else name, loc.file, loc.line,
                            getattr(loc, "class_name", None), getattr(loc, "method_name", None)))
                    seeds.extend(found or [self._seed(match.knowledge_id, "THREAT_MATCH", kind, value)])
            seeds.extend(self._seed(match.knowledge_id, "THREAT_MATCH", "permission", value) for value in match.matched_permissions)
        return self.prioritize(seeds)

    def from_profile(self, analysis):
        seeds = []
        kinds = {"api_calls": "api", "manifest": "permission", "components_and_intents": "component", "exact_strings": "string"}
        for match in analysis.artifact_matches:
            kind = kinds.get(match.artifact_group, "capability")
            value = match.value
            if kind == 'api':
                actual = next((a for a in self.extraction.apis if a.location.file == match.file
                    and a.location.line == match.line and a.api_name == match.value.rsplit('.',1)[-1]),None)
                if actual:
                    value = actual.full_reference
            seeds.append(self._seed(analysis.family_id, "PROFILE_MATCH", kind, value,
                match.file, match.line, ref=match.reference,
                eligible=match.classification in {"reported_exact_token", "reported_behavior", "behavior_derived_search_target"}))
        return self.prioritize(seeds)

    @staticmethod
    def prioritize(seeds):
        order = {SourceProvenance.APPLICATION: 0, SourceProvenance.UNKNOWN: 1,
                 SourceProvenance.THIRD_PARTY: 2, SourceProvenance.FRAMEWORK: 2,
                 SourceProvenance.GENERATED: 4}
        return sorted({s.seed_id:s for s in seeds}.values(), key=lambda s: (
            not s.selected_for_investigation, order[s.source_provenance] if s.located else 3,
            -s.match_strength, s.file or "", s.line or 0, s.seed_id))
