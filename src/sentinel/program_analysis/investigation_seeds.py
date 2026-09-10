"""Convert existing matches into prioritized APK investigation candidates."""

from enum import Enum
import hashlib
from pathlib import Path
import re
from typing import Literal

from pydantic import BaseModel, Field

from sentinel.program_analysis.source_index import SourceIndex
from sentinel.program_analysis.source_ownership import SourceProvenance, SourceOwnershipClassifier, PROVENANCE_ORDER


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
    FRAMEWORK = "FRAMEWORK_BOUNDARY_ONLY"
    DUPLICATE = "GROUPED_DUPLICATE"
    BUDGET = "BEHAVIOR_SEED_BUDGET"


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
    provenance_confidence: float = Field(default=0,ge=0,le=1)
    provenance_reasons: list[str] = Field(default_factory=list)
    ownership_evidence_refs: list[str] = Field(default_factory=list)
    representative_seed_id: str | None = None
    duplicate_count: int = 0
    grouped_evidence_refs: list[str] = Field(default_factory=list)
    selection_eligible: bool | None = None
    eligibility_reason: SelectionReason | None = None
    quality: SeedQuality = SeedQuality.WEAK
    corroborating_evidence_refs: list[str] = Field(default_factory=list)
    selected_for_investigation: bool = False
    selection_reason: SelectionReason = SelectionReason.GENERIC
    match_strength: float = Field(default=0, ge=0, le=1)


class InvestigationSeedBuilder:
    # Examples augment a context/specificity policy; unqualified one-word names
    # are weak by default, rather than all other names being automatically strong.
    GENERIC = {"performAction", "onReceive", "run", "start", "execute", "handle", "process", "send", "read", "write", "getText", "exec", "loadClass"}
    def __init__(self, extraction, application_package=None, source_index=None, manifest=None, ownership=None, max_seeds_per_behavior=12):
        if max_seeds_per_behavior < 1:
            raise ValueError('Behavior seed budget must be positive')
        self.max_seeds_per_behavior = max_seeds_per_behavior
        self.extraction = extraction
        self.package = application_package
        self.index = source_index or SourceIndex.from_extraction(extraction)
        self.ownership = ownership or SourceOwnershipClassifier(self.index,application_package,manifest)

    def provenance(self, file):
        return self.ownership.get(file).source_provenance

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
            provenance_confidence=self.ownership.get(file).provenance_confidence,
            provenance_reasons=self.ownership.get(file).provenance_reasons,
            ownership_evidence_refs=self.ownership.get(file).evidence_refs,
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
        elif provenance == SourceProvenance.FRAMEWORK:
            seed.quality, seed.selection_reason = SeedQuality.CONTEXTUAL, SelectionReason.FRAMEWORK
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
        return self.select(seeds)

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
        return self.select(seeds)

    def select(self,seeds):
        seeds = list({s.seed_id:s for s in seeds}.values())
        groups = {}
        for seed in seeds:
            if seed.selection_eligible is None:
                seed.selection_eligible = seed.selected_for_investigation
                seed.eligibility_reason = seed.selection_reason
            seed.selected_for_investigation = seed.selection_eligible
            seed.selection_reason = seed.eligibility_reason
            seed.representative_seed_id = None
            seed.duplicate_count = 0
            seed.grouped_evidence_refs = []
        ordered = self.prioritize(seeds)
        for seed in ordered:
            if not seed.selection_eligible:
                continue
            method = self.index.containing(seed.file,seed.line) if seed.located else None
            key = (seed.behavior_id,seed.origin,method.key if method else seed.file or seed.seed_id,
                   seed.indicator_type,seed.matched_value.rsplit('.',1)[-1] if seed.indicator_type=='api' else seed.matched_value,
                   seed.source_provenance)
            representative = groups.setdefault(key,seed)
            seed.representative_seed_id = representative.seed_id
            representative.grouped_evidence_refs = list(dict.fromkeys(representative.grouped_evidence_refs+seed.evidence_refs))
            if representative is not seed:
                representative.duplicate_count += 1
                seed.selected_for_investigation = False
                seed.selection_reason = SelectionReason.DUPLICATE
        counts = {}
        for seed in ordered:
            if not seed.selected_for_investigation:
                continue
            count = counts.get(seed.behavior_id,0)
            if count >= self.max_seeds_per_behavior:
                seed.selected_for_investigation = False
                seed.selection_reason = SelectionReason.BUDGET
            else:
                counts[seed.behavior_id] = count+1
        return self.prioritize(ordered)

    @staticmethod
    def prioritize(seeds):
        return sorted({s.seed_id:s for s in seeds}.values(), key=lambda s: (
            not s.selected_for_investigation, PROVENANCE_ORDER[s.source_provenance] if s.located else 6,
            -s.match_strength, s.file or "", s.line or 0, s.seed_id))
