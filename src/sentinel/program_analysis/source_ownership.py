"""Deterministic ownership hints; independent of evidence state and coverage."""

from enum import Enum
from pathlib import Path
import re

from pydantic import BaseModel, Field
from sentinel.program_analysis.source_index import TOKEN


class SourceProvenance(str, Enum):
    APPLICATION = "APPLICATION"
    APPLICATION_CANDIDATE = "APPLICATION_CANDIDATE"
    UNKNOWN = "UNKNOWN"
    THIRD_PARTY = "THIRD_PARTY"
    FRAMEWORK = "FRAMEWORK"
    GENERATED = "GENERATED"


PROVENANCE_ORDER = {value: rank for rank, value in enumerate(SourceProvenance)}


class SourceOwnership(BaseModel):
    file: str | None = None
    class_name: str | None = None
    source_provenance: SourceProvenance = SourceProvenance.UNKNOWN
    provenance_confidence: float = Field(default=0, ge=0, le=1)
    provenance_reasons: list[str] = Field(default_factory=lambda: ["Insufficient ownership evidence"])
    evidence_refs: list[str] = Field(default_factory=list)


class SourceOwnershipClassifier:
    FRAMEWORK = ("android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.", "org.jetbrains.", "dalvik.")
    LIBRARIES = ("com.google.gson.", "com.google.firebase.", "okhttp3.", "okio.", "retrofit2.", "com.bumptech.glide.")

    def __init__(self, index, application_package=None, manifest=None, propagation_depth=2):
        if not 0 <= propagation_depth <= 2:
            raise ValueError("Ownership propagation depth must be 0..2")
        self.index, self.package = index, application_package
        self.records = {}
        components = set()
        if manifest:
            for component in manifest.activities + manifest.services + manifest.receivers + manifest.providers:
                name = component.name
                if name.startswith('.'):
                    name = (manifest.package_name or '') + name
                elif '.' not in name and manifest.package_name:
                    name = manifest.package_name + '.' + name
                components.add(name)
        for file, source in index.masked.items():
            package = index.packages.get(file)
            cls = index.classes.get(file)
            owner = cls[0] if cls else None
            record = SourceOwnership(file=file,class_name=owner)
            name = Path(file).name
            if name in {'R.java','R.kt','BuildConfig.java','BuildConfig.kt'} or name.startswith('R$') or re.search(r'@(?:[\w.]+\.)?Generated\b',source):
                self._set(record,SourceProvenance.GENERATED,1,'Generated source artifact')
            elif package and self._namespace_matches(package, self.FRAMEWORK):
                self._set(record,SourceProvenance.FRAMEWORK,0.99,'Recognized platform/framework namespace')
            elif package and self._namespace_matches(package, self.LIBRARIES):
                self._set(record,SourceProvenance.THIRD_PARTY,0.95,'Recognized library namespace')
            elif package and application_package and (package == application_package or package.startswith(application_package+'.')):
                self._set(record,SourceProvenance.APPLICATION,0.99,'Manifest package or application subpackage')
            elif owner in components:
                self._set(record,SourceProvenance.APPLICATION,0.99,'Exact recovered manifest component class')
                record.evidence_refs.append(f'apk:manifest:{manifest.manifest_path}:component:{owner}')
            else:
                record.provenance_reasons = ['Recovered namespace is not recognized as framework or a known library']
                record.provenance_confidence = 0.2
                # Resource use and application package constants are independent
                # signals. An odd namespace alone never raises ownership.
                resources = bool(application_package and re.search(
                    rf'\b{re.escape(application_package)}\.R\.',source))
                imported_r = bool(application_package and re.search(
                    rf'\bimport\s+{re.escape(application_package)}\.R\s*;',source))
                resources |= imported_r and bool(re.search(r'\bR\.(?:id|layout|string|drawable)\.',source))
                literals = [m for m in TOKEN.finditer(index.sources[file])
                            if m[0] == f'"{application_package}"']
                package_constant = bool(application_package and literals)
                if resources:
                    record.provenance_reasons.append('References application-specific resources')
                if package_constant:
                    record.provenance_reasons.append('Contains application package literal (context only)')
                    record.evidence_refs.extend(
                        f'apk:source:{file}:{source.count(chr(10),0,m.start())+1}' for m in literals)
                if resources and package_constant:
                    record.source_provenance = SourceProvenance.APPLICATION_CANDIDATE
                    record.provenance_confidence = 0.6
            if cls:
                record.evidence_refs.append(f'apk:source:{file}:{source.count(chr(10),0,cls[1])+1}')
            self.records[file] = record
        # Each round uses a snapshot, so depth is real and independent of file order.
        for depth in range(propagation_depth):
            owned = {file for file,r in self.records.items() if r.source_provenance in
                     {SourceProvenance.APPLICATION,SourceProvenance.APPLICATION_CANDIDATE}}
            updates = {}
            for caller_key,calls in index.calls.items():
                caller = index.methods[caller_key]
                if caller.file not in owned:
                    continue
                for call in calls:
                    if not call.target:
                        continue
                    target = index.methods[call.target]
                    record = self.records[target.file]
                    if record.source_provenance != SourceProvenance.UNKNOWN:
                        continue
                    updates.setdefault(target.file,[]).append(f'apk:source:{caller.file}:{call.line}')
            for file,refs in updates.items():
                record = self.records[file]
                record.source_provenance = SourceProvenance.APPLICATION_CANDIDATE
                record.provenance_confidence = 0.65 - depth*0.1
                record.provenance_reasons.append(f'Locally resolved call from application-owned/candidate code; propagation hop {depth+1}')
                record.evidence_refs.extend(sorted(set(refs)))

    @staticmethod
    def _namespace_matches(package, prefixes):
        return any(package == prefix.rstrip('.') or package.startswith(prefix) for prefix in prefixes)

    @staticmethod
    def _set(record, provenance, confidence, reason):
        record.source_provenance = provenance
        record.provenance_confidence = confidence
        record.provenance_reasons = [reason]

    def get(self,file):
        return self.records.get(str(Path(file)),SourceOwnership(file=file)) if file else SourceOwnership()
