"""Bounded, evidence-only graph construction for Android accessibility behavior."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

from sentinel.extraction.models import ExtractionResult
from sentinel.manifest.analyzer import ManifestAnalysis

if TYPE_CHECKING:
    from sentinel.profiles.models import ExtractionProfile


class BehaviorGraphNode(BaseModel):
    node_id: str
    kind: str
    label: str
    scope: str = "APK"
    file: str | None = None
    line: int | None = None
    class_name: str | None = None
    method_name: str | None = None


class BehaviorGraphEdge(BaseModel):
    source: str
    target: str
    relation: str
    scope: str = "APK"
    evidence_refs: list[str] = Field(default_factory=list)


class AccessibilityBehaviorGraph(BaseModel):
    nodes: list[BehaviorGraphNode] = Field(default_factory=list)
    edges: list[BehaviorGraphEdge] = Field(default_factory=list)
    investigation_seed_refs: list[str] = Field(default_factory=list)
    unsupported_relationships: list[str] = Field(default_factory=list)
    analysis_limitations: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class _SourceClass:
    name: str
    qualified_name: str
    superclass: str | None
    file: str
    line: int


class AccessibilityBehaviorGraphBuilder:
    """Build direct accessibility relationships; profile data selects only seeds."""

    BIND_PERMISSION = "android.permission.BIND_ACCESSIBILITY_SERVICE"
    SERVICE_INTENT = "android.accessibilityservice.AccessibilityService"
    CALLBACK = "onAccessibilityEvent"
    ACTIONS = {"performAction", "performGlobalAction", "dispatchGesture"}
    TEXT_READS = {"getText", "findAccessibilityNodeInfosByText"}
    PACKAGE_PATTERN = re.compile(r"^\s*package\s+([A-Za-z_$][\w.$]*)\s*;?", re.MULTILINE)
    JAVA_CLASS_PATTERN = re.compile(
        r"\bclass\s+(?P<name>[A-Za-z_$][\w$]*)"
        r"(?:\s+extends\s+(?P<parent>[A-Za-z_$][\w.$]*))?"
    )
    KOTLIN_CLASS_PATTERN = re.compile(
        r"\bclass\s+(?P<name>[A-Za-z_$][\w$]*)\s*:\s*"
        r"(?P<parent>[A-Za-z_$][\w.$]*)"
    )

    def build(self, profile: ExtractionProfile, extraction: ExtractionResult,
              manifest: ManifestAnalysis | None) -> AccessibilityBehaviorGraph:
        graph = AccessibilityBehaviorGraph()
        template_ref = next((bundle.template_ref for bundle in profile.behavior_bundles
                             if "accessibility" in bundle.template_ref), None)
        if not template_ref or manifest is None:
            return graph
        seed_methods = {item.method for item in profile.extractors.api_calls
                        if item.method and template_ref in item.supports}
        seed_strings = {item.value for item in profile.extractors.exact_strings
                        if item.value and template_ref in item.supports}
        graph.investigation_seed_refs = list(dict.fromkeys(
            [f"{api.location.file}:{api.location.line}" for api in extraction.apis if api.api_name in seed_methods]
            + [f"{item.location.file}:{item.location.line}" for item in extraction.strings if item.value in seed_strings]
        ))
        services = {
            service.name for service in manifest.services
            if service.permission == self.BIND_PERMISSION
            and any(self.SERVICE_INTENT in item.actions for item in service.intent_filters)
        }
        class_index = self._class_index(extraction.source_root)
        resolved_callback_count = 0
        for service_name in sorted(services):
            service = service_name.rsplit(".", 1)[-1]
            service_class = self._resolve_class(service_name, class_index)
            service_id = f"service:{service_name}"
            graph.nodes.append(BehaviorGraphNode(
                node_id=service_id, kind="accessibility_service", label=service_name,
                file=service_class.file if service_class else None,
                line=service_class.line if service_class else None,
                class_name=service,
            ))
            if service_class is None and extraction.source_root is not None:
                graph.analysis_limitations.append(
                    "SOURCE_IMPLEMENTATION_UNAVAILABLE: Manifest accessibility "
                    f"service class {service_name} was not present in available JADX source."
                )

            hierarchy = self._hierarchy(service_class, class_index)
            hierarchy_names = {item.name for item in hierarchy} or {service}
            callbacks = [method for method in extraction.methods
                         if method.name == self.CALLBACK
                         and method.class_name in hierarchy_names]
            for callback in callbacks:
                resolved_callback_count += 1
                callback_id = f"callback:{service}:{callback.line}"
                graph.nodes.append(BehaviorGraphNode(
                    node_id=callback_id, kind="accessibility_callback", label=callback.name,
                    file=callback.file, line=callback.line, class_name=callback.class_name,
                    method_name=callback.name,
                ))
                graph.edges.append(BehaviorGraphEdge(
                    source=service_id, target=callback_id,
                    relation=("implements_callback" if callback.class_name == service
                              else "inherits_callback"),
                    evidence_refs=[f"{callback.file}:{callback.line}"],
                ))
                self._add_method_evidence(graph, callback_id, callback, extraction)
                self._add_direct_helpers(graph, callback_id, callback, extraction)
        if not resolved_callback_count:
            graph.unsupported_relationships.append("No onAccessibilityEvent callback was resolved in a declared accessibility service.")
        if not any(edge.relation == "calls_accessibility_action" for edge in graph.edges):
            graph.unsupported_relationships.append("No direct callback-to-accessibility-action relationship was resolved.")
        graph.unsupported_relationships.append("Configuration-to-callback control is not established by this bounded analysis.")
        return graph

    def _add_method_evidence(self, graph, source_id, method, extraction) -> None:
        for api in extraction.apis:
            if (api.location.class_name, api.location.method_name) != (method.class_name, method.name):
                continue
            if api.api_name not in self.ACTIONS | self.TEXT_READS:
                continue
            kind = "accessibility_action" if api.api_name in self.ACTIONS else "accessibility_text_read"
            relation = "calls_accessibility_action" if api.api_name in self.ACTIONS else "reads_accessibility_text"
            api_id = f"api:{api.location.file}:{api.location.line}:{api.api_name}"
            if not any(node.node_id == api_id for node in graph.nodes):
                graph.nodes.append(BehaviorGraphNode(
                    node_id=api_id, kind=kind, label=api.full_reference,
                    file=api.location.file, line=api.location.line,
                    class_name=api.location.class_name, method_name=api.location.method_name,
                ))
            graph.edges.append(BehaviorGraphEdge(
                source=source_id, target=api_id, relation=relation,
                evidence_refs=[f"{api.location.file}:{api.location.line}"],
            ))

    def _add_direct_helpers(self, graph, callback_id, callback, extraction) -> None:
        callback_calls = [api for api in extraction.apis
                          if (api.location.class_name, api.location.method_name)
                          == (callback.class_name, callback.name)]
        for call in callback_calls:
            if call.api_name in self.ACTIONS | self.TEXT_READS:
                continue
            candidates = [method for method in extraction.methods
                          if method.name == call.api_name
                          and self._local_receiver_matches(call, method)]
            if len(candidates) != 1:
                continue
            helper = candidates[0]
            helper_actions = [api for api in extraction.apis
                              if (api.location.class_name, api.location.method_name)
                              == (helper.class_name, helper.name)
                              and api.api_name in self.ACTIONS | self.TEXT_READS]
            if not helper_actions:
                continue
            helper_id = f"helper:{helper.class_name}:{helper.name}:{helper.line}"
            graph.nodes.append(BehaviorGraphNode(
                node_id=helper_id, kind="accessibility_helper", label=helper.name,
                file=helper.file, line=helper.line, class_name=helper.class_name,
                method_name=helper.name,
            ))
            graph.edges.append(BehaviorGraphEdge(
                source=callback_id, target=helper_id, relation="delegates_to_local_helper",
                evidence_refs=[f"{call.location.file}:{call.location.line}"],
            ))
            self._add_method_evidence(graph, helper_id, helper, extraction)

    @staticmethod
    def _local_receiver_matches(call, method) -> bool:
        receiver = call.full_reference.rsplit(".", 1)[0] if "." in call.full_reference else ""
        if receiver in {"this", "super"} or method.class_name == call.location.class_name:
            return method.class_name == call.location.class_name
        try:
            source = Path(call.location.file).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return False
        declaration = re.compile(
            rf"\b(?P<type>[A-Z][A-Za-z0-9_$.]*)\s+(?:this\.)?{re.escape(receiver)}\b"
        )
        return any(match.group("type").rsplit(".", 1)[-1] == method.class_name
                   for match in declaration.finditer(source))

    def _class_index(self, source_root: Path | None) -> dict[str, _SourceClass | None]:
        if source_root is None or not Path(source_root).is_dir():
            return {}
        index: dict[str, _SourceClass | None] = {}
        for file_path in Path(source_root).rglob("*"):
            if not file_path.is_file() or file_path.suffix.lower() not in {".java", ".kt"}:
                continue
            try:
                source = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            package_match = self.PACKAGE_PATTERN.search(source)
            package = package_match.group(1) if package_match else ""
            matches = list(self.KOTLIN_CLASS_PATTERN.finditer(source))
            matches.extend(self.JAVA_CLASS_PATTERN.finditer(source))
            for match in matches:
                name = match.group("name")
                qualified = f"{package}.{name}" if package else name
                item = _SourceClass(
                    name=name, qualified_name=qualified,
                    superclass=match.groupdict().get("parent"),
                    file=str(file_path), line=source.count("\n", 0, match.start()) + 1,
                )
                index.setdefault(qualified, item)
                if name not in index:
                    index[name] = item
                elif index[name] != item:
                    # A simple class name is not usable when more than one
                    # source class has that name. Fully-qualified lookup still works.
                    index[name] = None
        return index

    @staticmethod
    def _resolve_class(name: str, index: dict[str, _SourceClass | None]) -> _SourceClass | None:
        return index.get(name) or index.get(name.rsplit(".", 1)[-1])

    def _hierarchy(self, source_class, index) -> list[_SourceClass]:
        hierarchy: list[_SourceClass] = []
        seen: set[str] = set()
        current = source_class
        while current is not None and current.qualified_name not in seen:
            hierarchy.append(current)
            seen.add(current.qualified_name)
            if not current.superclass:
                current = None
                continue
            package = current.qualified_name.rsplit(".", 1)[0] if "." in current.qualified_name else ""
            qualified_parent = (
                f"{package}.{current.superclass}"
                if package and "." not in current.superclass else current.superclass
            )
            current = self._resolve_class(qualified_parent, index)
        return hierarchy
