"""Bounded syntactic APK graphs. Edges do not assert execution or intent."""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from sentinel.analysis.artifact_coverage import ArtifactCoverage
from sentinel.program_analysis.source_index import SourceIndex, TOKEN
from sentinel.program_analysis.behavior_slice import BehaviorSliceBuilder
from sentinel.validation.local_flow import LocalDataFlowAnalyzer


class NodeType(str, Enum):
    COMPONENT = "manifest_component"
    CLASS = "class"
    METHOD = "method"
    API = "api_call"
    STRING = "string"
    PERMISSION = "permission"
    CAPABILITY = "capability"
    CONFIGURATION = "configuration"


class EdgeType(str, Enum):
    DECLARES = "DECLARES"
    IMPLEMENTS = "IMPLEMENTS"
    EXTENDS = "EXTENDS"
    CONTAINS = "CONTAINS"
    CALLS = "CALLS"
    READS = "READS"
    WRITES = "WRITES"
    USES = "USES"
    PASSES_TO = "PASSES_TO"
    DELEGATES_TO = "DELEGATES_TO"
    CONFIGURES = "CONFIGURES"
    TRIGGERS = "TRIGGERS"


class BehaviorNode(BaseModel):
    node_id: str
    kind: NodeType
    label: str
    scope: Literal["APK"] = "APK"
    file: str | None = None
    line: int | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    seed_ids: list[str] = Field(default_factory=list)


class BehaviorEdge(BaseModel):
    source: str
    target: str
    relation: EdgeType
    evidence_refs: list[str] = Field(min_length=1)
    scope: Literal["APK"] = "APK"


class UnresolvedRelationship(BaseModel):
    reference: str
    reason: str


class BehaviorGraph(BaseModel):
    nodes: list[BehaviorNode] = Field(default_factory=list)
    edges: list[BehaviorEdge] = Field(default_factory=list)
    unresolved_relationships: list[UnresolvedRelationship] = Field(default_factory=list)
    artifact_coverage: ArtifactCoverage | None = None
    analysis_limitations: list[str] = Field(default_factory=list)
    max_depth: int = 1
    max_methods: int = 40
    max_nodes: int = 500


class BehaviorGraphBuilder:
    def __init__(self, max_depth=1, max_methods=40, max_nodes=500):
        if not 0 <= max_depth <= 3 or max_methods < 1 or max_nodes < 1:
            raise ValueError("Expansion requires depth 0..3 and positive method/node budgets")
        self.depth, self.method_limit, self.node_limit = max_depth, max_methods, max_nodes

    def build(self, context, extraction, seeds, coverage=None, source_index=None, accessibility_graphs=()):
        index = source_index or SourceIndex.from_extraction(extraction)
        graph = BehaviorGraph(artifact_coverage=coverage, max_depth=self.depth,
                              max_methods=self.method_limit, max_nodes=self.node_limit)
        nodes, edges, unresolved = {}, {}, {}

        def node(key, kind, label, file=None, line=None, refs=None, seed_ids=None):
            if key not in nodes and len(nodes) >= self.node_limit:
                if "GRAPH_NODE_LIMIT" not in graph.analysis_limitations:
                    graph.analysis_limitations.append("GRAPH_NODE_LIMIT")
                return None
            if key not in nodes:
                nodes[key] = BehaviorNode(node_id=key, kind=kind, label=label, file=file,
                    line=line, evidence_refs=refs or [], seed_ids=seed_ids or [])
            return key

        def edge(source, target, relation, refs):
            if source in nodes and target in nodes:
                edges[(source,target,relation)] = BehaviorEdge(source=source,target=target,
                    relation=relation,evidence_refs=refs)

        def missing(ref, reason):
            if len(unresolved) >= self.node_limit:
                if 'UNRESOLVED_RELATIONSHIP_LIMIT' not in graph.analysis_limitations:
                    graph.analysis_limitations.append('UNRESOLVED_RELATIONSHIP_LIMIT')
                return
            unresolved[(ref,reason)] = UnresolvedRelationship(reference=ref,reason=reason)

        queue = []
        for seed in seeds:
            if not seed.selected_for_investigation:
                continue
            kind = {"api":NodeType.API, "method":NodeType.METHOD, "string":NodeType.STRING,
                    "permission":NodeType.PERMISSION, "component":NodeType.CONFIGURATION,
                    "capability":NodeType.CAPABILITY}[seed.indicator_type.value]
            node(seed.seed_id,kind,seed.matched_value,seed.file,seed.line,seed.evidence_refs,[seed.seed_id])
            method = index.containing(seed.file,seed.line) if seed.located else None
            if method:
                queue.append((method.key,0))
            else:
                missing(seed.seed_id,"CONTAINING_METHOD_UNAVAILABLE" if seed.located else "UNLOCATED_APK_INDICATOR")
        incoming = {}
        for calls in index.calls.values():
            for call in calls:
                if call.target:
                    incoming.setdefault(call.target, []).append(call)
        visited = set()
        while queue and len(visited) < self.method_limit:
            key, depth = queue.pop(0)
            if key in visited:
                continue
            visited.add(key)
            method = index.methods[key]
            refs = [f"apk:source:{method.file}:{method.line}"]
            mid = node(key,NodeType.METHOD,f"{method.owner}.{method.name}",method.file,method.line,refs)
            class_offset = int(method.owner.rsplit('@',1)[1]) if '$anonymous@' in method.owner else index.classes[method.file][1]
            class_line = index.masked[method.file].count('\n',0,class_offset)+1
            class_refs = [f"apk:source:{method.file}:{class_line}"]
            cls = node(f"class:{method.owner}:{method.file}",NodeType.CLASS,method.owner,method.file,class_line,class_refs)
            edge(cls,mid,EdgeType.CONTAINS,class_refs+refs)
            for seed in seeds:
                if seed.seed_id in nodes and seed.file == method.file and seed.line and method.line <= seed.line <= method.end_line:
                    edge(mid,seed.seed_id,EdgeType.CONTAINS,seed.evidence_refs)
            for call in index.calls.get(key,[]):
                cref = [f"apk:source:{method.file}:{call.line}"]
                aid = node(f"call:{method.file}:{call.offset}",NodeType.API,
                    f"{call.receiver+'.' if call.receiver else ''}{call.name}",method.file,call.line,cref)
                if aid is None:
                    break
                edge(mid,aid,EdgeType.CALLS,cref)
                if call.target:
                    target = index.methods[call.target]
                    if depth < self.depth:
                        tid = node(target.key,NodeType.METHOD,f"{target.owner}.{target.name}",target.file,target.line,
                                   [f"apk:source:{target.file}:{target.line}"])
                        edge(mid,tid,EdgeType.CALLS,cref)
                        queue.append((target.key,depth+1))
                    else:
                        missing(aid or key,"EXPANSION_DEPTH_LIMIT")
                else:
                    missing(aid or key,call.issue or "TARGET_UNRESOLVED")
            if depth < self.depth:
                for call in incoming.get(key,[]):
                    caller = index.methods[call.caller]
                    cid = node(caller.key,NodeType.METHOD,f"{caller.owner}.{caller.name}",caller.file,caller.line,
                               [f"apk:source:{caller.file}:{caller.line}"])
                    edge(cid,mid,EdgeType.CALLS,[f"apk:source:{caller.file}:{call.line}"])
                    queue.append((caller.key,depth+1))
            for literal in TOKEN.finditer(index.sources[method.file],method.start,method.end):
                if not literal[0].startswith('"') or len(literal[0]) < 4:
                    continue
                line = index.sources[method.file].count('\n',0,literal.start())+1
                lrefs = [f"apk:source:{method.file}:{line}"]
                lid = node(f"string:{method.file}:{literal.start()}",NodeType.STRING,literal[0][1:-1],method.file,line,lrefs)
                # Presence in a method is not proof of passing a value to a sink.
                edge(mid,lid,EdgeType.CONTAINS,lrefs)
        if queue:
            graph.analysis_limitations.append("GRAPH_METHOD_LIMIT")
        # Reuse the existing deterministic flow validator for its supported
        # bounded pattern; never infer data flow from graph proximity.
        for seed in seeds:
            if seed.seed_id not in nodes or not seed.located or seed.indicator_type != "api":
                continue
            api = next((a for a in extraction.apis if a.location.file == seed.file
                        and a.location.line == seed.line and a.api_name == 'exec'),None)
            if api is None:
                continue
            sliced = BehaviorSliceBuilder().build_from_api(api)
            if sliced is None:
                continue
            for flow in LocalDataFlowAnalyzer().analyze(sliced):
                refs = [f"apk:source:{flow.file}:{n}" for n in range(flow.start_line,flow.end_line+1)]
                previous = node(f"flow:{seed.seed_id}:source",NodeType.API,flow.source,flow.file,flow.start_line,refs)
                for i,transform in enumerate(flow.transforms):
                    current = node(f"flow:{seed.seed_id}:transform:{i}",NodeType.CONFIGURATION,transform,flow.file,flow.start_line,refs)
                    edge(previous,current,EdgeType.PASSES_TO,refs)
                    previous = current
                sink = node(f"flow:{seed.seed_id}:sink",NodeType.API,flow.sink,flow.file,flow.end_line,refs)
                edge(previous,sink,EdgeType.PASSES_TO,refs)
        graph.analysis_limitations.extend(index.issues)
        # Compatibility adapter: preserve observed Accessibility declarations,
        # map only relationships also resolved by the generic source index.
        for legacy in accessibility_graphs:
            for item in legacy.get("nodes",[]):
                if item["kind"] == "accessibility_service":
                    ref = f"apk:manifest:{getattr(context,'manifest_path',None)}:service:{item['label']}"
                    node(item["node_id"],NodeType.COMPONENT,item["label"],refs=[ref])
            for issue in legacy.get("unsupported_relationships",[]):
                missing("accessibility",issue)
            graph.analysis_limitations.extend(legacy.get("analysis_limitations",[]))
            for item in legacy.get("nodes",[]):
                if item["kind"] != "accessibility_callback" or not item.get("file"):
                    continue
                method = index.containing(item['file'],item.get('line'))
                if not method or method.key not in nodes:
                    continue
                for component in list(nodes.values()):
                    if component.kind == NodeType.COMPONENT and component.label == method.owner:
                        edge(component.node_id,method.key,EdgeType.IMPLEMENTS,
                             component.evidence_refs+[f"apk:source:{method.file}:{method.line}"])
        graph.nodes, graph.edges = list(nodes.values()),list(edges.values())
        graph.unresolved_relationships = list(unresolved.values())
        graph.analysis_limitations = list(dict.fromkeys(graph.analysis_limitations))
        return graph
