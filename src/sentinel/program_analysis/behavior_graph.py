"""Bounded syntactic APK graphs. Edges do not assert execution or intent."""

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

from sentinel.analysis.artifact_coverage import ArtifactCoverage
from sentinel.program_analysis.source_index import SourceIndex, TOKEN
from sentinel.program_analysis.behavior_slice import BehaviorSliceBuilder
from sentinel.validation.local_flow import LocalDataFlowAnalyzer
from sentinel.program_analysis.source_ownership import SourceOwnershipClassifier, SourceProvenance, PROVENANCE_ORDER


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
    source_provenance: SourceProvenance = SourceProvenance.UNKNOWN
    provenance_reasons: list[str] = Field(default_factory=list)
    provenance_confidence: float = Field(default=0,ge=0,le=1)
    boundary: bool = False
    target_provenance: SourceProvenance | None = None


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
    max_methods_per_behavior: int = 8
    max_nodes_per_method: int = 24
    third_party_method_budget: int = 2
    limit_reached: bool = False
    expanded_methods_by_provenance: dict[str,int] = Field(default_factory=dict)


class BehaviorGraphBuilder:
    def __init__(self, max_depth=1, max_methods=40, max_nodes=500,
                 max_methods_per_behavior=8, max_nodes_per_method=24, third_party_method_budget=2):
        if not 0 <= max_depth <= 3 or not 1 <= max_methods <= 40 or not 1 <= max_nodes <= 500:
            raise ValueError("Expansion requires depth 0..3, 1..40 methods and 1..500 nodes")
        self.depth, self.method_limit, self.node_limit = max_depth, max_methods, max_nodes
        if min(max_methods_per_behavior,max_nodes_per_method) < 1 or third_party_method_budget < 0:
            raise ValueError('Expansion budgets must be positive (library budget may be zero)')
        self.behavior_limit, self.method_node_limit, self.library_limit = max_methods_per_behavior,max_nodes_per_method,third_party_method_budget

    def build(self, context, extraction, seeds, coverage=None, source_index=None, accessibility_graphs=(), ownership=None):
        index = source_index or SourceIndex.from_extraction(extraction)
        ownership = ownership or SourceOwnershipClassifier(index,getattr(context,'package_name',None))
        graph = BehaviorGraph(artifact_coverage=coverage, max_depth=self.depth,
                              max_methods=self.method_limit, max_nodes=self.node_limit,
                              max_methods_per_behavior=self.behavior_limit,max_nodes_per_method=self.method_node_limit,
                              third_party_method_budget=self.library_limit)
        nodes, edges, unresolved = {}, {}, {}
        active_method = None
        method_node_counts = {}

        def node(key, kind, label, file=None, line=None, refs=None, seed_ids=None):
            if key not in nodes and active_method and method_node_counts.get(active_method,0) >= self.method_node_limit:
                if 'PER_METHOD_NODE_LIMIT' not in graph.analysis_limitations:
                    graph.analysis_limitations.append('PER_METHOD_NODE_LIMIT')
                return None
            if key not in nodes and len(nodes) >= self.node_limit:
                if "GRAPH_NODE_LIMIT" not in graph.analysis_limitations:
                    graph.analysis_limitations.append("GRAPH_NODE_LIMIT")
                return None
            if key not in nodes:
                owner = ownership.get(file)
                nodes[key] = BehaviorNode(node_id=key, kind=kind, label=label, file=file,
                    line=line, evidence_refs=refs or [], seed_ids=seed_ids or [],
                    source_provenance=owner.source_provenance,provenance_reasons=owner.provenance_reasons,
                    provenance_confidence=owner.provenance_confidence)
                if active_method:
                    method_node_counts[active_method] = method_node_counts.get(active_method,0)+1
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
            if ownership.get(seed.file).source_provenance in {SourceProvenance.FRAMEWORK,SourceProvenance.GENERATED}:
                continue
            kind = {"api":NodeType.API, "method":NodeType.METHOD, "string":NodeType.STRING,
                    "permission":NodeType.PERMISSION, "component":NodeType.CONFIGURATION,
                    "capability":NodeType.CAPABILITY}[seed.indicator_type.value]
            node(seed.seed_id,kind,seed.matched_value,seed.file,seed.line,
                 seed.grouped_evidence_refs or seed.evidence_refs,[seed.seed_id])
            method = index.containing(seed.file,seed.line) if seed.located else None
            if method:
                queue.append((method.key,0,seed.behavior_id))
            else:
                missing(seed.seed_id,"CONTAINING_METHOD_UNAVAILABLE" if seed.located else "UNLOCATED_APK_INDICATOR")
        incoming = index.incoming_calls
        visited = set()
        behavior_counts = {}
        library_count = 0
        while queue and len(visited) < self.method_limit:
            queue.sort(key=lambda item:(PROVENANCE_ORDER[ownership.get(index.methods[item[0]].file).source_provenance],
                behavior_counts.get(item[2],0),item[1],item[2],item[0]))
            key, depth, behavior = queue.pop(0)
            if key in visited:
                continue
            method = index.methods[key]
            provenance = ownership.get(method.file).source_provenance
            if provenance in {SourceProvenance.FRAMEWORK,SourceProvenance.GENERATED}:
                continue
            if behavior_counts.get(behavior,0) >= self.behavior_limit:
                missing(key,'BEHAVIOR_METHOD_BUDGET')
                continue
            if provenance == SourceProvenance.THIRD_PARTY and library_count >= self.library_limit:
                missing(key,'THIRD_PARTY_METHOD_BUDGET')
                continue
            visited.add(key)
            behavior_counts[behavior] = behavior_counts.get(behavior,0)+1
            library_count += provenance == SourceProvenance.THIRD_PARTY
            graph.expanded_methods_by_provenance[provenance.value] = graph.expanded_methods_by_provenance.get(provenance.value,0)+1
            active_method = key
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
                nodes[aid].boundary = call.target is None
                if call.target:
                    target = index.methods[call.target]
                    target_provenance = ownership.get(target.file).source_provenance
                    nodes[aid].target_provenance = target_provenance
                    if target_provenance in {SourceProvenance.FRAMEWORK,SourceProvenance.GENERATED}:
                        nodes[aid].boundary = True
                        continue
                    if depth < self.depth:
                        tid = node(target.key,NodeType.METHOD,f"{target.owner}.{target.name}",target.file,target.line,
                                   [f"apk:source:{target.file}:{target.line}"])
                        edge(mid,tid,EdgeType.CALLS,cref)
                        queue.append((target.key,depth+1,behavior))
                    else:
                        missing(aid or key,"EXPANSION_DEPTH_LIMIT")
                else:
                    missing(aid or key,call.issue or "TARGET_UNRESOLVED")
            if depth < self.depth:
                for call in incoming.get(key,[]):
                    caller = index.methods[call.caller]
                    if ownership.get(caller.file).source_provenance in {SourceProvenance.FRAMEWORK,SourceProvenance.GENERATED}:
                        continue
                    cid = node(caller.key,NodeType.METHOD,f"{caller.owner}.{caller.name}",caller.file,caller.line,
                               [f"apk:source:{caller.file}:{caller.line}"])
                    edge(cid,mid,EdgeType.CALLS,[f"apk:source:{caller.file}:{call.line}"])
                    queue.append((caller.key,depth+1,behavior))
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
        active_method = None
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
                if sink:
                    nodes[sink].boundary = True
                    nodes[sink].target_provenance = SourceProvenance.FRAMEWORK
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
        graph.limit_reached = 'GRAPH_NODE_LIMIT' in graph.analysis_limitations or 'GRAPH_METHOD_LIMIT' in graph.analysis_limitations
        return graph
