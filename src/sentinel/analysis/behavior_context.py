"""Select bounded, source-backed facts; never turn templates into observations."""
import hashlib
import re

from sentinel.analysis.behavior_models import BehaviorContext, ContextFact, ContextRelationship, SourceSinkAnnotation
from sentinel.validation.local_flow import LocalDataFlowAnalyzer


def evidence_id(value):
    return 'apk:' + hashlib.sha256(value.encode()).hexdigest()[:24]


class BehaviorContextBuilder:
    MAX_FACTS = 64
    MAX_RELATIONSHIPS = 64
    MAX_VALUE = 240

    def build(self, match, seeds, graph, index, manifest=None, record=None, flows=()):
        context = BehaviorContext(behavior_id=match.knowledge_id, behavior_name=match.knowledge_name,
            seeds=seeds[:12], local_data_flows=list(flows)[:4])
        if graph.artifact_coverage:
            context.coverage_limitations = [f'{x.code}: {x.message}' for x in graph.artifact_coverage.limitations]
        context.unresolved_relationships = [f'{r.reference}: {r.reason}' for r in graph.unresolved_relationships[:24]]
        context.context_limitations = graph.analysis_limitations[:12]
        if len(graph.unresolved_relationships) > 24:
            context.context_limitations.append('Unresolved relationship context truncated; full graph retained')
        if record:
            context.expected_relationships = [f'{r.source or "?"} -> {r.operation} -> {r.sink or "?"}' for r in record.behaviors][:12]
        # Prefer call/seed evidence, followed by method/class context. A graph node
        # proves source presence only, even when its name sounds like a behavior.
        nodes = sorted(graph.nodes, key=lambda n: (not bool(n.seed_ids), n.kind not in {'api_call','method'}, n.node_id))
        for node in nodes:
            if len(context.facts) >= self.MAX_FACTS:
                break
            if node.file:
                text = index.sources.get(node.file)
                if text is None or not node.line or not 1 <= node.line <= text.count('\n')+1:
                    continue
            context.facts.append(ContextFact(evidence_id=node.node_id, scope='LOCAL' if node.file else 'APK',
                value=node.label[:self.MAX_VALUE], file=node.file, line=node.line,
                references=node.evidence_refs, kind=node.kind.value))
        # Broad matches have explicit APK scope and cannot establish local edges.
        for kind, values in [('api',match.matched_apis),('permission',match.matched_permissions),
                             ('string',match.matched_strings),('method',match.matched_methods)]:
            for value in values[:12]:
                if len(context.facts) >= self.MAX_FACTS:
                    break
                ref = f'apk:{kind}:{value}'
                context.facts.append(ContextFact(evidence_id=evidence_id(ref),scope='APK',value=value[:self.MAX_VALUE],references=[ref],kind=kind))
        if manifest:
            selected_classes = {s.class_name for s in seeds}
            relevant_components = set(record.components if record else [])
            relevant_intents = set(record.intents if record else [])
            for component in manifest.activities+manifest.services+manifest.receivers+manifest.providers:
                name = component.name
                if name.startswith('.'):
                    name = (manifest.package_name or '')+name
                elif '.' not in name and manifest.package_name:
                    name = manifest.package_name+'.'+name
                actions = [a for f in component.intent_filters for a in f.actions]
                relevant = name in selected_classes or component.permission in match.matched_permissions or bool(relevant_intents.intersection(actions)) or name in relevant_components
                if relevant and len(context.facts) < self.MAX_FACTS:
                    ref = f'apk:manifest:{manifest.manifest_path}:component:{name}'
                    context.facts.append(ContextFact(evidence_id=evidence_id(ref), scope='APK',
                        value=f'{component.component_type}: {name}; actions: {", ".join(actions)}'[:self.MAX_VALUE],
                        references=[ref],kind='component'))
        ids = {f.evidence_id for f in context.facts}
        for edge in graph.edges:
            if edge.source in ids and edge.target in ids and len(context.relationships)<self.MAX_RELATIONSHIPS:
                context.relationships.append(ContextRelationship(
                    evidence_id=evidence_id(f'{edge.source}|{edge.relation}|{edge.target}'),source=edge.source,
                    target=edge.target,relation=edge.relation.value,references=edge.evidence_refs))
        if len(graph.nodes) > len(context.facts) or len(graph.edges)>len(context.relationships):
            context.context_limitations.append('Behavior prompt includes a bounded graph subset; omitted edges remain in report')
        context.source_sink_annotations = categorize(context.facts)
        return context


def categorize(facts):
    # Labels guide investigation. They are not edges and do not prove data flow.
    patterns = [
        ('SOURCE','user/UI text',r'\b(?:getText|findAccessibilityNodeInfosByText|getRootInActiveWindow)\b'),
        ('SOURCE','SMS',r'\b(?:getMessageBody|getDisplayMessageBody|createFromPdu)\b'),
        ('SOURCE','clipboard',r'\bgetPrimaryClip\b'),
        ('SOURCE','location',r'\b(?:getLastKnownLocation|requestLocationUpdates)\b'),
        ('SOURCE','notifications',r'\b(?:onNotificationPosted|getActiveNotifications)\b'),
        ('SOURCE','microphone',r'\bstartRecording\b'),
        ('SOURCE','camera',r'\b(?:openCamera|takePicture)\b'),
        ('SOURCE','files',r'\b(?:openInputStream|listFiles)\b'),
        ('SOURCE','content provider (provider unresolved)',r'\bquery\b'),
        ('SOURCE','device/app inventory',r'\b(?:getDeviceId|getInstalledPackages|getInstalledApplications)\b'),
        ('SINK','command execution',r'\b(?:exec|ProcessBuilder)\b'),
        ('SINK','dynamic loading',r'\b(?:loadClass|DexClassLoader|loadLibrary)\b'),
        ('SINK','network',r'\b(?:openConnection|newWebSocket|sendTextMessage)\b'),
        ('SINK','storage',r'\b(?:openFileOutput|putString|insert)\b'),
        ('SINK','reflection',r'\binvoke\b'),
        ('SINK','activity',r'\bstartActivity\b'),
    ]
    return [SourceSinkAnnotation(evidence_id=f.evidence_id,role=role,category=category)
            for f in facts if f.kind in {'api','api_call','method'}
            for role,category,pattern in patterns if re.search(pattern,f.value)]
