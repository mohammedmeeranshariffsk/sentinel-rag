from pathlib import Path
from types import SimpleNamespace

import pytest

from sentinel.extraction.api_extractor import APIExtractor
from sentinel.extraction.models import ExtractionResult
from sentinel.manifest.analyzer import ManifestAnalysis, ComponentInfo
from sentinel.program_analysis.source_index import SourceIndex
from sentinel.program_analysis.source_ownership import SourceOwnershipClassifier, SourceProvenance, PROVENANCE_ORDER
from sentinel.program_analysis.investigation_seeds import InvestigationSeedBuilder
from sentinel.program_analysis.behavior_graph import BehaviorGraphBuilder
from sentinel.reporting.models import SecurityReport, APKMetadata, AnalysisMetadata
from sentinel.threat_intel.models import ThreatMatch


def setup(tmp_path, sources, components=(), **kwargs):
    files = []
    extraction = ExtractionResult(source_root=tmp_path)
    for name, source in sources.items():
        file = tmp_path / name
        file.write_text(source, encoding='utf-8')
        files.append(file)
        extraction.apis.extend(APIExtractor().extract_file(file))
    index = SourceIndex(files)
    manifest = ManifestAnalysis(manifest_path=tmp_path/'AndroidManifest.xml', package_name='example.app',
        services=[ComponentInfo(name=n, component_type='service') for n in components])
    ownership = SourceOwnershipClassifier(index, 'example.app', manifest, **kwargs)
    return extraction, index, ownership


@pytest.mark.parametrize('package,name,expected', [
    ('example.app.services','Main','APPLICATION'),
    ('androidx.core','Main','FRAMEWORK'),
    ('java.lang','Main','FRAMEWORK'),
    ('kotlin.collections','Main','FRAMEWORK'),
    ('kotlin','Main','FRAMEWORK'),
    ('okhttp3.internal','Main','THIRD_PARTY'),
    ('okhttp3','Main','THIRD_PARTY'),
    ('odd.scrambled.xyz','Main','UNKNOWN'),
    ('example.app','R','GENERATED'),
    ('example.app','BuildConfig','GENERATED'),
])
def test_namespace_classification(tmp_path, package, name, expected):
    _, _, ownership = setup(tmp_path, {name+'.java':f'package {package};\nclass {name} {{}}'})
    record = ownership.get(str(tmp_path/(name+'.java')))
    assert record.source_provenance == expected
    assert record.provenance_reasons
    assert record.evidence_refs


def test_exact_manifest_component_outside_package(tmp_path):
    _, _, ownership = setup(tmp_path, {'RequestAdmin.java':'package strange.obfuscated;\nclass RequestAdmin {}'},
                            components=['strange.obfuscated.RequestAdmin'])
    record = ownership.get(str(tmp_path/'RequestAdmin.java'))
    assert record.source_provenance == 'APPLICATION'
    assert any('Exact recovered manifest' in reason for reason in record.provenance_reasons)
    assert any('apk:manifest:' in ref for ref in record.evidence_refs)


@pytest.mark.parametrize('extra,expected', [
    ('', 'UNKNOWN'),
    ('// "example.app"', 'UNKNOWN'),
    ('String p = "example.app";', 'APPLICATION_CANDIDATE'),
])
def test_candidate_requires_multiple_noncomment_signals(tmp_path, extra, expected):
    _, _, ownership = setup(tmp_path, {'Helper.java':
        'package odd.scrambled;\nclass Helper { int r = example.app.R.id.action;\n'+extra+'\n}'})
    assert ownership.get(str(tmp_path/'Helper.java')).source_provenance == expected


def test_bounded_resolved_helper_propagation(tmp_path):
    sources = {'Main.java':'package example.app;\nimport odd.A;\nclass Main {\n void entry() { A a = new A(); a.act(); }\n}'}
    for name, following in [('A','B'),('B','C'),('C','D')]:
        sources[name+'.java'] = f'package odd;\nclass {name} {{\n void act() {{ {following} v = new {following}(); v.act(); }}\n}}'
    sources['D.java'] = 'package odd;\nclass D {\n void act() {}\n}'
    _, index, ownership = setup(tmp_path, sources)
    assert any(call.target for calls in index.calls.values() for call in calls)
    assert ownership.get(str(tmp_path/'A.java')).source_provenance == 'APPLICATION_CANDIDATE'
    assert ownership.get(str(tmp_path/'B.java')).source_provenance == 'APPLICATION_CANDIDATE'
    assert ownership.get(str(tmp_path/'C.java')).source_provenance == 'UNKNOWN'
    assert 'hop 2' in ownership.get(str(tmp_path/'B.java')).provenance_reasons[-1]


@pytest.mark.parametrize('package,receiver,expected', [
    ('odd', 'Helper h', 'UNKNOWN'),
    ('androidx.core', '', 'FRAMEWORK'),
    ('okhttp3.internal', '', 'THIRD_PARTY'),
])
def test_propagation_respects_unresolved_and_negative_boundaries(tmp_path, package, receiver, expected):
    declaration = '' if receiver else 'Helper h = new Helper();'
    _, _, ownership = setup(tmp_path, {
        'Main.java':f'package example.app;\nimport {package}.Helper;\nclass Main {{\n void entry({receiver}) {{ {declaration} h.act(); }}\n}}',
        'Helper.java':f'package {package};\nclass Helper {{\n void act() {{}}\n}}'})
    assert ownership.get(str(tmp_path/'Helper.java')).source_provenance == expected


def test_grouping_keeps_original_refs_and_is_idempotent(tmp_path):
    extraction, index, ownership = setup(tmp_path, {'Main.java':
        'package example.app;\nclass Main {\n void entry() {\n Runtime.getRuntime().exec("a");\n Runtime.getRuntime().exec("b");\n }\n}'})
    builder = InvestigationSeedBuilder(extraction, 'example.app', index, ownership=ownership)
    seeds = builder.from_threats([ThreatMatch(knowledge_id='T',knowledge_name='T',matched_apis=['exec'])])
    assert len(seeds) == 2
    representative = next(s for s in seeds if s.selected_for_investigation)
    assert representative.duplicate_count == 1
    assert set(representative.grouped_evidence_refs) == {r for s in seeds for r in s.evidence_refs}
    assert len([s for s in builder.select(seeds+seeds) if s.selected_for_investigation]) == 1


def test_framework_noise_cannot_starve_application_or_other_behavior(tmp_path):
    sources = {'Main.java':'package example.app;\nclass Main {\n void entry() { Runtime.getRuntime().exec("ping"); }\n}'}
    for i in range(35):
        sources[f'Framework{i}.java'] = f'package androidx.core;\nclass Framework{i} {{\n void action() {{ node.findAccessibilityNodeInfosByText("a"); }}\n}}'
    extraction, index, ownership = setup(tmp_path, sources)
    builder = InvestigationSeedBuilder(extraction, 'example.app', index, ownership=ownership, max_seeds_per_behavior=2)
    seeds = builder.from_threats([
        ThreatMatch(knowledge_id='ACCESS',knowledge_name='A',matched_apis=['findAccessibilityNodeInfosByText']),
        ThreatMatch(knowledge_id='EXEC',knowledge_name='E',matched_apis=['exec'])])
    assert len(seeds) == 36
    assert all(not s.selected_for_investigation for s in seeds if s.source_provenance == 'FRAMEWORK')
    graph = BehaviorGraphBuilder(max_nodes=30).build(SimpleNamespace(package_name='example.app'), extraction, seeds,
                                                   source_index=index, ownership=ownership)
    assert graph.expanded_methods_by_provenance == {'APPLICATION':1}
    assert any(n.boundary and n.label.endswith('exec') for n in graph.nodes)
    assert not any(n.source_provenance == 'FRAMEWORK' for n in graph.nodes)
    assert not graph.limit_reached


def test_resolved_framework_helper_is_boundary(tmp_path):
    extraction, index, ownership = setup(tmp_path, {
        'Main.java':'package example.app;\nimport androidx.core.Helper;\nclass Main {\n void entry() { Helper h = new Helper(); h.dispatchGesture(); }\n}',
        'Helper.java':'package androidx.core;\nclass Helper {\n void dispatchGesture() { list.size(); }\n}'})
    builder = InvestigationSeedBuilder(extraction, 'example.app', index, ownership=ownership)
    seeds = builder.from_threats([ThreatMatch(knowledge_id='A',knowledge_name='A',matched_apis=['dispatchGesture'])])
    graph = BehaviorGraphBuilder().build(SimpleNamespace(), extraction, seeds, source_index=index, ownership=ownership)
    assert any(n.boundary and n.target_provenance == 'FRAMEWORK' for n in graph.nodes)
    assert not any(n.label == 'list.size' for n in graph.nodes)


def test_priority_and_serialization(tmp_path):
    assert [p.value for p in sorted(SourceProvenance, key=PROVENANCE_ORDER.get)] == [
        'APPLICATION','APPLICATION_CANDIDATE','UNKNOWN','THIRD_PARTY','FRAMEWORK','GENERATED']
    _, _, ownership = setup(tmp_path, {'Main.java':'package example.app;\nclass Main {}'})
    report = SecurityReport(apk_metadata=APKMetadata(path='sample.apk',sha256='test'), evidence_summary={},
        analysis_metadata=AnalysisMetadata(reasoning_model='fake'), source_ownership=list(ownership.records.values()))
    recovered = SecurityReport.model_validate_json(report.model_dump_json())
    assert recovered.source_ownership[0].source_provenance == 'APPLICATION'
    assert 'malware' not in recovered.source_ownership[0].model_dump_json().lower()


def test_behavior_budget_preserves_unselected_candidates(tmp_path):
    sources = {f'M{i}.java':f'package example.app;\nclass M{i} {{\n void entry() {{ Runtime.getRuntime().exec("ping"); }}\n}}' for i in range(6)}
    extraction, index, ownership = setup(tmp_path, sources)
    builder = InvestigationSeedBuilder(extraction, 'example.app', index, ownership=ownership, max_seeds_per_behavior=3)
    seeds = builder.from_threats([ThreatMatch(knowledge_id='E',knowledge_name='E',matched_apis=['exec'])])
    assert len(seeds) == 6
    assert sum(s.selected_for_investigation for s in seeds) == 3
    assert sum(s.selection_reason == 'BEHAVIOR_SEED_BUDGET' for s in seeds) == 3
    graph = BehaviorGraphBuilder(max_methods_per_behavior=1).build(SimpleNamespace(), extraction, seeds,
        source_index=index, ownership=ownership)
    assert graph.expanded_methods_by_provenance == {'APPLICATION':1}
    assert any(r.reason == 'BEHAVIOR_METHOD_BUDGET' for r in graph.unresolved_relationships)


def test_behavior_fairness_and_candidate_seed_priority(tmp_path):
    sources = {f'M{i}.java':f'package example.app;\nclass M{i} {{\n void entry() {{ node.findAccessibilityNodeInfosByText("x"); }}\n}}' for i in range(5)}
    sources['Z.java'] = 'package example.app;\nclass Z {\n void entry() { Runtime.getRuntime().exec("ping"); }\n}'
    sources['Helper.java'] = 'package obfuscated;\nclass Helper { int r = example.app.R.id.action; String p = "example.app";\n void entry() { Runtime.getRuntime().exec("ping"); }\n}'
    sources['Unknown.java'] = 'package unidentified;\nclass Unknown {\n void entry() { Runtime.getRuntime().exec("ping"); }\n}'
    extraction, index, ownership = setup(tmp_path, sources)
    builder = InvestigationSeedBuilder(extraction, 'example.app', index, ownership=ownership)
    seeds = builder.from_threats([
        ThreatMatch(knowledge_id='ACCESS',knowledge_name='A',matched_apis=['findAccessibilityNodeInfosByText']),
        ThreatMatch(knowledge_id='EXEC',knowledge_name='E',matched_apis=['exec'])])
    exec_seeds = [s for s in seeds if s.behavior_id == 'EXEC']
    assert [s.source_provenance.value for s in exec_seeds] == ['APPLICATION','APPLICATION_CANDIDATE','UNKNOWN']
    graph = BehaviorGraphBuilder(max_methods=2).build(SimpleNamespace(), extraction, seeds, source_index=index, ownership=ownership)
    assert any(n.label.endswith('exec') and n.boundary for n in graph.nodes)
    assert any(n.label.endswith('findAccessibilityNodeInfosByText') and n.boundary for n in graph.nodes)
    assert graph.expanded_methods_by_provenance == {'APPLICATION':2}
    assert graph.limit_reached


@pytest.mark.parametrize('budgets', [{'max_nodes':501}, {'max_methods':41}])
def test_hard_limits_cannot_be_disabled(budgets):
    with pytest.raises(ValueError):
        BehaviorGraphBuilder(**budgets)
