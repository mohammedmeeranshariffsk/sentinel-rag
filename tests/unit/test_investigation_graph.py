from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from sentinel.analysis.artifact_coverage import ArtifactCoverage
from sentinel.extraction.api_extractor import APIExtractor
from sentinel.extraction.method_extractor import MethodExtractor
from sentinel.extraction.models import ExtractionResult
from sentinel.program_analysis.investigation_seeds import InvestigationSeedBuilder
from sentinel.program_analysis.source_index import SourceIndex
from sentinel.program_analysis.behavior_graph import BehaviorGraphBuilder, BehaviorEdge, BehaviorGraph
from sentinel.profiles.models import ProfileAnalysis, ProfileArtifactMatch
from sentinel.threat_intel.models import ThreatMatch


def fixture(tmp_path, sources, api='exec', methods=()):
    extraction = ExtractionResult(source_root=tmp_path)
    for name,source in sources.items():
        file = tmp_path / name
        file.write_text(source,encoding='utf-8')
        extraction.apis.extend(APIExtractor().extract_file(file))
        extraction.methods.extend(MethodExtractor().extract_file(file))
    index = SourceIndex.from_extraction(extraction)
    builder = InvestigationSeedBuilder(extraction,'example.app',index)
    matches = [ThreatMatch(knowledge_id='T',knowledge_name='review',matched_apis=[api],matched_methods=list(methods))]
    seeds = builder.from_threats(matches)
    return extraction,index,builder,seeds


@pytest.mark.parametrize('package',['example.app','example.app.services','example.app.foo.bar'])
def test_application_subpackages(tmp_path,package):
    _,_,_,seeds = fixture(tmp_path,{'Main.java':f'package {package};\nclass Main {{\n void test() {{ Runtime.getRuntime().exec("ping"); }}\n}}'})
    assert seeds[0].source_provenance == 'APPLICATION'
    assert seeds[0].quality == 'STRONG'
    assert seeds[0].located and seeds[0].evidence_scope == 'LOCAL'


@pytest.mark.parametrize('name',['R.java','BuildConfig.java'])
def test_generated_code_not_selected(tmp_path,name):
    _,_,_,seeds=fixture(tmp_path,{name:'package example.app;\nclass R {\n void test() { Runtime.getRuntime().exec("x"); }\n}'})
    assert seeds[0].source_provenance == 'GENERATED'
    assert not seeds[0].selected_for_investigation


def test_library_generic_match_retained_but_not_selected(tmp_path):
    _,_,_,seeds=fixture(tmp_path,{'Noise.java':'package com.glide.blade;\nclass Noise {\n void work() { delegate.performAction(action); }\n}'},'performAction')
    assert len(seeds)==1
    assert seeds[0].source_provenance == 'THIRD_PARTY'
    assert seeds[0].quality == 'WEAK'
    assert not seeds[0].selected_for_investigation
    assert seeds[0].evidence_refs
    assert 'family' not in seeds[0].model_dump_json().lower()


def test_broader_permission_does_not_corroborate_local_generic_call(tmp_path):
    _,_,builder,_=fixture(tmp_path,{'Noise.java':'package com.glide.blade;\nclass Noise {\n void work() { delegate.performAction(action); }\n}'},'performAction')
    seeds=builder.from_threats([ThreatMatch(knowledge_id='T',knowledge_name='Accessibility',matched_apis=['performAction'],
        matched_permissions=['android.permission.BIND_ACCESSIBILITY_SERVICE'])])
    assert len(seeds)==2
    assert not next(s for s in seeds if s.indicator_type=='api').selected_for_investigation


def test_receiver_from_closed_scope_is_not_local_helper(tmp_path):
    _,index,_,_=fixture(tmp_path,{
        'Main.java':'package example.app;\nclass Main {\n private void entry() { if (ok) { Helper h = new Helper(); } h.act(); }\n}',
        'Helper.java':'package example.app;\nclass Helper {\n public void act() { }\n}'})
    call=next(c for calls in index.calls.values() for c in calls if c.name=='act')
    assert call.target is None
    assert call.issue=='RECEIVER_OUT_OF_SCOPE'


def test_report_keeps_weak_matches_and_graph(tmp_path):
    from sentinel.reporting.models import SecurityReport, APKMetadata, AnalysisMetadata
    _,graph=graph_case(tmp_path)
    _,_,_,seeds=fixture(tmp_path,{'Noise.java':'package com.glide.blade;\nclass Noise {\n void work() { delegate.performAction(action); }\n}'},'performAction')
    report=SecurityReport(apk_metadata=APKMetadata(path='sample.apk',sha256='abc'),evidence_summary={},
        investigation_seeds=seeds,behavior_graph=graph,
        matched_indicators=[ThreatMatch(knowledge_id='T',knowledge_name='Accessibility',matched_apis=['performAction'])],
        analysis_metadata=AnalysisMetadata(reasoning_model='fake'))
    restored=SecurityReport.model_validate_json(report.model_dump_json())
    assert restored.matched_indicators[0].matched_apis==['performAction']
    assert restored.investigation_seeds==seeds
    assert restored.behavior_graph==graph


def test_concrete_accessibility_application_seed(tmp_path):
    _,_,_,seeds=fixture(tmp_path,{'Service.java':'package example.app.services;\nclass Service extends AccessibilityService {\n void onAccessibilityEvent(Object e) { this.dispatchGesture(g, null, null); }\n}'},'dispatchGesture')
    assert seeds[0].quality == 'STRONG'
    assert seeds[0].corroborating_evidence_refs


def test_app_priority_over_unknown_library_and_unlocated(tmp_path):
    code='\nclass Main {\n void test() { Runtime.getRuntime().exec("ping"); }\n}'
    _,_,builder,seeds=fixture(tmp_path,{'Z.java':'package example.app;'+code,'A.java':'package library.other;'+code,'B.java':code})
    seeds += builder.from_threats([ThreatMatch(knowledge_id='P',knowledge_name='P',matched_permissions=['permission'])])
    seeds=builder.prioritize(seeds)
    assert [s.source_provenance.value for s in seeds[:3]]==['APPLICATION','UNKNOWN','THIRD_PARTY']
    assert seeds[-1].quality=='BROADER'
    assert not seeds[-1].located


def test_profile_conversion_preserves_external_reference_separation(tmp_path):
    _,_,builder,_=fixture(tmp_path,{})
    analysis=ProfileAnalysis(profile_path='profile.json',profile_schema_version='1',profile_status='research',family_id='family:test',conclusion='unknown',
        artifact_matches=[ProfileArtifactMatch(reference='apk:permission',artifact_group='manifest',value='permission',classification='reported_behavior',source_refs=['external:article'])])
    seeds=builder.from_profile(analysis)
    assert seeds[0].origin=='PROFILE_MATCH'
    assert seeds[0].evidence_refs==['apk:permission']
    assert seeds[0].evidence_scope=='APK'
    assert 'external:article' not in seeds[0].model_dump_json()


SOURCE='''package example.app;
class Main {
 private void caller() { helper(); }
 private void helper() { Runtime.getRuntime().exec("ping "); }
}
'''


def graph_case(tmp_path,source=SOURCE,depth=1):
    extraction,index,_,seeds=fixture(tmp_path,{'Main.java':source})
    graph=BehaviorGraphBuilder(max_depth=depth).build(SimpleNamespace(),extraction,seeds,source_index=index)
    return index,graph


def test_direct_caller_and_callee_edges_are_source_backed(tmp_path):
    index,graph=graph_case(tmp_path)
    caller=next(m.key for m in index.methods.values() if m.name=='caller')
    helper=next(m.key for m in index.methods.values() if m.name=='helper')
    assert any(e.source==caller and e.target==helper and e.relation=='CALLS' for e in graph.edges)
    assert all(e.evidence_refs for e in graph.edges)
    assert any(n.kind=='string' and n.label=='ping ' for n in graph.nodes)
    assert BehaviorGraph.model_validate_json(graph.model_dump_json())==graph


def test_one_hop_fresh_local_helper(tmp_path):
    extraction,index,_,seeds=fixture(tmp_path,{
        'Main.java':'package example.app;\nclass Main {\n private void entry() { Helper h = new Helper(); h.act(); Runtime.getRuntime().exec("ping"); }\n}',
        'Helper.java':'package example.app;\nclass Helper {\n public void act() { }\n}'})
    graph=BehaviorGraphBuilder().build(SimpleNamespace(),extraction,seeds,source_index=index)
    assert any(e.relation=='CALLS' and e.target.endswith(':act') for e in graph.edges)


def test_overloads_are_unresolved(tmp_path):
    index,graph=graph_case(tmp_path,SOURCE.replace(' private void helper()', ' private void helper(int x) {}\n private void helper()'))
    assert not any(c.target for calls in index.calls.values() for c in calls if c.name=='helper')


def test_cycle_and_depth_limits(tmp_path):
    source=SOURCE.replace('Runtime.getRuntime()', 'caller(); Runtime.getRuntime()')
    _,graph=graph_case(tmp_path,source)
    assert len(graph.nodes)<20
    assert any(u.reason=='EXPANSION_DEPTH_LIMIT' for u in graph.unresolved_relationships)


def test_zero_depth_does_not_expand_callers(tmp_path):
    _,graph=graph_case(tmp_path,depth=0)
    assert not any(n.label=='example.app.Main.caller' for n in graph.nodes)


def test_missing_source_coverage_and_accessibility_declaration(tmp_path):
    extraction,index,builder,_=fixture(tmp_path,{})
    seeds=builder.from_threats([ThreatMatch(knowledge_id='T',knowledge_name='T',matched_permissions=['BIND_ACCESSIBILITY_SERVICE'])])
    coverage=ArtifactCoverage(analysis_mode='partial')
    legacy={'nodes':[{'kind':'accessibility_service','node_id':'service:missing','label':'example.app.Missing'}],
            'unsupported_relationships':['callback unresolved'],'analysis_limitations':['SOURCE_IMPLEMENTATION_UNAVAILABLE']}
    graph=BehaviorGraphBuilder().build(SimpleNamespace(manifest_path='AndroidManifest.xml'),extraction,seeds,coverage,index,[legacy])
    assert graph.artifact_coverage==coverage
    assert graph.edges==[]
    assert any(n.kind=='manifest_component' for n in graph.nodes)
    assert 'SOURCE_IMPLEMENTATION_UNAVAILABLE' in graph.analysis_limitations


def test_edge_requires_evidence():
    with pytest.raises(ValidationError):
        BehaviorEdge(source='a',target='b',relation='CALLS',evidence_refs=[])


def test_quoted_api_is_retained_but_not_expanded(tmp_path):
    _,_,_,seeds=fixture(tmp_path,{'Main.java':'package example.app;\nclass Main {\n void test() { log("Runtime.getRuntime().exec(ip)"); }\n}'})
    assert seeds and all(not s.selected_for_investigation for s in seeds)


def test_androgoat_anonymous_callback_flow(tmp_path):
    source='''package example.app;
class Main {
 public void onCreate() {
  button.setOnClickListener(new View.OnClickListener() {
   public final void onClick(View v) {
    StringBuilder sb = new StringBuilder();
    sb.append("ping ");
    EditText ip2 = ip;
    sb.append(ip2.getText().toString());
    String ip1 = sb.toString();
    Runtime.getRuntime().exec(ip1);
   }
  });
 }
}
'''
    index,graph=graph_case(tmp_path,source)
    assert any('anonymous@' in m.owner and m.name=='onClick' for m in index.methods.values())
    labels={n.node_id:n.label for n in graph.nodes}
    flow=[(labels[e.source],labels[e.target]) for e in graph.edges if e.relation=='PASSES_TO']
    assert ('ip2.getText().toString()','StringBuilder command construction') in flow
    assert ('StringBuilder command construction','Runtime.getRuntime().exec(ip1)') in flow
