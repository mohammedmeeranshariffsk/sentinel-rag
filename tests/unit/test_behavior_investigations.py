import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from sentinel.analysis.behavior_models import BehaviorContext, ContextFact, ContextRelationship, BehaviorReasoningResult
from sentinel.analysis.behavior_context import BehaviorContextBuilder, categorize
from sentinel.analysis.investigation import BehaviorInvestigator
from sentinel.analysis.artifact_coverage import ArtifactCoverage, CoverageLimitation
from sentinel.config.settings import AnalysisOptions
from sentinel.extraction.api_extractor import APIExtractor
from sentinel.extraction.models import ExtractionResult
from sentinel.program_analysis.source_index import SourceIndex
from sentinel.program_analysis.investigation_seeds import InvestigationSeedBuilder
from sentinel.program_analysis.behavior_graph import BehaviorGraphBuilder
from sentinel.rag.models import RetrievedKnowledge
from sentinel.rag.query_builder import RetrievalQueryBuilder
from sentinel.reasoning.behavior import BehaviorReasoningAnalyzer
from sentinel.validation.behavior import BehaviorClaimValidator
from sentinel.threat_intel.models import ThreatMatch
from sentinel.threat_intel.starter_catalog import starter_records, catalog_documents
from sentinel.reporting.models import SecurityReport, APKMetadata, AnalysisMetadata
from sentinel.reporting.markdown import render_markdown


@pytest.fixture
def investigation_setup(tmp_path):
    file = tmp_path/'Main.java'
    file.write_text('package example.app;\nclass Main {\n void command() { Runtime.getRuntime().exec("ping"); }\n void unrelated() { secret.uploadPhotos("PRIVATE"); }\n}')
    extraction = ExtractionResult(source_root=tmp_path,apis=APIExtractor().extract_file(file))
    index = SourceIndex.from_extraction(extraction)
    builder = InvestigationSeedBuilder(extraction,'example.app',index)
    match = ThreatMatch(knowledge_id='THREAT-PROCESS-001',knowledge_name='Command execution',matched_apis=['exec'])
    seeds = builder.from_threats([match])
    return extraction,index,builder,match,seeds


def context_for(values):
    extraction,index,builder,match,seeds = values
    graph = BehaviorGraphBuilder().build(SimpleNamespace(),extraction,seeds,source_index=index,ownership=builder.ownership)
    return BehaviorContextBuilder().build(match,seeds,graph,index)


def reasoning(context, **kwargs):
    return BehaviorReasoningResult(behavior_id=context.behavior_id,behavior_name=context.behavior_name,
        summary=kwargs.pop('summary','Insufficient evidence of malicious behavior'),confidence=kwargs.pop('confidence',0.5),**kwargs)


def knowledge():
    return [RetrievedKnowledge(document_id='d',chunk_id='c',title='External context',content='Not APK evidence',source='local review',score=0.9)]


def test_context_excludes_unrelated_implementation(investigation_setup):
    context = context_for(investigation_setup)
    encoded = context.model_dump_json()
    assert 'PRIVATE' not in encoded
    assert 'uploadPhotos' not in encoded
    assert any(f.scope=='LOCAL' for f in context.facts)
    assert any(f.scope=='APK' for f in context.facts)
    assert len(context.facts)<=64 and len(context.relationships)<=64


def test_graph_query_contains_actual_facts_without_external_text(investigation_setup):
    query = RetrievalQueryBuilder().build_context(context_for(investigation_setup))
    assert 'exec' in query and 'Source relationship:' in query
    assert 'PRIVATE' not in query and len(query)<=6000


def test_fake_provider_structured_context_and_knowledge_separation(investigation_setup):
    context = context_for(investigation_setup)
    provider = Mock()
    provider.generate_structured.return_value = reasoning(context).model_dump_json()
    result = BehaviorReasoningAnalyzer(provider).analyze(context,knowledge())
    assert result.behavior_id == context.behavior_id
    prompt = provider.generate_structured.call_args.args[0]
    data = json.loads(prompt.split('\nINPUT DATA:\n')[1])
    assert data['external_knowledge'][0]['reference']=='knowledge:c'
    assert 'Not APK evidence' not in json.dumps(data['apk_evidence'])
    assert 'No chain-of-thought' in prompt
    assert len(prompt)<55000


@pytest.mark.parametrize('confidence',[-0.1,1.1,float('nan')])
def test_reasoning_rejects_invalid_confidence(confidence):
    with pytest.raises(ValidationError):
        reasoning(BehaviorContext(behavior_id='b',behavior_name='b'),confidence=confidence)


def test_validator_accepts_exact_fact_and_edge(investigation_setup):
    context = context_for(investigation_setup)
    fact,edge = context.facts[0],context.relationships[0]
    result = reasoning(context,observed_facts=[{'evidence_id':fact.evidence_id,'value':fact.value}],
        supported_relationships=[{k:v for k,v in edge.model_dump().items() if k!='references'}])
    validation = BehaviorClaimValidator().validate(context,result,[],investigation_setup[1])
    assert validation.accepted_fact_ids == [fact.evidence_id]
    assert validation.accepted_relationship_ids == [edge.evidence_id]
    assert not validation.rejected_claims


@pytest.mark.parametrize('claim_id,value',[('invented','exec'),('knowledge:c','External context')])
def test_unknown_or_knowledge_ids_never_become_apk_facts(investigation_setup,claim_id,value):
    context = context_for(investigation_setup)
    result = reasoning(context,observed_facts=[{'evidence_id':claim_id,'value':value}])
    validation = BehaviorClaimValidator().validate(context,result,knowledge(),investigation_setup[1])
    assert validation.rejected_claims
    assert not validation.accepted_fact_ids


def test_existing_id_does_not_license_invented_behavior(investigation_setup):
    context = context_for(investigation_setup)
    result = reasoning(context,observed_facts=[{'evidence_id':context.facts[0].evidence_id,'value':'Confirmed TrickMo steals credentials'}])
    validation = BehaviorClaimValidator().validate(context,result,[],investigation_setup[1])
    assert validation.rejected_claims and not validation.accepted_fact_ids


def test_unsupported_flow_is_unresolved_hypothesis(investigation_setup):
    context = context_for(investigation_setup)
    edge = context.relationships[0]
    result = reasoning(context,supported_relationships=[dict(evidence_id=edge.evidence_id,
        source=edge.source,target=edge.target,relation='PASSES_TO')])
    validation = BehaviorClaimValidator().validate(context,result,[],investigation_setup[1])
    assert not validation.accepted_relationship_ids
    assert validation.unresolved_hypotheses
    assert validation.evidence_state=='CORRELATED'


def test_unavailable_location_is_rejected(investigation_setup):
    context = context_for(investigation_setup)
    fact = next(f for f in context.facts if f.file)
    fact.line = 1000000
    result = reasoning(context,observed_facts=[dict(evidence_id=fact.evidence_id,value=fact.value)])
    validation = BehaviorClaimValidator().validate(context,result,[],investigation_setup[1])
    assert validation.rejected_claims


def test_coverage_and_contradictions_are_explicit(investigation_setup):
    context = context_for(investigation_setup)
    context.coverage_limitations=['SOURCE_IMPLEMENTATION_UNAVAILABLE']
    result = reasoning(context,contradictions=['No behavior despite missing source'])
    validation = BehaviorClaimValidator().validate(context,result,[],investigation_setup[1])
    assert any('cannot be interpreted as absent' in i for i in validation.issues)
    assert any('contradiction' in i for i in validation.issues)


def test_knowledge_validation_is_separate(investigation_setup):
    context = context_for(investigation_setup)
    result = reasoning(context,knowledge_context=[dict(evidence_id='knowledge:c',value='External context')])
    validation = BehaviorClaimValidator().validate(context,result,knowledge(),investigation_setup[1])
    assert validation.accepted_knowledge_ids == ['knowledge:c']
    assert not validation.accepted_fact_ids


@pytest.mark.parametrize('failure',['llm','rag','both','disabled'])
def test_optional_ai_failure_preserves_deterministic_report(investigation_setup,failure):
    extraction,index,builder,match,seeds = investigation_setup
    options = AnalysisOptions(reasoning_enabled=failure!='disabled',rag_enabled=failure!='disabled')
    provider,retriever = Mock(),Mock()
    provider.generate_structured.side_effect=RuntimeError('private credential')
    retriever.retrieve.side_effect=RuntimeError('private credential')
    item = BehaviorInvestigator(extraction,index,builder.ownership,options).investigate(match,seeds,SimpleNamespace(),ArtifactCoverage(),
        retriever=retriever if failure in {'rag','both','disabled'} else None,
        provider=provider if failure in {'llm','both','disabled'} else None)
    assert len(item.validated_findings)==1
    assert item.validated_findings[0].severity=='INFO'
    assert 'private credential' not in item.model_dump_json()
    assert item.reasoning_is_evidence is False
    if failure=='disabled':
        provider.generate_structured.assert_not_called()
        retriever.retrieve.assert_not_called()


@pytest.mark.parametrize('confidence',[0.01,0.99])
def test_model_confidence_and_family_prose_cannot_set_findings(investigation_setup,confidence):
    extraction,index,builder,match,seeds = investigation_setup
    context=context_for(investigation_setup)
    provider=Mock()
    provider.generate_structured.return_value=reasoning(context,confidence=confidence,summary='Confirmed TrickMo malware; critical exploit').model_dump_json()
    item=BehaviorInvestigator(extraction,index,builder.ownership,AnalysisOptions(rag_enabled=False)).investigate(
        match,seeds,SimpleNamespace(),ArtifactCoverage(),provider=provider)
    finding=item.validated_findings[0]
    assert finding.severity=='INFO' and finding.confidence==0.35
    assert 'Confirmed TrickMo' not in finding.model_dump_json()


def test_source_sink_labels_are_not_flows():
    facts=[ContextFact(evidence_id=str(i),scope='LOCAL',value=v,kind='api_call') for i,v in enumerate(['ip.getText','Runtime.exec','manager.getPrimaryClip'])]
    annotations=categorize(facts)
    assert {a.role for a in annotations} == {'SOURCE','SINK'}
    assert all('no data flow' in a.qualification for a in annotations)


def test_catalog_is_versioned_complete_and_not_family_signatures():
    records=starter_records()
    assert len(records)==35 and len({r.knowledge_id for r in records})==35
    assert all(r.behaviors and r.known_false_positives and r.schema_version and r.references for r in records)
    assert all(not r.families for r in records)
    assert all(d.metadata['scope']=='KNOWLEDGE' for d in catalog_documents(records))


def test_json_and_markdown_are_readable_and_escape_apk_markup(investigation_setup,tmp_path):
    extraction,index,builder,match,seeds=investigation_setup
    item=BehaviorInvestigator(extraction,index,builder.ownership,AnalysisOptions(reasoning_enabled=False,rag_enabled=False)).investigate(
        match,seeds,SimpleNamespace(),ArtifactCoverage())
    item.context.facts[0].value='![remote](https://example.invalid/image) <script>x</script>'
    report=SecurityReport(apk_metadata=APKMetadata(path='test.apk',sha256='abc'),evidence_summary={'apis':2},
        analysis_metadata=AnalysisMetadata(reasoning_model='fake'),behavior_investigations=[item],artifact_coverage=ArtifactCoverage())
    restored=SecurityReport.model_validate_json(report.model_dump_json())
    report.write_markdown(tmp_path/'result.md')
    content=(tmp_path/'result.md').read_text()
    assert '## Behavior Investigations' in content and '**Retrieved Threat Knowledge' in content
    assert '<script>' not in content and '![remote]' not in content
    assert restored.behavior_investigations[0].context.behavior_id == match.knowledge_id


def test_cli_disable_flags_produce_both_reports_without_provider(tmp_path,monkeypatch):
    from sentinel.cli import main as cli
    from sentinel.decompiler.pipeline import DecompilationResult
    apk=tmp_path/'sample.apk';apk.touch()
    monkeypatch.setattr(cli,'run_extraction',Mock(return_value=(SimpleNamespace(apk_path=apk,sha256='abc',package_name=None),
        None,ExtractionResult(),DecompilationResult())))
    provider=Mock(side_effect=AssertionError('Provider must not initialize'))
    monkeypatch.setattr(cli,'GeminiEmbeddingProvider',provider)
    monkeypatch.setattr(cli,'GeminiReasoningProvider',type('Provider',(),{'MODEL':'fake','__init__':lambda self:provider()}))
    output=CliRunner().invoke(cli.app,['analyze',str(apk),'--no-llm','--no-rag','--graph-depth','0',
        '--output-json',str(tmp_path/'result.json'),'--output-markdown',str(tmp_path/'result.md')])
    assert output.exit_code==0,output.output
    assert (tmp_path/'result.json').exists() and (tmp_path/'result.md').exists()
    provider.assert_not_called()


def test_offline_positive_command_flow(tmp_path):
    file=tmp_path/'Main.java'
    file.write_text('''package example.app;
class Main {
 void onClick() {
  StringBuilder sb = new StringBuilder();
  sb.append("ping ");
  EditText ip2 = ip;
  sb.append(ip2.getText().toString());
  String ip1 = sb.toString();
  Runtime.getRuntime().exec(ip1);
 }
}''')
    extraction=ExtractionResult(source_root=tmp_path,apis=APIExtractor().extract_file(file))
    index=SourceIndex.from_extraction(extraction)
    builder=InvestigationSeedBuilder(extraction,'example.app',index)
    match=ThreatMatch(knowledge_id='THREAT-PROCESS-001',knowledge_name='Command execution',matched_apis=['exec'])
    seeds=builder.from_threats([match])
    item=BehaviorInvestigator(extraction,index,builder.ownership,AnalysisOptions(reasoning_enabled=False,rag_enabled=False)).investigate(
        match,seeds,SimpleNamespace(),ArtifactCoverage())
    assert item.validated_findings[0].severity=='MEDIUM'
    assert item.validated_findings[0].evidence_state=='OBSERVED'
    assert any(e.relation=='PASSES_TO' for e in item.graph.edges)


def test_malformed_catalog_is_skipped_with_explicit_error(tmp_path):
    from sentinel.threat_intel.knowledge_base import ThreatKnowledgeBase
    file=tmp_path/'catalog.json'
    file.write_text(json.dumps([{'bad':'record'},starter_records()[0].model_dump()]))
    base=ThreatKnowledgeBase()
    assert len(base.load_json(file))==1
    assert len(base.errors)==1


def test_knowledge_commands_are_local():
    from sentinel.cli.main import app
    assert CliRunner().invoke(app,['knowledge','status']).exit_code==0
    assert CliRunner().invoke(app,['knowledge','validate']).exit_code==0


def test_missing_sources_preserve_manifest_evidence(tmp_path,monkeypatch):
    from sentinel.cli import main as cli
    from sentinel.decompiler.pipeline import DecompilationResult
    apk=tmp_path/'test.apk';apk.touch()
    manifest=tmp_path/'AndroidManifest.xml'
    manifest.write_text('<manifest package="example.app" xmlns:android="http://schemas.android.com/apk/res/android"><uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/></manifest>')
    monkeypatch.setattr(cli,'DecompilerPipeline',Mock(return_value=SimpleNamespace(run=Mock(return_value=DecompilationResult(manifest_path=manifest,apktool_success=True)))))
    _,parsed,extraction,_=cli.run_extraction(apk,include_decompilation=True)
    assert parsed.package_name=='example.app'
    assert extraction.permissions[0].permission=='android.permission.RECEIVE_BOOT_COMPLETED'
    assert not extraction.apis and extraction.source_root is None


def test_failed_tools_can_return_authoritative_coverage_state(tmp_path):
    from sentinel.decompiler.pipeline import DecompilerPipeline
    from sentinel.apk.inspector import APKInspector
    apk=tmp_path/'test.apk';apk.touch()
    context=APKInspector(tmp_path/'workspace').inspect(apk)
    result=DecompilerPipeline(tmp_path/'missing-apktool',tmp_path/'missing-jadx').run(context,allow_failed=True)
    assert not result.apktool_success and not result.jadx_success
    assert len(result.errors)==2


def test_gemini_wire_schema_keeps_structure_and_local_bounds(investigation_setup):
    from sentinel.reasoning.behavior import wire_schema
    schema=wire_schema(BehaviorReasoningResult.model_json_schema())
    assert 'maxItems' not in json.dumps(schema) and 'maxLength' not in json.dumps(schema)
    assert schema['properties']['confidence']['maximum']==1
    assert schema['additionalProperties'] is False
    with pytest.raises(ValidationError):
        reasoning(context_for(investigation_setup),summary='x'*1201)


def test_real_legacy_relationships_remain_models_after_catalog_merge():
    from sentinel.threat_intel.models import ThreatKnowledge
    template=starter_records()[0]
    legacy=ThreatKnowledge(knowledge_id=template.knowledge_id,name='Legacy',description='Legacy',
        behaviors=[dict(source='source',operation='operation',sink='sink')])
    from sentinel.threat_intel.starter_catalog import merge_catalog
    merged=next(r for r in merge_catalog([legacy]) if r.knowledge_id==legacy.knowledge_id)
    assert merged.behaviors[0].source=='source'
