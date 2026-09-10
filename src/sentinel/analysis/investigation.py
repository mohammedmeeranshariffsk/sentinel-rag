"""One bounded behavior graph -> optional AI -> deterministic finding."""
from time import perf_counter

from sentinel.analysis.behavior_models import BehaviorInvestigation
from sentinel.analysis.behavior_context import BehaviorContextBuilder
from sentinel.program_analysis.behavior_graph import BehaviorGraphBuilder
from sentinel.program_analysis.behavior_slice import BehaviorSliceBuilder
from sentinel.reasoning.behavior import BehaviorReasoningAnalyzer
from sentinel.reasoning.errors import safe_reasoning_error
from sentinel.reasoning.models import SecurityReasoningResult
from sentinel.rag.query_builder import RetrievalQueryBuilder
from sentinel.validation.behavior import BehaviorClaimValidator
from sentinel.validation.local_flow import LocalDataFlowAnalyzer
from sentinel.validation.models import EvidenceValidationResult, EvidenceState
from sentinel.findings.builder import FindingBuilder
from sentinel.findings.models import APKEvidence, KnowledgeReference, SecurityFinding, Severity


class BehaviorInvestigator:
    def __init__(self, extraction, index, ownership, options, slice_builder=None):
        self.extraction, self.index, self.ownership, self.options = extraction,index,ownership,options
        self.slice_builder = slice_builder or BehaviorSliceBuilder(context_lines=8)
        self.api_locations = {(a.location.file,a.location.line,a.full_reference):a for a in extraction.apis}

    def investigate(self, match, seeds, apk_context, coverage, manifest=None, record=None,
                    retriever=None, provider=None, notify=lambda message:None):
        seeds = [s for s in seeds if s.behavior_id == match.knowledge_id and s.selected_for_investigation]
        started = perf_counter()
        graph = BehaviorGraphBuilder(max_depth=self.options.graph_depth,
            max_nodes=min(self.options.graph_node_limit,160),max_methods=min(self.options.graph_method_limit,8)
        ).build(apk_context,self.extraction,seeds,coverage,self.index,ownership=self.ownership)
        flows, slices = [], []
        for seed in seeds:
            api = self.api_locations.get((seed.file,seed.line,seed.matched_value))
            if api and api.api_name == 'exec':
                sliced = self.slice_builder.build_from_api(api)
                if sliced:
                    slices.append(sliced)
                    flows.extend(LocalDataFlowAnalyzer().analyze(sliced))
        context = BehaviorContextBuilder().build(match,seeds,graph,self.index,manifest,record,flows)
        investigation = BehaviorInvestigation(behavior_id=match.knowledge_id,behavior_name=match.knowledge_name,
            matched_indicators=match, selected_seeds=seeds,graph=graph,context=context)
        investigation.stage_timings['graph_context'] = perf_counter()-started
        investigation.retrieval_query = RetrievalQueryBuilder().build_context(context)
        if self.options.rag_enabled:
            investigation.retrieval_status = 'unavailable'
            if retriever:
                notify('Retrieving threat knowledge')
                started = perf_counter()
                try:
                    investigation.retrieved_knowledge = retriever.retrieve(
                        query=investigation.retrieval_query,limit=self.options.retrieval_top_k)
                    investigation.retrieval_status = 'completed'
                except Exception as error:
                    investigation.errors.append('Retrieval unavailable: '+safe_reasoning_error(error))
                investigation.stage_timings['retrieval'] = perf_counter()-started
        if self.options.reasoning_enabled:
            investigation.reasoning_status = 'unavailable'
            if provider:
                notify('Running structured reasoning')
                started = perf_counter()
                try:
                    investigation.reasoning_result = BehaviorReasoningAnalyzer(provider).analyze(context,investigation.retrieved_knowledge)
                    investigation.reasoning_status = 'completed'
                except Exception as error:
                    investigation.errors.append('Security reasoning unavailable: '+safe_reasoning_error(error))
                investigation.stage_timings['reasoning'] = perf_counter()-started
        notify('Validating claims and generating findings')
        investigation.validation = BehaviorClaimValidator().validate(context,investigation.reasoning_result,
            investigation.retrieved_knowledge,self.index)
        if investigation.validation.rejected_claims:
            investigation.errors.append('Structured reasoning contained rejected claims; deterministic findings retained')
        investigation.validated_findings = [self.finding(investigation,match,slices)]
        return investigation

    def finding(self, investigation, match, slices):
        context, validation = investigation.context, investigation.validation
        if context.local_data_flows and slices and match.knowledge_id == 'THREAT-PROCESS-001':
            sliced = next((s for s in slices if s.file == context.local_data_flows[0].file), slices[0])
            placeholder = SecurityReasoningResult(hypothesis=match.knowledge_name,behavior='',security_assessment='',
                confidence=0,apk_evidence_refs=[],knowledge_refs=[],missing_evidence=[],remediation=None,reasoning_summary='')
            finding = FindingBuilder().build(match,sliced,investigation.retrieved_knowledge,placeholder,
                EvidenceValidationResult(evidence_state=EvidenceState.OBSERVED,supported_apk_refs=['apk:behavior_slice'],
                    local_data_flows=context.local_data_flows,issues=validation.issues,
                    supported_knowledge_refs=[f'knowledge:{k.chunk_id}' for k in investigation.retrieved_knowledge]))
        else:
            summary = ('Matched APK indicators support investigation. Source call expressions, when present, do not '
                'establish the complete proposed behavior, data flow, malicious intent or malware-family attribution.')
            if context.coverage_limitations:
                summary += ' Incomplete artifact coverage prevents conclusions that unobserved behavior is absent.'
            evidence = [APKEvidence(reference=f.evidence_id,scope=f.scope,file=f.file,line=f.line,seed=f.value)
                        for f in context.facts[:16]]
            finding = SecurityFinding(finding_id='BF-'+match.knowledge_id,title='Investigation: '+match.knowledge_name,
                category='MALWARE_BEHAVIOR_INVESTIGATION',severity=Severity.INFO,
                confidence=0.35 if context.facts else 0,evidence_state=(EvidenceState.CORRELATED if context.facts else EvidenceState.NOT_VERIFIABLE_FROM_APK),
                hypothesis='Unverified behavior hypothesis: '+match.knowledge_name,behavior=summary,
                assessment='Insufficient evidence of malicious intent or confirmed security impact. '+summary,
                apk_evidence=evidence,knowledge_references=[KnowledgeReference(reference=f'knowledge:{k.chunk_id}',
                    chunk_id=k.chunk_id,document_id=k.document_id,title=k.title,source=k.source)
                    for k in investigation.retrieved_knowledge],
                missing_evidence=list(dict.fromkeys(context.expected_relationships+context.unresolved_relationships+
                    ['Runtime reachability, data flow, intent and impact require validation.']+validation.rejected_claims)),
                remediation='Review cited implementation and unresolved relationships in an isolated static-analysis environment.',
                reasoning_summary=summary)
        finding.behavior_id = match.knowledge_id
        finding.graph_evidence_refs = [r.evidence_id for r in context.relationships]
        finding.coverage_limitations = context.coverage_limitations
        finding.unresolved_relationships = context.unresolved_relationships
        return finding
