"""Readable static report; APK strings are escaped, never executable markup."""
import html
import re
from enum import Enum


def text(value):
    if isinstance(value,Enum):
        value = value.value
    value = html.escape(str(value)).replace('`','&#96;').replace('\n',' ').replace('|','&#124;')
    return re.sub(r'([\\*_[\]#!])', r'\\\1', value)


def render_markdown(report):
    lines = ['# SentinelRAG Malware Behavior Analysis', '', '## Executive Summary', '',
        f'{len(report.behavior_investigations)} behavior investigations; {len(report.validated_findings)} findings. '
        'This is a static investigation, not a malware-family verdict.', '',
        'LLM output is untrusted interpretation. Similarity is retrieval relevance, not evidence confidence.', '',
        '## APK Identity','',f'- File: {text(report.apk_metadata.path)}',
        f'- SHA256: {text(report.apk_metadata.sha256)}', f'- Package: {text(report.apk_metadata.package_name)}',
        '', '## Artifact / Decompilation Coverage','']
    coverage = report.artifact_coverage
    if coverage:
        lines += [f'- Mode: {coverage.analysis_mode.value}',f'- JADX: {coverage.jadx_status.value}; Apktool: {coverage.apktool_status.value}',
            f'- DEX directly readable: {coverage.dex_readable}',
            f'- Source files: {coverage.jadx_class_count}; application-package implementation: {coverage.jadx_application_implementation_class_count}']
        lines += [f'- {text(l.code)}: {text(l.message)}' for l in coverage.limitations]
    lines += ['', '## Manifest Attack Surface','', 'Declarations are APK evidence, not security violations.','']
    for kind in ('activities','services','receivers','providers'):
        components = report.manifest_evidence.get(kind,[])
        lines += [f'- {kind}: {len(components)} declarations; {sum(c.get("declared_exported") is True for c in components)} explicitly exported']
    lines += ['', '## Evidence Summary','']+[f'- {text(k)}: {v}' for k,v in report.evidence_summary.items()]
    lines += ['', '## Threat-Matched Behaviors','']+[f'- {text(m.knowledge_name)}: indicator score {m.score} (not confidence)' for m in report.matched_indicators]
    selected = [s for s in report.investigation_seeds if s.selected_for_investigation]
    lines += ['', '## Investigation Seeds','',f'{len(report.investigation_seeds)} candidates retained; {len(selected)} selected. Full provenance and grouping are in JSON.']
    lines += [f'- {text(s.matched_value)} — {s.source_provenance.value} / {s.quality.value}' for s in selected[:20]]
    lines += ['', '## Behavior Investigations','']
    for investigation in report.behavior_investigations:
        lines += [f'### {text(investigation.behavior_name)}','',
            f'Graph: {len(investigation.graph.nodes)} nodes / {len(investigation.graph.edges)} edges. '
            f'Retrieval: {investigation.retrieval_status}; reasoning: {investigation.reasoning_status}.','']
        for finding in investigation.validated_findings:
            lines += [f'{finding.evidence_state.value} · {finding.severity.value} · confidence {finding.confidence:.2f}',
                '', '**Analyst Assessment**', '',text(finding.assessment),'']
        lines += ['**Observed Evidence**','']+[f'- [{f.scope}] {text(f.value)} ({text(f.file or "APK-wide")}:{f.line or "—"}); {text(f.evidence_id)}' for f in investigation.context.facts[:10]]
        labels = {f.evidence_id:f.value for f in investigation.context.facts}
        lines += ['', '**Behavior Graph / Supported Source Relationships**','']
        lines += [f'- {text(labels.get(e.source,e.source))} → {e.relation} → {text(labels.get(e.target,e.target))}' for e in investigation.context.relationships[:10]]
        lines += ['', '**Retrieved Threat Knowledge (external context only)**','']
        lines += [f'- {text(k.title)}; document {text(k.document_id)}; chunk {text(k.chunk_id)}; relevance {k.score:.3f}; source {text(k.source)}' for k in investigation.retrieved_knowledge]
        lines += ['', '**Missing Evidence / Coverage Limitations**','']
        lines += [f'- {text(v)}' for v in (investigation.context.expected_relationships+investigation.context.unresolved_relationships+investigation.context.coverage_limitations)[:12]]
        lines += [f'- Rejected claim: {text(v)}' for v in investigation.validation.rejected_claims[:8]]
        lines += ['','Model prose is retained in JSON as untrusted suggestions; validated findings use deterministic summaries.','']
    lines += ['## Validated Findings','']+[f'- [{f.severity.value}] {text(f.title)} — {f.evidence_state.value}: {text(f.assessment)}' for f in report.validated_findings]
    lines += ['', '## Unresolved Relationships','', 'Unresolved does not mean absent. Detailed per-behavior relationships are retained in JSON.',
        '', '## Analysis Limitations','', 'Static call expressions do not prove runtime reachability, intent, exploitability or family attribution. Ownership candidates are heuristic.']
    lines += [f'- {text(e)}' for e in report.analysis_metadata.errors[:15]]
    lines += ['', '## Evidence Appendix','',f'Analysis ID: {report.analysis_metadata.analysis_id}. '
        'The companion JSON contains full graph nodes, source references, matched candidates, validation rejections and coverage.','']
    return '\n'.join(lines)
