import pytest
from pydantic import ValidationError

from sentinel.findings.builder import FindingBuilder
from sentinel.findings.models import SecurityFinding, Severity
from sentinel.program_analysis.behavior_slice import BehaviorSlice
from sentinel.rag.models import RetrievedKnowledge
from sentinel.reasoning.models import EvidenceClaim, SecurityReasoningResult
from sentinel.reporting.models import APKMetadata, AnalysisMetadata, SecurityReport
from sentinel.threat_intel.models import ThreatMatch
from sentinel.validation.models import EvidenceState
from sentinel.validation.validator import EvidenceValidator


@pytest.fixture
def inputs():
    return (
        ThreatMatch(knowledge_id="T1", knowledge_name="Command execution",
                    matched_apis=["exec"], matched_strings=["/system/bin/su"]),
        BehaviorSlice(seed="exec", file="Example.java", line=42,
                      code_context=['exec("ping ip");'], related_strings=["ping ip"]),
        [RetrievedKnowledge(chunk_id="c1", document_id="d1", title="Context",
                            content="Family X uses /system/bin/su", source="https://example.org/source", score=0.9)],
    )


def reasoning(**updates):
    data = dict(hypothesis="Unverified", behavior="Unverified", security_assessment="Insufficient evidence",
                confidence=0.9, apk_evidence_refs=[], knowledge_refs=[], missing_evidence=[],
                remediation=None, reasoning_summary="Insufficient evidence")
    data.update(updates)
    return SecurityReasoningResult(**data)


def test_broader_string_cannot_be_promoted_to_local_flow(inputs):
    result = reasoning(apk_evidence_refs=["apk:behavior_slice", "apk:matched_indicators"], claims=[
        EvidenceClaim(scope="LOCAL", reference="apk:behavior_slice", value="/system/bin/su"),
        EvidenceClaim(scope="APK", reference="apk:matched_indicators", value="/system/bin/su"),
    ])
    validation = EvidenceValidator().validate(*inputs, result)
    assert validation.evidence_state == EvidenceState.NOT_VERIFIABLE_FROM_APK
    assert len(validation.supported_claims) == 1
    assert validation.supported_claims[0].scope == "APK"
    assert "Unsupported LOCAL" in validation.issues[0]


@pytest.mark.parametrize("scope,ref,value", [
    ("LOCAL", "apk:matched_indicators", "/system/bin/su"),
    ("APK", "apk:behavior_slice", "ping ip"),
    ("LOCAL", "knowledge:c1", "/system/bin/su"),
    ("APK", "apk:matched_indicators", "invented"),
    ("EXTERNAL", "knowledge:c1", "invented"),
    ("LOCAL", "apk:behavior_slice", "   "),
])
def test_wrong_scope_or_absent_claim_is_unsupported(inputs, scope, ref, value):
    result = reasoning(apk_evidence_refs=["apk:behavior_slice", "apk:matched_indicators"],
                       knowledge_refs=["knowledge:c1"],
                       claims=[EvidenceClaim(scope=scope, reference=ref, value=value)])
    validation = EvidenceValidator().validate(*inputs, result)
    assert validation.issues
    assert not validation.supported_claims


def test_token_presence_does_not_prove_flow(inputs):
    result = reasoning(apk_evidence_refs=["apk:behavior_slice"], claims=[
        EvidenceClaim(scope="LOCAL", reference="apk:behavior_slice", value="ping ip", kind="FLOW")
    ])
    validation = EvidenceValidator().validate(*inputs, result)
    assert validation.evidence_state == EvidenceState.NOT_VERIFIABLE_FROM_APK
    assert "FLOW" in validation.issues[0]


@pytest.mark.parametrize("apk_refs,knowledge_refs,claims,state", [
    (["apk:behavior_slice"], [], [dict(scope="LOCAL", reference="apk:behavior_slice", value="ping ip")], "OBSERVED"),
    (["apk:behavior_slice"], [], [], "INFERRED"),
    (["apk:matched_indicators"], [], [], "CORRELATED"),
    (["apk:behavior_slice", "apk:matched_indicators"], [], [], "CORRELATED"),
    ([], ["knowledge:c1"], [], "SEMANTIC_SUSPECT"),
    ([], [], [], "NOT_VERIFIABLE_FROM_APK"),
    (["apk:invented"], [], [], "NOT_VERIFIABLE_FROM_APK"),
    (["knowledge:c1"], [], [], "NOT_VERIFIABLE_FROM_APK"),
])
def test_evidence_states(inputs, apk_refs, knowledge_refs, claims, state):
    validation = EvidenceValidator().validate(*inputs, reasoning(
        apk_evidence_refs=apk_refs, knowledge_refs=knowledge_refs, claims=claims
    ))
    assert validation.evidence_state.value == state


def test_ambiguous_knowledge_provenance_rejected(inputs):
    threat, source, knowledge = inputs
    knowledge.append(knowledge[0].model_copy(update={"document_id": "other"}))
    result = EvidenceValidator().validate(threat, source, knowledge, reasoning(knowledge_refs=["knowledge:c1"]))
    assert result.unsupported_references == ["knowledge:c1"]
    assert not result.supported_knowledge_refs


def test_findings_preserve_provenance_without_publishing_unverified_prose(inputs):
    result = reasoning(apk_evidence_refs=["apk:behavior_slice", "apk:matched_indicators"], knowledge_refs=["knowledge:c1"],
                       behavior="/system/bin/su participates in this local flow", security_assessment="Confirmed Family X",
                       reasoning_summary="Confirmed Family X", remediation="Delete everything")
    validation = EvidenceValidator().validate(*inputs, result)
    finding = FindingBuilder().build(*inputs, result, validation)
    local, broader = finding.apk_evidence
    assert local.scope == "LOCAL" and local.file == "Example.java" and local.line == 42
    assert local.code_context == inputs[1].code_context
    assert not local.matched_indicators
    assert broader.scope == "APK" and broader.file is None and broader.line is None
    assert broader.matched_indicators["matched_strings"] == ["/system/bin/su"]
    assert finding.knowledge_references[0].source == inputs[2][0].source
    assert finding.knowledge_references[0].document_id == "d1"
    assert "Confirmed Family X" not in finding.model_dump_json()
    assert "participates in this local flow" not in finding.behavior
    assert "Delete everything" not in finding.model_dump_json()
    assert finding.severity == Severity.INFO
    assert finding.confidence == 0.5
    assert finding.finding_id == FindingBuilder().build(*inputs, result, validation).finding_id


def test_unsupported_claim_downgrades_confidence_and_records_gap(inputs):
    result = reasoning(apk_evidence_refs=["apk:invented"], confidence=1)
    validation = EvidenceValidator().validate(*inputs, result)
    finding = FindingBuilder().build(*inputs, result, validation)
    assert finding.confidence == 0
    assert finding.apk_evidence == []
    assert "apk:invented" in finding.missing_evidence[0]


@pytest.mark.parametrize("confidence", [0, 0.2, 1])
def test_severity_independent_of_confidence_and_serialization(inputs, confidence, tmp_path):
    result = reasoning(apk_evidence_refs=["apk:behavior_slice"], confidence=confidence)
    validation = EvidenceValidator().validate(*inputs, result)
    finding = FindingBuilder().build(*inputs, result, validation)
    assert finding.severity == Severity.INFO
    with pytest.raises(ValidationError):
        SecurityFinding(**{**finding.model_dump(), "severity": "URGENT"})
    for severity in Severity:
        assert SecurityFinding(**{**finding.model_dump(), "severity": severity.value}).severity == severity
    report = SecurityReport(apk_metadata=APKMetadata(path="example.apk", sha256="abc"),
                            evidence_summary={"apis": 1}, validated_findings=[finding],
                            analysis_metadata=AnalysisMetadata(reasoning_model="fake"))
    path = tmp_path / "nested" / "report.json"
    report.write_json(path)
    assert SecurityReport.model_validate_json(path.read_text(encoding="utf-8")) == report


def test_empty_report_serializes(tmp_path):
    report = SecurityReport(apk_metadata=APKMetadata(path="example.apk", sha256="abc"),
                            evidence_summary={}, analysis_metadata=AnalysisMetadata(reasoning_model="fake"))
    path = tmp_path / "empty.json"
    report.write_json(path)
    assert SecurityReport.model_validate_json(path.read_text()).validated_findings == []
