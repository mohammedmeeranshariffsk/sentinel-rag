import pytest

from sentinel.findings.builder import FindingBuilder
from sentinel.findings.models import Severity
from sentinel.program_analysis.behavior_slice import BehaviorSlice
from sentinel.reasoning.models import SecurityReasoningResult
from sentinel.threat_intel.models import ThreatMatch
from sentinel.validation.local_flow import LocalDataFlowAnalyzer
from sentinel.validation.models import EvidenceState
from sentinel.validation.validator import EvidenceValidator
from sentinel.cli.main import render_validated_finding


ANDROGOAT_LINES = [
    "EditText ip2 = findViewById(R.id.ip);",
    "StringBuilder builder = new StringBuilder();",
    'builder.append("ping ");',
    "builder.append(ip2.getText().toString());",
    "String ip1 = builder.toString();",
    "Log.d(TAG, ip1);",
    "Runtime.getRuntime().exec(ip1, null, null);",
]


def behavior(lines=ANDROGOAT_LINES):
    return BehaviorSlice(seed="Runtime.exec", file="InsecureCommands.java", line=27,
                         code_context=lines, related_strings=["ping", "ip"])


def reason(confidence=0.4):
    return SecurityReasoningResult(
        hypothesis="Command execution", behavior="Unverified", security_assessment="Unverified",
        confidence=confidence, apk_evidence_refs=[], knowledge_refs=[], missing_evidence=[],
        remediation=None, reasoning_summary="No intent established",
    )


def threat():
    return ThreatMatch(knowledge_id="COMMAND", knowledge_name="Command execution", matched_apis=["exec"])


def test_observed_local_source_transform_sink():
    flow = LocalDataFlowAnalyzer().analyze(behavior())[0]
    assert flow.source == "ip2.getText().toString()"
    assert flow.transforms == ["StringBuilder command construction"]
    assert flow.sink == "Runtime.getRuntime().exec(ip1)"
    assert flow.command_prefix == "ping "
    assert flow.file == "InsecureCommands.java"
    assert (flow.start_line, flow.end_line) == (22, 27)
    assert flow.evidence_lines[0].startswith("StringBuilder")
    validation = EvidenceValidator().validate(threat(), behavior(), [], reason())
    assert validation.evidence_state == EvidenceState.OBSERVED


@pytest.mark.parametrize("lines", [
    ["String ip1 = getDefaultCommand();", "Runtime.getRuntime().exec(ip1);"],
    ["String input = ip2.getText().toString();", 'String safe = "ping";'],
    ["String input = ip2.getText().toString();", "unrelatedApi(input);",
     'String ip1 = "ping";', "Runtime.getRuntime().exec(ip1);"],
])
def test_incomplete_or_unrelated_flow_is_not_observed(lines):
    assert LocalDataFlowAnalyzer().analyze(behavior(lines)) == []


def test_string_concatenation_flow():
    lines = ['String ip1 = "ping " + ip2.getText().toString();',
             "Runtime.getRuntime().exec(ip1);"]
    flow = LocalDataFlowAnalyzer().analyze(behavior(lines))[0]
    assert flow.transforms == ["String concatenation / assignment"]


@pytest.mark.parametrize("confidence", [0, 0.5, 1])
def test_flow_severity_is_deterministic_and_no_intent_is_inferred(confidence):
    validation = EvidenceValidator().validate(threat(), behavior(), [], reason(confidence))
    finding = FindingBuilder().build(threat(), behavior(), [], reason(confidence), validation)
    assert finding.severity == Severity.MEDIUM
    assert finding.confidence == 0.9
    assert "observed input-to-command-execution flow" in finding.assessment
    assert "additional validation" in finding.assessment
    text = finding.model_dump_json().lower()
    assert "confirmed malicious" not in text
    assert "arbitrary command execution" not in text
    assert "exploitable" not in text


def test_console_output_is_concise(capsys):
    validation = EvidenceValidator().validate(threat(), behavior(), [], reason())
    finding = FindingBuilder().build(threat(), behavior(), [], reason(), validation)
    render_validated_finding(finding)
    output = capsys.readouterr().out
    assert "File: InsecureCommands.java" in output
    assert "Line: 27" in output
    assert "Source: ip2.getText().toString()" in output
    assert "Transform: StringBuilder command construction" in output
    assert "Sink: Runtime.getRuntime().exec(ip1)" in output
    assert "Strings: ping, ip" in output
    assert '"code_context"' not in output
    assert '"evidence_lines"' not in output
