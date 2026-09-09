import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from sentinel.extraction.models import (
    EvidenceLocation,
    ExtractedAPI,
    ExtractedPermission,
    ExtractedString,
    ExtractedMethod,
    ExtractionResult,
)
from sentinel.decompiler.pipeline import DecompilationResult
from sentinel.manifest.analyzer import ComponentInfo, IntentFilterInfo, ManifestAnalysis
from sentinel.profiles.analyzer import ProfileAnalyzer
from sentinel.profiles.finding_builder import ProfileFindingBuilder
from sentinel.profiles.loader import ProfileLoader
from sentinel.profiles.models import ProfileOutcome
from sentinel.profiles.reasoning import ProfileReasoningAnalyzer


PROFILE_PATH = Path("docs/research/trickmo/extraction-profile.json")


def extracted() -> tuple[ExtractionResult, ManifestAnalysis]:
    location = EvidenceLocation(file="AgentService.java", line=12)
    extraction = ExtractionResult(
        apis=[ExtractedAPI(
            api_name="dispatchGesture",
            full_reference="AccessibilityService.dispatchGesture",
            location=location,
        )],
        strings=[
            ExtractedString(value="SaveHtml", location=location),
            ExtractedString(value="get_inject", location=location),
        ],
        permissions=[ExtractedPermission(
            permission="android.permission.SYSTEM_ALERT_WINDOW"
        )],
    )
    manifest = ManifestAnalysis(
        manifest_path=Path("AndroidManifest.xml"),
        package_name="example.app",
        services=[ComponentInfo(
            name=".AgentService",
            component_type="service",
            permission="android.permission.BIND_ACCESSIBILITY_SERVICE",
            intent_filters=[IntentFilterInfo(actions=[
                "android.accessibilityservice.AccessibilityService"
            ])],
        )],
    )
    return extraction, manifest


def test_profile_loader_and_deterministic_matching():
    profile = ProfileLoader().load(PROFILE_PATH)
    extraction, manifest = extracted()
    result = ProfileAnalyzer().analyze(profile, PROFILE_PATH, extraction, manifest)

    assert result.family_id == "family:trickmo"
    values = {item.value for item in result.artifact_matches}
    assert "android.permission.BIND_ACCESSIBILITY_SERVICE" in values
    assert "android.permission.SYSTEM_ALERT_WINDOW" in values
    assert "android.accessibilityservice.AccessibilityService.dispatchGesture" in values
    assert "SaveHtml" in values
    assert "get_inject" in values

    accessibility = next(
        item for item in result.behavior_assessments
        if item.bundle_id == "bundle:accessibility-automation"
    )
    assert accessibility.outcome == ProfileOutcome.APK_COOCCURRENCE
    assert accessibility.missing_evidence
    assert result.family_attribution_supported is False
    assert result.accessibility_graph is not None

    # An unverified candidate remains visible in the inventory but cannot seed
    # or strengthen a behavior assessment.
    candidate = next(item for item in result.artifact_matches if item.value == "get_inject")
    assert candidate.classification == "unverified_candidate"


def test_profile_analysis_uses_observed_accessibility_callback_action_path():
    profile = ProfileLoader().load(PROFILE_PATH)
    extraction, manifest = extracted()
    extraction.methods.append(ExtractedMethod(
        name="onAccessibilityEvent", class_name="AgentService",
        file="AgentService.java", line=10,
    ))
    extraction.apis[0].location.class_name = "AgentService"
    extraction.apis[0].location.method_name = "onAccessibilityEvent"

    result = ProfileAnalyzer().analyze(profile, PROFILE_PATH, extraction, manifest)
    assessment = next(item for item in result.behavior_assessments
                      if item.bundle_id == "bundle:accessibility-automation")

    assert assessment.outcome == ProfileOutcome.PARTIAL_RELATIONSHIP
    assert "Configuration-to-callback" in " ".join(assessment.missing_evidence)
    assert result.accessibility_graph is not None
    assert any(edge["relation"] == "calls_accessibility_action"
               for edge in result.accessibility_graph["edges"])


def test_accessibility_graph_console_output_is_concise(capsys):
    from sentinel.cli.main import render_accessibility_graph

    render_accessibility_graph({
        "nodes": [{"node_id": "service:AgentService"}],
        "edges": [{
            "relation": "calls_accessibility_action",
            "evidence_refs": ["AgentService.java:14"],
        }],
        "unsupported_relationships": [
            "Configuration-to-callback control is not established by this bounded analysis."
        ],
    })

    output = capsys.readouterr().out
    assert "Accessibility Behavior Graph (APK evidence)" in output
    assert "calls accessibility action: AgentService.java:14" in output
    assert "Not established: Configuration-to-callback" in output
    assert "{'nodes'" not in output


def test_profile_api_matching_rejects_same_method_on_wrong_owner(tmp_path):
    profile = ProfileLoader().load(PROFILE_PATH)
    source = tmp_path / "WrongOwners.java"
    source.write_text(
        "AccessibilityEvent event = AccessibilityEvent.obtain();\n"
        "FrameLayout layout = new FrameLayout(context);\n"
        "event.getText();\n"
        "layout.addView(view);\n"
        "Locale.getDefault();\n",
        encoding="utf-8",
    )
    extraction = ExtractionResult(apis=[
        ExtractedAPI(
            api_name="getText", full_reference="event.getText",
            location=EvidenceLocation(file=str(source), line=3),
        ),
        ExtractedAPI(
            api_name="addView", full_reference="layout.addView",
            location=EvidenceLocation(file=str(source), line=4),
        ),
        ExtractedAPI(
            api_name="getDefault", full_reference="Locale.getDefault",
            location=EvidenceLocation(file=str(source), line=5),
        ),
    ])

    result = ProfileAnalyzer().analyze(
        profile, PROFILE_PATH, extraction, None
    )

    assert result.artifact_matches == []


def test_profile_api_matching_resolves_declared_receiver_type(tmp_path):
    profile = ProfileLoader().load(PROFILE_PATH)
    source = tmp_path / "AccessibilityReader.java"
    source.write_text(
        "AccessibilityNodeInfo node = getRoot();\n"
        "node.getText();\n",
        encoding="utf-8",
    )
    extraction = ExtractionResult(apis=[ExtractedAPI(
        api_name="getText",
        full_reference="node.getText",
        location=EvidenceLocation(file=str(source), line=2),
    )])

    result = ProfileAnalyzer().analyze(
        profile, PROFILE_PATH, extraction, None
    )

    assert [item.value for item in result.artifact_matches] == [
        "android.view.accessibility.AccessibilityNodeInfo.getText"
    ]


def test_profile_with_no_matches_reports_no_seed():
    profile = ProfileLoader().load(PROFILE_PATH)
    result = ProfileAnalyzer().analyze(
        profile, PROFILE_PATH, ExtractionResult(), None
    )
    assert result.artifact_matches == []
    assert all(
        item.outcome == ProfileOutcome.NO_SEED
        for item in result.behavior_assessments
    )
    assert "No source-backed" in result.conclusion


class FakeProvider:
    def __init__(self, response):
        self.response = response
        self.prompts = []

    def generate_structured(self, prompt, *, response_schema):
        self.prompts.append((prompt, response_schema))
        return json.dumps(self.response)


def reasoning_response(apk_refs):
    return {
        "hypothesis": "Possible accessibility automation",
        "behavior": "Profile seeds co-occur in the APK.",
        "security_assessment": "The required relationship is not verified.",
        "confidence": 0.8,
        "apk_evidence_refs": apk_refs,
        "knowledge_refs": [
            "profile:family:trickmo:verify:trickmo:accessibility-automation:v1"
        ],
        "missing_evidence": ["Required APK-local relationship"],
        "remediation": None,
        "reasoning_summary": "The matches justify review but not TrickMo attribution.",
        "claims": [],
    }


def test_profile_reasoning_is_bounded_and_finding_is_conservative():
    profile = ProfileLoader().load(PROFILE_PATH)
    extraction, manifest = extracted()
    analysis = ProfileAnalyzer().analyze(profile, PROFILE_PATH, extraction, manifest)
    index = next(
        i for i, item in enumerate(analysis.behavior_assessments)
        if item.bundle_id == "bundle:accessibility-automation"
    )
    assessment = analysis.behavior_assessments[index]
    provider = FakeProvider(reasoning_response(assessment.matched_evidence_refs))
    reasoning = ProfileReasoningAnalyzer(provider).analyze(profile, analysis, index)
    finding = ProfileFindingBuilder().build(analysis, assessment, reasoning)

    assert reasoning.confidence == 0.5
    assert finding is not None
    assert finding.severity.value == "INFO"
    assert finding.evidence_state.value == "CORRELATED"
    assert "family attribution is unsupported" in finding.assessment
    assert finding.reasoning_summary == reasoning.reasoning_summary
    prompt = provider.prompts[0][0]
    assert "external research context, not APK evidence" in prompt
    assert "Do not attribute the APK to a malware" in prompt


def test_profile_reasoning_rejects_invented_apk_reference():
    profile = ProfileLoader().load(PROFILE_PATH)
    extraction, manifest = extracted()
    analysis = ProfileAnalyzer().analyze(profile, PROFILE_PATH, extraction, manifest)
    index = next(
        i for i, item in enumerate(analysis.behavior_assessments)
        if item.bundle_id == "bundle:accessibility-automation"
    )
    provider = FakeProvider(reasoning_response(["apk:invented"]))
    with pytest.raises(ValueError, match="unsupported APK evidence"):
        ProfileReasoningAnalyzer(provider).analyze(profile, analysis, index)


def test_cli_profile_review_survives_unavailable_gemini(tmp_path, monkeypatch):
    import sentinel.cli.main as cli

    apk = tmp_path / "sample.apk"
    apk.touch()
    extraction, manifest = extracted()
    monkeypatch.setattr(cli, "run_extraction", Mock(return_value=(
        SimpleNamespace(
            apk_path=apk, sha256="abc", file_size=0,
            package_name="example.app", version_name=None, version_code=None,
        ),
        manifest,
        extraction,
        DecompilationResult(
            jadx_success=True, source_path=tmp_path, jadx_return_code=0
        ),
    )))
    monkeypatch.setattr(cli, "ThreatKnowledgeBase", Mock())
    monkeypatch.setattr(
        cli, "ThreatMatcher",
        Mock(return_value=SimpleNamespace(match=Mock(return_value=[]))),
    )
    monkeypatch.setattr(cli, "KnowledgeDocumentLoader", Mock())
    monkeypatch.setattr(cli, "GeminiEmbeddingProvider", Mock(side_effect=RuntimeError("offline")))
    class MissingGemini:
        MODEL = "gemini-3.5-flash-lite"

        def __init__(self):
            raise ValueError("no key")

    monkeypatch.setattr(cli, "GeminiReasoningProvider", MissingGemini)

    report_path = tmp_path / "report.json"
    output = CliRunner().invoke(cli.app, [
        "analyze", str(apk), "--profile", str(PROFILE_PATH),
        "--output-json", str(report_path),
    ])
    assert output.exit_code == 0, output.output
    assert "[progress] Matching extracted evidence to threat knowledge" in output.output
    assert "[progress] Reviewing 1 extraction profile(s)" in output.output
    assert "[progress] Analysis complete" in output.output
    assert "# Malware Profile Reviews" in output.output
    assert "Profile: family:trickmo" in output.output
    assert "APK_COOCCURRENCE" in output.output
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["profile_analyses"][0]["family_id"] == "family:trickmo"
    assert report["analysis_metadata"]["profile_count"] == 1
    assert report["analysis_metadata"]["profile_seed_count"] >= 1
    assert report["validated_findings"]
    assert report["validated_findings"][0]["severity"] == "INFO"
