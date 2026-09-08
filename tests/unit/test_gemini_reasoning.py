import importlib
import json
import socket
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from google.genai import types
from typer.testing import CliRunner

from sentinel.extraction.models import EvidenceLocation, ExtractedAPI, ExtractionResult
from sentinel.reasoning.gemini import GeminiReasoningProvider
from sentinel.reasoning.models import SecurityReasoningResult
from sentinel.rag.models import RetrievedKnowledge
from sentinel.threat_intel.models import ThreatMatch


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Network forbidden")
    monkeypatch.setattr(socket.socket, "connect", fail)
    monkeypatch.setattr(socket, "create_connection", fail)


@pytest.fixture
def sdk(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "fake-key")
    client = Mock()
    factory = Mock(return_value=client)
    monkeypatch.setattr("sentinel.reasoning.gemini.genai.Client", factory)
    return factory, client


def completed(text):
    return types.GenerateContentResponse(candidates=[types.Candidate(
        finish_reason="STOP", content=types.Content(parts=[
            types.Part(text="private deliberation", thought=True), types.Part(text=text)
        ])
    )])


def test_gemini_configuration_and_thought_filtering(sdk):
    factory, client = sdk
    client.models.generate_content.return_value = completed('{"ok": true}')
    schema = SecurityReasoningResult.model_json_schema()
    assert GeminiReasoningProvider().generate_structured("prompt", response_schema=schema) == '{"ok": true}'
    assert factory.call_args.kwargs["api_key"] == "fake-key"
    assert factory.call_args.kwargs["http_options"].timeout == 30000
    args = client.models.generate_content.call_args.kwargs
    assert args["model"] == "gemini-3.5-flash-lite"
    assert args["contents"] == "prompt"
    config = args["config"]
    assert config.temperature == 0
    assert config.candidate_count == 1
    assert config.max_output_tokens == 2048
    assert config.response_mime_type == "application/json"
    assert config.response_json_schema == schema
    assert config.thinking_config.thinking_budget is None
    assert config.thinking_config.thinking_level == types.ThinkingLevel.MINIMAL
    assert config.thinking_config.include_thoughts is False
    assert config.automatic_function_calling is None
    assert config.tools is None
    assert config.tool_config is None


def test_sdk_structured_json_works_without_tools_or_afc_configuration(sdk, monkeypatch, caplog):
    from google.genai.models import Models

    actual_models = Models(Mock())
    transport = Mock(return_value=completed('{"ok": true}'))
    monkeypatch.setattr(actual_models, "_generate_content", transport)
    monkeypatch.setattr(Models, "_logged_afc_warning", False)
    sdk[1].models = actual_models
    assert GeminiReasoningProvider().generate_structured(
        "prompt", response_schema={"type": "object"}
    ) == '{"ok": true}'
    transport.assert_called_once()
    config = transport.call_args.kwargs["config"]
    assert config.tools is None
    assert config.tool_config is None


@pytest.mark.parametrize("response", [
    types.GenerateContentResponse(), completed(""),
    types.GenerateContentResponse(candidates=[types.Candidate(finish_reason="MAX_TOKENS")]),
])
def test_empty_or_incomplete_output_rejected(sdk, response):
    sdk[1].models.generate_content.return_value = response
    with pytest.raises(ValueError):
        GeminiReasoningProvider().generate_structured("prompt", response_schema={})


def test_missing_key(sdk, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY")
    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        GeminiReasoningProvider()
    sdk[0].assert_not_called()


@pytest.mark.parametrize("failure", [None, "generation", "validation", "init", "index", "retrieve", "seed", "no_findings"])
def test_analyze_integration_continues_on_failure(tmp_path, monkeypatch, sdk, failure):
    cli = importlib.import_module("sentinel.cli.main")
    apk = tmp_path / "example.apk"
    apk.touch()
    source = tmp_path / "Example.java"
    source.write_text('Runtime.getRuntime().exec("su");', encoding="utf-8")
    extraction = ExtractionResult(apis=[ExtractedAPI(
        api_name="exec", full_reference="Runtime.exec",
        location=EvidenceLocation(file=str(source), line=1),
    )])
    monkeypatch.setattr(cli, "run_extraction", Mock(return_value=(
        SimpleNamespace(apk_path=apk, sha256="abc"), None, extraction
    )))
    monkeypatch.setattr(cli, "ThreatKnowledgeBase", Mock())
    matches = [ThreatMatch(knowledge_id=str(i), knowledge_name=f"Seed {i}", matched_apis=["exec"]) for i in range(2)]
    if failure == "no_findings":
        matches = []
    if failure == "seed":
        from sentinel.program_analysis.behavior_slice import BehaviorSlice
        builder = Mock()
        builder.build_from_api.side_effect = [RuntimeError("private error"), BehaviorSlice(
            seed="exec", file=str(source), line=1, code_context=["exec()"]
        )]
        monkeypatch.setattr(cli, "BehaviorSliceBuilder", Mock(return_value=builder))
    monkeypatch.setattr(cli, "ThreatMatcher", Mock(return_value=SimpleNamespace(match=Mock(return_value=matches))))
    monkeypatch.setattr(cli, "KnowledgeDocumentLoader", Mock())
    monkeypatch.setattr(cli, "GeminiEmbeddingProvider", Mock())
    monkeypatch.setattr(cli, "QdrantVectorStore", Mock())
    indexer = Mock()
    monkeypatch.setattr(cli, "KnowledgeIndexer", Mock(return_value=indexer))
    retrieved = [RetrievedKnowledge(chunk_id="c1", document_id="d1", title="External report", content="Context only", score=0.8)]
    retriever = Mock()
    retriever.retrieve.return_value = retrieved
    monkeypatch.setattr(cli, "ThreatKnowledgeRetriever", Mock(return_value=retriever))
    if failure == "index":
        indexer.index.side_effect = RuntimeError("private error")
    if failure == "retrieve":
        retriever.retrieve.side_effect = RuntimeError("private error")
    result = dict(
        hypothesis="Command execution", behavior="Code invokes exec.",
        security_assessment="Insufficient evidence of malicious intent.", confidence=0.3,
        apk_evidence_refs=["apk:behavior_slice"],
        knowledge_refs=[] if failure in ("index", "retrieve") else ["knowledge:c1"],
        missing_evidence=["Runtime reachability"], remediation=None,
        reasoning_summary="The snippet alone does not establish malicious intent or family attribution.",
    )
    model = sdk[1].models.generate_content
    model.return_value = completed(json.dumps(result))
    if failure == "generation":
        model.side_effect = [RuntimeError("private error"), completed(json.dumps(result))]
    if failure == "validation":
        model.side_effect = [completed(json.dumps({**result, "confidence": 2})), completed(json.dumps(result))]
    if failure == "init":
        sdk[0].side_effect = ValueError("private error")
    json_path = tmp_path / "reports" / "analysis.json"
    output = CliRunner().invoke(cli.app, ["analyze", str(apk), "--output-json", str(json_path)])
    assert output.exit_code == 0, output.output
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["apk_metadata"]["sha256"] == "abc"
    assert report["evidence_summary"]["apis"] == 1
    assert report["analysis_metadata"]["reasoning_model"] == "gemini-3.5-flash-lite"
    if failure == "no_findings":
        assert report["validated_findings"] == []
        assert "No validated findings." in output.output
        model.assert_not_called()
        return
    assert report["analysis_metadata"]["status"] == ("complete" if failure is None else "partial")
    assert output.output.count("Retrieved Security Knowledge") == (1 if failure == "seed" else 2)
    assert "Seed 1" in output.output
    assert "private" not in output.output
    if failure == "generation":
        assert "Security reasoning unavailable: RuntimeError:" in output.output
    if failure == "validation":
        assert "Security reasoning unavailable: ValidationError:" in output.output
    if failure != "init":
        assert "# Validated Findings" in output.output
        assert "Insufficient evidence of malicious intent" in output.output
        assert model.call_count == (1 if failure == "seed" else 2)
        assert len(report["validated_findings"]) == (1 if failure in ("seed", "generation", "validation") else 2)
        data = json.loads(model.call_args.kwargs["contents"].split("\nINPUT DATA:\n")[1])
        assert bool(data["external_knowledge"]) == (failure not in ("index", "retrieve"))
        assert "apk:behavior_slice" in data["apk_evidence"]
    else:
        assert "Security reasoning unavailable" in output.output
        model.assert_not_called()
    if failure not in ("index", "retrieve"):
        assert "External report" in output.output
