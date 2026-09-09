from pathlib import Path

from sentinel.extraction.models import EvidenceLocation, ExtractedAPI, ExtractedMethod, ExtractionResult
from sentinel.manifest.analyzer import ComponentInfo, IntentFilterInfo, ManifestAnalysis
from sentinel.program_analysis.accessibility_graph import AccessibilityBehaviorGraphBuilder
from sentinel.profiles.loader import ProfileLoader


PROFILE = Path("docs/research/trickmo/extraction-profile.json")


def test_graph_links_declared_service_callback_and_direct_action():
    manifest = ManifestAnalysis(
        manifest_path=Path("AndroidManifest.xml"),
        services=[ComponentInfo(
            name=".AgentService", component_type="service",
            permission="android.permission.BIND_ACCESSIBILITY_SERVICE",
            intent_filters=[IntentFilterInfo(actions=["android.accessibilityservice.AccessibilityService"])],
        )],
    )
    extraction = ExtractionResult(
        methods=[ExtractedMethod(name="onAccessibilityEvent", class_name="AgentService", file="AgentService.java", line=10)],
        apis=[ExtractedAPI(
            api_name="dispatchGesture", full_reference="service.dispatchGesture",
            location=EvidenceLocation(file="AgentService.java", line=14, class_name="AgentService", method_name="onAccessibilityEvent"),
        )],
    )
    graph = AccessibilityBehaviorGraphBuilder().build(ProfileLoader().load(PROFILE), extraction, manifest)
    assert [(edge.relation, edge.scope) for edge in graph.edges] == [
        ("implements_callback", "APK"), ("calls_accessibility_action", "APK")
    ]
    assert {node.kind for node in graph.nodes} == {
        "accessibility_service", "accessibility_callback", "accessibility_action"
    }
    assert "Configuration-to-callback control is not established by this bounded analysis." in graph.unsupported_relationships


def test_graph_does_not_infer_an_edge_from_profile_seed_presence():
    graph = AccessibilityBehaviorGraphBuilder().build(
        ProfileLoader().load(PROFILE), ExtractionResult(),
        ManifestAnalysis(manifest_path=Path("AndroidManifest.xml")),
    )
    assert graph.nodes == []
    assert graph.edges == []


def test_graph_resolves_callback_in_local_superclass(tmp_path):
    source = tmp_path / "Services.java"
    source.write_text(
        "package example;\n"
        "class AgentService extends BaseService {}\n"
        "class BaseService extends AccessibilityService {\n"
        "  void onAccessibilityEvent(Object event) { performGlobalAction(1); }\n"
        "}\n",
        encoding="utf-8",
    )
    manifest = ManifestAnalysis(
        manifest_path=Path("AndroidManifest.xml"),
        services=[ComponentInfo(
            name="example.AgentService", component_type="service",
            permission="android.permission.BIND_ACCESSIBILITY_SERVICE",
            intent_filters=[IntentFilterInfo(actions=["android.accessibilityservice.AccessibilityService"])],
        )],
    )
    extraction = ExtractionResult(
        source_root=tmp_path,
        methods=[ExtractedMethod(
            name="onAccessibilityEvent", class_name="BaseService",
            file=str(source), line=4,
        )],
        apis=[ExtractedAPI(
            api_name="performGlobalAction", full_reference="this.performGlobalAction",
            location=EvidenceLocation(
                file=str(source), line=4, class_name="BaseService",
                method_name="onAccessibilityEvent",
            ),
        )],
    )

    graph = AccessibilityBehaviorGraphBuilder().build(
        ProfileLoader().load(PROFILE), extraction, manifest
    )

    assert [edge.relation for edge in graph.edges] == [
        "inherits_callback", "calls_accessibility_action"
    ]
    service = next(node for node in graph.nodes if node.kind == "accessibility_service")
    assert service.file == str(source)


def test_graph_follows_one_direct_typed_local_helper(tmp_path):
    service_source = tmp_path / "AgentService.java"
    helper_source = tmp_path / "ActionHelper.java"
    service_source.write_text(
        "package example;\n"
        "class AgentService extends AccessibilityService {\n"
        "  ActionHelper helper;\n"
        "  void onAccessibilityEvent(Object event) { helper.handle(event); }\n"
        "}\n",
        encoding="utf-8",
    )
    helper_source.write_text(
        "package example;\n"
        "class ActionHelper {\n"
        "  void handle(Object event) { service.dispatchGesture(gesture, null, null); }\n"
        "}\n",
        encoding="utf-8",
    )
    manifest = ManifestAnalysis(
        manifest_path=Path("AndroidManifest.xml"),
        services=[ComponentInfo(
            name="example.AgentService", component_type="service",
            permission="android.permission.BIND_ACCESSIBILITY_SERVICE",
            intent_filters=[IntentFilterInfo(actions=["android.accessibilityservice.AccessibilityService"])],
        )],
    )
    extraction = ExtractionResult(
        source_root=tmp_path,
        methods=[
            ExtractedMethod(name="onAccessibilityEvent", class_name="AgentService", file=str(service_source), line=4),
            ExtractedMethod(name="handle", class_name="ActionHelper", file=str(helper_source), line=3),
        ],
        apis=[
            ExtractedAPI(
                api_name="handle", full_reference="helper.handle",
                location=EvidenceLocation(file=str(service_source), line=4, class_name="AgentService", method_name="onAccessibilityEvent"),
            ),
            ExtractedAPI(
                api_name="dispatchGesture", full_reference="service.dispatchGesture",
                location=EvidenceLocation(file=str(helper_source), line=3, class_name="ActionHelper", method_name="handle"),
            ),
        ],
    )

    graph = AccessibilityBehaviorGraphBuilder().build(
        ProfileLoader().load(PROFILE), extraction, manifest
    )

    assert [edge.relation for edge in graph.edges] == [
        "implements_callback", "delegates_to_local_helper", "calls_accessibility_action"
    ]
