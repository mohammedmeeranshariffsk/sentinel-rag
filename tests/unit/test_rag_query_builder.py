from sentinel.program_analysis.behavior_slice import BehaviorSlice
from sentinel.rag.query_builder import RetrievalQueryBuilder
from sentinel.threat_intel.models import ThreatMatch


def test_build_retrieval_query():
    threat_match = ThreatMatch(
        knowledge_id="THREAT-PROCESS-001",
        knowledge_name="Process and Command Execution",
        score=3.5,
        matched_apis=["exec"],
        matched_strings=["/system/bin/su"],
    )

    behavior_slice = BehaviorSlice(
        seed="exec",
        file="RootCheck.java",
        line=10,
        code_context=[
            'String command = "/system/bin/su";',
            "Runtime.getRuntime().exec(command);",
        ],
        related_strings=[
            "/system/bin/su",
        ],
    )

    query = RetrievalQueryBuilder().build(
        threat_match=threat_match,
        behavior_slice=behavior_slice,
    )

    assert "Process and Command Execution" in query
    assert "exec" in query
    assert "/system/bin/su" in query
    assert "Runtime.getRuntime().exec" in query