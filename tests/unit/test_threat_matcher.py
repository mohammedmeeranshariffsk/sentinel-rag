from sentinel.extraction.models import (
    EvidenceLocation,
    ExtractedAPI,
    ExtractedPermission,
    ExtractionResult,
)
from sentinel.threat_intel.matcher import ThreatMatcher
from sentinel.threat_intel.models import ThreatKnowledge


def test_match_threat_knowledge():
    extraction = ExtractionResult(
        apis=[
            ExtractedAPI(
                api_name="getRootInActiveWindow",
                full_reference="service.getRootInActiveWindow",
                location=EvidenceLocation(
                    file="Example.java",
                    line=10,
                ),
            )
        ],
        permissions=[
            ExtractedPermission(
                permission=(
                    "android.permission."
                    "BIND_ACCESSIBILITY_SERVICE"
                )
            )
        ],
    )

    knowledge = [
        ThreatKnowledge(
            knowledge_id="THREAT-001",
            name="Accessibility Abuse",
            description="Accessibility capability test",
            apis=[
                "getRootInActiveWindow",
                "performAction",
            ],
            permissions=[
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
            ],
        )
    ]

    matches = ThreatMatcher().match(
        extraction=extraction,
        knowledge=knowledge,
    )

    assert len(matches) == 1

    match = matches[0]

    assert match.knowledge_id == "THREAT-001"
    assert "getRootInActiveWindow" in match.matched_apis
    assert (
        "android.permission.BIND_ACCESSIBILITY_SERVICE"
        in match.matched_permissions
    )
    assert match.score == 3.0