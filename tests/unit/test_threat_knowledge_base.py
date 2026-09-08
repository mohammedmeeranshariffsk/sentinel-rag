import json

from sentinel.threat_intel.knowledge_base import ThreatKnowledgeBase


def test_load_threat_knowledge(tmp_path):
    file_path = tmp_path / "knowledge.json"

    file_path.write_text(
        json.dumps(
            [
                {
                    "knowledge_id": "THREAT-001",
                    "name": "Accessibility Abuse",
                    "description": "Accessibility capability test",
                    "apis": [
                        "getRootInActiveWindow",
                        "performAction",
                    ],
                    "permissions": [
                        "android.permission.BIND_ACCESSIBILITY_SERVICE"
                    ],
                }
            ]
        ),
        encoding="utf-8",
    )

    kb = ThreatKnowledgeBase()

    records = kb.load_json(file_path)

    assert len(records) == 1
    assert records[0].knowledge_id == "THREAT-001"
    assert records[0].name == "Accessibility Abuse"