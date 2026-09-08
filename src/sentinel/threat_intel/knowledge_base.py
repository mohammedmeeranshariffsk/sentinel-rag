import json
from pathlib import Path

from sentinel.threat_intel.models import ThreatKnowledge


class ThreatKnowledgeBase:
    def __init__(self) -> None:
        self.records: list[ThreatKnowledge] = []

    def load_json(
        self,
        file_path: Path | str,
    ) -> list[ThreatKnowledge]:

        path = Path(file_path)

        data = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

        self.records = [
            ThreatKnowledge.model_validate(item)
            for item in data
        ]

        return self.records

    def get_all(self) -> list[ThreatKnowledge]:
        return self.records

    def get_by_id(
        self,
        knowledge_id: str,
    ) -> ThreatKnowledge | None:

        for record in self.records:
            if record.knowledge_id == knowledge_id:
                return record

        return None