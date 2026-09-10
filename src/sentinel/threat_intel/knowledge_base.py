import json
from pathlib import Path

from sentinel.threat_intel.models import ThreatKnowledge


class ThreatKnowledgeBase:
    def __init__(self) -> None:
        self.records: list[ThreatKnowledge] = []
        self.errors: list[str] = []

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
        if not isinstance(data, list):
            raise ValueError('Threat catalog must contain a JSON array')

        self.records = []
        self.errors = []
        for index,item in enumerate(data):
            try:
                self.records.append(ThreatKnowledge.model_validate(item))
            except (ValueError, TypeError):
                self.errors.append(f'Invalid threat record at index {index}; skipped')

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
