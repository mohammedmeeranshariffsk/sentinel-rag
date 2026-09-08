import json
from pathlib import Path

from sentinel.rag.models import KnowledgeDocument


class KnowledgeDocumentLoader:
    def load_json(
        self,
        path: Path | str,
    ) -> list[KnowledgeDocument]:

        file_path = Path(path)

        data = json.loads(
            file_path.read_text(
                encoding="utf-8"
            )
        )

        return [
            KnowledgeDocument.model_validate(item)
            for item in data
        ]