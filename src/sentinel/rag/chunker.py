from sentinel.rag.models import (
    KnowledgeChunk,
    KnowledgeDocument,
)


class KnowledgeChunker:
    """
    Splits threat/security documents into bounded text chunks.
    """

    def __init__(
        self,
        chunk_size: int = 1200,
        overlap: int = 200,
    ) -> None:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be greater than zero")

        if overlap < 0:
            raise ValueError("overlap cannot be negative")

        if overlap >= chunk_size:
            raise ValueError(
                "overlap must be smaller than chunk_size"
            )

        self.chunk_size = chunk_size
        self.overlap = overlap

    def chunk(
        self,
        document: KnowledgeDocument,
    ) -> list[KnowledgeChunk]:

        text = document.content.strip()

        if not text:
            return []

        chunks: list[KnowledgeChunk] = []

        start = 0
        index = 0

        while start < len(text):
            end = min(
                start + self.chunk_size,
                len(text),
            )

            content = text[start:end].strip()

            if content:
                chunks.append(
                    KnowledgeChunk(
                        chunk_id=(
                            f"{document.document_id}:"
                            f"{index}"
                        ),
                        document_id=document.document_id,
                        title=document.title,
                        content=content,
                        source=document.source,
                        metadata=document.metadata.copy(),
                    )
                )

            if end >= len(text):
                break

            start = end - self.overlap
            index += 1

        return chunks