import uuid

from qdrant_client import QdrantClient, models

from sentinel.rag.models import (
    KnowledgeChunk,
    RetrievedKnowledge,
)


class QdrantVectorStore:
    def __init__(
        self,
        collection_name: str = "sentinel_security",
        dimension: int = 768,
        location: str = ":memory:",
    ) -> None:
        self.collection_name = collection_name
        self.dimension = dimension

        self.client = QdrantClient(location=location)

        self._ensure_collection()

    def _ensure_collection(self) -> None:
        if self.client.collection_exists(
            self.collection_name
        ):
            return

        self.client.create_collection(
            collection_name=self.collection_name,
            vectors_config=models.VectorParams(
                size=self.dimension,
                distance=models.Distance.COSINE,
            ),
        )

    def upsert(
        self,
        chunks: list[KnowledgeChunk],
        vectors: list[list[float]],
    ) -> None:
        if len(chunks) != len(vectors):
            raise ValueError(
                "chunks and vectors must have equal length"
            )

        points = []

        for chunk, vector in zip(
            chunks,
            vectors,
            strict=True,
        ):
            point_id = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    chunk.chunk_id,
                )
            )

            points.append(
                models.PointStruct(
                    id=point_id,
                    vector=vector,
                    payload={
                        "chunk_id": chunk.chunk_id,
                        "document_id": chunk.document_id,
                        "title": chunk.title,
                        "content": chunk.content,
                        "source": chunk.source,
                        "metadata": chunk.metadata,
                    },
                )
            )

        if points:
            self.client.upsert(
                collection_name=self.collection_name,
                points=points,
                wait=True,
            )

    def search(
        self,
        vector: list[float],
        limit: int = 5,
    ) -> list[RetrievedKnowledge]:

        result = self.client.query_points(
            collection_name=self.collection_name,
            query=vector,
            limit=limit,
            with_payload=True,
        )

        findings = []

        for point in result.points:
            payload = point.payload or {}

            findings.append(
                RetrievedKnowledge(
                    chunk_id=payload["chunk_id"],
                    document_id=payload["document_id"],
                    title=payload["title"],
                    content=payload["content"],
                    source=payload.get("source"),
                    score=point.score,
                    metadata=payload.get(
                        "metadata",
                        {},
                    ),
                )
            )

        return findings