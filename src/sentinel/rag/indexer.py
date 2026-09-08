from sentinel.rag.chunker import KnowledgeChunker
from sentinel.rag.embeddings import GeminiEmbeddingProvider
from sentinel.rag.models import KnowledgeDocument
from sentinel.rag.vector_store import QdrantVectorStore


class KnowledgeIndexer:
    def __init__(
        self,
        embedding_provider: GeminiEmbeddingProvider,
        vector_store: QdrantVectorStore,
        chunker: KnowledgeChunker | None = None,
    ) -> None:
        self.embedding_provider = embedding_provider
        self.vector_store = vector_store
        self.chunker = chunker or KnowledgeChunker()

    def index(
        self,
        documents: list[KnowledgeDocument],
    ) -> int:
        chunks = []

        for document in documents:
            chunks.extend(
                self.chunker.chunk(document)
            )

        if not chunks:
            return 0

        vectors = (
            self.embedding_provider.embed_documents(
                [chunk.content for chunk in chunks]
            )
        )

        self.vector_store.upsert(
            chunks=chunks,
            vectors=vectors,
        )

        return len(chunks)