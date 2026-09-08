from sentinel.rag.embeddings import GeminiEmbeddingProvider
from sentinel.rag.models import RetrievedKnowledge
from sentinel.rag.vector_store import QdrantVectorStore


class ThreatKnowledgeRetriever:
    def __init__(
        self,
        embedding_provider: GeminiEmbeddingProvider,
        vector_store: QdrantVectorStore,
    ) -> None:
        self.embedding_provider = embedding_provider
        self.vector_store = vector_store

    def retrieve(
        self,
        query: str,
        limit: int = 5,
    ) -> list[RetrievedKnowledge]:

        vector = self.embedding_provider.embed_query(
            query
        )

        return self.vector_store.search(
            vector=vector,
            limit=limit,
        )