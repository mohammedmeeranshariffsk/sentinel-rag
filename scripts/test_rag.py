import json
from pathlib import Path

from dotenv import load_dotenv

from sentinel.rag.chunker import KnowledgeChunker
from sentinel.rag.embeddings import GeminiEmbeddingProvider
from sentinel.rag.indexer import KnowledgeIndexer
from sentinel.rag.models import KnowledgeDocument
from sentinel.rag.retriever import ThreatKnowledgeRetriever
from sentinel.rag.vector_store import QdrantVectorStore


load_dotenv()


def main():
    data = json.loads(
        Path(
            "data/knowledge/android_security.json"
        ).read_text(encoding="utf-8")
    )

    documents = [
        KnowledgeDocument.model_validate(item)
        for item in data
    ]

    embeddings = GeminiEmbeddingProvider(
        dimension=768
    )

    vector_store = QdrantVectorStore(
        collection_name="sentinel_security_test",
        dimension=768,
        location=":memory:",
    )

    indexer = KnowledgeIndexer(
        embedding_provider=embeddings,
        vector_store=vector_store,
        chunker=KnowledgeChunker(
            chunk_size=1200,
            overlap=200,
        ),
    )

    indexed = indexer.index(documents)

    print(f"\nIndexed chunks: {indexed}")

    retriever = ThreatKnowledgeRetriever(
        embedding_provider=embeddings,
        vector_store=vector_store,
    )

    query = """
    Android application executes /system/bin/su
    using Runtime.getRuntime().exec.
    Investigate process execution and possible root-related behavior.
    """

    results = retriever.retrieve(
        query=query,
        limit=3,
    )

    print("\nQuery:")
    print(query.strip())

    print("\nRetrieved Knowledge")
    print("=" * 60)

    for index, result in enumerate(results, start=1):
        print(
            f"\n[{index}] {result.title}"
        )
        print(f"Score: {result.score:.4f}")
        print(f"Source: {result.source}")
        print(f"Chunk: {result.chunk_id}")
        print()
        print(result.content)


if __name__ == "__main__":
    main()