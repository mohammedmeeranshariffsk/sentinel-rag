from sentinel.rag.chunker import KnowledgeChunker
from sentinel.rag.models import KnowledgeDocument


def test_chunk_small_document():
    document = KnowledgeDocument(
        document_id="doc-001",
        title="Android Command Execution",
        content=(
            "Android applications may execute commands using "
            "Runtime.exec. Security analysis must determine "
            "whether execution is legitimate or suspicious."
        ),
        source="synthetic-test",
    )

    chunker = KnowledgeChunker(
        chunk_size=500,
        overlap=50,
    )

    chunks = chunker.chunk(document)

    assert len(chunks) == 1
    assert chunks[0].document_id == "doc-001"
    assert "Runtime.exec" in chunks[0].content


def test_chunk_large_document():
    document = KnowledgeDocument(
        document_id="doc-002",
        title="Large Threat Report",
        content="A" * 1000,
    )

    chunker = KnowledgeChunker(
        chunk_size=300,
        overlap=50,
    )

    chunks = chunker.chunk(document)

    assert len(chunks) > 1

    assert all(
        len(chunk.content) <= 300
        for chunk in chunks
    )


def test_empty_document():
    document = KnowledgeDocument(
        document_id="doc-003",
        title="Empty",
        content="",
    )

    chunker = KnowledgeChunker()

    assert chunker.chunk(document) == []