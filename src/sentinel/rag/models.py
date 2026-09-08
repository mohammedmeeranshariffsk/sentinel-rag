from pydantic import BaseModel, Field


class KnowledgeDocument(BaseModel):
    document_id: str
    title: str
    content: str
    source: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class KnowledgeChunk(BaseModel):
    chunk_id: str
    document_id: str
    title: str
    content: str
    source: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class RetrievedKnowledge(BaseModel):
    chunk_id: str
    document_id: str
    title: str
    content: str
    source: str | None = None
    score: float
    metadata: dict[str, str] = Field(default_factory=dict)