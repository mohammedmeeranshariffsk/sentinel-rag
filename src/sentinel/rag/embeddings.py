import os

from google import genai
from google.genai import types


class GeminiEmbeddingProvider:
    def __init__(
        self,
        model: str | None = None,
        dimension: int = 768,
    ) -> None:
        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise ValueError(
                "GEMINI_API_KEY is not configured"
            )

        self.model = (
            model
            or os.getenv(
                "GEMINI_EMBEDDING_MODEL",
                "gemini-embedding-001",
            )
        )

        self.dimension = dimension
        self.client = genai.Client(api_key=api_key)

    def embed_documents(
        self,
        texts: list[str],
    ) -> list[list[float]]:
        if not texts:
            return []

        response = self.client.models.embed_content(
            model=self.model,
            contents=texts,
            config=types.EmbedContentConfig(
                task_type="RETRIEVAL_DOCUMENT",
                output_dimensionality=self.dimension,
            ),
        )

        return [
            embedding.values
            for embedding in response.embeddings
        ]

    def embed_query(
        self,
        text: str,
    ) -> list[float]:
        response = self.client.models.embed_content(
            model=self.model,
            contents=text,
            config=types.EmbedContentConfig(
                task_type="RETRIEVAL_QUERY",
                output_dimensionality=self.dimension,
            ),
        )

        return response.embeddings[0].values