import os
from typing import Any

from google import genai
from google.genai import types


class GeminiReasoningProvider:
    """Google GenAI implementation of the LLMProvider protocol."""

    MODEL = "gemini-3.5-flash-lite"

    def __init__(self) -> None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY is not configured")
        self.client = genai.Client(
            api_key=api_key, http_options=types.HttpOptions(timeout=30000)
        )

    def generate_structured(
        self, prompt: str, *, response_schema: dict[str, Any]
    ) -> str:
        response = self.client.models.generate_content(
            model=self.MODEL,
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0,
                candidate_count=1,
                max_output_tokens=2048,
                response_mime_type="application/json",
                response_json_schema=response_schema,
                thinking_config=types.ThinkingConfig(
                    thinking_level=types.ThinkingLevel.MINIMAL,
                    include_thoughts=False,
                ),
            ),
        )
        if not response.candidates:
            raise ValueError("Gemini returned no candidate")
        candidate = response.candidates[0]
        if candidate.finish_reason != types.FinishReason.STOP:
            raise ValueError("Gemini did not complete structured output")
        parts = candidate.content.parts if candidate.content else []
        text = "".join(part.text for part in (parts or []) if part.text and not part.thought)
        if not text.strip():
            raise ValueError("Gemini returned no structured output")
        return text
