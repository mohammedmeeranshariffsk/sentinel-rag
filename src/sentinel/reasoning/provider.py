from typing import Any, Protocol


class LLMProvider(Protocol):
    """A provider returns a JSON object encoded as text, without Markdown."""

    def generate_structured(
        self, prompt: str, *, response_schema: dict[str, Any]
    ) -> str:
        ...
