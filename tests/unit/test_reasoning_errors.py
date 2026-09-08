import httpx
import pytest
from google.genai.errors import ClientError
from pydantic import ValidationError

from sentinel.reasoning.errors import safe_reasoning_error
from sentinel.reasoning.models import SecurityReasoningResult


@pytest.mark.parametrize("code, expected", [
    (400, "invalid"), (403, "access denied"), (404, "unavailable"), (429, "quota or rate limit"),
])
def test_api_errors_are_safe_and_actionable(code, expected):
    error = ClientError(code, {"error": {"message": "secret API key and full prompt", "status": "SECRET"}})
    text = safe_reasoning_error(error)
    assert f"HTTP {code}" in text
    assert expected in text
    assert "secret" not in text.lower()
    assert "ClientError:" in text


def test_unknown_exception_does_not_echo_prompt_or_config():
    text = safe_reasoning_error(RuntimeError("API_KEY=secret contents=private prompt config=private"))
    assert "secret" not in text and "private" not in text
    assert text.startswith("RuntimeError:")


def test_validation_error_omits_input():
    try:
        SecurityReasoningResult.model_validate({"confidence": "secret prompt"})
    except ValidationError as error:
        text = safe_reasoning_error(error)
    assert "secret prompt" not in text
    assert "Structured output failed validation" in text


def test_timeout_error_is_safe():
    assert safe_reasoning_error(httpx.ReadTimeout("private URL with key")) == "ReadTimeout: Gemini request timed out"
