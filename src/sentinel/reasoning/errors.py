from google.genai.errors import APIError
from pydantic import ValidationError
import httpx


def safe_reasoning_error(error: Exception) -> str:
    """Never echo arbitrary exception text: it can contain inputs or credentials."""
    message = "Unexpected reasoning failure; exception details withheld to protect input data"
    if isinstance(error, ValidationError):
        message = f"Structured output failed validation ({error.error_count()} errors; input values withheld)"
    elif isinstance(error, APIError):
        code = error.code
        descriptions = {
            400: "Gemini rejected the request as invalid",
            401: "Gemini authentication failed",
            403: "Gemini access denied",
            404: "Gemini model or endpoint unavailable",
            429: "Gemini quota or rate limit exceeded",
            500: "Gemini internal server error",
            503: "Gemini service unavailable",
        }
        message = descriptions.get(code, "Gemini API request failed")
        if isinstance(code, int):
            message += f" (HTTP {code})"
        # Fixed diagnostic labels only; never echo a server's arbitrary text.
        detail = str(getattr(error, "message", ""))
        for token, label in (
            ("response_json_schema", "response JSON schema rejected"),
            ("responseJsonSchema", "response JSON schema rejected"),
            ("thinking_budget", "thinking budget rejected"),
            ("API key not valid", "API key is invalid"),
        ):
            if token in detail:
                message += f"; {label}"
    elif isinstance(error, (httpx.TimeoutException, TimeoutError)):
        message = "Gemini request timed out"
    elif isinstance(error, httpx.TransportError):
        message = "Gemini connection failed"
    elif isinstance(error, ValueError) and str(error) in {
        "GEMINI_API_KEY is not configured", "Gemini returned no candidate",
        "Gemini did not complete structured output", "Gemini returned no structured output",
    }:
        message = str(error)
    return f"{type(error).__name__}: {message}"
