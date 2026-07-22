import re
from typing import Any
from app.config import settings


class SecurityGuardrails:
    """Enforces AI output validation and masks internal sensitive tokens."""

    @classmethod
    def mask_sensitive_tokens(cls, text: str) -> str:
        """Mask API keys, internal paths, or secrets before logging or rendering."""
        if not text:
            return text

        masked = text
        # Mask API keys if present
        if settings.GEMINI_API_KEY:
            masked = masked.replace(settings.GEMINI_API_KEY, "[REDACTED_API_KEY]")
        if settings.OPENAI_API_KEY:
            masked = masked.replace(settings.OPENAI_API_KEY, "[REDACTED_API_KEY]")

        # Mask generic high-entropy API key patterns
        masked = re.sub(r"(AIzaSy[A-Za-z0-9_-]{33})", "[REDACTED_GEMINI_KEY]", masked)
        masked = re.sub(r"(sk-[a-zA-Z0-9]{32,})", "[REDACTED_OPENAI_KEY]", masked)

        return masked

    @classmethod
    def validate_risk_score(cls, score: float) -> float:
        """Ensure risk score remains strictly within valid [0.0, 10.0] boundaries."""
        try:
            val = float(score)
            return max(0.0, min(10.0, val))
        except (ValueError, TypeError):
            return 5.0


security_guard = SecurityGuardrails()
