"""
Git Security Sentinel - AI Token Estimation and Query Cost Calculation.
Zero external dependencies.
"""

from typing import Any, Dict

PRICING_TABLE: Dict[str, Dict[str, float]] = {
    "ollama": {"input": 0.0, "output": 0.0},
    "gemini": {"input": 0.075 / 1_000_000, "output": 0.30 / 1_000_000},
    "openai": {"input": 0.15 / 1_000_000, "output": 0.60 / 1_000_000},
    "groq": {"input": 0.59 / 1_000_000, "output": 0.79 / 1_000_000},
}


def calculate_token_estimate(prompt_text: str) -> int:
    """
    Estimates token count for English code and prompts (~4 characters per token).
    """
    if not prompt_text:
        return 0
    return max(1, len(prompt_text) // 4)


def estimate_query_cost(
    prompt_tokens: int,
    completion_tokens: int = 500,
    provider: str = "ollama",
) -> float:
    """
    Calculates estimated USD monetary cost for an AI inference query across providers.
    """
    rates = PRICING_TABLE.get(provider.lower(), PRICING_TABLE["ollama"])
    return (prompt_tokens * rates["input"]) + (completion_tokens * rates["output"])
