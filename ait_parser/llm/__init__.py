"""LLM pipelines for AIT-ADS alert triage (LLM-only and LLM+RAG)."""

from .alert_repr import compact_alert_text, retrieval_query_text
from .ollama_client import (
    LlmResponse, generate, check_ollama,
    DEFAULT_MODEL, DEFAULT_OLLAMA_URL,
)
from .prompts import (
    ATTACK_PHASES,
    build_llm_only_prompt, build_rag_prompt, normalise_llm_output,
)

__all__ = [
    "compact_alert_text", "retrieval_query_text",
    "LlmResponse", "generate", "check_ollama",
    "DEFAULT_MODEL", "DEFAULT_OLLAMA_URL",
    "ATTACK_PHASES",
    "build_llm_only_prompt", "build_rag_prompt", "normalise_llm_output",
]
