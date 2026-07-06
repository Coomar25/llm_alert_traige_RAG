"""
Ollama client.

Ollama runs Mistral-7B (and other open models) locally and exposes an HTTP
API at http://localhost:11434. This module is a thin, resilient wrapper
around that API tailored to our needs:

    - Deterministic generation (temperature 0) for reproducible triage
    - Strict JSON output parsing with fallback extraction
    - Retries on transient failures
    - Latency measurement per request (needed for the dissertation's
      latency comparison between rule-based, LLM-only, and LLM+RAG)

Why Ollama rather than transformers/llama.cpp directly?
    - One-line model install: `ollama pull mistral`
    - Handles GGUF quantisation automatically (runs 7B on modest hardware)
    - Stable HTTP API, no Python/CUDA dependency hell
    - Same interface whether running on CPU or GPU
"""

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional


DEFAULT_OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "mistral"  # resolves to mistral:7b by default in Ollama


@dataclass
class LlmResponse:
    """Result of one generation call."""
    raw_text: str
    latency_ms: float
    parsed_json: Optional[dict]
    parse_ok: bool
    error: Optional[str] = None


def _extract_json(text: str) -> Optional[dict]:
    """Best-effort extraction of a JSON object from model output.

    LLMs sometimes wrap JSON in markdown fences or add prose before/after.
    We try, in order:
        1. Direct json.loads
        2. Strip markdown ```json fences
        3. Regex-extract the first {...} block
    """
    text = text.strip()

    # Attempt 1: direct parse
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass

    # Attempt 2: strip markdown fences
    fenced = re.sub(r"^```(?:json)?\s*|\s*```$", "", text,
                    flags=re.MULTILINE).strip()
    try:
        return json.loads(fenced)
    except (json.JSONDecodeError, ValueError):
        pass

    # Attempt 3: regex-grab the first balanced-looking object
    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except (json.JSONDecodeError, ValueError):
            pass

    return None


def generate(
    prompt: str,
    model: str = DEFAULT_MODEL,
    url: str = DEFAULT_OLLAMA_URL,
    temperature: float = 0.0,
    timeout: int = 120,
    max_retries: int = 2,
    expect_json: bool = True,
) -> LlmResponse:
    """Call Ollama's /api/generate endpoint once (with retries).

    temperature=0.0 gives greedy decoding — deterministic, reproducible
    triage decisions. This matters for the dissertation: the same alert
    must produce the same decision on re-runs.
    """
    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            # Cap output length — triage JSON is small
            "num_predict": 512,
        },
    }
    # Ask Ollama to constrain output to JSON when supported
    if expect_json:
        payload["format"] = "json"

    data = json.dumps(payload).encode("utf-8")

    last_err = None
    for attempt in range(max_retries + 1):
        t0 = time.perf_counter()
        try:
            req = urllib.request.Request(
                url, data=data,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = json.loads(resp.read())
            latency_ms = (time.perf_counter() - t0) * 1000.0

            raw_text = body.get("response", "")
            parsed = _extract_json(raw_text) if expect_json else None
            return LlmResponse(
                raw_text=raw_text,
                latency_ms=latency_ms,
                parsed_json=parsed,
                parse_ok=parsed is not None,
            )
        except (urllib.error.URLError, urllib.error.HTTPError,
                TimeoutError, ConnectionError) as e:
            last_err = str(e)
            if attempt < max_retries:
                time.sleep(1.0 * (attempt + 1))  # linear backoff
                continue

    return LlmResponse(
        raw_text="",
        latency_ms=0.0,
        parsed_json=None,
        parse_ok=False,
        error=f"All {max_retries + 1} attempts failed. Last error: {last_err}",
    )


def check_ollama(model: str = DEFAULT_MODEL,
                 url: str = DEFAULT_OLLAMA_URL) -> tuple[bool, str]:
    """Quick health check: is Ollama up and is the model responsive?

    Returns (ok, message). Call this before a big batch run to fail fast
    if Ollama isn't running or the model isn't pulled.
    """
    resp = generate(
        prompt='Reply with this exact JSON: {"status": "ok"}',
        model=model, url=url, timeout=30, max_retries=1, expect_json=True,
    )
    if resp.error:
        return False, resp.error
    if resp.parse_ok:
        return True, f"Ollama responsive; model '{model}' returned valid JSON " \
                     f"in {resp.latency_ms:.0f}ms"
    return True, f"Ollama responsive but model output wasn't clean JSON " \
                 f"(raw: {resp.raw_text[:80]!r})"
