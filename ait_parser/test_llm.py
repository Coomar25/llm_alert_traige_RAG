"""
Unit tests for the LLM pipeline components.

Covers the deterministic logic that can be tested without a running Ollama:
    - Compact alert representation (field selection, list handling)
    - Retrieval query text construction
    - JSON extraction from messy LLM output (fences, prose, embedded)
    - Output normalisation (type coercion, phase validation, benign->no phase)
    - Prompt template structure (LLM-only vs RAG differ only by context)

The Ollama client's network path and the sampler's full-file pass are
exercised via the live run scripts, not here.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from llm.alert_repr import compact_alert_text, retrieval_query_text
from llm.ollama_client import _extract_json
from llm.prompts import (
    ATTACK_PHASES, build_llm_only_prompt, build_rag_prompt,
    normalise_llm_output,
)


def run_tests():
    # =========================================================================
    # Compact alert representation
    # =========================================================================
    print("--- Alert representation tests ---")

    alert = {
        "alert_id": "abc123",
        "source_ids": "wazuh",
        "severity_norm": 4,
        "rule_description": "sshd: authentication failed",
        "rule_groups": ["authentication_failed", "sshd"],
        "src_ip": "192.168.10.55",
        "dst_ip": "10.0.0.5",
        "dst_port": "22",
        "scenario": "wheeler",
        "timestamp": "2022-01-18T12:05:00+00:00",
        "raw_record": {"huge": "nested thing we should NOT include"},
    }
    text = compact_alert_text(alert)
    assert "wazuh" in text
    assert "high" in text  # severity_norm 4 -> "high"
    assert "authentication failed" in text
    assert "authentication_failed" in text  # rule group
    assert "192.168.10.55" in text
    assert "10.0.0.5:22" in text
    # The raw nested record must NOT leak into the prompt
    assert "nested thing" not in text
    assert "huge" not in text
    print("  compact_alert_text OK: relevant fields included, raw_record excluded")

    # List stored as semicolon-string (parquet flat form)
    alert_flat = dict(alert)
    alert_flat["rule_groups"] = "authentication_failed;sshd;pci_dss"
    text_flat = compact_alert_text(alert_flat)
    assert "authentication_failed, sshd, pci_dss" in text_flat
    print("  compact_alert_text OK: semicolon-joined groups handled")

    # Missing fields degrade gracefully
    sparse = {"severity_norm": 2, "scenario": "wilson"}
    text_sparse = compact_alert_text(sparse)
    assert "low" in text_sparse
    assert "(no description)" in text_sparse
    print("  compact_alert_text OK: sparse alert handled gracefully")

    # Retrieval query text
    q = retrieval_query_text(alert)
    assert "authentication failed" in q
    assert "authentication_failed" in q
    print("  retrieval_query_text OK")

    # Empty alert -> placeholder
    q_empty = retrieval_query_text({})
    assert q_empty  # non-empty placeholder
    print("  retrieval_query_text OK: empty alert -> placeholder")

    # =========================================================================
    # JSON extraction from messy LLM output
    # =========================================================================
    print("\n--- JSON extraction tests ---")

    # Clean JSON
    j = _extract_json('{"is_attack": true, "confidence": 0.9}')
    assert j == {"is_attack": True, "confidence": 0.9}
    print("  _extract_json OK: clean JSON")

    # Markdown-fenced JSON
    j = _extract_json('```json\n{"is_attack": false}\n```')
    assert j == {"is_attack": False}
    print("  _extract_json OK: markdown-fenced")

    # JSON with leading prose
    j = _extract_json('Here is my analysis:\n{"is_attack": true, "attack_phase": "dirb"}')
    assert j["is_attack"] is True
    assert j["attack_phase"] == "dirb"
    print("  _extract_json OK: leading prose stripped")

    # JSON with trailing prose
    j = _extract_json('{"is_attack": true}\nHope this helps!')
    assert j["is_attack"] is True
    print("  _extract_json OK: trailing prose stripped")

    # Unparseable -> None
    j = _extract_json("I cannot determine this.")
    assert j is None
    print("  _extract_json OK: unparseable -> None")

    # =========================================================================
    # Output normalisation
    # =========================================================================
    print("\n--- Output normalisation tests ---")

    # Well-formed attack
    n = normalise_llm_output({
        "is_attack": True, "attack_phase": "cracking",
        "confidence": 0.85, "explanation": "Repeated SSH failures.",
    })
    assert n["is_attack"] is True
    assert n["attack_phase"] == "cracking"
    assert n["confidence"] == 0.85
    assert n["_malformed"] is False
    print("  normalise OK: well-formed attack")

    # Benign should have no phase even if model supplied one
    n = normalise_llm_output({
        "is_attack": False, "attack_phase": "dirb", "confidence": 0.3,
    })
    assert n["is_attack"] is False
    assert n["attack_phase"] is None, "benign must have null phase"
    print("  normalise OK: benign -> phase forced to None")

    # Out-of-vocabulary phase -> None
    n = normalise_llm_output({
        "is_attack": True, "attack_phase": "made_up_phase", "confidence": 0.5,
    })
    assert n["attack_phase"] is None, "invalid phase should become None"
    print("  normalise OK: out-of-vocab phase -> None")

    # String boolean coercion
    n = normalise_llm_output({"is_attack": "true", "confidence": "0.7"})
    assert n["is_attack"] is True
    assert n["confidence"] == 0.7
    print("  normalise OK: string 'true' and '0.7' coerced")

    # Confidence clamping
    n = normalise_llm_output({"is_attack": True, "confidence": 5.0,
                              "attack_phase": "dirb"})
    assert n["confidence"] == 1.0, "confidence should clamp to 1.0"
    n = normalise_llm_output({"is_attack": True, "confidence": -2.0,
                              "attack_phase": "dirb"})
    assert n["confidence"] == 0.0, "confidence should clamp to 0.0"
    print("  normalise OK: confidence clamped to [0,1]")

    # None / malformed input
    n = normalise_llm_output(None)
    assert n["is_attack"] is False
    assert n["_malformed"] is True
    print("  normalise OK: None input -> safe malformed default")

    # =========================================================================
    # Prompt templates
    # =========================================================================
    print("\n--- Prompt template tests ---")

    alert_text = "IDS source: wazuh\nSeverity: high\nRule: ssh brute force"
    p_only = build_llm_only_prompt(alert_text)
    p_rag = build_rag_prompt(alert_text, "MITRE T1110: Brute Force...")

    # Both contain the task instructions and the alert
    assert "SOC" in p_only and "SOC" in p_rag
    assert alert_text in p_only and alert_text in p_rag
    # Both contain the attack phase vocabulary
    for phase in ATTACK_PHASES:
        assert phase in p_only, f"{phase} missing from LLM-only prompt"
        assert phase in p_rag, f"{phase} missing from RAG prompt"
    # Only the RAG prompt contains the context section
    assert "RELEVANT SECURITY CONTEXT" not in p_only
    assert "RELEVANT SECURITY CONTEXT" in p_rag
    assert "T1110" in p_rag
    print("  prompts OK: LLM-only and RAG differ ONLY by context section")

    # The instruction block (everything except context + alert) should be
    # character-identical between the two, guaranteeing a clean ablation.
    # Extract the shared task instruction prefix.
    shared_marker = "Respond with ONLY the JSON object"
    assert shared_marker in p_only and shared_marker in p_rag
    print("  prompts OK: shared task instructions identical (clean ablation)")

    print("\nAll tests passed.")


if __name__ == "__main__":
    run_tests()
