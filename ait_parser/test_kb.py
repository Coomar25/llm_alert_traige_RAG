"""
Smoke tests for the knowledge base pipeline using synthetic STIX fixtures.

We test parsing, filtering (revoked/deprecated), sub-technique detection,
AIT-relevance tagging, and chunk generation — without hitting the network or
loading sentence-transformers (which is heavy and tested implicitly by the
build pipeline).

ChromaDB and embedder tests are deliberately omitted here because:
    - sentence-transformers loads ~80MB of model weights on first import
    - ChromaDB's persistent collection is best tested via the full pipeline
    - Both are well-tested upstream — we just need the integration to work
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from kb.mitre_loader import (
    AIT_PHASE_TO_MITRE, _build_phase_lookup, parse_techniques, summarise,
)
from kb.chunker import (
    KnowledgeDocument, chunk_mitre_technique, chunk_all_techniques,
)


# ---------------------------------------------------------------------------
# Synthetic STIX fixture — mirrors the real MITRE structure
#  # six different objects covering every edge case---------------------------------------------------------------------------
FAKE_BUNDLE = {
    "type": "bundle",
    "objects": [
        # T1110 Brute Force — live, AIT-relevant (cracking)
        {
            "type": "attack-pattern",
            "id": "attack-pattern--uuid-1",
            "name": "Brute Force",
            "description": "Adversaries may use brute force techniques to gain access.",
            "x_mitre_detection": "Monitor authentication logs for system and application "
                                 "login failures of valid accounts.",
            "x_mitre_platforms": ["Linux", "Windows"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1110",
                 "url": "https://attack.mitre.org/techniques/T1110"},
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"},
            ],
        },
        # T1110.001 Password Guessing — sub-technique, AIT-relevant
        {
            "type": "attack-pattern",
            "id": "attack-pattern--uuid-2",
            "name": "Password Guessing",
            "description": "Adversaries may try to brute force credentials.",
            "x_mitre_platforms": ["Linux"],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1110.001",
                 "url": "https://attack.mitre.org/techniques/T1110/001"},
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "credential-access"},
            ],
        },
        # T9999 — revoked, should be filtered out
        {
            "type": "attack-pattern",
            "id": "attack-pattern--uuid-3",
            "name": "Deprecated Technique",
            "description": "This was removed.",
            "revoked": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9999"},
            ],
        },
        # T9998 — deprecated, should be filtered out
        {
            "type": "attack-pattern",
            "id": "attack-pattern--uuid-4",
            "name": "Another Old Technique",
            "description": "Also removed.",
            "x_mitre_deprecated": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T9998"},
            ],
        },
        # T1234 — live but NOT in AIT_PHASE_TO_MITRE, so no relevance_tags
        {
            "type": "attack-pattern",
            "id": "attack-pattern--uuid-5",
            "name": "Unrelated Technique",
            "description": "Not relevant to AIT-ADS.",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1234"},
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
            ],
        },
        # Non-technique object — should be ignored
        {
            "type": "x-mitre-tactic",
            "id": "x-mitre-tactic--uuid",
            "name": "Credential Access",
            "x_mitre_shortname": "credential-access",
        },
    ],
}


def run_tests():
    # ------------------------------------------------------------------
    # AIT_PHASE_TO_MITRE & inverse lookup
    # ------------------------------------------------------------------
    assert "cracking" in AIT_PHASE_TO_MITRE
    assert "T1110" in AIT_PHASE_TO_MITRE["cracking"]
    inv = _build_phase_lookup()
    assert "cracking" in inv["T1110"]
    assert "cracking" in inv["T1110.001"]
    assert "network_scans" in inv["T1046"]
    assert len(AIT_PHASE_TO_MITRE) == 10, "Expected 10 AIT-ADS attack phases"
    print(f"  AIT mapping OK: 10 phases, {len(inv)} unique MITRE IDs mapped")

    # ------------------------------------------------------------------
    # parse_techniques
    # ------------------------------------------------------------------
    techniques = parse_techniques(FAKE_BUNDLE)
    # Expect 3: T1110, T1110.001, T1234. Revoked and deprecated are filtered.
    assert len(techniques) == 3, f"Expected 3 live techniques, got {len(techniques)}"
    ids = {t.mitre_id for t in techniques}
    assert ids == {"T1110", "T1110.001", "T1234"}, f"Wrong IDs: {ids}"
    print(f"  parse_techniques OK: 3 live techniques after filtering "
          f"revoked/deprecated (T9999, T9998)")

    # Verify each parsed technique's fields
    t1110 = next(t for t in techniques if t.mitre_id == "T1110")
    assert t1110.name == "Brute Force"
    assert "credential-access" in t1110.tactics
    assert "Linux" in t1110.platforms
    assert "Windows" in t1110.platforms
    assert t1110.is_subtechnique is False
    assert t1110.parent_id is None
    assert t1110.detection.startswith("Monitor authentication")
    assert "cracking" in t1110.relevance_tags  # AIT-relevant
    print(f"  T1110 OK: name='{t1110.name}', tactics={t1110.tactics}, "
          f"relevance={t1110.relevance_tags}")

    # Sub-technique detection
    t1110_001 = next(t for t in techniques if t.mitre_id == "T1110.001")
    assert t1110_001.is_subtechnique is True
    assert t1110_001.parent_id == "T1110"
    print(f"  T1110.001 OK: detected as sub-technique of T1110")

    # Unrelated technique has empty relevance_tags
    t1234 = next(t for t in techniques if t.mitre_id == "T1234")
    assert t1234.relevance_tags == [], \
        f"Unrelated technique should have no relevance tags, got {t1234.relevance_tags}"
    print(f"  T1234 OK: no relevance tags (correctly identified as AIT-unrelated)")

    # ------------------------------------------------------------------
    # summarise
    # ------------------------------------------------------------------
    summary = summarise(techniques)
    assert summary["total_techniques"] == 3
    assert summary["parent_techniques"] == 2
    assert summary["sub_techniques"] == 1
    assert summary["ait_relevant"] == 2  # T1110 and T1110.001
    assert "credential-access" in summary["by_tactic"]
    print(f"  summarise OK: {summary['parent_techniques']} parent, "
          f"{summary['sub_techniques']} sub, "
          f"{summary['ait_relevant']} AIT-relevant")

    # ------------------------------------------------------------------
    # chunk_mitre_technique
    # ------------------------------------------------------------------
    # T1110 has both description and detection → 2 chunks
    chunks_1110 = chunk_mitre_technique(t1110)
    assert len(chunks_1110) == 2, \
        f"T1110 should produce 2 chunks (desc+det), got {len(chunks_1110)}"
    sections = {c.metadata["section"] for c in chunks_1110}
    assert sections == {"description", "detection"}
    desc_chunk = next(c for c in chunks_1110 if c.metadata["section"] == "description")
    assert desc_chunk.doc_id == "mitre:T1110:description"
    assert desc_chunk.source == "mitre"
    assert "Brute Force" in desc_chunk.text
    assert "credential-access" in desc_chunk.metadata["tactics"]
    assert "cracking" in desc_chunk.metadata["relevance_tags"]
    print(f"  T1110 chunks OK: 2 chunks (description + detection), "
          f"metadata preserved")

    # T1234 has description only (no detection) → 1 chunk
    chunks_1234 = chunk_mitre_technique(t1234)
    assert len(chunks_1234) == 1, \
        f"T1234 should produce 1 chunk (desc only), got {len(chunks_1234)}"
    assert chunks_1234[0].metadata["section"] == "description"
    # No relevance tags should be in metadata (empty string)
    assert chunks_1234[0].metadata["relevance_tags"] == ""
    print(f"  T1234 chunks OK: 1 chunk (no detection guidance available)")

    # ------------------------------------------------------------------
    # chunk_all_techniques aggregate
    # ------------------------------------------------------------------
    all_chunks = chunk_all_techniques(techniques)
    # T1110 (2) + T1110.001 (1, no detection) + T1234 (1) = 4
    assert len(all_chunks) == 4, f"Expected 4 total chunks, got {len(all_chunks)}"
    all_ids = {c.doc_id for c in all_chunks}
    assert all_ids == {
        "mitre:T1110:description",
        "mitre:T1110:detection",
        "mitre:T1110.001:description",
        "mitre:T1234:description",
    }
    print(f"  chunk_all_techniques OK: 4 chunks total with unique doc_ids")

    # ------------------------------------------------------------------
    # KnowledgeDocument structure sanity
    # ------------------------------------------------------------------
    sample = all_chunks[0]
    assert isinstance(sample, KnowledgeDocument)
    assert sample.doc_id
    assert sample.source == "mitre"
    assert sample.text
    assert isinstance(sample.metadata, dict)
    # Metadata values must be ChromaDB-compatible scalars
    for k, v in sample.metadata.items():
        assert isinstance(v, (str, int, float, bool)), \
            f"Metadata field {k!r} has non-scalar value {v!r} of type {type(v)}"
    print(f"  KnowledgeDocument structure OK: ChromaDB-compatible metadata scalars")

    print("\nAll tests passed.")


if __name__ == "__main__":
    run_tests()
