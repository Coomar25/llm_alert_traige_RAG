"""
Unit tests for the full knowledge base pipeline (Parts 1 + 2).

Covers:
    - MITRE STIX parsing, filtering, sub-technique detection, AIT-relevance
    - CVE JSON parsing, CPE filter, keyword filter, CVSS extraction
    - Runbook markdown parsing with YAML-style frontmatter
    - Chunking for all three sources into KnowledgeDocument objects

ChromaDB and embedder integration are tested in build_knowledge_base.py via
the sanity-query path; here we focus on the deterministic logic that can be
tested with synthetic data and no network or heavyweight model loads.
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from kb.mitre_loader import (
    AIT_PHASE_TO_MITRE, _build_phase_lookup, parse_techniques,
    summarise as summarise_mitre,
)
from kb.cve_loader import (
    RELEVANT_CPE_VENDORS_PRODUCTS, RELEVANT_DESCRIPTION_KEYWORDS,
    is_relevant, parse_cve_object, _extract_cvss, _extract_cwes,
    _vendor_product_from_cpe, summarise as summarise_cves,
)
from kb.runbooks import (
    parse_runbook_file, load_runbooks, _split_frontmatter,
    summarise as summarise_runbooks,
)
from kb.chunker import (
    KnowledgeDocument,
    chunk_mitre_technique, chunk_all_techniques,
    chunk_cve, chunk_all_cves,
    chunk_runbook, chunk_all_runbooks,
)


# =============================================================================
# MITRE — same fixtures as Part 1; sanity-check they still work
# =============================================================================

FAKE_MITRE_BUNDLE = {
    "type": "bundle",
    "objects": [
        {
            "type": "attack-pattern",
            "name": "Brute Force",
            "description": "Adversaries may use brute force techniques.",
            "x_mitre_detection": "Monitor authentication logs.",
            "x_mitre_platforms": ["Linux", "Windows"],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1110",
                                     "url": "https://attack.mitre.org/techniques/T1110"}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack",
                                   "phase_name": "credential-access"}],
        },
        {
            "type": "attack-pattern", "name": "Deprecated", "description": "x",
            "revoked": True,
            "external_references": [{"source_name": "mitre-attack", "external_id": "T9999"}],
        },
    ],
}


# =============================================================================
# CVE — realistic synthetic NVD 2.0 records
# =============================================================================

# An Apache HTTP server vuln — should pass via CPE allowlist
FAKE_CVE_APACHE = {
    "id": "CVE-2024-12345",
    "published": "2024-06-15T00:00:00.000",
    "lastModified": "2024-06-20T00:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": [
        {"lang": "en", "value": "Apache HTTP Server before 2.4.59 allows a "
                                 "remote attacker to bypass authentication."},
    ],
    "metrics": {
        "cvssMetricV31": [{
            "cvssData": {
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            },
        }],
    },
    "weaknesses": [
        {"description": [{"lang": "en", "value": "CWE-287"}]},
    ],
    "configurations": [
        {"nodes": [{"cpeMatch": [
            {"vulnerable": True,
             "criteria": "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"},
        ]}]},
    ],
    "references": [
        {"url": "https://httpd.apache.org/security/vulnerabilities_24.html"},
    ],
}

# A WordPress plugin vuln — should pass via keyword (sql injection)
FAKE_CVE_WP_PLUGIN = {
    "id": "CVE-2024-22222",
    "published": "2024-03-10T00:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": [
        {"lang": "en", "value": "SQL injection vulnerability in the contact form "
                                 "WordPress plugin before 5.2.1 allows attackers..."},
    ],
    "metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 8.8, "baseSeverity": "HIGH",
                                         "vectorString": "CVSS:3.1/..."}}],
    },
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89"}]}],
    "configurations": [],  # no CPE — should pass via keyword
    "references": [],
}

# An iOS bug — should be FILTERED OUT (no relevant CPE, no relevant keyword)
FAKE_CVE_IRRELEVANT = {
    "id": "CVE-2024-99999",
    "published": "2024-04-01T00:00:00.000",
    "vulnStatus": "Analyzed",
    "descriptions": [
        {"lang": "en", "value": "An issue was discovered in iOS Calendar app "
                                 "where a malformed invite caused a UI glitch."},
    ],
    "metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 5.5, "baseSeverity": "MEDIUM",
                                         "vectorString": "..."}}],
    },
    "weaknesses": [],
    "configurations": [
        {"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:o:apple:iphone_os:17.0:*:*:*:*:*:*:*"},
        ]}]},
    ],
    "references": [],
}

# A rejected CVE — should be filtered out
FAKE_CVE_REJECTED = {
    "id": "CVE-2024-55555",
    "vulnStatus": "Rejected",
    "descriptions": [
        {"lang": "en", "value": "** REJECTED ** Duplicate of CVE-2024-12345."},
    ],
    "metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}],
    },
}

# A low-severity vuln — should be filtered out by min_cvss
FAKE_CVE_LOW_SEVERITY = {
    "id": "CVE-2024-11111",
    "descriptions": [
        {"lang": "en", "value": "Apache HTTP Server SQL injection in obscure module."},
    ],
    "metrics": {
        "cvssMetricV31": [{"cvssData": {"baseScore": 2.0, "baseSeverity": "LOW",
                                         "vectorString": "..."}}],
    },
    "configurations": [
        {"nodes": [{"cpeMatch": [
            {"vulnerable": True, "criteria": "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"},
        ]}]},
    ],
}


# =============================================================================
# Runbook — synthetic markdown with frontmatter
# =============================================================================

FAKE_RUNBOOK = """---
id: RB-TEST
title: Test runbook
applies_to: cracking
mitre_ids: T1110, T1110.001
severity_guidance: P2 if successful.
references: https://example.com/ref1, https://example.com/ref2
---

# Test runbook

## Step 1
Do the first thing.

## Step 2
Do the second thing.
"""


def run_tests():
    # =========================================================================
    # MITRE
    # =========================================================================
    print("--- MITRE tests ---")
    techniques = parse_techniques(FAKE_MITRE_BUNDLE)
    assert len(techniques) == 1, f"Expected 1 live technique, got {len(techniques)}"
    t = techniques[0]
    assert t.mitre_id == "T1110"
    assert "cracking" in t.relevance_tags
    print(f"  parse_techniques OK")

    inv = _build_phase_lookup()
    assert "T1110" in inv
    assert "cracking" in inv["T1110"]
    print(f"  phase lookup OK")

    m_summary = summarise_mitre(techniques)
    assert m_summary["total_techniques"] == 1
    assert m_summary["ait_relevant"] == 1
    print(f"  summarise_mitre OK")

    mitre_chunks = chunk_all_techniques(techniques)
    assert len(mitre_chunks) == 2  # T1110 has description + detection
    for c in mitre_chunks:
        assert c.source == "mitre"
        # metadata values must be ChromaDB scalars
        for k, v in c.metadata.items():
            assert isinstance(v, (str, int, float, bool)), \
                f"non-scalar metadata: {k}={v!r}"
    print(f"  chunk_mitre OK ({len(mitre_chunks)} chunks)")

    # =========================================================================
    # CVE — filtering logic
    # =========================================================================
    print("\n--- CVE tests ---")

    # Helper: extract CVSS works for v3.1
    score, severity, _ = _extract_cvss(FAKE_CVE_APACHE)
    assert score == 9.8 and severity == "CRITICAL"
    print(f"  _extract_cvss OK (v3.1)")

    # Helper: extract CWEs
    cwes = _extract_cwes(FAKE_CVE_APACHE)
    assert cwes == ["CWE-287"]
    print(f"  _extract_cwes OK")

    # Helper: vendor:product from CPE
    vp = _vendor_product_from_cpe("cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*")
    assert vp == "apache:http_server"
    print(f"  _vendor_product_from_cpe OK")

    # is_relevant: Apache should pass via CPE
    assert is_relevant(FAKE_CVE_APACHE) is True, "Apache vuln should pass CPE filter"
    print(f"  is_relevant OK: Apache (CPE match)")

    # is_relevant: WordPress plugin should pass via keyword
    assert is_relevant(FAKE_CVE_WP_PLUGIN) is True, "WP plugin vuln should pass keyword filter"
    print(f"  is_relevant OK: WP plugin (keyword match: 'sql injection')")

    # is_relevant: iOS bug should be REJECTED
    assert is_relevant(FAKE_CVE_IRRELEVANT) is False, "iOS bug should be rejected"
    print(f"  is_relevant OK: iOS rejected (no CPE, no keyword)")

    # is_relevant: REJECTED CVE should be REJECTED
    assert is_relevant(FAKE_CVE_REJECTED) is False, "Rejected CVE should be filtered"
    print(f"  is_relevant OK: '** REJECTED **' filtered")

    # is_relevant: low-severity vuln should be REJECTED by CVSS threshold
    assert is_relevant(FAKE_CVE_LOW_SEVERITY) is False, \
        "Low CVSS should be filtered even with matching CPE"
    print(f"  is_relevant OK: low CVSS filtered (2.0 < 4.0 default threshold)")

    # parse_cve_object
    apache = parse_cve_object(FAKE_CVE_APACHE)
    assert apache.cve_id == "CVE-2024-12345"
    assert apache.cvss_score == 9.8
    assert apache.cvss_severity == "CRITICAL"
    assert "CWE-287" in apache.cwes
    assert "apache:http_server" in apache.affected_products
    print(f"  parse_cve_object OK")

    # summarise_cves
    entries = [parse_cve_object(FAKE_CVE_APACHE), parse_cve_object(FAKE_CVE_WP_PLUGIN)]
    c_summary = summarise_cves(entries)
    assert c_summary["total_cves"] == 2
    assert "CRITICAL" in c_summary["by_severity"]
    print(f"  summarise_cves OK")

    # CVE chunking
    cve_chunks = chunk_all_cves(entries)
    assert len(cve_chunks) == 2
    for c in cve_chunks:
        assert c.source == "cve"
        # metadata scalars
        for k, v in c.metadata.items():
            assert isinstance(v, (str, int, float, bool)), \
                f"non-scalar metadata: {k}={v!r}"
    # Affected products should appear in the embedded text for retrieval
    apache_chunk = next(c for c in cve_chunks if "12345" in c.doc_id)
    assert "Affected products:" in apache_chunk.text
    assert "apache:http_server" in apache_chunk.text
    assert "CWE-287" in apache_chunk.text
    print(f"  chunk_cve OK (rich text with products + CWE included)")

    # =========================================================================
    # Runbooks
    # =========================================================================
    print("\n--- Runbook tests ---")

    # _split_frontmatter
    fm, body = _split_frontmatter(FAKE_RUNBOOK)
    assert fm["id"] == "RB-TEST"
    assert fm["title"] == "Test runbook"
    assert fm["applies_to"] == "cracking"
    assert fm["mitre_ids"] == "T1110, T1110.001"
    assert "Step 1" in body
    print(f"  _split_frontmatter OK")

    # Frontmatter-less file: returns empty dict and full content as body
    fm2, body2 = _split_frontmatter("# Just a heading\n\nContent.")
    assert fm2 == {}
    assert "Just a heading" in body2
    print(f"  _split_frontmatter OK (no frontmatter case)")

    # parse_runbook_file via a temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False) as f:
        f.write(FAKE_RUNBOOK)
        tmp_path = Path(f.name)

    try:
        rb = parse_runbook_file(tmp_path)
        assert rb.runbook_id == "RB-TEST"
        assert rb.title == "Test runbook"
        assert rb.applies_to == "cracking"
        assert rb.mitre_ids == ["T1110", "T1110.001"]
        assert len(rb.references) == 2
        assert "Step 1" in rb.body and "Step 2" in rb.body
        print(f"  parse_runbook_file OK")
    finally:
        tmp_path.unlink()

    # load_runbooks on temp directory
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        (td_path / "rb1.md").write_text(FAKE_RUNBOOK)
        (td_path / "rb2.md").write_text(
            FAKE_RUNBOOK.replace("RB-TEST", "RB-TEST-2").replace("cracking", "dirb")
        )
        (td_path / "README.md").write_text("# Not a runbook")
        rbs = load_runbooks(td_path)
        assert len(rbs) == 2, f"Should find 2 runbooks (README excluded), got {len(rbs)}"
        ids = {r.runbook_id for r in rbs}
        assert ids == {"RB-TEST", "RB-TEST-2"}
        print(f"  load_runbooks OK (README.md correctly excluded)")

        # summarise_runbooks
        r_summary = summarise_runbooks(rbs)
        assert r_summary["total_runbooks"] == 2
        assert r_summary["by_applies_to"]["cracking"] == 1
        assert r_summary["by_applies_to"]["dirb"] == 1
        assert "T1110" in r_summary["mitre_ids_covered"]
        print(f"  summarise_runbooks OK")

    # Chunking a runbook
    rb_chunks = chunk_all_runbooks(rbs)
    assert len(rb_chunks) == 2
    for c in rb_chunks:
        assert c.source == "runbook"
        # Title and applies_to should be in the embedded text for retrieval
        assert "Test runbook" in c.text
        assert "Applies to attack phase:" in c.text
        # metadata scalars
        for k, v in c.metadata.items():
            assert isinstance(v, (str, int, float, bool)), \
                f"non-scalar metadata: {k}={v!r}"
    print(f"  chunk_runbook OK (title + applies_to embedded)")

    # =========================================================================
    # Real runbook corpus — load the actual 8 runbooks we shipped
    # =========================================================================
    print("\n--- Real runbook corpus tests ---")
    corpus_dir = Path(__file__).parent / "kb" / "runbook_corpus"
    if corpus_dir.exists():
        real_rbs = load_runbooks(corpus_dir)
        assert len(real_rbs) >= 8, \
            f"Expected at least 8 runbooks in corpus, found {len(real_rbs)}"
        # Every one should have all required fields populated
        for rb in real_rbs:
            assert rb.runbook_id.startswith("RB-"), \
                f"Bad runbook ID in {rb.file_path}: {rb.runbook_id}"
            assert rb.title, f"Empty title in {rb.file_path}"
            assert rb.applies_to, f"Empty applies_to in {rb.file_path}"
            assert rb.mitre_ids, f"No mitre_ids in {rb.file_path}"
            assert rb.body, f"Empty body in {rb.file_path}"
        print(f"  Real corpus OK: {len(real_rbs)} runbooks, all fields populated")
        # Coverage of AIT phases
        phases_covered = {rb.applies_to for rb in real_rbs}
        expected_phases = {"cracking", "dirb", "wpscan", "dnsteal",
                           "privilege_escalation", "reverse_shell",
                           "webshell", "service_stop"}
        missing = expected_phases - phases_covered
        assert not missing, f"Missing runbook coverage for phases: {missing}"
        print(f"  Phase coverage OK: 8 phases covered")
    else:
        print(f"  (Real corpus check skipped: {corpus_dir} not present)")

    print("\nAll tests passed.")


if __name__ == "__main__":
    run_tests()
