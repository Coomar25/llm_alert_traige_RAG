"""
MITRE ATT&CK loader — downloads STIX 2.1 enterprise data and parses it into
KnowledgeDocument records.

Why STIX 2.1 and not the website API?
    - Single canonical source, no scraping
    - Versioned (we can pin a specific release for reproducibility)
    - Includes ALL fields: descriptions, detection guidance, platforms,
      mitigations, kill-chain phases (tactics)

Data source:
    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/
    enterprise-attack/enterprise-attack.json

    ~50MB single JSON file containing ~700 techniques, ~14 tactics, plus
    relationships, mitigations, and groups.

Filtering policy:
    - Drop revoked or deprecated techniques (their content is misleading)
    - Keep only techniques (attack-pattern objects), not malware, tools,
      campaigns, or groups (those are about specific actors, not behaviour)
    - Keep ALL techniques, not just AIT-ADS-relevant ones — the metadata
      we tag with relevance_tags lets us filter at retrieval time
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set
from urllib.request import urlopen, Request

MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

# Map from AIT-ADS attack phases to MITRE technique IDs that we consider
# directly relevant. Used to tag the metadata of each loaded technique with
# `relevance_tags`, which allows filtered retrieval at query time.
#
# Mappings derived from the AIT-ADS Zenodo dataset documentation and standard
# MITRE ATT&CK technique definitions.
AIT_PHASE_TO_MITRE: dict[str, List[str]] = {
    "network_scans":        ["T1046", "T1018", "T1595", "T1595.001"],
    "service_scans":        ["T1046", "T1595", "T1595.002"],
    "dirb":                 ["T1595.003", "T1083", "T1190"],
    "wpscan":               ["T1595.002", "T1190", "T1592.002"],
    "webshell":             ["T1505.003", "T1059.004", "T1190"],
    "cracking":             ["T1110", "T1110.001", "T1110.003", "T1110.004"],
    "reverse_shell":        ["T1059", "T1059.004", "T1071", "T1071.001"],
    "privilege_escalation": ["T1068", "T1548", "T1078"],
    "service_stop":         ["T1489", "T1529"],
    "dnsteal":              ["T1048", "T1048.003", "T1071.004"],
}


@dataclass
class MitreTechnique:
    """One parsed MITRE ATT&CK technique with the fields we care about."""
    mitre_id: str                            # e.g., "T1110" or "T1110.001"
    name: str
    description: str
    detection: str = ""
    tactics: List[str] = field(default_factory=list)        # e.g., ["credential-access"]
    platforms: List[str] = field(default_factory=list)      # e.g., ["Linux"]
    is_subtechnique: bool = False
    parent_id: str | None = None
    url: str = ""
    relevance_tags: List[str] = field(default_factory=list)  # AIT phases this maps to


def _build_phase_lookup() -> dict[str, List[str]]:
    """Invert AIT_PHASE_TO_MITRE → mitre_id -> [phases]."""
    inv: dict[str, List[str]] = {}
    for phase, ids in AIT_PHASE_TO_MITRE.items():
        for mid in ids:
            inv.setdefault(mid, []).append(phase)
    return inv


def download_stix(cache_path: Path, force: bool = False) -> dict:
    """Download MITRE ATT&CK STIX JSON; cache on disk after first download.

    The file is ~50MB. Re-downloading every run wastes time and bandwidth.
    Cache it; set force=True to refresh.
    """
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    if cache_path.exists() and not force:
        with cache_path.open("r") as f:
            return json.load(f)

    print(f"Downloading MITRE ATT&CK STIX data from:\n  {MITRE_STIX_URL}")
    req = Request(MITRE_STIX_URL, headers={"User-Agent": "ait-parser-kb/1.0"})
    with urlopen(req, timeout=120) as resp:
        raw = resp.read()
    cache_path.write_bytes(raw)
    print(f"  Saved {len(raw):,} bytes to {cache_path}")
    return json.loads(raw)


def parse_techniques(stix_bundle: dict) -> List[MitreTechnique]:
    """Extract live (non-revoked, non-deprecated) techniques from a STIX bundle."""
    objects = stix_bundle.get("objects", [])
    phase_lookup = _build_phase_lookup()

    techniques: List[MitreTechnique] = []
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked", False):
            continue
        if obj.get("x_mitre_deprecated", False):
            continue

        # Extract the MITRE ID from external_references
        mitre_id = None
        url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id")
                url = ref.get("url", "")
                break
        if not mitre_id:
            continue

        # Sub-techniques look like "T1110.001"; parents are "T1110"
        is_sub = "." in mitre_id
        parent = mitre_id.split(".")[0] if is_sub else None

        tactics = [
            kc.get("phase_name", "")
            for kc in obj.get("kill_chain_phases", [])
            if kc.get("kill_chain_name") == "mitre-attack"
        ]

        relevance = sorted(set(phase_lookup.get(mitre_id, [])))

        techniques.append(MitreTechnique(
            mitre_id=mitre_id,
            name=obj.get("name", ""),
            description=obj.get("description", "").strip(),
            detection=obj.get("x_mitre_detection", "").strip(),
            tactics=[t for t in tactics if t],
            platforms=list(obj.get("x_mitre_platforms", []) or []),
            is_subtechnique=is_sub,
            parent_id=parent,
            url=url,
            relevance_tags=relevance,
        ))

    return techniques


def load_mitre(cache_dir: Path, force_refresh: bool = False) -> List[MitreTechnique]:
    """Top-level entry point: download (or use cache) + parse."""
    cache_file = cache_dir / "mitre_enterprise.json"
    bundle = download_stix(cache_file, force=force_refresh)
    techniques = parse_techniques(bundle)
    return techniques


def summarise(techniques: List[MitreTechnique]) -> dict:
    """Human-readable summary of what was loaded."""
    n_total = len(techniques)
    n_sub = sum(1 for t in techniques if t.is_subtechnique)
    n_parent = n_total - n_sub
    n_relevant = sum(1 for t in techniques if t.relevance_tags)
    by_tactic: dict[str, int] = {}
    for t in techniques:
        for tac in t.tactics:
            by_tactic[tac] = by_tactic.get(tac, 0) + 1
    return {
        "total_techniques": n_total,
        "parent_techniques": n_parent,
        "sub_techniques": n_sub,
        "ait_relevant": n_relevant,
        "by_tactic": dict(sorted(by_tactic.items(), key=lambda x: -x[1])),
    }
