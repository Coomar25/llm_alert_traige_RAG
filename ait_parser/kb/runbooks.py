"""
Runbook loader.

Runbooks are short SOC playbooks for handling specific alert patterns. They
provide the *operational* knowledge that neither MITRE (which describes
adversary behaviour) nor CVE (which describes vulnerabilities) covers:
"if you see X, do Y".

File format
-----------
Each runbook is a single markdown file in kb/runbook_corpus/ with YAML-like
frontmatter delimited by `---`:

    ---
    id: RB-001
    title: SSH brute force response procedure
    applies_to: cracking
    mitre_ids: T1110, T1110.001, T1110.003
    severity_guidance: Escalate to P2 if successful authentication observed.
    references: https://attack.mitre.org/techniques/T1110
    ---

    # SSH brute force response procedure

    ## Step 1 — Confirm the attack pattern
    ...

The body is freeform markdown. We embed the entire file (frontmatter
stripped) as a single retrieval chunk — runbooks are short enough (~300-500
words) that splitting them hurts semantic coherence.

Why not use a real YAML parser?
    - PyYAML is a heavyweight dependency for ~5 fields per file
    - The frontmatter format is simple: `key: value` lines
    - Rolling our own keeps the project dependency footprint minimal
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Set


@dataclass
class Runbook:
    """A parsed runbook ready for embedding."""
    runbook_id: str
    title: str
    applies_to: str = ""              # AIT phase name, e.g., "cracking"
    mitre_ids: List[str] = field(default_factory=list)
    severity_guidance: str = ""
    references: List[str] = field(default_factory=list)
    body: str = ""                     # the markdown content below frontmatter
    file_path: str = ""


def _split_frontmatter(text: str) -> tuple[dict, str]:
    """Split a markdown file into (frontmatter_dict, body_string).

    Expects content like:
        ---
        key1: value1
        key2: value2
        ---

        # body starts here
    """
    if not text.startswith("---"):
        return {}, text

    # Find the closing ---
    rest = text[3:]  # drop opening ---
    end = rest.find("\n---")
    if end < 0:
        return {}, text

    frontmatter_block = rest[:end].strip()
    body = rest[end + len("\n---"):].lstrip("\n")

    fm: dict = {}
    for line in frontmatter_block.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        fm[key.strip().lower()] = value.strip()

    return fm, body


def parse_runbook_file(path: Path) -> Runbook:
    """Parse a single runbook markdown file."""
    text = path.read_text()
    fm, body = _split_frontmatter(text)

    # Normalise comma-separated fields into lists
    def _split_csv(value: str) -> List[str]:
        return [v.strip() for v in value.split(",") if v.strip()]

    return Runbook(
        runbook_id=fm.get("id", path.stem),
        title=fm.get("title", path.stem),
        applies_to=fm.get("applies_to", ""),
        mitre_ids=_split_csv(fm.get("mitre_ids", "")),
        severity_guidance=fm.get("severity_guidance", ""),
        references=_split_csv(fm.get("references", "")),
        body=body.strip(),
        file_path=str(path),
    )


def load_runbooks(corpus_dir: Path) -> List[Runbook]:
    """Load every .md file in corpus_dir (excluding README.md)."""
    if not corpus_dir.exists():
        return []
    runbooks: List[Runbook] = []
    for path in sorted(corpus_dir.glob("*.md")):
        if path.name.lower() == "readme.md":
            continue
        try:
            runbooks.append(parse_runbook_file(path))
        except Exception as e:
            print(f"  WARNING: failed to parse {path.name}: {e}")
    return runbooks


def summarise(runbooks: List[Runbook]) -> dict:
    """Human-readable summary of the loaded runbooks."""
    by_phase: dict[str, int] = {}
    mitre_coverage: Set[str] = set()
    for rb in runbooks:
        by_phase[rb.applies_to or "unspecified"] = \
            by_phase.get(rb.applies_to or "unspecified", 0) + 1
        for mid in rb.mitre_ids:
            mitre_coverage.add(mid)
    return {
        "total_runbooks": len(runbooks),
        "by_applies_to": dict(sorted(by_phase.items())),
        "mitre_ids_covered": sorted(mitre_coverage),
    }
