"""
Chunking strategy for the knowledge base.

Each source uses a different approach:

    MITRE techniques:
        - One chunk per technique (description + detection joined where
          detection is available)
        - The all-MiniLM-L6-v2 model handles 512 tokens fine, so we don't
          split long descriptions

    CVE entries:
        - One chunk per CVE
        - Title combines CVE ID + CVSS severity + score for retrieval boost
        - Body includes description + affected products + CWE references

    Runbooks:
        - One chunk per runbook
        - We keep them whole because splitting hurts the "if-then" structure
          of operational guidance

A `KnowledgeDocument` is the universal type that goes into ChromaDB. Once an
object becomes a KnowledgeDocument, the embedding/indexing/retrieval pipeline
doesn't care which source it came from.
"""

from dataclasses import dataclass
from typing import List

from .mitre_loader import MitreTechnique
from .cve_loader import CveEntry
from .runbooks import Runbook


@dataclass
class KnowledgeDocument:
    """One retrievable unit in the knowledge base."""
    doc_id: str           # globally unique: e.g., "mitre:T1110", "cve:CVE-2021-44228"
    source: str           # "mitre" | "cve" | "runbook"
    title: str            # human-readable header
    text: str             # the body that gets embedded
    metadata: dict        # filterable attributes (relevance_tags, tactic, etc.)


def _make_doc(doc_id: str, source: str, title: str, text: str,
              metadata: dict) -> KnowledgeDocument:
    return KnowledgeDocument(
        doc_id=doc_id,
        source=source,
        title=title,
        text=text.strip(),
        metadata=metadata,
    )


# -----------------------------------------------------------------------------
# MITRE chunking
# -----------------------------------------------------------------------------

def chunk_mitre_technique(t: MitreTechnique) -> List[KnowledgeDocument]:
    """Produce 1-2 KnowledgeDocuments per MITRE technique.

    Description chunk: always emitted.
    Detection chunk: emitted only when x_mitre_detection field is non-empty
    (which is increasingly rare — MITRE has moved detection guidance to
    separate STIX 'data source' objects that we don't ingest yet).
    """
    base_meta = {
        "mitre_id": t.mitre_id,
        "name": t.name,
        "tactics": ";".join(t.tactics),
        "platforms": ";".join(t.platforms),
        "is_subtechnique": t.is_subtechnique,
        "parent_id": t.parent_id or "",
        "url": t.url,
        "relevance_tags": ";".join(t.relevance_tags),
    }

    chunks: List[KnowledgeDocument] = []

    if t.description:
        chunks.append(_make_doc(
            doc_id=f"mitre:{t.mitre_id}:description",
            source="mitre",
            title=f"{t.mitre_id} {t.name}",
            text=f"{t.name}.\n\n{t.description}",
            metadata={**base_meta, "section": "description"},
        ))

    if t.detection:
        chunks.append(_make_doc(
            doc_id=f"mitre:{t.mitre_id}:detection",
            source="mitre",
            title=f"Detection guidance for {t.mitre_id} {t.name}",
            text=(
                f"Detection guidance for the MITRE ATT&CK technique "
                f"{t.mitre_id} ({t.name}):\n\n{t.detection}"
            ),
            metadata={**base_meta, "section": "detection"},
        ))

    return chunks


def chunk_all_techniques(techniques: List[MitreTechnique]) -> List[KnowledgeDocument]:
    """Convert a list of techniques into a flat list of KnowledgeDocuments."""
    docs: List[KnowledgeDocument] = []
    for t in techniques:
        docs.extend(chunk_mitre_technique(t))
    return docs


# -----------------------------------------------------------------------------
# CVE chunking
# -----------------------------------------------------------------------------

def chunk_cve(cve: CveEntry) -> KnowledgeDocument:
    """Produce one KnowledgeDocument per CVE.

    We don't split a CVE — the description is short (typically 50-300 words)
    and the cohesion between description + products + CWE is important for
    retrieval relevance.
    """
    # Build a richer embedded text that includes all the useful signals.
    # The model will index on the entire string, so we want to make sure
    # things like affected products and CWE descriptions are searchable.
    parts: List[str] = [cve.description]
    if cve.affected_products:
        parts.append(f"Affected products: {', '.join(cve.affected_products)}.")
    if cve.cwes:
        parts.append(f"Weakness types: {', '.join(cve.cwes)}.")
    if cve.cvss_severity:
        parts.append(f"CVSS severity: {cve.cvss_severity} ({cve.cvss_score}).")
    text = "\n\n".join(parts)

    metadata = {
        "cve_id": cve.cve_id,
        "cvss_score": float(cve.cvss_score),
        "cvss_severity": cve.cvss_severity,
        "cvss_vector": cve.cvss_vector,
        "cwes": ";".join(cve.cwes),
        "affected_products": ";".join(cve.affected_products),
        "published": cve.published,
        "references": ";".join(cve.references),
    }

    return _make_doc(
        doc_id=f"cve:{cve.cve_id}",
        source="cve",
        title=f"{cve.cve_id} ({cve.cvss_severity} {cve.cvss_score})",
        text=text,
        metadata=metadata,
    )


def chunk_all_cves(cves: List[CveEntry]) -> List[KnowledgeDocument]:
    return [chunk_cve(c) for c in cves]


# -----------------------------------------------------------------------------
# Runbook chunking
# -----------------------------------------------------------------------------

def chunk_runbook(rb: Runbook) -> KnowledgeDocument:
    """Produce one KnowledgeDocument per runbook.

    Runbooks are short and their value lies in the connection between
    'symptom' (the alert pattern) and 'response' (the steps). Splitting them
    would break that connection.
    """
    # Pre-pend the title and key metadata to the body so embedding picks them up
    embedded_text = (
        f"{rb.title}\n\n"
        f"Applies to attack phase: {rb.applies_to}\n"
        f"Severity guidance: {rb.severity_guidance}\n\n"
        f"{rb.body}"
    )

    metadata = {
        "runbook_id": rb.runbook_id,
        "applies_to": rb.applies_to,
        "mitre_ids": ";".join(rb.mitre_ids),
        "severity_guidance": rb.severity_guidance,
        "references": ";".join(rb.references),
        "file_path": rb.file_path,
    }

    return _make_doc(
        doc_id=f"runbook:{rb.runbook_id}",
        source="runbook",
        title=rb.title,
        text=embedded_text,
        metadata=metadata,
    )


def chunk_all_runbooks(runbooks: List[Runbook]) -> List[KnowledgeDocument]:
    return [chunk_runbook(rb) for rb in runbooks]