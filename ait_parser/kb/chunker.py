"""
Chunking strategy for the knowledge base.

Each source needs a different chunking approach:

    MITRE techniques:
        - Description (the main behavioural summary)
        - Detection (separate concern: how to find this behaviour)
        - Mitigation (different concern: how to defend)
        - Each becomes its own chunk so retrieval can prefer detection-
          focused chunks for a "how do I spot this?" query versus
          mitigation chunks for "how do I prevent this?"
        - We DON'T further split descriptions even if long (~500 words),
          because the all-MiniLM-L6-v2 model handles 512 tokens fine.

    CVE descriptions (future): no chunking — each CVE is a single short doc.
    Runbooks (future): one chunk per runbook, kept whole.

A `KnowledgeDocument` is the universal type that goes into ChromaDB. Once an
object becomes a KnowledgeDocument, the rest of the pipeline (embedding,
indexing, retrieval) doesn't care which source it came from.
"""

from dataclasses import dataclass, field
from typing import List

from .mitre_loader import MitreTechnique


@dataclass
class KnowledgeDocument:
    """One retrievable unit in the knowledge base."""
    doc_id: str           # globally unique: e.g., "mitre:T1110:description"
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


def chunk_mitre_technique(t: MitreTechnique) -> List[KnowledgeDocument]:
    """Produce 1-2 KnowledgeDocuments per MITRE technique.

    Always produces a 'description' chunk. Produces a 'detection' chunk only
    if x_mitre_detection is non-empty (~60% of techniques have one).
    """
    base_meta = {
        "mitre_id": t.mitre_id,
        "name": t.name,
        "tactics": ";".join(t.tactics),   # ChromaDB metadata must be flat
        "platforms": ";".join(t.platforms),
        "is_subtechnique": t.is_subtechnique,
        "parent_id": t.parent_id or "",
        "url": t.url,
        # Critical: this allows filtered retrieval like
        # "give me only entries relevant to brute_force"
        "relevance_tags": ";".join(t.relevance_tags),
    }

    chunks: List[KnowledgeDocument] = []

    # Always emit the description chunk
    if t.description:
        chunks.append(_make_doc(
            doc_id=f"mitre:{t.mitre_id}:description",
            source="mitre",
            title=f"{t.mitre_id} {t.name}",
            text=f"{t.name}.\n\n{t.description}",
            metadata={**base_meta, "section": "description"},
        ))

    # Emit a detection chunk if present
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
