"""AIT-ADS dissertation knowledge base — MITRE ATT&CK, CVE, runbooks."""

from .mitre_loader import (
    MITRE_STIX_URL,
    AIT_PHASE_TO_MITRE,
    MitreTechnique,
    download_stix,
    parse_techniques,
    load_mitre,
    summarise as summarise_mitre,
)
from .cve_loader import (
    CVE_FEED_URL_TEMPLATE,
    RELEVANT_CPE_VENDORS_PRODUCTS,
    RELEVANT_DESCRIPTION_KEYWORDS,
    DEFAULT_MIN_CVSS,
    CveEntry,
    is_relevant,
    parse_cve_object,
    load_cve_year,
    load_cves,
    summarise as summarise_cves,
)
from .runbooks import (
    Runbook,
    parse_runbook_file,
    load_runbooks,
    summarise as summarise_runbooks,
)
from .chunker import (
    KnowledgeDocument,
    chunk_mitre_technique, chunk_all_techniques,
    chunk_cve, chunk_all_cves,
    chunk_runbook, chunk_all_runbooks,
)
from .embedder import embed_texts, embedding_dim
from .chromadb_store import KnowledgeStore, COLLECTION_NAME

__all__ = [
    # MITRE
    "MITRE_STIX_URL", "AIT_PHASE_TO_MITRE", "MitreTechnique",
    "download_stix", "parse_techniques", "load_mitre", "summarise_mitre",
    # CVE
    "CVE_FEED_URL_TEMPLATE", "RELEVANT_CPE_VENDORS_PRODUCTS",
    "RELEVANT_DESCRIPTION_KEYWORDS", "DEFAULT_MIN_CVSS",
    "CveEntry", "is_relevant", "parse_cve_object",
    "load_cve_year", "load_cves", "summarise_cves",
    # Runbooks
    "Runbook", "parse_runbook_file", "load_runbooks", "summarise_runbooks",
    # Chunker
    "KnowledgeDocument",
    "chunk_mitre_technique", "chunk_all_techniques",
    "chunk_cve", "chunk_all_cves",
    "chunk_runbook", "chunk_all_runbooks",
    # Pipeline
    "embed_texts", "embedding_dim",
    "KnowledgeStore", "COLLECTION_NAME",
]