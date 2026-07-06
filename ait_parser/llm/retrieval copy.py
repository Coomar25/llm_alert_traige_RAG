"""
Retrieval API for the LLM+RAG pipeline.

This is the bridge between an incoming alert and the knowledge base. It takes
an alert, embeds its content, queries ChromaDB for the most relevant entries,
and formats them as lean context for injection into the LLM prompt.

CRITICAL CORRECTNESS PROPERTY — no ground-truth leakage
-------------------------------------------------------
At inference time this API uses ONLY the alert's observable content
(description, rule groups, raw message) to build the retrieval query. It NEVER
uses the alert's known `attack_phase` or `is_attack` label. The query is built
by `retrieval_query_text()`, which only reads observable fields.

WHY SOURCE-BALANCED RETRIEVAL
-----------------------------
The knowledge base is dominated by CVEs: 36,840 CVEs vs 697 MITRE techniques
vs 8 runbooks. Naive "top-K across all sources" retrieval almost always returns
K CVEs, because they vastly outnumber the other sources — and often the CVEs
are only loosely related (e.g. generic "web server denial of service" CVEs
retrieved for a WordPress scan). This starves the model of the operational
guidance (runbooks) and technique context (MITRE) that are most useful for
triage, and floods it with marginally-relevant CVE noise.

Source-balanced retrieval fixes this by querying EACH source separately and
taking the best match from each:
    - the single best-matching runbook (operational "what to do")
    - the single best-matching MITRE technique (behavioural "what is this")
    - the best-matching CVE(s) (specific vulnerability context)

This guarantees the model always sees a runbook and a technique alongside any
CVE, rather than three loosely-related CVEs. It uses ChromaDB metadata
filtering (the `source` field) to query each source.

Thread-safety
-------------
The RAG pipeline calls retrieve() from multiple worker threads. Retrieval is
guarded with a lock. Retrieval is fast (embedding + a few ChromaDB queries)
relative to the ~20-30s LLM call, so the lock has negligible impact on
throughput while eliminating any risk of a race in the underlying libraries.
The embedding model is warmed once at construction so the first real alert does
not pay the model-load cost.
"""

import threading
from pathlib import Path
from typing import List, Optional

from kb.chromadb_store import KnowledgeStore
from kb.embedder import embed_texts

from .alert_repr import retrieval_query_text


# Per-document character budget in the formatted context.
DOC_CHAR_BUDGET = 320

# Human-readable source labels.
_SOURCE_LABELS = {
    "mitre": "MITRE ATT&CK",
    "cve": "CVE",
    "runbook": "Runbook",
}


class Retriever:
    """Wraps the knowledge base for source-balanced, alert-driven retrieval."""

    def __init__(self, persist_dir: Path, top_k: int = 3,
                 balance_sources: bool = True):
        """
        top_k: total number of documents to inject.
        balance_sources: if True (default), retrieve the best runbook + best
            MITRE + fill the rest with CVEs, rather than pure top-k similarity.
        """
        self._store = KnowledgeStore(persist_dir)
        self._top_k = top_k
        self._balance = balance_sources
        self._lock = threading.Lock()
        # Warm the embedding model once so the first alert doesn't pay the
        # ~5s model-load cost inside the timed inference loop.
        _ = embed_texts(["warmup"])

    def document_count(self) -> int:
        return self._store.count()

    def _query_source(self, query_vec: List[float], source: str,
                      k: int) -> List[dict]:
        """Query a single source via metadata filter."""
        return self._store.query(query_vec, top_k=k,
                                  where_filter={"source": source})

    def retrieve(self, alert: dict, top_k: Optional[int] = None) -> List[dict]:
        """Return knowledge-base entries relevant to this alert.

        With balancing (default): best runbook + best MITRE + best CVE(s),
        de-duplicated and trimmed to top_k. Without balancing: pure top-k
        similarity across all sources.

        Uses ONLY observable alert content for the query (no ground-truth
        label).
        """
        k = top_k if top_k is not None else self._top_k
        query = retrieval_query_text(alert)  # observable content only

        with self._lock:
            query_vec = embed_texts([query])[0]

            if not self._balance:
                return self._store.query(query_vec, top_k=k)

            # Source-balanced: one runbook, one MITRE, remainder CVEs.
            hits: List[dict] = []
            seen_ids = set()

            def _add(results):
                for h in results:
                    if h["doc_id"] not in seen_ids:
                        seen_ids.add(h["doc_id"])
                        hits.append(h)

            # 1 runbook (operational guidance)
            _add(self._query_source(query_vec, "runbook", 1))
            # 1 MITRE technique (behavioural context)
            _add(self._query_source(query_vec, "mitre", 1))
            # Fill remaining slots with CVEs (specific vulnerabilities)
            remaining = max(0, k - len(hits))
            if remaining > 0:
                _add(self._query_source(query_vec, "cve", remaining))

            # If we still have room (e.g. k>3), top up with a general query
            if len(hits) < k:
                for h in self._store.query(query_vec, top_k=k):
                    if h["doc_id"] not in seen_ids:
                        seen_ids.add(h["doc_id"])
                        hits.append(h)
                    if len(hits) >= k:
                        break

            # Sort the final set by ascending distance (most relevant first)
            hits.sort(key=lambda h: h.get("distance", 1e9))
            return hits[:k]

    def retrieve_and_format(self, alert: dict,
                            top_k: Optional[int] = None) -> str:
        """Retrieve and format context ready for prompt injection."""
        hits = self.retrieve(alert, top_k=top_k)
        if not hits:
            return "(no relevant knowledge-base entries were retrieved)"

        blocks: List[str] = []
        for h in hits:
            meta = h.get("metadata", {})
            source = meta.get("source", "unknown")
            source_label = _SOURCE_LABELS.get(source, source)

            ident = (meta.get("mitre_id")
                     or meta.get("cve_id")
                     or meta.get("runbook_id")
                     or "")
            title = meta.get("title", "")
            header_bits = [b for b in (ident, title) if b]
            header = f"[{source_label}: {' '.join(header_bits)}]".strip()

            text = (h.get("text") or "").strip().replace("\n", " ")
            if len(text) > DOC_CHAR_BUDGET:
                text = text[:DOC_CHAR_BUDGET] + "…"

            blocks.append(f"{header}\n{text}")

        return "\n\n".join(blocks)