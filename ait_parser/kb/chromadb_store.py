"""
ChromaDB store wrapper.

ChromaDB is a lightweight vector database with three modes:
    - In-memory (ephemeral; lost when process ends)
    - Persistent (on-disk SQLite + flat files; survives restarts)
    - Client-server (over HTTP; for distributed setups)

We use the persistent mode — the knowledge base should be built once and
queried many times across the LLM pipelines. Rebuild only when the source
data changes.

Why ChromaDB specifically (vs FAISS, Qdrant, Weaviate)?
    - Pure Python install (no separate server, no Rust toolchain)
    - Built-in metadata filtering (we need this for relevance_tags)
    - Standard in academic RAG papers — easy to defend in methodology
    - MIT license, no commercial restrictions
"""

from pathlib import Path
from typing import List, Optional

from .chunker import KnowledgeDocument


COLLECTION_NAME = "ait_kb"


class KnowledgeStore:
    """Thin wrapper around a ChromaDB persistent collection."""

    def __init__(self, persist_dir: Path):
        import chromadb  # type: ignore
        from chromadb.config import Settings  # type: ignore

        persist_dir.mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(
            path=str(persist_dir),
            settings=Settings(anonymized_telemetry=False),
        )
        # get_or_create: idempotent — fine to call multiple times
        self._collection = self._client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"description": "AIT-ADS dissertation knowledge base"},
        )

    def count(self) -> int:
        """Number of documents currently in the store."""
        return self._collection.count()

    def add(self, docs: List[KnowledgeDocument], embeddings: List[List[float]]) -> None:
        """Insert documents into the store.

        ChromaDB upsert semantics: documents with the same doc_id will be
        REPLACED on re-insert. This means rebuilds are idempotent — running
        the pipeline twice does not duplicate entries.
        """
        if not docs:
            return
        assert len(docs) == len(embeddings), \
            f"docs ({len(docs)}) and embeddings ({len(embeddings)}) length mismatch"

        ids = [d.doc_id for d in docs]
        documents = [d.text for d in docs]
        # ChromaDB requires str/int/float/bool in metadata values
        metadatas = [
            {**d.metadata, "title": d.title, "source": d.source}
            for d in docs
        ]
        # `upsert` over `add` so re-runs replace rather than crash on duplicate IDs
        self._collection.upsert(
            ids=ids,
            documents=documents,
            metadatas=metadatas,
            embeddings=embeddings,
        )

    def query(
        self,
        query_embedding: List[float],
        top_k: int = 5,
        where_filter: Optional[dict] = None,
    ) -> List[dict]:
        """Retrieve top-K most similar documents.

        where_filter is a ChromaDB metadata filter:
            {"source": "mitre"}                       — only MITRE docs
            {"relevance_tags": {"$contains": "..."}}  — substring match in tags
            {"$and": [{"source": "mitre"}, {...}]}    — combined
        """
        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=top_k,
            where=where_filter,
        )
        # Flatten ChromaDB's nested output into a clean list
        out: List[dict] = []
        for i in range(len(results["ids"][0])):
            out.append({
                "doc_id": results["ids"][0][i],
                "text": results["documents"][0][i],
                "metadata": results["metadatas"][0][i],
                "distance": results["distances"][0][i] if results.get("distances") else None,
            })
        return out

    def clear(self) -> None:
        """Drop and recreate the collection. Used for clean rebuilds."""
        self._client.delete_collection(COLLECTION_NAME)
        self._collection = self._client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"description": "AIT-ADS dissertation knowledge base"},
        )
