"""
build_knowledge_base.py — Part 1: MITRE ATT&CK ingestion.

Workflow:
    mitreloader.py (downloads and parses MITRE STIX bundle) ->
    1. Download (or load from cache) the MITRE ATT&CK STIX bundle.
    2. Parse it into MitreTechnique objects, filtering revoked/deprecated.

    chunker.py (chunks MitreTechnique into retrievable KnowledgeDocuments) ->
    3. Chunk each technique into 1-2 KnowledgeDocuments (description +
       optional detection).

    embedder.py (embeds text with sentence-transformers) ->
    4. Embed all chunks with sentence-transformers/all-MiniLM-L6-v2.

    chromadb_store.py (thin wrapper around ChromaDB) ->
    5. Insert into the ChromaDB persistent collection.
    6. Run a few sanity queries to confirm retrieval works.
    7. Write summary statistics.

Usage:
    python build_knowledge_base.py \\
        --persist-dir data/kb \\
        --cache-dir data/kb/cache

    # Force re-download of MITRE data (otherwise uses cache after first run)
    python build_knowledge_base.py --persist-dir data/kb --cache-dir data/kb/cache --force-refresh

    # Wipe the existing collection and rebuild from scratch
    python build_knowledge_base.py --persist-dir data/kb --cache-dir data/kb/cache --clear

Outputs:
    <persist-dir>/             — ChromaDB persistent collection (binary files)
    <cache-dir>/mitre_enterprise.json   — cached MITRE STIX bundle
    <persist-dir>/kb_stats.json         — summary statistics
"""

import argparse
import json
import sys
from pathlib import Path

from kb import (
    load_mitre,
    summarise,
    chunk_all_techniques,
    embed_texts,
    embedding_dim,
    KnowledgeStore,
)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--persist-dir", required=True, type=Path,
                    help="Directory for the ChromaDB persistent collection")
    ap.add_argument("--cache-dir", required=True, type=Path,
                    help="Directory for cached MITRE/CVE source files")
    ap.add_argument("--force-refresh", action="store_true",
                    help="Re-download MITRE data even if cached")
    ap.add_argument("--clear", action="store_true",
                    help="Wipe the existing collection and rebuild from scratch")
    args = ap.parse_args()

    # -------------------------------------------------------------------------
    # Step 1: Load MITRE
    # -------------------------------------------------------------------------
    print("=" * 70, file=sys.stderr)
    print("Step 1: Loading MITRE ATT&CK", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    techniques = load_mitre(args.cache_dir, force_refresh=args.force_refresh)
    mitre_summary = summarise(techniques)

    print(f"  Loaded {mitre_summary['total_techniques']:,} live techniques",
          file=sys.stderr)
    print(f"    Parent techniques:  {mitre_summary['parent_techniques']:,}",
          file=sys.stderr)
    print(f"    Sub-techniques:     {mitre_summary['sub_techniques']:,}",
          file=sys.stderr)
    print(f"    AIT-relevant:       {mitre_summary['ait_relevant']:,}",
          file=sys.stderr)
    print(f"  Top tactics by technique count:", file=sys.stderr)
    for tactic, count in list(mitre_summary["by_tactic"].items())[:5]:
        print(f"    {tactic}: {count}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # Step 2: Chunk
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70, file=sys.stderr)
    print("Step 2: Chunking techniques into retrievable documents", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    docs = chunk_all_techniques(techniques)
    n_desc = sum(1 for d in docs if d.metadata.get("section") == "description")
    n_det = sum(1 for d in docs if d.metadata.get("section") == "detection")
    print(f"  Produced {len(docs):,} KnowledgeDocuments:", file=sys.stderr)
    print(f"    Description chunks: {n_desc:,}", file=sys.stderr)
    print(f"    Detection chunks:   {n_det:,}", file=sys.stderr)

    # -------------------------------------------------------------------------
    # Step 3: Embed
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70, file=sys.stderr)
    print("Step 3: Embedding documents (this loads the model on first run)",
          file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    texts = [d.text for d in docs]
    vectors = embed_texts(texts, batch_size=64)
    dim = embedding_dim()
    print(f"  Embedded {len(vectors):,} documents to {dim}-d vectors",
          file=sys.stderr)

    # -------------------------------------------------------------------------
    # Step 4: Store
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70, file=sys.stderr)
    print(f"Step 4: Writing to ChromaDB at {args.persist_dir}", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    store = KnowledgeStore(args.persist_dir)
    if args.clear and store.count() > 0:
        print(f"  Clearing existing collection ({store.count():,} entries)",
              file=sys.stderr)
        store.clear()

    store.add(docs, vectors)
    print(f"  Collection now contains {store.count():,} documents",
          file=sys.stderr)

    # -------------------------------------------------------------------------
    # Step 5: Sanity-check retrieval
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70, file=sys.stderr)
    print("Step 5: Sanity-check queries (one per AIT attack phase)", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    sanity_queries = [
        "SSH brute force authentication failures",
        "directory enumeration scan against web server",
        "DNS exfiltration of stolen data",
        "privilege escalation through kernel exploit",
        "reverse shell over TCP",
    ]
    sanity_results: list[dict] = []
    for q in sanity_queries:
        q_vec = embed_texts([q])[0]
        hits = store.query(q_vec, top_k=3)
        print(f"\n  Query: {q!r}", file=sys.stderr)
        for h in hits:
            print(f"    -> {h['metadata'].get('mitre_id', '?')} "
                  f"({h['metadata'].get('section', '?')}) "
                  f"distance={h['distance']:.4f}", file=sys.stderr)
        sanity_results.append({
            "query": q,
            "hits": [
                {
                    "doc_id": h["doc_id"],
                    "mitre_id": h["metadata"].get("mitre_id"),
                    "title": h["metadata"].get("title"),
                    "section": h["metadata"].get("section"),
                    "distance": h["distance"],
                } for h in hits
            ],
        })

    # -------------------------------------------------------------------------
    # Step 6: Write summary
    # -------------------------------------------------------------------------
    stats = {
        "stage": "MITRE only (Part 1 of 3)",
        "embedding_model": "sentence-transformers/all-MiniLM-L6-v2",
        "embedding_dim": dim,
        "mitre": mitre_summary,
        "total_chunks": len(docs),
        "chunks_by_section": {
            "description": n_desc,
            "detection": n_det,
        },
        "collection_count_after_insert": store.count(),
        "sanity_query_results": sanity_results,
    }
    stats_path = args.persist_dir / "kb_stats.json"
    stats_path.write_text(json.dumps(stats, indent=2, default=str))
    print(f"\nSummary written to {stats_path}", file=sys.stderr)
    print("\nDone.", file=sys.stderr)


if __name__ == "__main__":
    main()
