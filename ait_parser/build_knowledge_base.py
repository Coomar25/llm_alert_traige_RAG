"""
build_knowledge_base.py — Full knowledge-base construction.

Workflow:
    1. Load MITRE ATT&CK (download or cache)
    2. Load CVEs from selected years (download or cache, filter aggressively)
    3. Load runbooks from kb/runbook_corpus/*.md
    4. Chunk each source into KnowledgeDocuments
    5. Embed all chunks with sentence-transformers/all-MiniLM-L6-v2
    6. Upsert into ChromaDB persistent collection
    7. Run sanity queries to confirm retrieval is reasonable
    8. Write kb_stats.json with full breakdown

Usage:
    # Build everything (default 2015-2024 CVEs, takes 20-40 min first time)
    python build_knowledge_base.py \\
        --persist-dir data/kb --cache-dir data/kb/cache

    # MITRE + runbooks only (skip the heavy CVE download)
    python build_knowledge_base.py \\
        --persist-dir data/kb --cache-dir data/kb/cache --skip-cve

    # Limited CVE year range for faster builds
    python build_knowledge_base.py \\
        --persist-dir data/kb --cache-dir data/kb/cache \\
        --cve-start-year 2020 --cve-end-year 2024

    # Wipe and rebuild from scratch
    python build_knowledge_base.py \\
        --persist-dir data/kb --cache-dir data/kb/cache --clear
"""

import argparse
import json
import sys
from pathlib import Path

from kb import (
    # MITRE
    load_mitre, summarise_mitre, chunk_all_techniques,
    # CVE
    load_cves, summarise_cves, chunk_all_cves, DEFAULT_MIN_CVSS,
    # Runbooks
    load_runbooks, summarise_runbooks, chunk_all_runbooks,
    # Pipeline
    embed_texts, embedding_dim, KnowledgeStore,
)


SANITY_QUERIES = [
    "SSH brute force authentication failures from a single source IP",
    "directory enumeration scan dirb gobuster against web server",
    "WordPress plugin vulnerability scan and exploitation",
    "DNS exfiltration of stolen data through subdomain encoding",
    "Linux kernel privilege escalation exploit",
    "reverse shell connection bash netcat outbound",
    "PHP web shell uploaded to wp-content uploads directory",
    "stopping monitoring agent or critical service",
]


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--persist-dir", required=True, type=Path,
                    help="Directory for the ChromaDB persistent collection")
    ap.add_argument("--cache-dir", required=True, type=Path,
                    help="Directory for cached MITRE/CVE source files")
    ap.add_argument("--runbook-dir", type=Path, default=None,
                    help="Directory of runbook .md files "
                         "(defaults to kb/runbook_corpus next to this script)")
    ap.add_argument("--force-refresh", action="store_true",
                    help="Re-download MITRE and CVE data even if cached")
    ap.add_argument("--clear", action="store_true",
                    help="Wipe the existing collection before inserting")
    ap.add_argument("--skip-mitre", action="store_true",
                    help="Skip MITRE ingestion")
    ap.add_argument("--skip-cve", action="store_true",
                    help="Skip CVE ingestion (saves 15-30 min on first build)")
    ap.add_argument("--skip-runbooks", action="store_true",
                    help="Skip runbook ingestion")
    ap.add_argument("--cve-start-year", type=int, default=2015)
    ap.add_argument("--cve-end-year", type=int, default=2024)
    ap.add_argument("--cve-min-cvss", type=float, default=DEFAULT_MIN_CVSS,
                    help=f"Minimum CVSS score for CVE inclusion (default "
                         f"{DEFAULT_MIN_CVSS}; lower keeps more CVEs)")
    args = ap.parse_args()

    # Resolve runbook directory
    if args.runbook_dir is None:
        args.runbook_dir = Path(__file__).parent / "kb" / "runbook_corpus"

    args.persist_dir.mkdir(parents=True, exist_ok=True)
    args.cache_dir.mkdir(parents=True, exist_ok=True)

    print(f"Persist:   {args.persist_dir}", file=sys.stderr)
    print(f"Cache:     {args.cache_dir}", file=sys.stderr)
    print(f"Runbooks:  {args.runbook_dir}", file=sys.stderr)
    print(f"Skips:     mitre={args.skip_mitre} cve={args.skip_cve} "
          f"runbooks={args.skip_runbooks}", file=sys.stderr)
    print(f"CVE years: {args.cve_start_year}-{args.cve_end_year} "
          f"(min CVSS {args.cve_min_cvss})", file=sys.stderr)

    all_docs = []
    stats: dict = {
        "embedding_model": "sentence-transformers/all-MiniLM-L6-v2",
    }

    # -------------------------------------------------------------------------
    # MITRE
    # -------------------------------------------------------------------------
    if not args.skip_mitre:
        print("\n" + "=" * 70, file=sys.stderr)
        print("Step 1: MITRE ATT&CK", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

        techniques = load_mitre(args.cache_dir, force_refresh=args.force_refresh)
        m_summary = summarise_mitre(techniques)
        m_chunks = chunk_all_techniques(techniques)
        all_docs.extend(m_chunks)
        print(f"  {m_summary['total_techniques']:,} techniques → "
              f"{len(m_chunks):,} chunks", file=sys.stderr)
        stats["mitre"] = m_summary
        stats["mitre_chunks"] = len(m_chunks)

    # -------------------------------------------------------------------------
    # CVE
    # -------------------------------------------------------------------------
    if not args.skip_cve:
        print("\n" + "=" * 70, file=sys.stderr)
        print(f"Step 2: CVE ({args.cve_start_year}-{args.cve_end_year})",
              file=sys.stderr)
        print("=" * 70, file=sys.stderr)
        print("This will download ~100-200MB per year on first run.",
              file=sys.stderr)

        cve_cache = args.cache_dir / "cve"
        cves = load_cves(
            cve_cache,
            start_year=args.cve_start_year,
            end_year=args.cve_end_year,
            min_cvss=args.cve_min_cvss,
            force_refresh=args.force_refresh,
        )
        c_summary = summarise_cves(cves)
        c_chunks = chunk_all_cves(cves)
        all_docs.extend(c_chunks)
        print(f"\n  Total: {c_summary['total_cves']:,} relevant CVEs → "
              f"{len(c_chunks):,} chunks", file=sys.stderr)
        stats["cve"] = c_summary
        stats["cve_chunks"] = len(c_chunks)

    # -------------------------------------------------------------------------
    # Runbooks
    # -------------------------------------------------------------------------
    if not args.skip_runbooks:
        print("\n" + "=" * 70, file=sys.stderr)
        print("Step 3: Runbooks", file=sys.stderr)
        print("=" * 70, file=sys.stderr)

        runbooks = load_runbooks(args.runbook_dir)
        r_summary = summarise_runbooks(runbooks)
        r_chunks = chunk_all_runbooks(runbooks)
        all_docs.extend(r_chunks)
        print(f"  {r_summary['total_runbooks']} runbooks → "
              f"{len(r_chunks)} chunks", file=sys.stderr)
        for phase, count in r_summary["by_applies_to"].items():
            print(f"    applies_to={phase}: {count}", file=sys.stderr)
        stats["runbooks"] = r_summary
        stats["runbook_chunks"] = len(r_chunks)

    # -------------------------------------------------------------------------
    # Embed
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70, file=sys.stderr)
    print(f"Step 4: Embedding {len(all_docs):,} documents", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    if not all_docs:
        print("ERROR: no documents to embed (all sources were skipped?)",
              file=sys.stderr)
        sys.exit(1)

    texts = [d.text for d in all_docs]
    vectors = embed_texts(texts, batch_size=64)
    dim = embedding_dim()
    print(f"  Embedded {len(vectors):,} documents to {dim}-d vectors",
          file=sys.stderr)
    stats["embedding_dim"] = dim

    # -------------------------------------------------------------------------
    # Store
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70, file=sys.stderr)
    print(f"Step 5: Writing to ChromaDB at {args.persist_dir}",
          file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    store = KnowledgeStore(args.persist_dir)
    if args.clear and store.count() > 0:
        print(f"  Clearing existing collection ({store.count():,} entries)",
              file=sys.stderr)
        store.clear()
    store.add(all_docs, vectors)
    print(f"  Collection now contains {store.count():,} documents",
          file=sys.stderr)
    stats["total_chunks"] = len(all_docs)
    stats["collection_count_after_insert"] = store.count()

    # -------------------------------------------------------------------------
    # Sanity-check retrieval
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70, file=sys.stderr)
    print("Step 6: Sanity-check queries", file=sys.stderr)
    print("=" * 70, file=sys.stderr)

    sanity_results = []
    for q in SANITY_QUERIES:
        q_vec = embed_texts([q])[0]
        hits = store.query(q_vec, top_k=3)
        print(f"\n  Q: {q!r}", file=sys.stderr)
        for h in hits:
            src = h["metadata"].get("source", "?")
            label = (h["metadata"].get("mitre_id")
                     or h["metadata"].get("cve_id")
                     or h["metadata"].get("runbook_id")
                     or "?")
            print(f"    [{src}] {label}  distance={h['distance']:.4f}",
                  file=sys.stderr)
        sanity_results.append({
            "query": q,
            "hits": [
                {
                    "doc_id": h["doc_id"],
                    "source": h["metadata"].get("source"),
                    "label": (
                        h["metadata"].get("mitre_id")
                        or h["metadata"].get("cve_id")
                        or h["metadata"].get("runbook_id")
                    ),
                    "distance": h["distance"],
                } for h in hits
            ],
        })
    stats["sanity_query_results"] = sanity_results

    # -------------------------------------------------------------------------
    # Stats output
    # -------------------------------------------------------------------------
    stats_path = args.persist_dir / "kb_stats.json"
    stats_path.write_text(json.dumps(stats, indent=2, default=str))
    print(f"\nSummary written to {stats_path}", file=sys.stderr)
    print("\nDone.", file=sys.stderr)


if __name__ == "__main__":
    main()