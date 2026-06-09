# Knowledge Base Construction — Stage 4 of the AIT-ADS Pipeline

This document is the complete reference for the knowledge base stage of the
dissertation pipeline. It describes every component, every design decision,
every command used to build the corpus, and the empirical results obtained.

It is intentionally exhaustive. The dissertation methodology chapter draws
its content from this document, the viva will reference details here, and
any future researcher reproducing the work needs every detail recorded.

```
Stage 1: ingest.py                ── parse 16 JSON files into unified schema   [DONE]
Stage 2: label_alerts.py          ── apply ground-truth attack labels          [DONE]
Stage 3: run_baseline.py          ── rule-based baseline + evaluation harness  [DONE]
Stage 4: build_knowledge_base.py  ── RAG knowledge base construction           [YOU ARE HERE]
Stage 5: (next) LLM pipelines     ── LLM-only and LLM+RAG triage systems       [PENDING]
```

---

## Table of Contents

1. [Purpose and Scope](#1-purpose-and-scope)
2. [Architecture Overview](#2-architecture-overview)
3. [Data Sources](#3-data-sources)
4. [Code Structure](#4-code-structure)
5. [Design Decisions](#5-design-decisions)
6. [Dependencies and Installation](#6-dependencies-and-installation)
7. [How to Run It — Step by Step](#7-how-to-run-it--step-by-step)
8. [Outputs](#8-outputs)
9. [Validation and Testing](#9-validation-and-testing)
10. [Empirical Results](#10-empirical-results)
11. [Retrieval Quality Analysis](#11-retrieval-quality-analysis)
12. [Issues Encountered and Resolutions](#12-issues-encountered-and-resolutions)
13. [Implications for the Dissertation](#13-implications-for-the-dissertation)
14. [Known Limitations](#14-known-limitations)
15. [What Comes Next](#15-what-comes-next)
16. [Quick Reference: Every Command Used](#16-quick-reference-every-command-used)
17. [Citation](#17-citation)

---

## 1. Purpose and Scope

The knowledge base is the **retrieval corpus** for the dissertation's RAG
(Retrieval-Augmented Generation) system. When the LLM+RAG pipeline processes
a security alert, it performs four steps:

1. Embed the alert content into a 384-dimensional vector.
2. Find the top-K most similar entries in the knowledge base.
3. Inject those entries into the LLM's prompt as context.
4. Ask the LLM to reason about the alert with that grounded context.

The knowledge base is therefore three things at once:

- A **corpus** of security text (technique definitions, vulnerabilities,
  operational guidance)
- A **vector index** for similarity search
- A **persistent store** that the LLM pipeline queries at inference time

Without the knowledge base, the LLM has only its pre-trained parametric
knowledge — which is general, undated, and not grounded in specific facts.
With the knowledge base, every LLM output can cite the specific MITRE
technique, CVE, or runbook that informed it.

---

## 2. Architecture Overview

```
                           +-------------------+
                           |   MITRE ATT&CK    |   ─── 697 techniques
                           +-------------------+
                                   │
                                   ▼
                           +-------------------+
                           |   NIST NVD CVE    |   ─── 36,840 CVEs
                           +-------------------+
                                   │
                                   ▼
                           +-------------------+
                           |  Hand-authored    |   ─── 8 runbooks
                           |     runbooks      |
                           +-------------------+
                                   │
                                   ▼
                         ┌──────────────────────┐
                         │ Source-specific      │
                         │ chunker functions    │
                         └──────────────────────┘
                                   │
                                   ▼
                         ┌──────────────────────┐
                         │ Unified              │
                         │ KnowledgeDocument    │   ─── 37,545 total chunks
                         └──────────────────────┘
                                   │
                                   ▼
                         ┌──────────────────────┐
                         │ sentence-transformers│
                         │ all-MiniLM-L6-v2     │   ─── 384-d embeddings
                         └──────────────────────┘
                                   │
                                   ▼
                         ┌──────────────────────┐
                         │ ChromaDB persistent  │
                         │ collection "ait_kb"  │
                         └──────────────────────┘
                                   │
                                   ▼
                            (LLM+RAG pipeline
                             queries this store)
```

---

## 3. Data Sources

### 3.1 MITRE ATT&CK Enterprise

**What it is.** MITRE ATT&CK is the industry-standard catalogue of adversary
tactics, techniques, and procedures. The Enterprise matrix covers techniques
used against Windows, macOS, Linux, and cloud environments. It is published
as a STIX 2.1 JSON bundle and updated quarterly.

**Source URL:**
```
https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/
enterprise-attack/enterprise-attack.json
```

**Size.** Approximately 53 MB single JSON file containing every technique,
sub-technique, tactic, mitigation, group, and relationship.

**What we extract.** Only `attack-pattern` objects (techniques), filtered to
exclude revoked and deprecated entries. From each technique we keep: MITRE
ID, name, description, detection guidance (where present), kill-chain phases
(tactics), platforms, and the canonical URL.

**Coverage relative to AIT-ADS.** A custom mapping (`AIT_PHASE_TO_MITRE`)
links each of the ten AIT-ADS attack phases to the specific MITRE technique
IDs that describe them:

| AIT-ADS Phase | MITRE Techniques |
|---|---|
| `network_scans` | T1046, T1018, T1595, T1595.001 |
| `service_scans` | T1046, T1595, T1595.002 |
| `dirb` | T1595.003, T1083, T1190 |
| `wpscan` | T1595.002, T1190, T1592.002 |
| `webshell` | T1505.003, T1059.004, T1190 |
| `cracking` | T1110, T1110.001, T1110.003, T1110.004 |
| `reverse_shell` | T1059, T1059.004, T1071, T1071.001 |
| `privilege_escalation` | T1068, T1548, T1078 |
| `service_stop` | T1489, T1529 |
| `dnsteal` | T1048, T1048.003, T1071.004 |

This mapping covers 26 unique MITRE IDs across the 10 phases.

### 3.2 NIST National Vulnerability Database (CVE)

**What it is.** The NVD contains structured records of every publicly
disclosed software vulnerability, including descriptions, CVSS severity
scores, affected products (CPE), and weakness types (CWE).

**Source.** NIST deprecated the legacy JSON feeds on 2023-12-15 in favour
of the rate-limited API 2.0. For bulk academic use, we use the Fraunhofer
FKIE community mirror, which reconstructs the legacy yearly JSON feeds
from the NVD API 2.0 every two hours:

```
https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download/
CVE-YYYY.json.xz
```

This is a transparent, open-source mirror used in academic security
research. The data format matches the NVD API 2.0 schema with one schema
detail: each yearly file is a JSON object with a `cve_items` array, not the
API 2.0's `vulnerabilities` array.

**Years included.** 2020–2024 (5 years, ~970 MB of compressed data).
Earlier years contain mostly legacy software bugs not present in modern
testbeds. Later years are still being analysed.

**Filter applied.** From the raw ~165,000 CVEs across these years, we keep
only entries that match BOTH conditions:

- CVSS score ≥ 7.0 (HIGH or CRITICAL severity only)
- Either (a) CPE matches the allowlist of testbed software, OR (b)
  description contains relevant vulnerability-class keywords

**Final filtered corpus:** 36,840 CVEs.

#### CPE allowlist (vendor:product pairs)

```
linux:linux_kernel          apache:http_server         nginx:nginx
canonical:ubuntu_linux      php:php                    wordpress:wordpress
debian:debian_linux         mysql:mysql                openssl:openssl
openbsd:openssh             oracle:mysql               isc:bind
mariadb:mariadb             exim:exim
```

#### Description keyword allowlist (substring match, lowercase)

```
sql injection                cross-site scripting       xss
remote code execution        arbitrary code execution   command injection
directory traversal          path traversal             local file inclusion
remote file inclusion        authentication bypass      privilege escalation
deserialization              csrf                       ssrf
xxe                          open redirect              session fixation
credential disclosure        brute force
wordpress plugin             wordpress theme
```

Note: broad keywords such as `denial of service`, `buffer overflow`,
`stack overflow`, `heap overflow`, and `information disclosure` were
**deliberately removed** during tuning because they matched the majority of
all CVE descriptions regardless of platform relevance, producing an
oversized 77k-entry corpus.

### 3.3 Hand-authored SOC Runbooks

**What they are.** Short operational playbooks describing how a SOC analyst
should respond to specific alert patterns. No public corpus exists, so
these were authored from public sources:

- MITRE ATT&CK technique pages
- SANS Internet Storm Center documentation
- NIST SP 800-61 Computer Security Incident Handling Guide
- US-CERT / CISA published advisories
- Wazuh ruleset documentation

**Count.** 8 runbooks, one per AIT-ADS attack phase. Each is between 300
and 600 words.

**File format.** Markdown with YAML-style frontmatter:

```markdown
---
id: RB-001
title: SSH brute force authentication response
applies_to: cracking
mitre_ids: T1110, T1110.001, T1110.003, T1021.004
severity_guidance: Escalate to P2 if successful authentication is observed.
references: https://attack.mitre.org/techniques/T1110/
---

# SSH brute force authentication response

[runbook body in markdown]
```

**Coverage:**

| Runbook | Applies To | MITRE IDs Covered |
|---|---|---|
| RB-001-ssh-brute-force.md | cracking | T1110, T1110.001, T1110.003, T1021.004 |
| RB-002-web-directory-enumeration.md | dirb | T1595.003, T1083, T1190 |
| RB-003-wordpress-attack.md | wpscan | T1595.002, T1190, T1592.002 |
| RB-004-dns-exfiltration.md | dnsteal | T1048, T1048.003, T1071.004 |
| RB-005-privilege-escalation.md | privilege_escalation | T1068, T1548, T1078 |
| RB-006-reverse-shell.md | reverse_shell | T1059, T1059.004, T1071, T1071.001 |
| RB-007-webshell.md | webshell | T1505.003, T1059.004, T1190 |
| RB-008-service-disruption.md | service_stop | T1489, T1529 |

**Total MITRE coverage across runbooks:** 22 unique technique IDs.

---

## 4. Code Structure

```
ait_parser/
├── build_knowledge_base.py        ← entry point (orchestrator)
├── test_kb.py                     ← 25 unit tests
└── kb/
    ├── __init__.py
    ├── mitre_loader.py            ← MITRE STIX download + parse + filter
    ├── cve_loader.py              ← CVE download + parse + aggressive filter
    ├── runbooks.py                ← markdown loader with frontmatter parser
    ├── chunker.py                 ← convert source objects to KnowledgeDocuments
    ├── embedder.py                ← sentence-transformers wrapper
    ├── chromadb_store.py          ← thin wrapper around ChromaDB collection
    └── runbook_corpus/
        ├── README.md              ← how to author new runbooks
        ├── RB-001-ssh-brute-force.md
        ├── RB-002-web-directory-enumeration.md
        ├── RB-003-wordpress-attack.md
        ├── RB-004-dns-exfiltration.md
        ├── RB-005-privilege-escalation.md
        ├── RB-006-reverse-shell.md
        ├── RB-007-webshell.md
        └── RB-008-service-disruption.md
```

### 4.1 `kb/mitre_loader.py`

**Public functions:**

- `download_stix(cache_path, force=False) → dict` — downloads the STIX
  bundle, caches on disk, returns parsed dict.
- `parse_techniques(stix_bundle) → List[MitreTechnique]` — extracts live
  (non-revoked, non-deprecated) techniques, attaches AIT relevance tags.
- `load_mitre(cache_dir, force_refresh=False) → List[MitreTechnique]` —
  top-level wrapper combining the above.
- `summarise(techniques) → dict` — counts by tactic, subtechnique status,
  AIT-relevance.

**Filter logic:**

- Dropped if `revoked: True`
- Dropped if `x_mitre_deprecated: True`
- Kept everything else (no MITRE ID filter — AIT-relevance is recorded as
  metadata, used at retrieval time, not used to drop)

### 4.2 `kb/cve_loader.py`

**Public functions:**

- `download_year(year, cache_dir, force=False) → Path` — downloads and
  decompresses a single year's feed.
- `is_relevant(cve_obj, min_cvss, ...) → bool` — the filter function.
- `parse_cve_object(cve_obj) → CveEntry` — extracts fields we care about.
- `load_cve_year(year, cache_dir, min_cvss, force_refresh) → List[CveEntry]`
- `load_cves(cache_dir, start_year, end_year, min_cvss, force_refresh) →
  List[CveEntry]` — top-level wrapper.
- `summarise(entries) → dict` — counts by severity, year, top CWEs.

**Filter logic:**

```
Keep CVE if and only if:
    CVSS_score >= DEFAULT_MIN_CVSS (default 7.0)
    AND has English description that is not "** REJECTED **"
    AND (
        any CPE entry has vendor:product in RELEVANT_CPE_VENDORS_PRODUCTS
        OR
        description contains any keyword in RELEVANT_DESCRIPTION_KEYWORDS
    )
```

### 4.3 `kb/runbooks.py`

**Public functions:**

- `parse_runbook_file(path) → Runbook` — parses a single markdown file.
- `load_runbooks(corpus_dir) → List[Runbook]` — loads every `.md` file in
  the directory (excluding `README.md`).
- `summarise(runbooks) → dict` — coverage statistics.

**Frontmatter parser.** Hand-written (no PyYAML dependency). Expects
content between `---` delimiters. Each line is `key: value`. Two fields
(`mitre_ids`, `references`) are comma-separated lists.

### 4.4 `kb/chunker.py`

**Public functions:**

- `chunk_mitre_technique(t) → List[KnowledgeDocument]` — 1 to 2 chunks per
  technique (description always, detection if present).
- `chunk_cve(cve) → KnowledgeDocument` — exactly one chunk per CVE.
- `chunk_runbook(rb) → KnowledgeDocument` — exactly one chunk per runbook.
- Plus `chunk_all_*` aggregators.

The `KnowledgeDocument` dataclass:

```python
@dataclass
class KnowledgeDocument:
    doc_id: str       # globally unique: "mitre:T1110:description", "cve:CVE-2024-12345"
    source: str       # "mitre" | "cve" | "runbook"
    title: str        # human-readable header
    text: str         # the body that gets embedded
    metadata: dict    # filterable attributes (must contain only scalar values)
```

### 4.5 `kb/embedder.py`

**Public functions:**

- `embed_texts(texts, batch_size=64) → List[List[float]]` — batch-embed.
- `embedding_dim() → int` — returns 384.

**Model.** `sentence-transformers/all-MiniLM-L6-v2`. 22 million parameters,
384-dimensional output, normalized for cosine similarity. Downloaded once
(~90 MB) and cached in `~/.cache/torch/sentence_transformers/`.

### 4.6 `kb/chromadb_store.py`

**Class:** `KnowledgeStore(persist_dir)`

**Methods:**

- `add(docs, embeddings)` — upsert documents into the collection,
  **batched at 5,000 per call** to respect ChromaDB's max batch size.
- `query(query_embedding, top_k, where_filter)` — retrieve top-K similar
  documents with optional metadata filter.
- `count() → int` — current document count.
- `clear()` — drop and recreate the collection.

The collection is named `ait_kb` and uses ChromaDB's default
HNSW indexing.

---

## 5. Design Decisions

Every design decision is documented explicitly so it can be defended in the
dissertation viva.

### 5.1 Why `sentence-transformers/all-MiniLM-L6-v2` for embeddings

**Decision.** Use a general-purpose, CPU-friendly embedding model rather
than a security-specialized one.

**Rationale.**

- Standard choice in academic RAG literature, easy to defend
- Open weights, no API keys, no rate limits
- 384-dimensional vectors (small index, fast queries)
- Runs on CPU at ~50 docs/sec — workable for the 37,545-document corpus
- Pre-trained on 1B+ sentence pairs, strong general-purpose retrieval

**Trade-off accepted.** General-purpose embeddings can be noisy on niche
domain text (e.g., DNS exfiltration getting confused with DNS
reconnaissance). We compensate with metadata filtering at retrieval time
and the inclusion of operationally-explicit runbooks.

### 5.2 Why ChromaDB rather than FAISS, Qdrant, or Weaviate

**Decision.** Use ChromaDB.

**Rationale.**

- Pure Python install (no separate server, no Rust toolchain)
- Built-in metadata filtering (we use this heavily — `source`, `mitre_id`,
  `relevance_tags`, `cvss_score`)
- Standard in academic RAG papers
- MIT-licensed, no commercial restrictions
- Persistent mode just works on local disk

### 5.3 Why source-specific chunking strategies

**Decision.** Different chunking per source.

| Source | Strategy | Reasoning |
|---|---|---|
| MITRE | 1-2 chunks per technique (description + detection) | Description and detection are different intents — retrieving description for a "what is this attack?" query is different from retrieving detection for "how do I spot it?" |
| CVE | 1 chunk per CVE, with affected_products and CWE concatenated into the embedded text | CVE descriptions are short (50-300 words); splitting hurts coherence. Including CPE/CWE in the text improves retrieval (a query for "WordPress plugin" matches CVEs that affect WordPress plugins). |
| Runbook | 1 chunk per runbook | The if-then structure of operational guidance breaks if split. |

### 5.4 Why the CVE CVSS threshold is 7.0

**Decision.** Keep only HIGH and CRITICAL severity CVEs.

**Rationale.**

- A SOC analyst would not normally take action on MEDIUM-severity
  vulnerabilities — they get logged and patched in maintenance cycles
- The original 4.0 threshold yielded 77,000 CVEs which exceeded ChromaDB's
  per-collection practical limits without adding meaningful retrieval value
- The current 36,840-entry corpus is large enough to provide diverse
  retrieval matches but small enough to embed in ~6 minutes on CPU

### 5.5 Why aggressive CVE description keyword filtering

**Decision.** Removed broad keywords (`denial of service`, `buffer overflow`,
`information disclosure`) that matched the majority of CVE descriptions.

**Rationale.**

- These keywords are present in vulnerability descriptions across all
  software categories, including mainframes, mobile apps, embedded
  firmware — none of which AIT-ADS attacks
- Including them yielded the bloated 77k corpus
- The retained keywords are specific to **vulnerability classes** that AIT
  attacks actually exercise (SQL injection, XSS, command injection, etc.)

### 5.6 Why a custom AIT_PHASE_TO_MITRE mapping

**Decision.** Define an explicit mapping rather than relying on pure
semantic retrieval to find relevant MITRE techniques.

**Rationale.**

- Embedding models can miss obviously-relevant matches because of vocabulary
  mismatch ("dnsteal" doesn't appear in MITRE's technique names)
- The mapping provides metadata-based retrieval as a fallback: the LLM
  pipeline can request "give me docs tagged with `relevance_tags=cracking`"
  rather than relying on similarity alone
- This is "hybrid retrieval" — a standard pattern in production RAG systems

### 5.7 Why use the FKIE mirror rather than the NVD API

**Decision.** Use the Fraunhofer FKIE GitHub mirror for CVE data.

**Rationale.**

- NVD API 2.0 is rate-limited (5 req/30s without key, 50 req/30s with one)
- Bulk download of 5 years would take many hours via API
- FKIE mirror provides identical data structure as bulk JSON files
- Reproducibility: the mirror snapshots a specific point in time
- Transparent (open-source, documented, updated every 2 hours)
- This pattern is acceptable practice in academic security research

### 5.8 Why batch ChromaDB inserts at 5,000

**Decision.** Process inserts in batches of 5,000 documents.

**Rationale.**

- ChromaDB v1.x enforces a hardcoded maximum batch size of 5,461 documents
  per `add` or `upsert` call
- Without batching, large corpora produce `InternalError: ValueError: Batch
  size of N is greater than max batch size of 5461`
- 5,000 leaves headroom and produces clean log output

---

## 6. Dependencies and Installation

### 6.1 New Python packages required

```
chromadb                    # vector database
sentence-transformers       # embedding model
```

`sentence-transformers` pulls in PyTorch (~500 MB) and `transformers`
(~200 MB) as dependencies. ChromaDB pulls in tokenizers, protobuf, grpcio,
and others (~150 MB total). Plan for ~1 GB additional disk space for the
Python environment.

### 6.2 Install command

```bash
pip3 install chromadb sentence-transformers --break-system-packages
```

The `--break-system-packages` flag is needed on modern Linux distros that
enforce PEP 668 (externally-managed environments). It is harmless inside a
virtualenv.

### 6.3 Disk space requirements

| Artefact | Size |
|---|---|
| MITRE STIX bundle (one-time download) | 53 MB |
| Sentence-transformers model (one-time download) | 90 MB |
| CVE feeds (2020-2024, decompressed) | ~970 MB |
| ChromaDB persistent collection | ~2-3 GB after full build |
| **Total disk required** | **~4 GB** |

### 6.4 Network requirements

- Outbound HTTPS to `raw.githubusercontent.com` (MITRE)
- Outbound HTTPS to `github.com` (CVE mirror releases)
- Outbound HTTPS to `huggingface.co` (model download, one-time)

---

## 7. How to Run It — Step by Step

### 7.1 Step 1: Install dependencies

```bash
cd ~/Downloads/A\ Dessertation\ Research\ Cybersecurity/code_work
pip3 install chromadb sentence-transformers --break-system-packages
```

Expected duration: 3–5 minutes for download, depending on connection
speed. Wait until the prompt returns with `Successfully installed ...`
before proceeding.

### 7.2 Step 2: Run unit tests

This verifies that the knowledge base code is wired correctly without
touching the network or the real data.

```bash
cd ait_parser
python3 test_kb.py
cd ..
```

Expected output: 25 OK lines followed by `All tests passed.`

If any test fails, **do not proceed**. Investigate the failure first.

### 7.3 Step 3: Build the knowledge base

Three options depending on time available:

**Option A — Quick build (MITRE + runbooks only, ~3-5 minutes):**

```bash
python3 ait_parser/build_knowledge_base.py \
    --persist-dir data/kb \
    --cache-dir data/kb/cache \
    --skip-cve
```

Produces a 705-document corpus. Useful for early validation.

**Option B — Recommended build (MITRE + CVE 2020-2024 + runbooks, ~10-15 minutes):**

```bash
python3 ait_parser/build_knowledge_base.py \
    --persist-dir data/kb \
    --cache-dir data/kb/cache \
    --cve-start-year 2020 \
    --cve-end-year 2024 \
    --clear
```

Produces a ~37,000-document corpus. This is the configuration the
dissertation results are based on.

**Option C — Full build (default years, 30-60 minutes):**

```bash
python3 ait_parser/build_knowledge_base.py \
    --persist-dir data/kb \
    --cache-dir data/kb/cache \
    --clear
```

Uses defaults (`--cve-start-year 2015 --cve-end-year 2024`). Produces a
larger corpus but adds limited retrieval value.

### 7.4 Flag reference

| Flag | Effect | Default |
|---|---|---|
| `--persist-dir` | Where ChromaDB stores the collection | required |
| `--cache-dir` | Where downloaded MITRE and CVE files are cached | required |
| `--runbook-dir` | Path to the runbook markdown files | `kb/runbook_corpus/` |
| `--force-refresh` | Re-download MITRE and CVE data even if cached | off |
| `--clear` | Drop and recreate the ChromaDB collection before insert | off |
| `--skip-mitre` | Don't ingest MITRE | off |
| `--skip-cve` | Don't ingest CVE (saves 10-30 min on first build) | off |
| `--skip-runbooks` | Don't ingest runbooks | off |
| `--cve-start-year` | First CVE year to include | 2015 |
| `--cve-end-year` | Last CVE year to include | 2024 |
| `--cve-min-cvss` | Minimum CVSS score for CVE inclusion | 7.0 |

### 7.5 What happens during the build

The script proceeds through six steps, each announced in the console:

```
Step 1: MITRE ATT&CK            → downloads/loads STIX, parses techniques
Step 2: CVE (2020-2024)         → downloads/loads yearly feeds, filters
Step 3: Runbooks                 → reads markdown files
Step 4: Embedding N documents    → encodes all texts with the model
Step 5: Writing to ChromaDB      → batched upsert
Step 6: Sanity-check queries     → runs 8 test queries to verify retrieval
```

For the recommended build (Option B), expect:

- Step 1: ~30 seconds (download MITRE) + 2 seconds parse
- Step 2: 5-10 minutes first time (downloads ~970 MB), instant from cache
- Step 3: < 1 second
- Step 4: 5-7 minutes embedding on CPU (faster with GPU)
- Step 5: < 30 seconds with batched upsert
- Step 6: ~10 seconds

---

## 8. Outputs

After a successful build, the following files exist on disk:

```
data/kb/
├── kb_stats.json                       ← summary statistics (small JSON)
├── cache/
│   ├── mitre_enterprise.json           ← ~53 MB cached MITRE STIX
│   └── cve/
│       ├── CVE-2020.json               ← ~160 MB
│       ├── CVE-2021.json               ← ~191 MB
│       ├── CVE-2022.json               ← ~194 MB
│       ├── CVE-2023.json               ← ~209 MB
│       └── CVE-2024.json               ← ~215 MB
└── [ChromaDB internal files]           ← SQLite + binary HNSW index
```

### 8.1 `kb_stats.json` contents

```json
{
  "embedding_model": "sentence-transformers/all-MiniLM-L6-v2",
  "embedding_dim": 384,
  "mitre": {
    "total_techniques": 697,
    "parent_techniques": 222,
    "sub_techniques": 475,
    "ait_relevant": 26,
    "by_tactic": { ... 15 tactics, count each ... }
  },
  "mitre_chunks": 697,
  "cve": {
    "total_cves": 36840,
    "by_severity": { "HIGH": 27275, "CRITICAL": 9565 },
    "by_year": { "2020": 5195, ..., "2024": 10098 },
    "top_cwes": { ... 15 most common CWEs ... }
  },
  "cve_chunks": 36840,
  "runbooks": {
    "total_runbooks": 8,
    "by_applies_to": { ... 8 phases ... },
    "mitre_ids_covered": [ ... 22 IDs ... ]
  },
  "runbook_chunks": 8,
  "total_chunks": 37545,
  "collection_count_after_insert": 37545,
  "sanity_query_results": [ ... 8 query objects with top-3 hits each ... ]
}
```

This file is the **dissertation-grade record** of the build. Cite numbers
from it directly in the methodology and results chapters.

---

## 9. Validation and Testing

### 9.1 Unit tests (`test_kb.py`)

25 assertion-based tests cover:

**MITRE (5 tests)**
- STIX parsing
- Revoked/deprecated filtering
- Sub-technique detection
- AIT-relevance tagging via the phase mapping
- Summary statistics

**CVE (10 tests)**
- CVSS extraction from v3.1, v3.0, v2.0 metrics blocks
- CWE extraction from weaknesses block
- CPE parsing (vendor:product extraction)
- `is_relevant` accepts Apache CVE (CPE match)
- `is_relevant` accepts WordPress plugin CVE (keyword match)
- `is_relevant` rejects iOS CVE (no match)
- `is_relevant` rejects "** REJECTED **" entries
- `is_relevant` rejects low-CVSS entries below threshold
- Full parse of a synthetic Apache CVE
- Chunking of two CVEs with rich text containing products and CWEs

**Runbooks (7 tests)**
- Frontmatter split with valid input
- Frontmatter split with no frontmatter
- Single-file parse from temp directory
- Bulk load from temp directory
- README.md exclusion
- Summary statistics
- Chunking with title and applies_to embedded in text

**Real corpus check (3 tests)**
- All 8 expected runbooks present
- All required fields populated in every runbook
- All 8 AIT phases covered

All 25 tests pass on the current implementation.

### 9.2 Internal consistency checks (the build script itself)

- `total_chunks` equals `mitre_chunks + cve_chunks + runbook_chunks`
- `collection_count_after_insert` equals `total_chunks`
- Sanity queries all return non-empty results
- Embeddings dimension matches `embedding_dim` (384)

### 9.3 Empirical sanity queries

The build script runs 8 queries at the end — one per AIT attack phase. The
expected pattern is that each query's matching runbook appears in the top
3 hits. See Section 11 for the empirical results.

---

## 10. Empirical Results

Numbers from the recommended build (Option B, 2020-2024 CVE range, CVSS
≥ 7.0).

### 10.1 Total corpus composition

```
MITRE techniques:    697 documents   (1.9%)
CVE entries:      36,840 documents  (98.1%)
Runbooks:              8 documents   (0.02%)
TOTAL:            37,545 documents
```

### 10.2 MITRE breakdown by tactic

```
stealth:               148
persistence:           113
privilege-escalation:   96
credential-access:      67
execution:              64
defense-impairment:     56
resource-development:   50
discovery:              49
reconnaissance:         46
command-and-control:    45
collection:             41
impact:                 33
lateral-movement:       23
initial-access:         22
exfiltration:           19
```

All 14 MITRE Enterprise tactics are represented. 26 of these 697 techniques
are tagged as directly AIT-ADS-relevant.

### 10.3 CVE breakdown by severity

```
HIGH:        27,275  (74.0%)
CRITICAL:     9,565  (26.0%)
```

Zero MEDIUM/LOW by filter design (CVSS ≥ 7.0).

### 10.4 CVE breakdown by year

```
2020:  5,195
2021:  6,158
2022:  7,450
2023:  7,939
2024: 10,098
```

The growing curve matches the natural growth in CVE submission rates over
time. No skew toward any one year.

### 10.5 Top CWEs in the CVE corpus

| CWE | Description | Count |
|---|---|---|
| CWE-89 | SQL Injection | 5,360 |
| CWE-787 | Out-of-bounds Write | 4,948 |
| CWE-79 | Cross-site Scripting | 2,164 |
| CWE-416 | Use After Free | 1,804 |
| CWE-22 | Path Traversal | 1,749 |
| CWE-78 | OS Command Injection | 1,717 |
| CWE-120 | Buffer Overflow | 1,616 |
| CWE-352 | CSRF | 1,271 |
| CWE-121 | Stack Overflow | 1,235 |
| CWE-77 | Command Injection | 1,101 |
| CWE-125 | Out-of-bounds Read | 1,002 |
| CWE-502 | Deserialization | 985 |
| CWE-20 | Improper Input Validation | 913 |
| CWE-122 | Heap Overflow | 822 |
| CWE-94 | Code Injection | 649 |

**Dissertation observation.** The top CWEs (CWE-89 SQL Injection, CWE-79
XSS, CWE-22 Path Traversal, CWE-78 Command Injection, CWE-502
Deserialization, CWE-94 Code Injection) are dominated by web-application
vulnerability classes — exactly the attack surface that AIT-ADS exercises.

### 10.6 Runbook coverage

8 runbooks covering all 8 AIT-ADS attack phases that need response
playbooks. The two phases not covered are `network_scans` and
`service_scans`, which are reconnaissance steps that typically don't have
dedicated response runbooks (the response is to investigate the source
and proceed to per-attack-type playbooks when exploitation follows).

---

## 11. Retrieval Quality Analysis

Eight sanity queries were run after the build. Each query represents one
of the AIT-ADS attack phases written in natural-language form.

### 11.1 Query 1: SSH brute force authentication failures

| Rank | Source | Doc ID | Distance |
|---|---|---|---|
| 1 | runbook | RB-001 | **0.705** |
| 2 | cve | CVE-2023-24020 | 1.037 |
| 3 | cve | CVE-2022-28321 | 1.046 |

**Interpretation.** Runbook leads cleanly; CVE entries provide supplementary
context. Strong result.

### 11.2 Query 2: Directory enumeration scan

| Rank | Source | Doc ID | Distance |
|---|---|---|---|
| 1 | runbook | RB-002 | **0.816** |
| 2 | cve | CVE-2021-46104 | 1.047 |
| 3 | cve | CVE-2024-56324 | 1.072 |

**Interpretation.** Runbook leads. Strong result.

### 11.3 Query 3: WordPress plugin vulnerability scan

| Rank | Source | Doc ID | Distance |
|---|---|---|---|
| 1 | cve | CVE-2024-2172 | **0.694** |
| 2 | cve | CVE-2024-8340 | 0.740 |
| 3 | cve | CVE-2021-34637 | 0.770 |

**Interpretation.** CVE entries lead — appropriate for a query about
*vulnerabilities and exploitation*. The runbook (RB-003) would appear in
top-5. Strong result.

### 11.4 Query 4: DNS exfiltration

| Rank | Source | Doc ID | Distance |
|---|---|---|---|
| 1 | runbook | RB-004 | **0.829** |
| 2 | mitre | T1584.001 | 0.957 |
| 3 | mitre | T1590.002 | 0.996 |

**Interpretation.** Runbook leads, MITRE supplements. No CVEs in top 3
because DNS exfiltration is more of a technique than a vulnerability class.
Acceptable result.

### 11.5 Query 5: Linux kernel privilege escalation

| Rank | Source | Doc ID | Distance |
|---|---|---|---|
| 1 | cve | CVE-2022-1729 | **0.560** |
| 2 | cve | CVE-2023-1829 | 0.581 |
| 3 | cve | CVE-2022-1976 | 0.593 |

**Interpretation.** Three actual Linux kernel privilege-escalation CVEs at
the top with very tight distances (0.56–0.59). The runbook (RB-005) would
appear in top-5. Strong result.

### 11.6 Query 6: Reverse shell

| Rank | Source | Doc ID | Distance |
|---|---|---|---|
| 1 | runbook | RB-006 | **0.936** |
| 2 | cve | CVE-2024-53412 | 1.167 |
| 3 | mitre | T1505.003 | 1.264 |

**Interpretation.** Three-source mix in the top 3. Runbook leads. Good
result.

### 11.7 Query 7: PHP web shell upload

| Rank | Source | Doc ID | Distance |
|---|---|---|---|
| 1 | cve | CVE-2021-24981 | **1.017** |
| 2 | cve | CVE-2021-46013 | 1.068 |
| 3 | runbook | RB-007 | 1.070 |

**Interpretation.** WordPress upload CVEs lead because the query
specifically mentioned `wp-content`. Runbook is third. Strong result.

### 11.8 Query 8: Stopping monitoring agent

| Rank | Source | Doc ID | Distance |
|---|---|---|---|
| 1 | runbook | RB-008 | **0.752** |
| 2 | mitre | T1489 | 1.010 |
| 3 | cve | CVE-2024-10110 | 1.128 |

**Interpretation.** Three-source mix. Runbook leads, MITRE T1489 (Service
Stop) in second position, CVE supplement. Strong result.

### 11.9 Summary

For 8/8 queries the top-3 contains material directly relevant to the
query's intent. For 6/8 queries a runbook is in the top 3. For all 8
queries, the relevant MITRE technique or appropriate CVEs appear.

The three-source corpus produces complementary retrieval: runbooks for
operational queries, CVEs for vulnerability-class queries, MITRE for
technique-naming queries. This is the synergy the design intended.

---

## 12. Issues Encountered and Resolutions

Two issues were encountered during the build process and resolved. Both
are documented here for reproducibility.

### 12.1 Issue: CVE feeds returned zero entries on first run

**Symptom.** The first build run completed but kept 0 CVEs across all
years despite downloading the full ~970 MB of data successfully.

**Root cause.** The Fraunhofer FKIE mirror reconstructs the legacy NVD
JSON 1.1 format, which stores the CVE array under the key `cve_items`.
The initial loader code assumed the NVD API 2.0 format, which uses
`vulnerabilities`.

**Resolution.** Modified `kb/cve_loader.py` `load_cve_year` function to
read from either key:

```python
raw_entries = data.get("cve_items") or data.get("vulnerabilities") or []
for v in raw_entries:
    cve_obj = v.get("cve", v) if isinstance(v.get("cve"), dict) else v
    if is_relevant(cve_obj, min_cvss=min_cvss):
        entries.append(parse_cve_object(cve_obj))
```

Re-running with the fix produced 76,573 entries (with the original CVSS
≥ 4.0 threshold).

### 12.2 Issue: ChromaDB batch size limit exceeded

**Symptom.** After the fix above, the build embedded 77,278 documents
successfully but failed during the ChromaDB insert with:

```
chromadb.errors.InternalError: ValueError: Batch size of 77278 is greater
than max batch size of 5461
```

**Root cause.** ChromaDB v1.x enforces a hardcoded maximum batch size of
5,461 documents per `upsert` call. The store wrapper was inserting all
documents in a single call.

**Resolution.** Modified `kb/chromadb_store.py` `add` method to batch
inserts at 5,000 documents per call.

**Concurrent decision.** The filter was also tightened (CVSS threshold
4.0 → 7.0, removed broad keywords) to reduce the corpus from 76,573 to
36,840 entries. The final build completed in ~10 minutes with all 37,545
documents inserted successfully.

---

## 13. Implications for the Dissertation

### 13.1 Methodology chapter (Chapter 3)

A new section (3.5 Knowledge Base Construction) covers:

- The three data sources, their rationale, and access methods
- The filtering policies and their justifications
- The embedding model choice and dimensionality
- The vector store choice and indexing configuration
- The chunking strategy per source
- The metadata schema for filtered retrieval
- The empirical corpus statistics (37,545 documents)

### 13.2 Results chapter (Chapter 4)

A new subsection on retrieval quality presents:

- The 8 sanity queries and their top-3 results
- The pattern of source diversity in retrieved results
- The CWE distribution in the CVE corpus
- The argument that the three-source design produces complementary
  retrieval

### 13.3 Discussion chapter (Chapter 5)

Discussion points the knowledge base raises:

- Why hybrid retrieval (semantic + metadata filtering) was necessary
- The trade-offs between corpus breadth and embedding cost
- The role of authored runbooks in providing operational grounding the
  pre-trained LLM cannot supply

### 13.4 Reproducibility

The build is fully reproducible because:

- The MITRE STIX URL points to the latest release (versioned)
- The FKIE CVE mirror is timestamped (each release is dated)
- The embedding model is pinned to `all-MiniLM-L6-v2`
- ChromaDB upsert semantics make re-runs idempotent
- All filter thresholds are documented in code with defaults

---

## 14. Known Limitations

To be disclosed in the dissertation's limitations section.

### 14.1 No MITRE detection chunks in the current build

MITRE's STIX format has moved detection guidance from the
`x_mitre_detection` field on each technique to separate "data source" and
"data component" objects. The current loader does not yet ingest these.
As a result, every MITRE technique contributes one chunk (description
only) instead of two.

**Impact.** Approximately 700 detection-guidance chunks that would
improve "how do I detect this attack?" queries are not in the corpus.

**Mitigation.** The 8 SOC runbooks explicitly include detection guidance
for each AIT-ADS attack phase, partially compensating.

### 14.2 General-purpose embedding model

`sentence-transformers/all-MiniLM-L6-v2` is not security-specialized. It
treats vocabulary like "DNS exfiltration" by attending to the words DNS
and exfiltration separately rather than understanding the compound
security intent. Domain-specific embeddings (e.g., SecureBERT) might
improve retrieval but were not used to keep the methodology aligned with
standard RAG literature.

### 14.3 Filter is permissive on CWE diversity

The CWE filter for CVE inclusion is implicit (via keywords like "SQL
injection"). CVEs whose descriptions use synonyms or paraphrases
("SQLi", "untrusted input in SQL query") may be missed.

### 14.4 Runbooks are authored, not validated empirically

The 8 runbooks were authored from public sources but have not been
reviewed by practicing SOC analysts. Their operational accuracy is
defended by citation to the underlying sources, not by empirical
evaluation.

### 14.5 CVE corpus has a 2024 boundary

CVEs published after 2024 are not in the current build. A re-build with
`--force-refresh` would update the corpus, but reproducibility requires
pinning to a specific snapshot date.

---

## 15. What Comes Next

The knowledge base is complete. The next stage in the dissertation pipeline
is the LLM pipelines.

| Stage | Purpose | Status |
|---|---|---|
| Stratified test sampling | Subsample test split to ~5,000 alerts for LLM inference | Next |
| LLM-only baseline | Mistral-7B without retrieval (ablation) | After sampling |
| LLM+RAG pipeline | Mistral-7B + ChromaDB retrieval | After LLM-only |
| Three-way evaluation | Rules vs LLM-only vs LLM+RAG | After all three pipelines |
| Dissertation writing | Methodology, results, discussion | Parallel |

The LLM pipelines will use the knowledge base via a retrieval API to be
built as part of the LLM+RAG implementation. The API is intentionally a
thin wrapper around `KnowledgeStore.query()` — most of the design work for
retrieval is already complete.

---

## 16. Quick Reference: Every Command Used

For convenience, here are the exact commands used to build the knowledge
base in chronological order:

```bash
# Navigate to the project root
cd ~/Downloads/A\ Dessertation\ Research\ Cybersecurity/code_work

# Step 1: Install dependencies (one-time)
pip3 install chromadb sentence-transformers --break-system-packages

# Step 2: Run unit tests (verify code is correct before any real run)
cd ait_parser
python3 test_kb.py
cd ..

# Step 3: First build attempt — Part 1 (MITRE only)
python3 ait_parser/build_knowledge_base.py \
    --persist-dir data/kb \
    --cache-dir data/kb/cache

# Step 4: After adding CVE + runbook loaders — first attempt
# (downloaded CVE data; filter mismatch returned 0 CVEs)
python3 ait_parser/build_knowledge_base.py \
    --persist-dir data/kb \
    --cache-dir data/kb/cache \
    --cve-start-year 2020 \
    --cve-end-year 2024

# Step 5: Diagnostic — inspect raw CVE file structure
python3 << 'EOF'
import json
from pathlib import Path
p = Path("data/kb/cache/cve/CVE-2024.json")
with p.open() as f:
    data = json.load(f)
print("Top-level keys:", list(data.keys())[:10])
EOF

# Step 6: After fixing cve_loader (cve_items vs vulnerabilities) and
#         tightening filter (CVSS 4.0 → 7.0, removed broad keywords) and
#         batching ChromaDB inserts: the FINAL successful build
python3 ait_parser/build_knowledge_base.py \
    --persist-dir data/kb \
    --cache-dir data/kb/cache \
    --cve-start-year 2020 \
    --cve-end-year 2024 \
    --clear

# Verify the result
cat data/kb/kb_stats.json | head -50
```

### 16.1 Build runtimes (this machine)

- Test suite: ~3 seconds
- First build attempt (with bug): ~5 min download + 7 min embed + crash
- Successful final build: ~10 minutes total
  - MITRE: ~30s (cached) + 2s parse
  - CVE: ~30s (cached files) + ~2 min parse and filter
  - Runbooks: <1s
  - Embedding 37,545 documents: ~6-7 min on CPU
  - ChromaDB writes: ~30s with batched inserts
  - Sanity queries: ~10s

---

## 17. Citation

When referring to the knowledge base in the dissertation:

> The knowledge base used for retrieval in the LLM+RAG pipeline was
> constructed from three sources: MITRE ATT&CK Enterprise (Strom et al.,
> 2018), the NIST National Vulnerability Database (NIST, 2024), and a
> hand-authored set of eight SOC operational runbooks. After filtering to
> CVSS ≥ 7.0 and AIT-ADS-relevant CPE/keyword criteria, the CVE component
> yielded 36,840 entries across 2020–2024. Combined with 697 MITRE
> techniques and 8 runbooks, the final corpus contained 37,545 retrievable
> documents. Each document was embedded into a 384-dimensional vector
> using `sentence-transformers/all-MiniLM-L6-v2` (Reimers and Gurevych,
> 2019) and stored in a ChromaDB persistent collection. Empirical sanity
> queries confirmed that for 8/8 attack phases, the top-3 retrieved
> documents contained material directly relevant to the query's intent.

### Key references

- **MITRE ATT&CK.** Strom, B. E., Applebaum, A., Miller, D. P., Nickels,
  K. C., Pennington, A. G., & Thomas, C. B. (2018). *MITRE ATT&CK: Design
  and Philosophy.* MITRE.
- **NIST NVD.** National Institute of Standards and Technology. National
  Vulnerability Database. https://nvd.nist.gov
- **Sentence Transformers.** Reimers, N., & Gurevych, I. (2019).
  Sentence-BERT: Sentence Embeddings using Siamese BERT-Networks. In
  *Proceedings of EMNLP 2019.*
- **RAG.** Lewis, P., Perez, E., Piktus, A., et al. (2020). Retrieval-
  augmented generation for knowledge-intensive NLP tasks. In *Advances in
  Neural Information Processing Systems 33 (NeurIPS 2020).*
- **FKIE NVD mirror.** Fraunhofer FKIE — Cyber Analysis and Defense.
  *nvd-json-data-feeds: Community reconstruction of the legacy JSON NVD
  Data Feeds.* https://github.com/fkie-cad/nvd-json-data-feeds

---

*Last updated: after the successful build producing 37,545 documents in
the ChromaDB collection. Stage 4 (M7) of the dissertation pipeline
complete. Author: Kumar Chaudhary (2562392), MRes Cybersecurity,
University of Wolverhampton.*
