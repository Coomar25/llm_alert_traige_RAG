"""
CVE (NIST NVD) loader with aggressive filtering.

Data source
-----------
The legacy NIST NVD JSON feeds were deprecated by NIST on 2023-12-15. The
official replacement is the API 2.0, but it is rate-limited (5 req / 30s
without an API key, 50 req / 30s with one) which makes bulk download
painfully slow.

We use the Fraunhofer FKIE community mirror instead:
    https://github.com/fkie-cad/nvd-json-data-feeds

They reconstruct the legacy yearly JSON feeds from the NVD API 2.0 every
two hours. The data format matches the NVD API 2.0 schema exactly. This is
a transparent, open-source mirror used in academic security research.

Filtering policy
----------------
There are ~240,000 CVEs going back to 1999. Most are completely irrelevant
to AIT-ADS (mobile, mainframe, embedded firmware). We aggressively filter
to keep only CVEs that match the AIT-ADS testbed environment:

    - Linux (Ubuntu) operating system
    - Apache HTTP server
    - WordPress and its plugins
    - MySQL / MariaDB
    - OpenSSH
    - DNS server software (BIND)
    - Exim mail server
    - General web application vulnerability classes (CWE-79, -89, -22, -78)

Two complementary filters:
    1. CPE filter — match the affected-product strings (cpe:2.3:a:vendor:...)
    2. Keyword filter — match security-relevant terms in the description

A CVE passes the filter if EITHER its CPE matches our allowlist OR its
description contains relevant keywords. This is intentionally permissive on
keywords (catches the long-tail) while strict on CPEs (catches the obvious).

After filtering 10 years of CVE data (2015-2024), we typically end up with
2,000-5,000 CVE entries — manageable for embedding and retrieval.

Year range
----------
Default 2015-2024. Earlier years contain mostly legacy software bugs not
present in modern testbeds; later years are still being analysed and may
have incomplete metadata.
"""

import gzip
import json
import lzma
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set
from urllib.request import Request, urlopen


# Community mirror — yearly feeds, lzma-compressed
CVE_FEED_URL_TEMPLATE = (
    "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/"
    "download/CVE-{year}.json.xz"
)


# -----------------------------------------------------------------------------
# Filtering rules — these define what "relevant to AIT-ADS" means in practice
# -----------------------------------------------------------------------------

# CPE vendor:product pairs that match the AIT-ADS testbed environment.
# A CVE matches if any of its CPE entries' vendor:product matches one of these.
RELEVANT_CPE_VENDORS_PRODUCTS: Set[str] = {
    # Linux / Ubuntu base OS
    "linux:linux_kernel",
    "canonical:ubuntu_linux",
    "debian:debian_linux",
    # Web servers
    "apache:http_server",
    "nginx:nginx",
    # PHP runtime
    "php:php",
    # Databases
    "mysql:mysql",
    "oracle:mysql",
    "mariadb:mariadb",
    # SSH
    "openbsd:openssh",
    # WordPress core
    "wordpress:wordpress",
    "wordpress.org:wordpress",
    "wordpress_foundation:wordpress",
    # DNS server
    "isc:bind",
    # Mail
    "exim:exim",
    # Common attack-target apps
    "openssl:openssl",
}

# Lowercase keywords that, when found in the description, mark a CVE as
# relevant even if the CPE doesn't match. These target the *type* of
# vulnerability (SQL injection, etc.) which is more useful for SOC retrieval
# than the specific product.
RELEVANT_DESCRIPTION_KEYWORDS: List[str] = [
    "sql injection",
    "cross-site scripting",
    "xss",
    "remote code execution",
    "arbitrary code execution",
    "command injection",
    "directory traversal",
    "path traversal",
    "local file inclusion",
    "remote file inclusion",
    "authentication bypass",
    "privilege escalation",
    "buffer overflow",
    "stack overflow",
    "heap overflow",
    "denial of service",
    "deserialization",
    "csrf",
    "ssrf",
    "xxe",
    "open redirect",
    "session fixation",
    "credential disclosure",
    "information disclosure",
    "brute force",
    "wordpress plugin",
    "wordpress theme",
]

# Minimum CVSS score to include — filters out trivial info-disclosure noise.
# 0.0 disables the filter; 4.0 keeps everything Medium+; 7.0 keeps High+ only.
DEFAULT_MIN_CVSS = 7.0


@dataclass
class CveEntry:
    """One parsed CVE with just the fields we care about for RAG."""
    cve_id: str
    description: str
    cvss_score: float = 0.0
    cvss_severity: str = ""               # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | ""
    cvss_vector: str = ""
    cwes: List[str] = field(default_factory=list)             # ["CWE-89", ...]
    affected_products: List[str] = field(default_factory=list) # short list, deduped
    published: str = ""
    last_modified: str = ""
    references: List[str] = field(default_factory=list)        # short URL list


def download_year(year: int, cache_dir: Path, force: bool = False) -> Path:
    """Download (or use cached) NVD feed for a single year.

    Returns the path to the decompressed JSON file. The compressed .xz is
    deleted after extraction to save disk space.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    json_path = cache_dir / f"CVE-{year}.json"
    xz_path = cache_dir / f"CVE-{year}.json.xz"

    if json_path.exists() and not force:
        return json_path

    url = CVE_FEED_URL_TEMPLATE.format(year=year)
    print(f"  Downloading CVE-{year} from {url}")
    req = Request(url, headers={"User-Agent": "ait-parser-kb/1.0"})
    with urlopen(req, timeout=180) as resp:
        xz_path.write_bytes(resp.read())

    # Decompress
    with lzma.open(xz_path, "rb") as f_in, json_path.open("wb") as f_out:
        f_out.write(f_in.read())
    xz_path.unlink()  # free the compressed copy

    return json_path


def _extract_cvss(cve_obj: dict) -> tuple[float, str, str]:
    """Pull CVSS score from the metrics block, preferring v3.1 > v3.0 > v2."""
    metrics = cve_obj.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        cvss_data = entries[0].get("cvssData", {})
        score = float(cvss_data.get("baseScore", 0.0))
        severity = cvss_data.get("baseSeverity", "")
        vector = cvss_data.get("vectorString", "")
        if not severity and key == "cvssMetricV2":
            # CVSS v2 stores severity under the entry itself, not cvssData
            severity = entries[0].get("baseSeverity", "")
        return score, severity, vector
    return 0.0, "", ""


def _extract_cwes(cve_obj: dict) -> List[str]:
    """Pull all CWE identifiers from the weaknesses block."""
    cwes: List[str] = []
    for w in cve_obj.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-"):
                cwes.append(v)
    # Dedupe preserving order
    seen: Set[str] = set()
    out: List[str] = []
    for c in cwes:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _extract_cpe_strings(cve_obj: dict) -> List[str]:
    """Pull all CPE criteria strings from configurations."""
    cpes: List[str] = []
    for cfg in cve_obj.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                criteria = m.get("criteria")
                if criteria:
                    cpes.append(criteria)
    return cpes


def _vendor_product_from_cpe(cpe: str) -> Optional[str]:
    """Extract "vendor:product" from a CPE 2.3 string.

    CPE format: cpe:2.3:part:vendor:product:version:...
    """
    parts = cpe.split(":")
    if len(parts) < 5:
        return None
    return f"{parts[3]}:{parts[4]}".lower()


def _description_text(cve_obj: dict) -> str:
    """Pull the English description text."""
    for d in cve_obj.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "").strip()
    return ""


def is_relevant(
    cve_obj: dict,
    min_cvss: float = DEFAULT_MIN_CVSS,
    relevant_vendor_products: Optional[Set[str]] = None,
    relevant_keywords: Optional[List[str]] = None,
) -> bool:
    """Decide whether this CVE should be kept.

    Truthy if:
        - CVSS score meets the minimum threshold AND
        - (CPE matches the allowlist OR description contains relevant keywords)
    """
    rvp = relevant_vendor_products if relevant_vendor_products is not None \
        else RELEVANT_CPE_VENDORS_PRODUCTS
    rkw = relevant_keywords if relevant_keywords is not None \
        else RELEVANT_DESCRIPTION_KEYWORDS

    # CVSS threshold first (cheap check)
    score, _, _ = _extract_cvss(cve_obj)
    if score < min_cvss:
        return False

    # Reject if no English description at all
    desc = _description_text(cve_obj)
    if not desc:
        return False
    desc_lower = desc.lower()

    # Skip "rejected" CVEs (placeholders for withdrawn entries)
    if desc_lower.startswith("** rejected **") or "** rejected **" in desc_lower:
        return False

    # CPE filter
    for cpe in _extract_cpe_strings(cve_obj):
        vp = _vendor_product_from_cpe(cpe)
        if vp and vp in rvp:
            return True

    # Description keyword filter
    for kw in rkw:
        if kw in desc_lower:
            return True

    return False


def _affected_products_summary(cve_obj: dict, limit: int = 5) -> List[str]:
    """Produce a short, deduped list of vendor:product strings."""
    seen: Set[str] = set()
    out: List[str] = []
    for cpe in _extract_cpe_strings(cve_obj):
        vp = _vendor_product_from_cpe(cpe)
        if vp and vp not in seen:
            seen.add(vp)
            out.append(vp)
            if len(out) >= limit:
                break
    return out


def parse_cve_object(cve_obj: dict) -> CveEntry:
    """Convert a raw CVE 2.0 JSON object into our flat CveEntry."""
    score, severity, vector = _extract_cvss(cve_obj)
    refs = [r.get("url", "") for r in cve_obj.get("references", []) if r.get("url")]
    return CveEntry(
        cve_id=cve_obj.get("id", ""),
        description=_description_text(cve_obj),
        cvss_score=score,
        cvss_severity=severity,
        cvss_vector=vector,
        cwes=_extract_cwes(cve_obj),
        affected_products=_affected_products_summary(cve_obj),
        published=cve_obj.get("published", ""),
        last_modified=cve_obj.get("lastModified", ""),
        references=refs[:3],  # cap references at 3 to keep metadata compact
    )


def load_cve_year(
    year: int,
    cache_dir: Path,
    min_cvss: float = DEFAULT_MIN_CVSS,
    force_refresh: bool = False,
) -> List[CveEntry]:
    """Download (or use cache) for a year, parse, and filter."""
    json_path = download_year(year, cache_dir, force=force_refresh)
    with json_path.open("r") as f:
        data = json.load(f)

    entries: List[CveEntry] = []
        # The FKIE mirror uses the legacy NVD JSON 1.1 key "cve_items"; the
        # current API 2.0 format uses "vulnerabilities". Support both for
        # future-proofing.
    raw_entries = data.get("cve_items") or data.get("vulnerabilities") or []
    for v in raw_entries:
            # Legacy format: CVE fields at top level. API 2.0 format: nested under "cve".
            cve_obj = v.get("cve", v) if isinstance(v.get("cve"), dict) else v
            if is_relevant(cve_obj, min_cvss=min_cvss):
                entries.append(parse_cve_object(cve_obj))
    return entries

def load_cves(
    cache_dir: Path,
    start_year: int = 2015,
    end_year: int = 2024,
    min_cvss: float = DEFAULT_MIN_CVSS,
    force_refresh: bool = False,
) -> List[CveEntry]:
    """Top-level entry point: download all years, parse, filter, return."""
    all_entries: List[CveEntry] = []
    for year in range(start_year, end_year + 1):
        print(f"\nProcessing CVE-{year}...")
        year_entries = load_cve_year(year, cache_dir, min_cvss, force_refresh)
        print(f"  CVE-{year}: kept {len(year_entries):,} relevant CVEs")
        all_entries.extend(year_entries)
    return all_entries


def summarise(entries: List[CveEntry]) -> dict:
    """Human-readable summary of the loaded CVE corpus."""
    n_total = len(entries)
    by_severity: dict[str, int] = {}
    by_year: dict[str, int] = {}
    cwe_counts: dict[str, int] = {}
    for e in entries:
        by_severity[e.cvss_severity or "UNKNOWN"] = by_severity.get(e.cvss_severity or "UNKNOWN", 0) + 1
        year = e.cve_id.split("-")[1] if "-" in e.cve_id else "unknown"
        by_year[year] = by_year.get(year, 0) + 1
        for cwe in e.cwes:
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    return {
        "total_cves": n_total,
        "by_severity": dict(sorted(by_severity.items(), key=lambda x: -x[1])),
        "by_year": dict(sorted(by_year.items())),
        "top_cwes": dict(sorted(cwe_counts.items(), key=lambda x: -x[1])[:15]),
    }
