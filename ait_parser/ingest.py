"""
ingest.py — Stream AIT-ADS JSONL files, normalise to UnifiedAlert, write outputs.

Usage:
    python ingest.py --input data/ait-ads --output data/processed
    python ingest.py --input data/ait-ads --output data/processed --scenarios fox shaw
    python ingest.py --input data/ait-ads --output data/processed --limit 1000  # smoke test

Outputs:
    data/processed/alerts.jsonl       -- one UnifiedAlert per line, preserves raw_record (for RAG/LLM)
    data/processed/alerts.parquet     -- flat columnar (for ML baselines)  [requires pyarrow]
    data/processed/alerts.csv         -- flat CSV (for inspection)         [fallback if no pyarrow]
    data/processed/stats.json         -- counts, breakdowns, validation
    data/processed/parse_errors.jsonl -- records that failed to parse, for debugging

Exit code 0 if counts match Zenodo's published numbers, 1 otherwise.
"""

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterator

from parsers import UnifiedAlert
from parsers import wazuh_parser, suricata_parser, aminer_parser


SCENARIOS = ["fox", "harrison", "russellmitchell", "santos",
             "shaw", "wardbeck", "wheeler", "wilson"]

# Zenodo-published expected counts (per source, totals across all scenarios)
EXPECTED_TOTALS = {"wazuh": 2_293_628, "suricata": 306_635, "aminer": 55_558}
EXPECTED_GRAND_TOTAL = 2_655_821


def iter_aminer_file(path: Path, scenario: str, error_log) -> Iterator[UnifiedAlert]:
    with path.open("r") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                error_log.write(json.dumps({"file": str(path), "line": line_no,
                                            "error": f"json: {e}"}) + "\n")
                continue
            alert = aminer_parser.parse_record(record, scenario)
            if alert is None:
                error_log.write(json.dumps({"file": str(path), "line": line_no,
                                            "error": "aminer parser returned None"}) + "\n")
                continue
            yield alert


def iter_wazuh_file(path: Path, scenario: str, error_log) -> Iterator[UnifiedAlert]:
    """Dispatches each line to either Suricata or native Wazuh parser."""
    with path.open("r") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as e:
                error_log.write(json.dumps({"file": str(path), "line": line_no,
                                            "error": f"json: {e}"}) + "\n")
                continue

            if suricata_parser.is_suricata_record(record):
                alert = suricata_parser.parse_record(record, scenario)
            else:
                alert = wazuh_parser.parse_record(record, scenario)

            if alert is None:
                error_log.write(json.dumps({"file": str(path), "line": line_no,
                                            "error": "parser returned None"}) + "\n")
                continue
            yield alert


def write_outputs(alerts_iter: Iterator[UnifiedAlert], out_dir: Path, limit: int | None):
    """Stream alerts to JSONL and a flat tabular file. Returns counters."""
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / "alerts.jsonl"

    # Try parquet via pyarrow; fall back to CSV.
    use_parquet = False
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
        use_parquet = True
    except ImportError:
        pass

    by_source = Counter()
    by_scenario_source = defaultdict(Counter)
    by_severity = Counter()
    n_attack_phase_eligible = 0  # filled later by labeller; placeholder here

    flat_rows: list[dict] = []   # accumulate flat rows in memory; 2.6M rows is fine
    written = 0

    with jsonl_path.open("w") as jf:
        for alert in alerts_iter:
            if limit is not None and written >= limit:
                break
            jf.write(json.dumps(alert.to_jsonl_dict(), default=str) + "\n")
            flat_rows.append(alert.to_flat_dict())
            by_source[alert.source_ids] += 1
            by_scenario_source[alert.scenario][alert.source_ids] += 1
            by_severity[alert.severity_norm] += 1
            written += 1
            if written % 100_000 == 0:
                print(f"  ... {written:,} alerts written", file=sys.stderr)

    # Write flat output
    if flat_rows:
        if use_parquet:
            table = pa.Table.from_pylist(flat_rows)
            pq.write_table(table, out_dir / "alerts.parquet")
        else:
            csv_path = out_dir / "alerts.csv"
            fieldnames = list(flat_rows[0].keys())
            with csv_path.open("w", newline="") as cf:
                writer = csv.DictWriter(cf, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(flat_rows)

    return {
        "total_written": written,
        "by_source": dict(by_source),
        "by_scenario_source": {k: dict(v) for k, v in by_scenario_source.items()},
        "by_severity_norm": dict(by_severity),
        "output_format": "parquet" if use_parquet else "csv",
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, type=Path,
                    help="Directory containing the unzipped AIT-ADS JSON files")
    ap.add_argument("--output", required=True, type=Path,
                    help="Directory to write alerts.jsonl, alerts.parquet, stats.json")
    ap.add_argument("--scenarios", nargs="*", default=None,
                    help="Subset of scenarios to ingest (default: all 8)")
    ap.add_argument("--limit", type=int, default=None,
                    help="Stop after N alerts (smoke testing)")
    ap.add_argument("--strict", action="store_true",
                    help="Exit non-zero if counts do not match Zenodo")
    args = ap.parse_args()

    scenarios = args.scenarios or SCENARIOS
    args.output.mkdir(parents=True, exist_ok=True)

    error_log_path = args.output / "parse_errors.jsonl"
    error_log = error_log_path.open("w")

    def all_alerts():
        for scenario in scenarios:
            aminer_path = args.input / f"{scenario}_aminer.json"
            wazuh_path = args.input / f"{scenario}_wazuh.json"
            if aminer_path.exists():
                print(f"[{scenario}] aminer: {aminer_path}", file=sys.stderr)
                yield from iter_aminer_file(aminer_path, scenario, error_log)
            else:
                print(f"  WARNING: missing {aminer_path}", file=sys.stderr)
            if wazuh_path.exists():
                print(f"[{scenario}] wazuh:  {wazuh_path}", file=sys.stderr)
                yield from iter_wazuh_file(wazuh_path, scenario, error_log)
            else:
                print(f"  WARNING: missing {wazuh_path}", file=sys.stderr)

    stats = write_outputs(all_alerts(), args.output, args.limit)
    error_log.close()

    # Validation against Zenodo expectations
    validation = {"matches_zenodo": True, "discrepancies": []}
    if args.scenarios is None and args.limit is None:
        for src, expected in EXPECTED_TOTALS.items():
            got = stats["by_source"].get(src, 0)
            if got != expected:
                validation["matches_zenodo"] = False
                validation["discrepancies"].append({
                    "source": src, "expected": expected, "got": got,
                    "diff": got - expected,
                })
        total_got = stats["total_written"]
        if total_got != EXPECTED_GRAND_TOTAL:
            validation["matches_zenodo"] = False
            validation["discrepancies"].append({
                "source": "TOTAL", "expected": EXPECTED_GRAND_TOTAL, "got": total_got,
                "diff": total_got - EXPECTED_GRAND_TOTAL,
            })

    stats["validation"] = validation
    stats["scenarios_ingested"] = scenarios
    stats["expected_totals"] = EXPECTED_TOTALS
    (args.output / "stats.json").write_text(json.dumps(stats, indent=2, default=str))

    print("\n=== Summary ===", file=sys.stderr)
    print(json.dumps(stats, indent=2, default=str), file=sys.stderr)

    if args.strict and not validation["matches_zenodo"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
