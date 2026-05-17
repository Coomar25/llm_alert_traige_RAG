"""
label_alerts.py — Apply ground-truth labels from labels.csv to parsed alerts.

Reads:
    data/processed/alerts.jsonl        (output of ingest.py)
    data/ait-ads/labels.csv            (Zenodo ground truth)

Writes:
    data/processed/alerts_labeled.jsonl       — same shape as alerts.jsonl with
                                                 is_attack and attack_phase filled in
    data/processed/alerts_labeled.parquet     — flat tabular for ML baselines
    data/processed/label_stats.json           — counts, ratios, validation summary

Usage:
    python label_alerts.py \\
        --alerts data/processed/alerts.jsonl \\
        --labels data/ait-ads/labels.csv \\
        --output data/processed

    # Smoke test on first N alerts
    python label_alerts.py --alerts ... --labels ... --output ... --limit 5000

Exit codes:
    0 if labelling succeeds
    1 if a fatal error occurs (missing input, malformed labels.csv)
"""

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from labeller import load_labels, summarise_labels, label_alert


def parse_alert_timestamp(ts_str: str) -> float:
    """Convert the ISO 8601 timestamp from the JSONL back to epoch seconds."""
    # The parser stored timestamps via datetime.isoformat(), which produces
    # strings like "2022-01-15T02:32:32+00:00". fromisoformat parses both
    # offset and Z-suffix forms in modern Python (3.11+).
    dt = datetime.fromisoformat(ts_str)
    return dt.timestamp()


def process(
    alerts_path: Path,
    labels_path: Path,
    out_dir: Path,
    limit: int | None,
):
    out_dir.mkdir(parents=True, exist_ok=True)

    # Load labels
    print(f"Loading labels from {labels_path}", file=sys.stderr)
    by_scenario = load_labels(labels_path)
    label_summary = summarise_labels(by_scenario)
    print(f"  Loaded {label_summary['total_windows']} attack windows across "
          f"{len(label_summary['scenarios'])} scenarios", file=sys.stderr)
    print(f"  Attack types: {', '.join(label_summary['attack_types'])}", file=sys.stderr)

    # Open outputs
    jsonl_out_path = out_dir / "alerts_labeled.jsonl"
    flat_rows = []  # will accumulate for parquet/csv write at the end

    # Counters
    n_total = 0
    n_attack = 0
    n_benign = 0
    n_unknown_scenario = 0
    by_scenario_counts = defaultdict(lambda: {"attack": 0, "benign": 0, "total": 0})
    by_attack_phase = Counter()
    by_scenario_phase = defaultdict(Counter)
    severity_x_attack = defaultdict(lambda: {"attack": 0, "benign": 0})

    # Use parquet if pyarrow available
    use_parquet = False
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
        use_parquet = True
    except ImportError:
        pass

    print(f"Streaming alerts from {alerts_path}", file=sys.stderr)
    with alerts_path.open("r") as in_f, jsonl_out_path.open("w") as out_f:
        for line_no, line in enumerate(in_f, 1):
            if limit is not None and n_total >= limit:
                break

            line = line.strip()
            if not line:
                continue

            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                # Bad input line — skip (the parser shouldn't have produced this,
                # but defensive code is cheap)
                continue

            scenario = alert.get("scenario", "")
            ts_str = alert.get("timestamp")

            if not ts_str or not scenario:
                # Skip alerts that lack required fields for labelling
                continue

            try:
                ts_epoch = parse_alert_timestamp(ts_str)
            except (ValueError, TypeError):
                continue

            windows = by_scenario.get(scenario)
            if windows is None:
                # Scenario in alerts but not in labels.csv — count it
                n_unknown_scenario += 1

            is_attack, attack_phase = label_alert(ts_epoch, scenario, windows)

            # Mutate the alert dict in place
            alert["is_attack"] = is_attack
            alert["attack_phase"] = attack_phase

            # Write JSONL line
            out_f.write(json.dumps(alert, default=str) + "\n")

            # Build the flat row (drop raw_record, join list fields)
            flat = {k: v for k, v in alert.items() if k != "raw_record"}
            for k, v in list(flat.items()):
                if isinstance(v, list):
                    flat[k] = ";".join(str(x) for x in v) if v else ""
            flat_rows.append(flat)

            # Update counters
            n_total += 1
            if is_attack:
                n_attack += 1
                by_attack_phase[attack_phase] += 1
                by_scenario_phase[scenario][attack_phase] += 1
                severity_x_attack[alert.get("severity_norm", 0)]["attack"] += 1
            else:
                n_benign += 1
                severity_x_attack[alert.get("severity_norm", 0)]["benign"] += 1

            sc_stats = by_scenario_counts[scenario]
            sc_stats["total"] += 1
            sc_stats["attack" if is_attack else "benign"] += 1

            if n_total % 100_000 == 0:
                print(f"  ... {n_total:,} alerts labelled "
                      f"({n_attack:,} attack, {n_benign:,} benign)", file=sys.stderr)

    # Write flat tabular output
    if flat_rows:
        if use_parquet:
            table = pa.Table.from_pylist(flat_rows)
            pq.write_table(table, out_dir / "alerts_labeled.parquet")
            output_format = "parquet"
        else:
            csv_path = out_dir / "alerts_labeled.csv"
            with csv_path.open("w", newline="") as cf:
                writer = csv.DictWriter(cf, fieldnames=list(flat_rows[0].keys()))
                writer.writeheader()
                writer.writerows(flat_rows)
            output_format = "csv"
    else:
        output_format = "none"

    # Build stats
    attack_ratio = (n_attack / n_total) if n_total > 0 else 0.0
    stats = {
        "input_alerts": n_total,
        "is_attack_true": n_attack,
        "is_attack_false": n_benign,
        "attack_ratio": round(attack_ratio, 6),
        "unknown_scenario_count": n_unknown_scenario,
        "by_scenario": {
            s: {
                "total": v["total"],
                "attack": v["attack"],
                "benign": v["benign"],
                "attack_ratio": round(v["attack"] / v["total"], 6) if v["total"] else 0,
            } for s, v in by_scenario_counts.items()
        },
        "by_attack_phase": dict(by_attack_phase.most_common()),
        "by_scenario_phase": {s: dict(c) for s, c in by_scenario_phase.items()},
        "severity_x_attack": {
            str(sev): {
                "attack": d["attack"],
                "benign": d["benign"],
                "attack_ratio": round(
                    d["attack"] / (d["attack"] + d["benign"]), 6
                ) if (d["attack"] + d["benign"]) else 0,
            } for sev, d in sorted(severity_x_attack.items())
        },
        "labels_summary": label_summary,
        "output_format": output_format,
    }

    (out_dir / "label_stats.json").write_text(json.dumps(stats, indent=2, default=str))

    print("\n=== Labelling Summary ===", file=sys.stderr)
    print(json.dumps(stats, indent=2, default=str), file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--alerts", required=True, type=Path,
                    help="Path to alerts.jsonl from ingest.py")
    ap.add_argument("--labels", required=True, type=Path,
                    help="Path to labels.csv from AIT-ADS Zenodo download")
    ap.add_argument("--output", required=True, type=Path,
                    help="Directory to write labeled outputs")
    ap.add_argument("--limit", type=int, default=None,
                    help="Stop after N alerts (for smoke testing)")
    args = ap.parse_args()

    if not args.alerts.exists():
        print(f"ERROR: alerts file not found: {args.alerts}", file=sys.stderr)
        sys.exit(1)
    if not args.labels.exists():
        print(f"ERROR: labels file not found: {args.labels}", file=sys.stderr)
        sys.exit(1)

    process(args.alerts, args.labels, args.output, args.limit)


if __name__ == "__main__":
    main()
