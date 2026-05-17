"""
Load labels.csv into a structure optimised for fast alert-to-window lookup.

The CSV format (4 columns, header row):
    scenario, attack, start, end
    "shaw", "network_scans", "1642507140", "1642508220"
    ...

We group windows by scenario for two reasons:
1. Most lookups only need to check that scenario's windows (~10 entries),
   not all 80 windows in the file.
2. It mirrors how the labeller iterates alerts (already grouped by scenario
   via the parser's scenario field).

Each window stores both numeric epoch bounds (for fast comparison) and
UTC datetime bounds (for human-readable logging if needed).
"""

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List


@dataclass(frozen=True)
class AttackWindow:
    """A single (scenario, attack_phase, time_range) row from labels.csv."""
    scenario: str
    attack: str
    start_epoch: float
    end_epoch: float
    start_utc: datetime
    end_utc: datetime

    def contains(self, epoch: float) -> bool:
        """True if epoch falls within this window (inclusive on both ends)."""
        return self.start_epoch <= epoch <= self.end_epoch


def load_labels(labels_csv: Path) -> Dict[str, List[AttackWindow]]:
    """Parse labels.csv into {scenario: [AttackWindow, ...]}.

    Returns a dict where each key is a scenario name and each value is a
    chronologically sorted list of attack windows for that scenario.

    Raises ValueError if the CSV is malformed or contains bad timestamps.
    """
    by_scenario: Dict[str, List[AttackWindow]] = {}

    with labels_csv.open("r", newline="") as f:
        reader = csv.DictReader(f)
        required_cols = {"scenario", "attack", "start", "end"}
        if not required_cols.issubset(reader.fieldnames or []):
            raise ValueError(
                f"labels.csv must contain columns {required_cols}, "
                f"got {reader.fieldnames}"
            )

        for line_no, row in enumerate(reader, 2):  # start at 2 because of header
            try:
                start = float(row["start"])
                end = float(row["end"])
            except (ValueError, TypeError) as e:
                raise ValueError(
                    f"labels.csv line {line_no}: bad epoch values "
                    f"start={row['start']!r}, end={row['end']!r}: {e}"
                )

            if end < start:
                raise ValueError(
                    f"labels.csv line {line_no}: end {end} < start {start} "
                    f"for {row['scenario']}/{row['attack']}"
                )

            window = AttackWindow(
                scenario=row["scenario"],
                attack=row["attack"],
                start_epoch=start,
                end_epoch=end,
                start_utc=datetime.fromtimestamp(start, tz=timezone.utc),
                end_utc=datetime.fromtimestamp(end, tz=timezone.utc),
            )
            by_scenario.setdefault(row["scenario"], []).append(window)

    # Sort each scenario's windows by start time (helps the labeller short-circuit
    # if windows are guaranteed sequential, and improves readability of logs)
    for scenario in by_scenario:
        by_scenario[scenario].sort(key=lambda w: w.start_epoch)

    return by_scenario


def summarise_labels(by_scenario: Dict[str, List[AttackWindow]]) -> dict:
    """Produce a human-readable summary of loaded labels."""
    total = sum(len(ws) for ws in by_scenario.values())
    per_scenario = {s: len(ws) for s, ws in by_scenario.items()}
    attack_types = set()
    for ws in by_scenario.values():
        for w in ws:
            attack_types.add(w.attack)
    return {
        "total_windows": total,
        "scenarios": sorted(by_scenario.keys()),
        "windows_per_scenario": per_scenario,
        "attack_types": sorted(attack_types),
    }
