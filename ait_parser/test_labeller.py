"""
Smoke test for the labeller using synthetic fixtures matching the real
labels.csv format observed in AIT-ADS.

The fixtures here are constructed to test specific edge cases:
  - Alerts inside a window
  - Alerts outside any window
  - Alerts exactly at start/end (boundary inclusivity)
  - Alerts in a scenario not present in labels.csv (defensive)
  - Multiple sequential windows in the same scenario
"""

import csv
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from labeller import load_labels, label_alert, summarise_labels


# Real labels.csv content for the 'shaw' scenario (small subset for fixtures).
# This is the exact format and values we'll see in the real file.
LABELS_CSV_CONTENT = """scenario,attack,start,end
shaw,network_scans,1642507140,1642508220
shaw,service_scans,1642508220,1642508267
shaw,dirb,1642508267,1642509480
fox,network_scans,1642507140,1642508220
fox,service_scans,1642508220,1642508267
"""


def run_tests():
    # Write fixture labels.csv to a temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
        f.write(LABELS_CSV_CONTENT)
        labels_path = Path(f.name)

    try:
        # --- Test 1: Loading labels ---
        by_scenario = load_labels(labels_path)
        assert "shaw" in by_scenario, "shaw scenario missing"
        assert "fox" in by_scenario, "fox scenario missing"
        assert len(by_scenario["shaw"]) == 3, f"shaw should have 3 windows, got {len(by_scenario['shaw'])}"
        assert len(by_scenario["fox"]) == 2, f"fox should have 2 windows, got {len(by_scenario['fox'])}"
        print(f"  Load OK: {len(by_scenario)} scenarios, "
              f"{sum(len(v) for v in by_scenario.values())} total windows")

        # --- Test 2: Sorted by start time ---
        shaw_starts = [w.start_epoch for w in by_scenario["shaw"]]
        assert shaw_starts == sorted(shaw_starts), "shaw windows not sorted"
        print(f"  Sort OK: windows are chronologically sorted within each scenario")

        # --- Test 3: Alert clearly inside a window ---
        # shaw network_scans runs 1642507140 to 1642508220.
        # Try an alert in the middle: 1642507500
        is_attack, phase = label_alert(1642507500, "shaw", by_scenario.get("shaw"))
        assert is_attack is True, "should be inside network_scans window"
        assert phase == "network_scans", f"phase should be 'network_scans', got {phase!r}"
        print(f"  Inside-window OK: ts=1642507500 → is_attack=True, phase=network_scans")

        # --- Test 4: Alert exactly at window start (inclusive) ---
        is_attack, phase = label_alert(1642507140, "shaw", by_scenario.get("shaw"))
        assert is_attack is True, "start boundary should be inclusive"
        assert phase == "network_scans"
        print(f"  Start-boundary OK: ts=1642507140 (window start) → is_attack=True")

        # --- Test 5: Alert exactly at window end (inclusive) ---
        is_attack, phase = label_alert(1642508220, "shaw", by_scenario.get("shaw"))
        # Note: 1642508220 is the END of network_scans AND the START of service_scans.
        # Whichever wins, we should still get is_attack=True.
        assert is_attack is True, "end boundary should be inclusive"
        # Sorting by start_epoch ASC means network_scans was inserted before
        # service_scans, so it's checked first and wins on a tie.
        assert phase == "network_scans", f"first matching window should win, got {phase!r}"
        print(f"  End-boundary OK: ts=1642508220 (boundary) → is_attack=True, "
              f"phase={phase} (first match wins on overlap)")

        # --- Test 6: Alert outside all windows ---
        # Anything before 1642507140 should be benign
        is_attack, phase = label_alert(1640000000, "shaw", by_scenario.get("shaw"))
        assert is_attack is False, "before all windows should be benign"
        assert phase is None, f"phase should be None, got {phase!r}"
        print(f"  Outside-window OK: ts=1640000000 (before any window) → is_attack=False")

        # --- Test 7: Alert in unknown scenario ---
        is_attack, phase = label_alert(1642507500, "wilson", by_scenario.get("wilson"))
        assert is_attack is False, "unknown scenario should be benign"
        assert phase is None
        print(f"  Unknown-scenario OK: wilson not in labels → is_attack=False, phase=None")

        # --- Test 8: Sequential window membership ---
        # service_scans runs 1642508220 to 1642508267
        is_attack, phase = label_alert(1642508250, "shaw", by_scenario.get("shaw"))
        assert is_attack is True
        assert phase == "service_scans", f"should match service_scans, got {phase!r}"
        print(f"  Second-window OK: ts=1642508250 → is_attack=True, phase=service_scans")

        # --- Test 9: AttackWindow.contains() helper ---
        w = by_scenario["shaw"][0]  # network_scans
        assert w.contains(w.start_epoch)
        assert w.contains(w.end_epoch)
        assert w.contains((w.start_epoch + w.end_epoch) / 2)
        assert not w.contains(w.start_epoch - 1)
        assert not w.contains(w.end_epoch + 1)
        print(f"  AttackWindow.contains OK: boundaries inclusive, outside excluded")

        # --- Test 10: Summary helper ---
        summary = summarise_labels(by_scenario)
        assert summary["total_windows"] == 5
        assert set(summary["scenarios"]) == {"shaw", "fox"}
        assert "network_scans" in summary["attack_types"]
        assert "dirb" in summary["attack_types"]
        print(f"  Summary OK: {summary['total_windows']} windows, "
              f"{len(summary['attack_types'])} unique attack types")

        # --- Test 11: Timezone — alert datetime → epoch conversion ---
        # Make a UTC datetime that matches 1642507500 epoch, run it through
        # the round-trip and confirm we get the same epoch back.
        dt = datetime.fromtimestamp(1642507500, tz=timezone.utc)
        round_tripped = dt.timestamp()
        assert abs(round_tripped - 1642507500) < 0.001, \
            f"timezone round-trip failed: {round_tripped} vs 1642507500"
        print(f"  Timezone round-trip OK: UTC datetime ↔ epoch consistent")

        print("\nAll tests passed.")

    finally:
        labels_path.unlink()  # clean up temp file


if __name__ == "__main__":
    run_tests()
