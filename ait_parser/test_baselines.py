"""
Smoke tests for the rule-based baselines and evaluation harness.

Covers:
    - Train/test split correctness (disjoint, covers all scenarios)
    - B1 threshold logic at each severity level
    - B2 severity branch
    - B2 rule-group branch (list and semicolon-string forms)
    - B2 burst-detection branch (with explicit timestamps)
    - ConfusionMatrix counters and derived metrics
    - EvaluationResult per-scenario and per-phase recording
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from baselines import (
    TRAIN_SCENARIOS, TEST_SCENARIOS, ALL_SCENARIOS, split_of, validate_splits,
    ConfusionMatrix, EvaluationResult,
    B1Config, B2Config, B2Predictor, predict_b1, KNOWN_BAD_GROUPS,
)


def run_tests():
    # --------------------------------------------------------------------------
    # Splits
    # --------------------------------------------------------------------------
    validate_splits()
    assert len(TRAIN_SCENARIOS) == 5
    assert len(TEST_SCENARIOS) == 3
    assert len(ALL_SCENARIOS) == 8
    assert not (TRAIN_SCENARIOS & TEST_SCENARIOS)
    assert split_of("fox") == "train"
    assert split_of("wheeler") == "test"
    assert split_of("unknown_scenario") == "unknown"
    print(f"  Splits OK: 5 train + 3 test = 8 scenarios, disjoint")

    # --------------------------------------------------------------------------
    # B1 — severity threshold
    # --------------------------------------------------------------------------
    cfg = B1Config(severity_threshold=3)
    assert predict_b1({"severity_norm": 1}, cfg) is False
    assert predict_b1({"severity_norm": 2}, cfg) is False
    assert predict_b1({"severity_norm": 3}, cfg) is True   # at threshold
    assert predict_b1({"severity_norm": 4}, cfg) is True
    assert predict_b1({"severity_norm": 5}, cfg) is True
    # Missing severity_norm defaults to 1 (below threshold)
    assert predict_b1({}, cfg) is False
    print(f"  B1 OK: threshold=3 fires for severity >= 3")

    # Different threshold
    cfg2 = B1Config(severity_threshold=5)
    assert predict_b1({"severity_norm": 4}, cfg2) is False
    assert predict_b1({"severity_norm": 5}, cfg2) is True
    print(f"  B1 OK: threshold=5 fires only for severity == 5")

    # --------------------------------------------------------------------------
    # B2 — severity branch
    # --------------------------------------------------------------------------
    b2 = B2Predictor(B2Config(severity_threshold=4, use_groups=False, use_burst=False))
    assert b2.predict({"severity_norm": 3}, ts_epoch=1000) is False
    assert b2.predict({"severity_norm": 4}, ts_epoch=1000) is True
    print(f"  B2 severity OK: only severity branch fires at threshold=4")

    # --------------------------------------------------------------------------
    # B2 — rule-group branch (list form, as in JSONL)
    # --------------------------------------------------------------------------
    b2 = B2Predictor(B2Config(use_severity=False, use_groups=True, use_burst=False))
    # known-bad group
    assert b2.predict({"rule_groups": ["web_attack", "syslog"], "severity_norm": 1}, ts_epoch=1000) is True
    # unrelated groups
    assert b2.predict({"rule_groups": ["syslog", "clamd"], "severity_norm": 1}, ts_epoch=1000) is False
    # empty groups
    assert b2.predict({"rule_groups": [], "severity_norm": 1}, ts_epoch=1000) is False
    print(f"  B2 groups OK (list form): known-bad group detected, others ignored")

    # --------------------------------------------------------------------------
    # B2 — rule-group branch (semicolon-string form, as in Parquet flat output)
    # --------------------------------------------------------------------------
    b2 = B2Predictor(B2Config(use_severity=False, use_groups=True, use_burst=False))
    assert b2.predict({"rule_groups": "web_attack;syslog", "severity_norm": 1}, ts_epoch=1000) is True
    assert b2.predict({"rule_groups": "syslog;clamd", "severity_norm": 1}, ts_epoch=1000) is False
    assert b2.predict({"rule_groups": "", "severity_norm": 1}, ts_epoch=1000) is False
    print(f"  B2 groups OK (string form): semicolon-joined groups handled correctly")

    # --------------------------------------------------------------------------
    # B2 — burst detection
    # --------------------------------------------------------------------------
    b2 = B2Predictor(B2Config(
        use_severity=False, use_groups=False, use_burst=True,
        burst_count=3, burst_window_seconds=10,
    ))
    base = {"src_ip": "10.0.0.1", "scenario": "fox", "severity_norm": 1}
    # First 2 alerts: not yet a burst
    assert b2.predict(base, ts_epoch=1000.0) is False
    assert b2.predict(base, ts_epoch=1001.0) is False
    # Third alert in 10-second window: BURST
    assert b2.predict(base, ts_epoch=1002.0) is True
    print(f"  B2 burst OK: 3 alerts in <10s from same src_ip → burst")

    # A different source IP — fresh state
    other = {"src_ip": "10.0.0.2", "scenario": "fox", "severity_norm": 1}
    assert b2.predict(other, ts_epoch=1003.0) is False
    print(f"  B2 burst OK: different src_ip has independent counter")

    # Time-window expiry: original burst expires after 10 seconds
    b2 = B2Predictor(B2Config(
        use_severity=False, use_groups=False, use_burst=True,
        burst_count=3, burst_window_seconds=10,
    ))
    b2.predict(base, ts_epoch=1000.0)
    b2.predict(base, ts_epoch=1001.0)
    # 60 seconds later: window should have expired, only 1 alert in current window
    assert b2.predict(base, ts_epoch=1060.0) is False
    print(f"  B2 burst OK: stale entries expire from the sliding window")

    # --------------------------------------------------------------------------
    # ConfusionMatrix metrics
    # --------------------------------------------------------------------------
    cm = ConfusionMatrix()
    cm.update(predicted_attack=True, actual_attack=True)    # TP
    cm.update(predicted_attack=True, actual_attack=True)    # TP
    cm.update(predicted_attack=True, actual_attack=False)   # FP
    cm.update(predicted_attack=False, actual_attack=False)  # TN
    cm.update(predicted_attack=False, actual_attack=True)   # FN
    assert cm.tp == 2 and cm.fp == 1 and cm.tn == 1 and cm.fn == 1
    assert cm.total == 5
    # precision = 2 / (2+1) = 0.6667
    assert abs(cm.precision - 0.6667) < 0.001
    # recall = 2 / (2+1) = 0.6667
    assert abs(cm.recall - 0.6667) < 0.001
    # F1 = 2 * (2/3 * 2/3) / (2/3 + 2/3) = 0.6667
    assert abs(cm.f1 - 0.6667) < 0.001
    # FPR = 1 / (1+1) = 0.5
    assert abs(cm.false_positive_rate - 0.5) < 0.001
    print(f"  ConfusionMatrix OK: precision={cm.precision:.4f}, recall={cm.recall:.4f}, "
          f"F1={cm.f1:.4f}, FPR={cm.false_positive_rate:.4f}")

    # Edge case: no predictions (all four are zero)
    empty_cm = ConfusionMatrix()
    assert empty_cm.precision == 0.0
    assert empty_cm.recall == 0.0
    assert empty_cm.f1 == 0.0
    assert empty_cm.false_positive_rate == 0.0
    print(f"  ConfusionMatrix edge cases OK: zero division → 0.0")

    # --------------------------------------------------------------------------
    # EvaluationResult — per-scenario and per-phase recording
    # --------------------------------------------------------------------------
    er = EvaluationResult(pipeline_name="test", split_name="train")
    # True positive on fox/dirb
    er.record(True, True, "fox", "dirb", latency_ms=0.5)
    # False positive on fox
    er.record(True, False, "fox", None, latency_ms=0.5)
    # True positive on shaw/webshell
    er.record(True, True, "shaw", "webshell", latency_ms=0.5)
    # False negative on shaw
    er.record(False, True, "shaw", "cracking", latency_ms=0.5)

    assert er.n_alerts == 4
    assert er.overall.tp == 2 and er.overall.fp == 1 and er.overall.fn == 1
    assert er.by_scenario["fox"].tp == 1 and er.by_scenario["fox"].fp == 1
    assert er.by_scenario["shaw"].tp == 1 and er.by_scenario["shaw"].fn == 1
    # Per-phase recall: dirb 1/1=1.0, webshell 1/1=1.0, cracking 0/1=0.0
    assert er.by_phase["dirb"].recall == 1.0
    assert er.by_phase["webshell"].recall == 1.0
    assert er.by_phase["cracking"].recall == 0.0
    assert abs(er.mean_latency_ms - 0.5) < 0.001
    print(f"  EvaluationResult OK: per-scenario and per-phase tracking correct")

    # --------------------------------------------------------------------------
    # Sanity: known-bad groups list is reasonable
    # --------------------------------------------------------------------------
    assert "web_attack" in KNOWN_BAD_GROUPS
    assert "brute_force" in KNOWN_BAD_GROUPS
    # We deliberately don't include very common noisy groups
    assert "syslog" not in KNOWN_BAD_GROUPS
    assert "clamd" not in KNOWN_BAD_GROUPS
    assert "web" not in KNOWN_BAD_GROUPS  # too broad
    print(f"  KNOWN_BAD_GROUPS OK: {len(KNOWN_BAD_GROUPS)} groups, "
          f"noisy ones excluded")

    print("\nAll tests passed.")


if __name__ == "__main__":
    run_tests()
