"""
Scenario-level train/test split for the AIT-ADS dataset.

Rationale:
    The labelling stage revealed that per-scenario attack ratios vary wildly:
    fox=89.1%, wardbeck=7.7%. Random row-level splitting would let the model
    cheat by memorising scenario-specific traffic patterns. Scenario-level
    splitting forces generalisation — the model trains on scenarios A, B, C
    and is evaluated on completely unseen scenarios D, E, F.

    Within scenario-level splitting, we want both splits to contain a mix of
    attack-heavy and attack-light scenarios. Otherwise the model trained on
    only attack-heavy data would degenerate to "always predict attack".

The chosen split:
    Train (5 scenarios): fox, harrison, russellmitchell, shaw, wardbeck
        - fox (89.1% attack):           heavy
        - harrison (72.6% attack):      heavy
        - russellmitchell (26.4%):      mid
        - shaw (9.8%):                  light
        - wardbeck (7.7%):              light
    Test (3 scenarios): wheeler, wilson, santos
        - wheeler (70.2% attack):       heavy
        - wilson (69.4% attack):        heavy
        - santos (9.9% attack):         light

    Train has 1,274,635 alerts; test has 1,381,186 alerts.
"""

from typing import Set

TRAIN_SCENARIOS: Set[str] = {
    "fox", "harrison", "russellmitchell", "shaw", "wardbeck",
}

TEST_SCENARIOS: Set[str] = {
    "wheeler", "wilson", "santos",
}

ALL_SCENARIOS: Set[str] = TRAIN_SCENARIOS | TEST_SCENARIOS


def split_of(scenario: str) -> str:
    """Return 'train', 'test', or 'unknown' for a given scenario."""
    if scenario in TRAIN_SCENARIOS:
        return "train"
    if scenario in TEST_SCENARIOS:
        return "test"
    return "unknown"


def validate_splits() -> None:
    """Defensive: ensure train and test are disjoint and cover all 8 scenarios."""
    assert not (TRAIN_SCENARIOS & TEST_SCENARIOS), \
        f"Train/test overlap: {TRAIN_SCENARIOS & TEST_SCENARIOS}"
    assert len(ALL_SCENARIOS) == 8, \
        f"Expected 8 scenarios in total, got {len(ALL_SCENARIOS)}"
