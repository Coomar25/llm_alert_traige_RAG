"""
The core labelling decision: given an alert and the windows for its scenario,
return (is_attack, attack_phase).

Logic:
  - If no windows exist for the scenario, return (False, None).
  - If the alert's timestamp falls within any window for that scenario,
    return (True, attack_name_of_first_matching_window).
  - Otherwise, return (False, None).

We take the first match if windows overlap. In AIT-ADS the windows are
sequential and non-overlapping, but defensive code is cheap.
"""

from datetime import datetime
from typing import List, Tuple

from .labels_loader import AttackWindow


def label_alert(
    timestamp_epoch: float,
    scenario: str,
    windows_for_scenario: List[AttackWindow] | None,
) -> Tuple[bool, str | None]:
    """Decide whether an alert falls within an attack window.

    Args:
        timestamp_epoch: alert timestamp as Unix epoch seconds.
        scenario: the alert's scenario name (e.g., "fox", "shaw").
        windows_for_scenario: the list of AttackWindow objects for this
            scenario, or None if no entries exist.

    Returns:
        (is_attack, attack_phase) where attack_phase is None when is_attack
        is False.
    """
    if not windows_for_scenario:
        return False, None

    for window in windows_for_scenario:
        if window.contains(timestamp_epoch):
            return True, window.attack

    return False, None


def datetime_to_epoch(dt: datetime) -> float:
    """Convert a UTC datetime to Unix epoch seconds (float)."""
    return dt.timestamp()
