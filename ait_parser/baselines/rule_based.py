"""
Rule-based baseline classifiers for alert triage.

Two variants are implemented:

    B1 — Severity threshold (the naive baseline)
        Predict attack if severity_norm >= threshold.
        This is what most SOCs do by default when overwhelmed: filter on
        severity and ignore the rest. Honest but simplistic.

    B2 — Severity + rule groups + source-IP burst correlation
        Predict attack if ANY of:
            (a) severity_norm >= threshold, OR
            (b) any rule_group is in a known-bad set, OR
            (c) source_ip has fired >= K alerts within a 60-second window.
        Closer to what a mature rule-based SIEM (e.g., Wazuh with cross-rule
        correlation) would deploy. This is the baseline the LLM+RAG system
        must beat to claim a meaningful contribution.

Both are PURE functions of the alert dict (B1) or stateful in a documented
way (B2's burst detector). No training is involved — the threshold is
tuned on the train split and the final number is reported on test.
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List


# Rule groups that, based on Wazuh's published taxonomy, indicate likely
# attack-relevant activity. Conservative: we include only unambiguous
# categories — not noisy ones like "web" or "syslog" which fire constantly.
KNOWN_BAD_GROUPS: set = {
    "attack",
    "authentication_failed",
    "authentication_failures",
    "brute_force",
    "exploit",
    "intrusion_attempt",
    "malware",
    "rootcheck",
    "vulnerability_scan",
    "web_attack",
    "web_scan",
}


@dataclass
class B1Config:
    """Config for the severity-threshold baseline."""
    severity_threshold: int = 3  # predict attack if severity_norm >= 3 (medium+)


@dataclass
class B2Config:
    """Config for the severity+groups+burst baseline."""
    severity_threshold: int = 3
    burst_count: int = 10          # K alerts ...
    burst_window_seconds: int = 60 # ... within this many seconds
    use_severity: bool = True
    use_groups: bool = True
    use_burst: bool = True


def predict_b1(alert: dict, config: B1Config) -> bool:
    """B1: predict attack if severity meets or exceeds the threshold."""
    sev = alert.get("severity_norm", 1)
    return sev >= config.severity_threshold


class B2Predictor:
    """B2: stateful predictor tracking per-source-IP burst rates.

    We hold a sliding window of recent alert timestamps for each src_ip and
    flag any alert whose window contains >= burst_count alerts.

    State is kept *per-scenario* — we don't bleed burst state from one
    scenario into another, since they're independent testbed environments.
    """

    def __init__(self, config: B2Config):
        self.config = config
        # scenario -> src_ip -> deque of recent epoch timestamps
        self._windows: Dict[str, Dict[str, Deque[float]]] = defaultdict(
            lambda: defaultdict(deque)
        )

    def _is_burst(self, scenario: str, src_ip: str, ts_epoch: float) -> bool:
        """Update the burst window for (scenario, src_ip); return True if it's a burst."""
        if not src_ip:
            return False
        dq = self._windows[scenario][src_ip]
        cutoff = ts_epoch - self.config.burst_window_seconds
        # Pop expired entries from the left
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(ts_epoch)
        return len(dq) >= self.config.burst_count

    def predict(self, alert: dict, ts_epoch: float) -> bool:
        """Predict attack/benign for a single alert.

        ts_epoch is the alert's timestamp converted to Unix epoch seconds.
        Caller computes this once and passes it in (saves re-parsing).
        """
        cfg = self.config

        # (a) severity threshold
        if cfg.use_severity and alert.get("severity_norm", 1) >= cfg.severity_threshold:
            return True

        # (b) rule-group match
        if cfg.use_groups:
            groups = alert.get("rule_groups", "")
            # Flat (parquet) form: semicolon-joined string. JSONL form: list.
            if isinstance(groups, str):
                group_set = set(groups.split(";")) if groups else set()
            else:
                group_set = set(groups or [])
            if group_set & KNOWN_BAD_GROUPS:
                return True

        # (c) source-IP burst
        if cfg.use_burst:
            src_ip = alert.get("src_ip") or alert.get("host_ip")
            scenario = alert.get("scenario", "")
            if self._is_burst(scenario, src_ip or "", ts_epoch):
                return True

        return False

    def reset(self) -> None:
        """Clear burst state (called between train and test runs)."""
        self._windows.clear()
