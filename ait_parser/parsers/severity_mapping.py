"""
Severity normalisation across the three IDS in AIT-ADS.

Target scale (1-5, higher = more severe):
    1 = informational / training-mode anomaly
    2 = low (e.g., routine policy notice)
    3 = medium (suspicious but not confirmed malicious)
    4 = high (likely malicious)
    5 = critical (confirmed exploit, privilege escalation, exfiltration)

WAZUH uses rule.level on a 0-16 scale where higher = more severe.
    0-3   -> 1 (informational, e.g., antivirus updates)
    4-6   -> 2 (low)
    7-9   -> 3 (medium)
    10-12 -> 4 (high)
    13-16 -> 5 (critical)
Reference: https://documentation.wazuh.com/current/user-manual/ruleset/
           rules-classification.html

SURICATA uses data.alert.severity on a 1-3 scale where LOWER = more severe.
This is the OPPOSITE convention from Wazuh — easy to get wrong.
    1 -> 5 (critical, e.g., admin privilege gain attempt)
    2 -> 4 (high)
    3 -> 2 (low / policy-style)
Reference: Suricata classification.config priorities.

AMINER has no native severity. Anomalies are categorical (path is new / value
is anomalous). We assign:
    Training mode anomaly -> 1 (informational; baseline still being learned)
    Detection mode anomaly -> 3 (medium; outside learned baseline)
This is a defensible default — analysts can adjust per detector type later.
"""


def normalise_wazuh(level: int | None) -> int:
    """Map Wazuh rule.level (0-16) to unified 1-5."""
    if level is None:
        return 1
    if level <= 3:
        return 1
    if level <= 6:
        return 2
    if level <= 9:
        return 3
    if level <= 12:
        return 4
    return 5


def normalise_suricata(severity: int | None) -> int:
    """Map Suricata severity (1-3, inverted) to unified 1-5."""
    if severity is None:
        return 3
    mapping = {1: 5, 2: 4, 3: 2}
    return mapping.get(severity, 3)

def normalise_aminer(training_mode: bool) -> int:
    """Map AMiner anomalies. Training-mode events are baseline noise."""
    return 1 if training_mode else 3