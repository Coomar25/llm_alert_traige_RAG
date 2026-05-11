"""
Parser for native Wazuh alerts in AIT-ADS *_wazuh.json files.

A record is "native Wazuh" (not Suricata-via-Wazuh) when:
    data.event_type != "alert"  OR  data.alert.signature is missing

Native Wazuh records have a populated `rule` block with description, level,
groups, and (often) compliance fields (pci_dss, nist_800_53, gdpr).
"""

from datetime import datetime, timezone
from typing import Any

from .unified_alert import UnifiedAlert
from .severity_mapping import normalise_wazuh


def _parse_timestamp(s: str) -> datetime:
    """Wazuh uses ISO 8601 with microsecond precision and Z suffix."""
    # Examples: "2022-01-15T02:32:32.000000Z", "2022-01-15T02:32:32+0000"
    s = s.replace("Z", "+00:00")
    # fromisoformat doesn't accept "+0000" without colon — normalise it
    if len(s) >= 5 and s[-5] in "+-" and s[-3] != ":":
        s = s[:-2] + ":" + s[-2:]
    try:
        return datetime.fromisoformat(s).astimezone(timezone.utc)
    except ValueError:
        # Fallback: treat as naive UTC
        return datetime.fromisoformat(s.split("+")[0].split("Z")[0]).replace(tzinfo=timezone.utc)
    

def _safe_get(d: dict, *path, default=None):
    """Walk a nested dict path safely. _safe_get(d, 'a', 'b') -> d['a']['b']."""
    cur: Any = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur
    

def parse_record(record: dict, scenario: str) -> UnifiedAlert | None:
    """Parse a single native Wazuh record into a UnifiedAlert.

    Returns None if the record is malformed (no timestamp, no rule).
    """
    ts_str = record.get("@timestamp")
    if not ts_str:
        return None

    rule = record.get("rule") or {}
    if not rule:
        return None

    try:
        ts = _parse_timestamp(ts_str)
    except (ValueError, TypeError):
        return None

    level = rule.get("level")
    mitre_block = rule.get("mitre") or {}





    return UnifiedAlert(
        alert_id=UnifiedAlert.new_id(),
        timestamp=ts,
        source_ids="wazuh",
        scenario=scenario,
        host=_safe_get(record, "agent", "name"),
        host_ip=_safe_get(record, "agent", "ip"),
        log_source=record.get("location"),
        program_name=_safe_get(record, "predecoder", "program_name"),
        severity_raw=level,
        severity_norm=normalise_wazuh(level),
        rule_id=str(rule.get("id")) if rule.get("id") is not None else None,
        description=rule.get("description", ""),
        raw_message=record.get("full_log", ""),
        src_ip=_safe_get(record, "data", "srcip"),
        dst_ip=_safe_get(record, "data", "dstip"),
        rule_groups=list(rule.get("groups", []) or []),
        mitre_techniques=list(mitre_block.get("id", []) or []),
        mitre_tactics=list(mitre_block.get("tactic", []) or []),
        pci_dss=list(rule.get("pci_dss", []) or []),
        nist_800_53=list(rule.get("nist_800_53", []) or []),
        gdpr=list(rule.get("gdpr", []) or []),
        raw_record=record,
    )