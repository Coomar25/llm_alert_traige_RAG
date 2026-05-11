"""
Parser for Suricata alerts wrapped in the Wazuh envelope.

In AIT-ADS, Suricata's EVE-JSON output is forwarded through Wazuh, which adds
its own envelope (agent, manager, rule blocks). The actual Suricata alert
content lives at:
    data.event_type == "alert"
    data.alert.signature, data.alert.severity, data.alert.category
    data.src_ip, data.dest_ip, data.src_port, data.dest_port, data.proto

CRITICAL: Suricata uses 1-3 severity where 1 is HIGHEST. Wazuh uses 0-16
where higher is HIGHER. The severity_mapping module handles the inversion.
"""

from datetime import datetime, timezone

from .unified_alert import UnifiedAlert
from .severity_mapping import normalise_suricata
from .wazuh_parser import _parse_timestamp, _safe_get


def _safe_int(v) -> int | None:
    """Suricata fields are sometimes strings ('3'), sometimes ints. Coerce."""
    if v is None:
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def is_suricata_record(record: dict) -> bool:
    """Detect Suricata-via-Wazuh records.

    The defining signal: data.event_type == "alert" AND data.alert exists
    with a signature field.
    """
    data = record.get("data") or {}
    if data.get("event_type") != "alert":
        return False
    alert = data.get("alert")
    if not isinstance(alert, dict):
        return False
    return "signature" in alert


def parse_record(record: dict, scenario: str) -> UnifiedAlert | None:
    """Parse a single Suricata-via-Wazuh record into a UnifiedAlert."""
    # Prefer Suricata's own timestamp (in data.timestamp) over Wazuh's wrapper
    data = record.get("data") or {}
    alert = data.get("alert") or {}

    ts_str = data.get("timestamp") or record.get("@timestamp")
    if not ts_str:
        return None
    try:
        ts = _parse_timestamp(ts_str)
    except (ValueError, TypeError):
        return None

    raw_severity = _safe_int(alert.get("severity"))
    rule = record.get("rule") or {}

    return UnifiedAlert(
        alert_id=UnifiedAlert.new_id(),
        timestamp=ts,
        source_ids="suricata",
        scenario=scenario,
        host=_safe_get(record, "agent", "name"),
        host_ip=_safe_get(record, "agent", "ip"),
        log_source=record.get("location"),
        severity_raw=raw_severity,
        severity_norm=normalise_suricata(raw_severity),
        rule_id=str(alert.get("signature_id")) if alert.get("signature_id") is not None else None,
        description=alert.get("signature", ""),
        raw_message=alert.get("category", ""),  # Suricata "category" is the human-readable bucket
        src_ip=data.get("src_ip"),
        dst_ip=data.get("dest_ip"),
        src_port=_safe_int(data.get("src_port")),
        dst_port=_safe_int(data.get("dest_port")),
        protocol=data.get("proto"),
        rule_groups=list(rule.get("groups", []) or []),
        raw_record=record,
    )