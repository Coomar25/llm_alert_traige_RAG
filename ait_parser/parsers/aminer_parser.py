"""
Parser for AMiner alerts in AIT-ADS *_aminer.json files.

AMiner is anomaly-based, not signature-based. Records have no severity, no
rule, no MITRE mapping. The structure is:

    AnalysisComponent: which detector fired (e.g., NewMatchPathDetector)
    LogData.RawLogData[0]: the actual log line that triggered the anomaly
    LogData.Timestamps[0]: Unix epoch (float, seconds)
    LogData.DetectionTimestamp[0]: when the detector noticed it
    LogData.LogResources[0]: source log file path
    AMiner.ID: the host IP

Important: AnalysisComponent.TrainingMode flags whether AMiner is still
building its baseline. Training-mode "anomalies" are noisy by design — we
mark them with severity_norm=1 and a flag in the unified alert so downstream
analysis can filter them.
"""

from datetime import datetime, timezone

from .unified_alert import UnifiedAlert
from .severity_mapping import normalise_aminer


def _epoch_to_dt(epoch) -> datetime | None:
    """Convert Unix epoch (float seconds) to UTC datetime."""
    if epoch is None:
        return None
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None


def _first(lst, default=None):
    """Safely get the first element of a list (AMiner wraps scalars in lists)."""
    if isinstance(lst, list) and lst:
        return lst[0]
    return default


def parse_record(record: dict, scenario: str) -> UnifiedAlert | None:
    """Parse a single AMiner record into a UnifiedAlert."""
    component = record.get("AnalysisComponent") or {}
    log_data = record.get("LogData") or {}
    aminer = record.get("AMiner") or {}

    # Detection timestamp is the alert time; Timestamps[0] is when the log line
    # was originally produced. We use detection time as the alert timestamp.
    det_ts = _first(log_data.get("DetectionTimestamp"))
    if det_ts is None:
        det_ts = _first(log_data.get("Timestamps"))
    ts = _epoch_to_dt(det_ts)
    if ts is None:
        return None

    raw_log = _first(log_data.get("RawLogData"), default="") or ""
    log_resource = _first(log_data.get("LogResources"))
    training_mode = bool(component.get("TrainingMode", False))
    detector = component.get("AnalysisComponentType") or component.get("AnalysisComponentName", "")

    return UnifiedAlert(
        alert_id=UnifiedAlert.new_id(),
        timestamp=ts,
        source_ids="aminer",
        scenario=scenario,
        host=aminer.get("ID"),     # AMiner identifies hosts by IP
        host_ip=aminer.get("ID"),
        log_source=log_resource,
        severity_raw=None,
        severity_norm=normalise_aminer(training_mode),
        rule_id=str(component.get("AnalysisComponentIdentifier"))
                if component.get("AnalysisComponentIdentifier") is not None else None,
        description=component.get("Message") or detector,
        raw_message=raw_log,
        rule_groups=[detector] if detector else [],
        aminer_detector=detector,
        aminer_training_mode=training_mode,
        raw_record=record,
    )