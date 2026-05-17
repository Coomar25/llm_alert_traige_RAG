"""
1.UnifiedAlert: the canonical schema all three parsers produce.

Design notes:
- We keep `raw_record` (the original parsed JSON) for the RAG/LLM path. It costs
  storage but preserves all information for downstream embedding and retrieval.
- For the flat (parquet/CSV) export, drop `raw_record` and serialise list fields
  as semicolon-separated strings.
- Timestamps are stored as Python datetime in UTC. Always convert at parse time;
  never carry mixed-timezone strings forward.
- severity_norm uses a common 1-5 scale (1 = informational, 5 = critical).
  IDS-specific mappings live in severity_mapping.py and are deliberately auditable.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any
import uuid

@dataclass
class UnifiedAlert:
    # --- Identity ---
    alert_id: str
    timestamp: datetime
    source_ids: str          # "wazuh" | "suricata" | "aminer"
    scenario: str     
    # --- Origin ---
    host: str | None = None
    host_ip: str | None = None
    log_source: str | None = None
    program_name: str | None = None       # "fox" | "harrison" | ... | "wilson"

    # --- Classification ---
    severity_raw: int | None = None
    severity_norm: int = 1
    rule_id: str | None = None
    description: str = ""
    raw_message: str = ""

    # --- Network (mostly Suricata) ---
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None

    # --- Security context ---
    rule_groups: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    pci_dss: list[str] = field(default_factory=list)
    nist_800_53: list[str] = field(default_factory=list)
    gdpr: list[str] = field(default_factory=list)
 
    # --- AMiner-specific flags ---
    aminer_detector: str | None = None
    aminer_training_mode: bool = False
 
    # --- Ground truth (filled by labeller, not parsers) ---
    is_attack: bool = False
    attack_phase: str | None = None
 
    # --- Provenance ---
    raw_record: dict = field(default_factory=dict)

    @classmethod
    def new_id(cls) -> str:
        return str(uuid.uuid4())
 
    def to_jsonl_dict(self) -> dict:
        """Serialise for JSONL output. Preserves raw_record."""
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        return d
 
    def to_flat_dict(self) -> dict:
        """Serialise for parquet/CSV. Drops raw_record, joins lists."""
        d = asdict(self)
        d["timestamp"] = self.timestamp.isoformat()
        d.pop("raw_record", None)
        for k, v in list(d.items()):
            if isinstance(v, list):
                d[k] = ";".join(str(x) for x in v) if v else ""
        return d
