"""
Smoke test using real records from the user's AIT-ADS files.
Records here are copied verbatim from the user's terminal output.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from parsers import wazuh_parser, suricata_parser, aminer_parser


# Real Wazuh record (ClamAV update — first line of fox_wazuh.json)
WAZUH_REAL = {
    "predecoder": {"hostname": "mail", "program_name": "freshclam",
                   "timestamp": "Jan 15 02:32:32"},
    "agent": {"ip": "172.17.131.81", "name": "wazuh-client", "id": "18"},
    "manager": {"name": "wazuh.manager"},
    "rule": {
        "firedtimes": 1, "mail": False, "level": 3,
        "pci_dss": ["5.2"], "tsc": ["A1.2"],
        "description": "ClamAV database update",
        "groups": ["clamd", "freshclam", "virus"],
        "id": "52507", "nist_800_53": ["SI.3"], "gpg13": ["4.4"],
        "gdpr": ["IV_35.7.d"]
    },
    "decoder": {"name": "freshclam"},
    "full_log": "Jan 15 02:32:32 mail freshclam[29266]: Sat Jan 15 02:32:32 2022 -> ClamAV update process started at Sat Jan 15 02:32:32 2022",
    "input": {"type": "log"},
    "@timestamp": "2022-01-15T02:32:32.000000Z",
    "location": "/var/log/syslog"
}

# Real Suricata-via-Wazuh record (Ubuntu APT package update)
SURICATA_REAL = {
    "agent": {"ip": "10.35.32.1", "name": "wazuh-client", "id": "29"},
    "manager": {"name": "wazuh.manager"},
    "data": {
        "tx_id": "0", "app_proto": "http", "in_iface": "ens3",
        "src_ip": "192.168.128.4", "src_port": "56852",
        "event_type": "alert",
        "alert": {
            "severity": "3", "signature_id": "2013504", "rev": "6",
            "metadata": {"updated_at": ["2020_04_22"], "former_category": ["POLICY"],
                         "created_at": ["2011_08_31"]},
            "gid": "1",
            "signature": "ET POLICY GNU/Linux APT User-Agent Outbound likely related to package management",
            "action": "allowed", "category": "Not Suspicious Traffic"
        },
        "flow_id": "124443513033886.000000",
        "dest_ip": "91.189.95.85", "proto": "TCP",
        "http": {"hostname": "ppa.launchpad.net", "protocol": "HTTP/1.1",
                 "http_method": "GET", "length": "0",
                 "url": "/oisf/suricata-stable/ubuntu/dists/bionic/InRelease",
                 "http_user_agent": "Debian APT-HTTP/1.3 (1.6.12ubuntu0.2)",
                 "status": "304"},
        "dest_port": "80",
        "flow": {"pkts_toserver": "4", "start": "2022-01-15T03:45:39.627870+0000",
                 "bytes_toclient": "449", "bytes_toserver": "508",
                 "pkts_toclient": "3"},
        "timestamp": "2022-01-15T03:45:39.681006+0000"
    },
    "rule": {"firedtimes": 1, "mail": False, "level": 3,
             "description": "Suricata: Alert - ET POLICY GNU/Linux APT User-Agent",
             "groups": ["ids", "suricata"], "id": "86601"},
    "decoder": {"name": "json"},
    "full_log": "{...}",
    "@timestamp": "2022-01-15T03:45:39.681006+0000",
    "location": "/var/log/suricata/eve.json"
}

# Real AMiner record (PAM accounting audit log)
AMINER_REAL = {
    "AnalysisComponent": {
        "AnalysisComponentIdentifier": 3,
        "AnalysisComponentType": "NewMatchPathDetector",
        "AnalysisComponentName": "AMiner: New event type.",
        "Message": "New path(es) detected",
        "PersistenceFileName": "nmpd",
        "TrainingMode": True,
        "AffectedLogAtomPaths": ["/model/type_str", "/model/type/user_acct"]
    },
    "LogData": {
        "RawLogData": ["type=USER_ACCT msg=audit(1642204801.159:657): pid=5790 uid=0 ..."],
        "Timestamps": [1642204801.16],
        "DetectionTimestamp": [1642204801.16],
        "LogLinesCount": 1,
        "LogResources": ["/var/log/audit/audit.log"]
    },
    "AMiner": {"ID": "172.17.129.140"}
}


def run_tests():
    failed = []

    # --- Wazuh ---
    a = wazuh_parser.parse_record(WAZUH_REAL, "fox")
    assert a is not None, "Wazuh parser returned None on valid record"
    assert a.source_ids == "wazuh"
    assert a.scenario == "fox"
    assert a.host == "wazuh-client"
    assert a.host_ip == "172.17.131.81"
    assert a.severity_raw == 3
    assert a.severity_norm == 1, f"severity_norm should be 1 for level 3, got {a.severity_norm}"
    assert a.rule_id == "52507"
    assert a.description == "ClamAV database update"
    assert "clamd" in a.rule_groups
    assert a.pci_dss == ["5.2"]
    assert a.nist_800_53 == ["SI.3"]
    assert a.gdpr == ["IV_35.7.d"]
    assert a.program_name == "freshclam"
    assert a.log_source == "/var/log/syslog"
    assert a.timestamp.year == 2022 and a.timestamp.month == 1
    print(f"parser object = {a}")

    print(f"  Wazuh OK: {a.description!r}, severity_norm={a.severity_norm}, "
          f"groups={a.rule_groups}, pci={a.pci_dss}")

    # --- Suricata ---
    assert suricata_parser.is_suricata_record(SURICATA_REAL), "Should detect as Suricata"
    assert not suricata_parser.is_suricata_record(WAZUH_REAL), "Should NOT detect Wazuh as Suricata"

    a = suricata_parser.parse_record(SURICATA_REAL, "fox")
    assert a is not None
    assert a.source_ids == "suricata"
    assert a.severity_raw == 3
    assert a.severity_norm == 2, f"severity_norm should be 2 for Suricata sev 3, got {a.severity_norm}"
    assert a.rule_id == "2013504"
    assert "ET POLICY" in a.description
    assert a.src_ip == "192.168.128.4"
    assert a.dst_ip == "91.189.95.85"
    assert a.src_port == 56852
    assert a.dst_port == 80
    assert a.protocol == "TCP"
    assert "suricata" in a.rule_groups
    print(f"  Suricata OK: {a.description[:50]!r}..., src={a.src_ip}, "
          f"dst={a.dst_ip}:{a.dst_port}, severity_norm={a.severity_norm}")

    # --- AMiner ---
    a = aminer_parser.parse_record(AMINER_REAL, "fox")
    assert a is not None
    assert a.source_ids == "aminer"
    assert a.aminer_training_mode is True
    assert a.severity_norm == 1, f"Training-mode AMiner should be severity 1, got {a.severity_norm}"
    assert a.host_ip == "172.17.129.140"
    assert a.aminer_detector == "NewMatchPathDetector"
    assert a.log_source == "/var/log/audit/audit.log"
    assert a.description == "New path(es) detected"
    assert "type=USER_ACCT" in a.raw_message
    assert a.timestamp.year == 2022
    print(f"  AMiner OK: {a.description!r}, detector={a.aminer_detector}, "
          f"training={a.aminer_training_mode}, severity_norm={a.severity_norm}")

    # --- Test inverse Suricata severity (severity=1 means CRITICAL) ---
    crit = json.loads(json.dumps(SURICATA_REAL))  # deep copy
    crit["data"]["alert"]["severity"] = "1"
    a = suricata_parser.parse_record(crit, "fox")
    assert a.severity_norm == 5, f"Suricata severity 1 (highest) should map to 5, got {a.severity_norm}"
    print(f"  Suricata severity inversion OK: raw=1 -> norm=5")

    # --- Test serialisation ---
    a = wazuh_parser.parse_record(WAZUH_REAL, "fox")
    jsonl_out = a.to_jsonl_dict()
    flat_out = a.to_flat_dict()
    assert "raw_record" in jsonl_out
    assert "raw_record" not in flat_out
    assert flat_out["rule_groups"] == "clamd;freshclam;virus"
    assert isinstance(jsonl_out["timestamp"], str)
    json.dumps(jsonl_out, default=str)  # must be JSON-serialisable
    print(f"  Serialisation OK: jsonl has raw_record, flat does not, "
          f"groups joined as {flat_out['rule_groups']!r}")

    print("\nAll tests passed.")


if __name__ == "__main__":
    run_tests()