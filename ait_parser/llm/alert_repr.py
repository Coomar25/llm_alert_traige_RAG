"""
Compact alert representation.

An AIT-ADS UnifiedAlert has ~30 fields, many noisy or redundant. Feeding the
raw JSON into an LLM prompt would waste context window and bury the
decision-relevant signal. This module distils each alert into a compact,
human-readable text block containing only the fields a SOC analyst would
actually look at when triaging.

The SAME representation is used for:
    - the LLM prompt (what the model reasons over)
    - the RAG retrieval query (what we embed to find relevant context)

Keeping them identical means the retrieved context is relevant to exactly
what the LLM sees — no train/serve skew.

DESIGN NOTE — why the raw log message is included
-------------------------------------------------
Early evaluation revealed that the normalised rule DESCRIPTION alone is often
insufficient to distinguish attack from benign. For example, a wpscan probe
for the vulnerable `timthumb.php` WordPress component is normalised by Wazuh
to the generic description "Web server 400 error code" — which sounds benign.
The discriminating evidence (the requested URL path, the HTTP method, the
user-agent) lives only in the RAW log message.

We therefore include a truncated form of the raw message. This is the single
most important field for triage accuracy: it contains the actual observed
behaviour, not just the rule that matched it.
"""

from typing import Optional


# Map the normalised 1-5 severity back to human labels for the prompt.
SEVERITY_LABELS = {
    1: "informational",
    2: "low",
    3: "medium",
    4: "high",
    5: "critical",
}

# Rule-group tokens that are strong attack indicators. When present we
# surface them explicitly so the model does not overlook them among the
# more benign-sounding tokens (e.g. "web", "accesslog").
ATTACK_INDICATING_GROUPS = {
    "attack", "exploit", "web_attack", "web_scan", "intrusion_attempt",
    "brute_force", "authentication_failed", "authentication_failures",
    "malware", "rootcheck", "vulnerability_scan", "sql_injection",
    "xss", "command_injection", "recon",
}

# Cap the raw message length so a single verbose log line can't blow up the
# prompt. 300 chars comfortably covers an HTTP request line + user-agent.
RAW_MESSAGE_MAX_CHARS = 300


def _get(alert: dict, *keys: str, default: str = "") -> str:
    """Return the first non-empty value among the given keys."""
    for k in keys:
        v = alert.get(k)
        if v not in (None, "", [], {}, "None"):
            return v if isinstance(v, str) else str(v)
    return default


def _as_list(value) -> list:
    """Normalise a list-or-semicolon-string field into a list of tokens."""
    if isinstance(value, list):
        return [str(x) for x in value if x]
    if isinstance(value, str):
        return [p for p in value.split(";") if p]
    return []


def _truncate(text: str, limit: int) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "…(truncated)"


def compact_alert_text(alert: dict) -> str:
    """Produce a compact, readable alert description for prompt + retrieval.

    Includes the decision-relevant fields, most importantly the raw log
    message which carries the observed behaviour. Omits internal IDs and the
    fully nested raw_record.
    """
    source = _get(alert, "source_ids", "source", default="unknown")
    sev_norm = alert.get("severity_norm")
    sev_label = SEVERITY_LABELS.get(sev_norm, "unknown") if sev_norm else "unknown"

    rule_desc = _get(alert, "description", "rule_description", "message",
                     default="(no description)")
    groups = _as_list(alert.get("rule_groups"))
    src_ip = _get(alert, "src_ip", "source_ip", default="")
    dst_ip = _get(alert, "dst_ip", "dest_ip", "destination_ip", default="")
    dst_port = _get(alert, "dst_port", "dest_port", default="")
    log_source = _get(alert, "log_source", default="")
    raw_message = _get(alert, "raw_message", "full_log", default="")

    lines = [
        f"IDS source: {source}",
        f"Severity: {sev_label}" + (f" (level {sev_norm})" if sev_norm else ""),
        f"Rule/signature: {rule_desc}",
    ]

    if groups:
        lines.append(f"Rule categories: {', '.join(groups)}")
        # Surface attack-indicating categories explicitly
        flagged = sorted(set(g.lower() for g in groups) & ATTACK_INDICATING_GROUPS)
        if flagged:
            lines.append(f"NOTE: rule categories include attack indicators: "
                         f"{', '.join(flagged)}")

    if log_source:
        lines.append(f"Log source: {log_source}")
    if src_ip:
        lines.append(f"Source IP: {src_ip}")
    if dst_ip:
        net = f"Destination: {dst_ip}"
        if dst_port:
            net += f":{dst_port}"
        lines.append(net)

    # The raw message is the most discriminative field — include it last so
    # it's the freshest thing in the model's context before it decides.
    if raw_message:
        lines.append(f"Raw log message: {_truncate(raw_message, RAW_MESSAGE_MAX_CHARS)}")

    return "\n".join(lines)


def retrieval_query_text(alert: dict) -> str:
    """Produce the text used to query the knowledge base for relevant context.

    Combines the rule description, categories, and a slice of the raw message
    — the fields that carry the most semantic signal for matching against
    MITRE / CVE / runbook content.
    """
    rule_desc = _get(alert, "description", "rule_description", "message", default="")
    groups = " ".join(_as_list(alert.get("rule_groups")))
    raw_message = _get(alert, "raw_message", "full_log", default="")
    # Only a short slice of the raw message for retrieval — enough to catch
    # things like "timthumb.php" or "UNION SELECT" without drowning the query.
    raw_slice = _truncate(raw_message, 160) if raw_message else ""
    parts = [rule_desc, groups, raw_slice]
    combined = " ".join(p for p in parts if p).strip()
    return combined or "(unspecified security alert)"