"""
Prompt templates for alert triage.

Two templates, deliberately near-identical:

    build_llm_only_prompt(alert_text)
        — the alert, the task, the required output schema. No retrieval context.

    build_rag_prompt(alert_text, retrieved_context)
        — IDENTICAL to llm_only, plus one extra section containing the
          retrieved knowledge-base entries.

The near-identity is intentional and important for the ablation: the ONLY
difference between the two pipelines is the presence of retrieved context.
Everything else — instructions, schema, phrasing, attack-phase vocabulary,
few-shot examples — is held constant so that any measured difference in
performance is attributable to retrieval, not to prompt wording.

CALIBRATION NOTE
----------------
An earlier version of this prompt produced an all-benign collapse: a small
instruction-tuned model, shown a single alert in isolation, applied its
general-world prior ("most log lines are normal") and classified every alert
as benign. Its explanations leaned on two false assumptions specific to this
dataset:
    1. low severity  => benign   (FALSE: 76% of severity-2 alerts here are
                                   part of real attacks)
    2. internal/known IP => safe (FALSE: all AIT-ADS attack traffic
                                   originates inside the testbed)

To correct this WITHOUT biasing the model toward always predicting "attack"
(which would be equally wrong), the prompt now:
    - Frames the task accurately: every alert was flagged by an IDS and comes
      from an environment under active testing where attacks are common.
    - States the base rate explicitly so the model has a calibrated prior.
    - Warns against the two specific false assumptions above.
    - Provides two few-shot examples (one attack, one benign) so the model
      has a concrete decision pattern rather than inventing a default.

These calibration statements are factual descriptions of the evaluation
environment, applied identically to both pipelines, so they do not
advantage LLM+RAG over LLM-only.
"""

# The ten AIT-ADS attack phases the model may choose from. Giving the model
# the closed vocabulary improves attack_phase accuracy and keeps outputs
# consistent with the ground-truth labels.
ATTACK_PHASES = [
    "network_scans", "service_scans", "dirb", "wpscan", "webshell",
    "cracking", "reverse_shell", "privilege_escalation", "service_stop",
    "dnsteal",
]

_PHASE_LIST = ", ".join(ATTACK_PHASES)


# Two few-shot examples. One attack (a scan that looks innocuous in isolation),
# one genuinely benign event. These anchor the model's decision pattern and
# demonstrate the required JSON output shape.
_FEW_SHOT = """Example 1:
--- ALERT ---
IDS source: suricata
Severity: low
Rule/signature: ET SCAN Suspicious inbound to mySQL port 3306
Rule categories: attempted-recon
Source IP: 10.34.12.9
Destination: 10.34.12.50:3306
--- END ALERT ---
JSON response:
{"is_attack": true, "attack_phase": "service_scans", "confidence": 0.78, "explanation": "An inbound probe to a database port matching a reconnaissance signature indicates active service scanning, despite the low severity rating."}

Example 2:
--- ALERT ---
IDS source: wazuh
Severity: low
Rule/signature: PAM: Login session opened for user backup by cron
Rule categories: authentication_success, pam
Source IP: 127.0.0.1
--- END ALERT ---
JSON response:
{"is_attack": false, "attack_phase": null, "confidence": 0.82, "explanation": "A local scheduled backup job opening a PAM session from localhost is routine system activity with no indicators of malicious behaviour."}"""


_TASK_INSTRUCTIONS = f"""You are a Security Operations Centre (SOC) analyst assistant. \
You are triaging alerts from an enterprise network that is under active security \
testing. Every alert below was raised by an intrusion detection system (Wazuh, \
Suricata, or AMiner) because it matched a rule or signature. In this environment, \
a substantial proportion of alerts correspond to genuine multi-step attack activity \
(reconnaissance, exploitation, and post-exploitation) interleaved with normal \
background traffic.

Your task is to decide whether each alert represents genuine attack activity or a \
benign event (false positive).

Important guidance for this environment:
- Do NOT assume an alert is benign simply because its severity is low. Attack steps \
such as scanning and enumeration frequently appear as low-severity alerts here.
- Do NOT assume traffic is safe simply because the source IP is internal or looks \
familiar. Attack traffic in this environment originates from inside the network.
- Weigh the rule/signature description and category most heavily. Signatures \
mentioning scanning, brute force, exploits, injection, enumeration, suspicious \
requests, or reconnaissance are strong indicators of attack activity.
- Genuine benign events include routine authentication successes, scheduled jobs, \
health checks, and normal application traffic that did not match an attack-oriented \
signature.

Respond with a JSON object containing exactly these fields:
- "is_attack": boolean, true if this alert represents genuine attack activity
- "attack_phase": if is_attack is true, the single best-matching phase from \
[{_PHASE_LIST}]; otherwise null
- "confidence": a number between 0.0 and 1.0 reflecting how certain you are
- "explanation": a concise (1-3 sentence) justification grounded in the alert details

Respond with ONLY the JSON object, no other text."""


def build_llm_only_prompt(alert_text: str) -> str:
    """Prompt for the LLM-only (no retrieval) pipeline."""
    return f"""{_TASK_INSTRUCTIONS}

{_FEW_SHOT}

Now analyse this alert:
--- ALERT ---
{alert_text}
--- END ALERT ---

JSON response:"""


def build_rag_prompt(alert_text: str, retrieved_context: str) -> str:
    """Prompt for the LLM+RAG pipeline.

    Identical to the LLM-only prompt except for the inserted
    'RELEVANT SECURITY CONTEXT' section. The instruction to use the context
    is added so the model knows what the extra section is for.
    """
    return f"""{_TASK_INSTRUCTIONS}

{_FEW_SHOT}

Use the following retrieved security knowledge to inform your analysis. \
This context may include MITRE ATT&CK techniques, known vulnerabilities (CVEs), \
and SOC response runbooks relevant to the alert. Consider it carefully, but \
rely on the alert details for your final decision.

--- RELEVANT SECURITY CONTEXT ---
{retrieved_context}
--- END CONTEXT ---

Now analyse this alert:
--- ALERT ---
{alert_text}
--- END ALERT ---

JSON response:"""


def normalise_llm_output(parsed: dict | None) -> dict:
    """Coerce the model's parsed JSON into a clean, predictable shape.

    Defends against missing fields, wrong types, and out-of-vocabulary
    attack_phase values. Always returns a dict with the four expected keys.
    """
    if not isinstance(parsed, dict):
        return {
            "is_attack": False,
            "attack_phase": None,
            "confidence": 0.0,
            "explanation": "",
            "_malformed": True,
        }

    # is_attack → bool
    raw_attack = parsed.get("is_attack", False)
    if isinstance(raw_attack, str):
        is_attack = raw_attack.strip().lower() in ("true", "yes", "1", "attack")
    else:
        is_attack = bool(raw_attack)

    # attack_phase → valid phase or None
    phase = parsed.get("attack_phase")
    if phase is not None:
        phase = str(phase).strip().lower()
        if phase not in ATTACK_PHASES:
            phase = None
    if not is_attack:
        phase = None  # benign alerts have no phase

    # confidence → float in [0, 1]
    try:
        confidence = float(parsed.get("confidence", 0.0))
        confidence = max(0.0, min(1.0, confidence))
    except (ValueError, TypeError):
        confidence = 0.0

    explanation = str(parsed.get("explanation", "")).strip()

    return {
        "is_attack": is_attack,
        "attack_phase": phase,
        "confidence": confidence,
        "explanation": explanation,
        "_malformed": False,
    }