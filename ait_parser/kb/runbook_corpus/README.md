# Runbook Corpus

This folder contains hand-authored SOC playbook entries used as the
operational-knowledge component of the dissertation's RAG knowledge base.

Each runbook is a markdown file with YAML-style frontmatter at the top. The
loader (`kb/runbooks.py`) parses the frontmatter into metadata and treats the
body as the embeddable content.

## Frontmatter fields

| Field | Required | Description |
|---|---|---|
| `id` | yes | Stable runbook identifier, e.g. `RB-001` |
| `title` | yes | Short one-line title |
| `applies_to` | yes | Which AIT-ADS attack phase this addresses |
| `mitre_ids` | yes | Comma-separated MITRE technique IDs |
| `severity_guidance` | yes | When to escalate, in one sentence |
| `references` | no | Comma-separated source URLs |

## Body structure

The body is freeform markdown but the established pattern is:

1. Brief description of the alert pattern (1-2 sentences)
2. Numbered investigation steps (3-6 steps)
3. Escalation criteria (1-2 sentences)
4. Common false-positive causes (1-2 sentences)

## Current corpus

Eight runbooks covering the major attack categories in AIT-ADS:

| Runbook | Applies to | MITRE coverage |
|---|---|---|
| RB-001 | cracking | T1110, T1110.001, T1110.003 |
| RB-002 | dirb | T1595.003, T1083, T1190 |
| RB-003 | wpscan | T1595.002, T1190 |
| RB-004 | dnsteal | T1048, T1048.003, T1071.004 |
| RB-005 | privilege_escalation | T1068, T1548 |
| RB-006 | reverse_shell | T1059, T1059.004, T1071 |
| RB-007 | webshell | T1505.003, T1059.004 |
| RB-008 | service_stop | T1489, T1529 |

These are dissertation-grade templates. They can be extended with additional
runbooks for sub-cases (e.g. SSH-specific brute force, vs RDP brute force) by
copying any existing file and updating the frontmatter and body.

## Authorship sources

All runbooks were authored from publicly documented sources:

- MITRE ATT&CK technique pages (https://attack.mitre.org/)
- SANS Internet Storm Center reading room
- NIST SP 800-61 Computer Security Incident Handling Guide
- US-CERT / CISA published advisories
- Wazuh ruleset documentation (https://documentation.wazuh.com/)

No proprietary or confidential SOC procedures are reproduced.
