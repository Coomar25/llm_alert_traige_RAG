---
id: RB-001
title: SSH brute force authentication response
applies_to: cracking
mitre_ids: T1110, T1110.001, T1110.003, T1021.004
severity_guidance: Escalate to P2 if a successful authentication is observed from the same source IP after sustained failures; otherwise P3.
references: https://attack.mitre.org/techniques/T1110/, https://documentation.wazuh.com/current/proof-of-concept-guide/detect-brute-force-attack.html
---

# SSH brute force authentication response

This runbook applies when authentication failures from a single source IP exceed
a threshold within a short time window. Typical Wazuh rules involved are rule
5710 (sshd authentication failed), 5712 (sshd brute force), and rule 5763
(multiple authentication failures). The Suricata equivalent is alert signature
ET SCAN Potential SSH Scan.

## Step 1 — Confirm the attack pattern

Verify the alert by inspecting `/var/log/auth.log` or the equivalent SIEM-indexed
auth log for the affected host. Look for ten or more `Failed password` or
`Invalid user` entries from a single source IP within a five-minute window. A
sparser pattern over a longer period suggests a low-and-slow brute force, which
is less common but more dangerous.

## Step 2 — Check whether the attack succeeded

Search the same log for `Accepted password` or `Accepted publickey` events from
the same source IP within the attack window or in the thirty minutes that
follow. A successful authentication after sustained failures is the strongest
possible signal that the attack worked. Treat this as a confirmed compromise.

## Step 3 — Investigate the source

Query threat-intelligence sources for the source IP. Public blocklists worth
checking include AbuseIPDB, the Spamhaus DROP list, and the Emerging Threats
compromised-IP feed. A confirmed malicious IP simplifies attribution but is not
required for response.

## Step 4 — Contain the source

Block the source IP at the perimeter firewall and on the affected host's
iptables or nftables rules. Apply the block for at minimum 24 hours. If
`fail2ban` is configured, verify the IP has been added to the relevant jail.

## Step 5 — Reset affected credentials

If step 2 indicates a successful authentication, immediately force a password
reset on the affected account, revoke any SSH keys belonging to it, and audit
all interactive sessions started from that IP using `last -i` and the auth log.

## Escalation criteria

Escalate to P2 (security lead notification within 15 minutes) if a successful
authentication is observed, if multiple accounts are targeted, or if the source
IP belongs to a known threat actor. Escalate to P1 (immediate response) if
post-authentication activity such as privilege escalation or lateral movement
is observed.

## Common false positives

A user repeatedly mistyping their password from a corporate IP is not an attack.
Automated systems with stale credentials (CI runners, backup jobs) commonly
produce repeated auth failures from internal IPs — verify before responding.
