---
id: RB-006
title: Reverse shell detection response
applies_to: reverse_shell
mitre_ids: T1059, T1059.004, T1071, T1071.001
severity_guidance: P1 if an outbound reverse shell connection is confirmed established; post-compromise activity.
references: https://attack.mitre.org/techniques/T1059/, https://attack.mitre.org/techniques/T1071/001/
---

# Reverse shell detection response

This runbook applies when a process on a server initiates an outbound network
connection to an external host on an unusual port, particularly when the
process is one that should not normally make network connections (such as
`bash`, `sh`, `python`, `nc`, `socat`, or `awk`). A reverse shell inverts the
usual client-server pattern — the compromised host initiates the connection
outbound, allowing the attacker to bypass inbound firewall restrictions.

## Step 1 — Identify the suspicious connection

In Wazuh or audit logs, look for an EXECVE event that includes one of the
known reverse-shell command patterns: `bash -i >& /dev/tcp/`, `nc -e /bin/sh`,
`python -c 'import socket'`, or `socat exec:/bin/sh`. Suricata signatures
matching common reverse-shell handshakes (`ET POLICY Outbound Bash Connection`,
`ET MALWARE Generic Reverse Shell`) trigger on the resulting network traffic.

The combination of an unusual process making an outbound connection plus a
recognisable reverse-shell command pattern is high-confidence.

## Step 2 — Identify the destination

Capture the destination IP, port, and any associated DNS resolution. Common
attacker patterns include connections to ports 4444, 1337, 8080, 443, and
9001. A connection to 443 (HTTPS) is a deliberate attempt to blend into
normal traffic and should not be dismissed because the port is common.

Run a WHOIS on the destination IP and check it against threat-intelligence
feeds. Newly registered domains, residential ISP addresses being used as
command-and-control infrastructure, and bulletproof hosting providers are
all common indicators.

## Step 3 — Determine the entry point

The reverse shell is the *result* of a prior compromise, not the initial
vector. Trace back to determine how the attacker achieved code execution:

- For web servers, look for malicious uploads, web shells, or exploited
  vulnerabilities (RCE in WordPress plugins, deserialisation flaws, etc.)
  in the request log shortly before the reverse shell triggered.
- For SSH-accessible servers, check whether a successful authentication
  preceded the reverse shell — the attacker may have obtained credentials
  through brute force.
- For all servers, examine recent process executions, scheduled tasks, and
  newly written executables in `/tmp`, `/var/tmp`, and home directories.

## Step 4 — Isolate the host

Block the outbound destination at the perimeter firewall. Isolate the
compromised host using the available network controls. Preserve memory and
disk state — do not power off.

## Step 5 — Identify and kill the reverse-shell process

The process listed in the alert (`bash`, `python`, etc.) is the active
reverse-shell process. Confirm it is still running with `ps`. Capture its
process tree, open file descriptors (`lsof -p PID`), and network connections
before killing it. The parent process is often the entry-point vulnerability
indicator — record it.

## Step 6 — Forensic capture and rebuild

A confirmed reverse shell means the attacker had arbitrary code execution
on the host. Capture full memory and disk images, then plan to rebuild the
host rather than clean it. Migrate workloads to a known-clean replacement.

## Escalation criteria

P1 for any confirmed established reverse shell. The incident commander
should be notified within 15 minutes and the formal incident response
process triggered. P2 for failed reverse-shell attempts where the
connection was blocked by the firewall but the attempt itself is recorded.

## Common false positives

Legitimate administrative tools occasionally produce outbound connections
that resemble reverse shells. Examples: container runtimes opening shell
connections to orchestrators, monitoring agents that include remote-debug
features, and developer tools that tunnel shells through SSH. Cross-reference
the source process against the asset inventory and the destination against
the allowlist before responding.
