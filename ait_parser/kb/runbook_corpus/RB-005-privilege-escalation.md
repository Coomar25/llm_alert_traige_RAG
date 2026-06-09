---
id: RB-005
title: Linux privilege escalation response
applies_to: privilege_escalation
mitre_ids: T1068, T1548, T1078
severity_guidance: P1 if root or equivalent privileges are confirmed obtained by an unauthorised account.
references: https://attack.mitre.org/techniques/T1068/, https://attack.mitre.org/techniques/T1548/
---

# Linux privilege escalation response

This runbook applies when a process running under a low-privileged user
account gains elevated privileges through means other than legitimate `sudo`
or `su` invocations. Indicators include kernel exploit attempts, setuid
binary abuse, kernel module loading by non-root users, capability changes,
and unexpected effective UID transitions in audit logs. Privilege escalation
is rarely an initial access vector — it is part of a multi-stage attack
that began with another vulnerability.

## Step 1 — Identify the compromised account

Determine which user account triggered the alert. This is the account the
attacker has already compromised. In auditd logs, look for the `auid`
(audit user ID) field — it reflects the original logged-in user even after
UID changes, which is invaluable for attribution.

## Step 2 — Identify the escalation technique

Several common escalation patterns produce distinct signatures:

- **Setuid binary abuse**: an unexpected setuid binary in user-writable
  paths (`/tmp`, `/var/tmp`, home directories) is a strong indicator.
  Common abused binaries that should not be setuid include `find`, `vim`,
  `awk`, and `bash`.
- **Kernel exploit (CVE-based)**: an unexpected `oops` or kernel panic
  message, combined with a process gaining capabilities it should not
  have, suggests a kernel vulnerability is being exploited. Cross-reference
  the kernel version against recent privilege-escalation CVEs.
- **Sudoers misconfiguration**: a user invoking `sudo` for a command
  pattern that should not be permitted, particularly with `NOPASSWD` set,
  indicates a `sudoers` misconfiguration that should be remediated even
  outside the immediate incident.
- **Cron job hijacking**: a modification to `/etc/cron.d/`, `/etc/crontab`,
  or any cron file owned by root but writable by a non-root user.

## Step 3 — Determine what the attacker did with elevated privileges

The escalation itself is rarely the goal. Look in root-owned process and
file activity in the minutes after the escalation for:

- New user accounts being created
- SSH keys being added to `~/.ssh/authorized_keys` for any account
- Modifications to `/etc/passwd`, `/etc/shadow`, or `/etc/sudoers`
- Installation of persistence mechanisms (systemd services, cron jobs,
  rootkit kernel modules)
- Connection to external command-and-control infrastructure

## Step 4 — Isolate the host

If escalation to root is confirmed, isolate the host from the network
immediately. Do not power it off — preserve memory and disk state for
forensic analysis. Use the network controls available (switch port disable,
ACL on the upstream router, VPN session termination).

## Step 5 — Forensic capture

Capture a full memory image with a tool like `LiME` or `avml` before any
remediation. Image the disk as well. The combination of memory and disk
forensics is necessary to identify the full extent of the compromise.

## Step 6 — Plan rebuild, not cleanup

Once root has been compromised, the standard guidance is to rebuild the
host rather than clean it. An attacker with root access on a compromised
machine cannot be reliably evicted because they may have installed
kernel-level persistence that is invisible to user-space tools. Migrate the
workload to a known-clean host and decommission the compromised one.

## Escalation criteria

P1 for any confirmed root escalation. The incident commander should be
involved and the formal incident response process triggered. P2 for failed
escalation attempts where the attacker did not succeed in gaining elevated
privileges but their attempt is documented.

## Common false positives

Legitimate `sudo` usage by administrators and authorised setuid binaries
(such as `passwd`, `mount`, `ping`) routinely trigger UID change events.
Cross-reference against the `auid` of the originating user and the command
being executed to distinguish legitimate from unauthorised escalation.
