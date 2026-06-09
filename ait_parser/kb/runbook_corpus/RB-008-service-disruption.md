---
id: RB-008
title: Unauthorised service disruption response
applies_to: service_stop
mitre_ids: T1489, T1529
severity_guidance: P2 if critical services are stopped during business hours; P1 if multiple services are stopped suggesting active impact.
references: https://attack.mitre.org/techniques/T1489/, https://attack.mitre.org/techniques/T1529/
---

# Unauthorised service disruption response

This runbook applies when a critical service (web server, database, SSH
daemon, monitoring agent) is stopped, killed, or disabled by a process or
user account other than the authorised system administrator. In a multi-step
attack scenario, attackers stop services to evade detection (killing the
monitoring agent), establish persistence (replacing a service binary), or
cause impact as the final stage of an attack.

## Step 1 — Identify the stopped service

The triggering alert should include the name of the service and the action
taken (`systemctl stop`, `kill`, `pkill`, `service ... stop`). Common
high-value targets that should not be stopped outside maintenance windows:

- Wazuh agent, osquery, auditd, or other monitoring agents (suggesting
  evasion)
- Apache, nginx, mysql, postgres (suggesting impact or availability attack)
- SSH daemon (suggesting either evasion or denial-of-admin-access)
- Backup processes (suggesting preparation for destructive action)

## Step 2 — Identify the actor

Determine who or what stopped the service. Auditd should capture the
originating process, parent process, and user. Check the `auid` field for
the originating logged-in user even if the action used `sudo` or a UID
switch.

If the actor is a system administrator account during an authorised
maintenance window, validate against the change management system and stand
down. If the actor is an account that should not be stopping services, or
is acting outside a window, proceed.

## Step 3 — Determine the timing context

The timing of service stops within an attack chain is diagnostic:

- **Monitoring agent stopped early in an incident**: the attacker is
  preparing to operate without telemetry. Treat subsequent activity from
  the affected host with heightened suspicion — assume monitoring is
  unreliable until the agent is restored.
- **Service binary replaced before being restarted**: the attacker is
  installing a backdoored version of the service. Check the binary hash
  against the package manager's expected value.
- **Multiple services stopped in sequence**: this is impact activity. The
  attacker may be at the destructive stage of the attack.

## Step 4 — Restart the service securely

Restart the affected service after verifying its binary integrity. For
package-managed services on Debian/Ubuntu, `debsums -s <package>` will
verify file hashes against the original package. For RHEL-family systems,
`rpm -V <package>` provides equivalent verification.

If the binary has been modified, replace it from a trusted source (package
manager, golden image) before restarting.

## Step 5 — Look for the precursor compromise

A service stop is rarely the initial attack vector. The actor must have
obtained the privileges to stop the service first — usually root or sudo
access on the host. Look back in time for the precursor event:

- Previous successful authentications, particularly from unusual sources
- Privilege escalation events on the host (see RB-005)
- Web shell access (see RB-007) by an attacker who has gained command
  execution as the web server user but has somehow elevated to root

## Step 6 — Containment decision

If a single service was stopped and the cause is identified as a contained
compromise (e.g. a compromised admin account whose password has now been
rotated), the host may be recoverable. If multiple services were stopped or
binary integrity is in question, treat the host as fully compromised and
follow the rebuild-rather-than-clean guidance.

## Escalation criteria

P2 if a single critical service is stopped outside an authorised
maintenance window. P1 if multiple services are stopped, if a monitoring
agent has been disabled, or if there is evidence of preceding privilege
escalation. P1 also if service stop is part of a coordinated activity
pattern across multiple hosts (suggesting an active multi-host incident).

## Common false positives

Authorised maintenance windows account for the majority of legitimate
service-stop events. Configuration management tools (Ansible, Puppet,
Chef) restart services as part of normal configuration runs. Auto-scaling
infrastructure terminates services as instances are decommissioned.
Cross-reference against the change management system, asset inventory, and
the originating user's role before treating as an incident.
