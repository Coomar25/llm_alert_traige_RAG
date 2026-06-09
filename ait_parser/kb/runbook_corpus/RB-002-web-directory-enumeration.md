---
id: RB-002
title: Web directory enumeration scan response
applies_to: dirb
mitre_ids: T1595.003, T1083, T1190
severity_guidance: P3 unless the scan transitions to exploitation attempts against discovered paths, then P2.
references: https://attack.mitre.org/techniques/T1595/003/, https://owasp.org/www-community/attacks/Forced_browsing
---

# Web directory enumeration scan response

This runbook applies to high-volume HTTP request patterns from a single source
IP probing for paths that do not exist. Common tools include `dirb`, `gobuster`,
`ffuf`, and `dirbuster`. Typical alert signatures include Wazuh rule 31151
(multiple 404 errors from a single IP), Suricata signatures matching common
wordlist patterns, and Apache mod_security rule 920280.

## Step 1 — Confirm the scan pattern

Verify that the source IP is generating an unusually high volume of HTTP
requests, typically several hundred per minute, with most responses being 404
or 403 status codes. The request paths often follow predictable patterns
(`/admin`, `/backup`, `/wp-admin`, `/phpmyadmin`, etc.) that match common
wordlists.

## Step 2 — Identify what the scanner found

The critical question is which paths returned 200 status codes. Search the web
server access log for `200` responses from the source IP during the scan
window. Any successful response from a path that should not be publicly
accessible warrants investigation. Pay particular attention to administrative
interfaces, backup files, configuration files, and exposed `.git` directories.

## Step 3 — Check for post-scan exploitation

Examine requests from the same source IP in the minutes following the scan.
Look for POST requests to login pages, requests with SQL injection patterns
(`UNION SELECT`, `' OR '1'='1`), or attempts to access discovered paths with
parameters. The scan itself is reconnaissance; immediate follow-up exploitation
is the actual threat.

## Step 4 — Containment

Block the source IP at the WAF or perimeter firewall. If exploitation attempts
were observed in step 3, also expedite a review of any discovered exposed
paths and harden access controls. Consider rate-limiting rules for repeated
404 responses.

## Step 5 — Document discovered exposure

If any sensitive paths returned 200 responses, document them in an incident
ticket regardless of whether exploitation occurred. The exposure itself is a
finding requiring remediation, independent of whether this particular attacker
exploited it.

## Escalation criteria

Escalate to P2 if the scan returned 200 responses for sensitive administrative
paths, if SQL injection or other exploitation attempts followed the scan, or
if the scan succeeded in accessing files that should not be public. P3 is
appropriate for scans that found nothing useful.

## Common false positives

Search engine crawlers, vulnerability scanning services authorised by the
organisation, and uptime-monitoring tools all generate scan-like traffic.
Verify the source IP is not on an authorised-scanner allowlist before
responding.
