---
id: RB-004
title: DNS exfiltration response
applies_to: dnsteal
mitre_ids: T1048, T1048.003, T1071.004
severity_guidance: P1 if encoded payloads in DNS queries are confirmed; this is post-compromise activity.
references: https://attack.mitre.org/techniques/T1048/003/, https://attack.mitre.org/techniques/T1071/004/
---

# DNS exfiltration response

This runbook applies when DNS query patterns suggest data is being exfiltrated
through DNS as a covert channel. Indicators include unusually long subdomain
labels, high-entropy hostname strings, sustained query volume to a single
domain that does not match normal user-driven DNS behaviour, and queries to
domains with very recent registration dates. The presence of this pattern
means an endpoint is already compromised — DNS exfiltration is post-compromise
activity, not initial access.

## Step 1 — Identify the source endpoint

Determine which internal host is making the suspicious queries. This is the
compromised endpoint. The destination DNS server (the attacker-controlled
nameserver) is secondary. Searches in Suricata DNS logs or Zeek `dns.log`
should yield the source IP, source port, and exact query strings.

## Step 2 — Confirm the exfiltration pattern

Examine a sample of the queries. Genuine DNS exfiltration shows clear
patterns:

- Subdomain labels of 30-63 characters (the maximum allowed by RFC 1035),
  comprised of base32 or base64-like character sets.
- Sequential or numbered subdomain labels indicating chunked data
  (`chunk1.exfil.attacker.com`, `chunk2.exfil.attacker.com`).
- Repeated queries to the same parent domain over an extended period.
- High character-entropy strings that do not match natural language patterns.

## Step 3 — Identify the destination

The parent domain that all suspicious queries resolve to is the
attacker-controlled exfiltration endpoint. Capture this domain immediately —
it will likely be blocked at the resolver and reported to threat intelligence.
Check the WHOIS record for registration date; newly registered domains
(within the previous 90 days) are a strong indicator.

## Step 4 — Isolate the compromised endpoint

The endpoint is actively communicating with an attacker. Isolate it from the
network immediately: disable its switch port, remove it from VPN, or block
its outbound traffic at the perimeter. Do not power off the device — volatile
memory may contain evidence and active sessions that forensics will need.

## Step 5 — Forensic snapshot

Before any cleanup, capture a memory image and full disk image of the
compromised endpoint. Identify the process making the DNS queries — common
patterns include unusual processes querying DNS directly, or known utilities
like `nslookup` running from scheduled tasks or scripts placed by the
attacker.

## Step 6 — Block and propagate intelligence

Add the attacker domain to the organisation's DNS sinkhole or block list at
the recursive resolver. Add the attacker IP, the domain, and any associated
nameservers to the SIEM blocklist. Share the indicators with your threat
intelligence sharing community if you participate in one.

## Escalation criteria

P1 in all confirmed cases. DNS exfiltration is post-compromise activity by
definition — there is no benign explanation. Notify the incident commander
immediately and trigger the formal incident response process.

## Common false positives

DNS-based content delivery networks and antivirus signature lookups can
produce high-volume DNS traffic to single domains, but the query strings
differ from exfiltration patterns. Examine the actual query content before
escalating. Some legitimate DNS-based monitoring tools also use long
subdomain labels for telemetry — verify against the asset inventory before
responding.
