---
id: RB-003
title: WordPress scanning and enumeration response
applies_to: wpscan
mitre_ids: T1595.002, T1190, T1592.002
severity_guidance: P3 for enumeration only; P2 if vulnerable plugins are confirmed exposed.
references: https://attack.mitre.org/techniques/T1595/002/, https://owasp.org/www-project-wordpress-security-implementation-guideline/
---

# WordPress scanning and enumeration response

This runbook applies to traffic patterns consistent with `wpscan` or similar
WordPress enumeration tools. Indicators include sequential requests to
`/wp-login.php`, `/wp-json/wp/v2/users`, `/?author=N` enumeration, `readme.html`
fetches, and theme or plugin directory listing attempts. Typical user-agent
strings contain `wpscan` or `WPScan/x.x.x`.

## Step 1 — Confirm the scanning pattern

Examine the access log for the affected host and verify the request pattern. A
genuine wpscan run produces between 30 and 200 requests within a few minutes,
heavily concentrated on WordPress-specific paths. The user-agent string is
often the giveaway, although attackers will sometimes mask it.

## Step 2 — Identify what was enumerated

Three categories of WordPress information are commonly enumerated:

- **Usernames** via the author archive trick (`/?author=1`, `/?author=2`).
  Check whether these returned 200 or were redirected. Successful enumeration
  reveals valid usernames for subsequent brute force attempts.
- **Plugin and theme inventory** via direct path probes (`/wp-content/plugins/{name}/readme.txt`).
  Each 200 response confirms a plugin is installed and may reveal its version.
- **WordPress core version** via the meta generator tag, `/wp-json/`, or
  `/readme.html`.

## Step 3 — Cross-reference enumerated plugins against known vulnerabilities

For each plugin identified in step 2, search the WPScan vulnerability database
(or the CVE database) for known issues affecting the disclosed version. A
vulnerable plugin exposed to the internet is a high-priority finding,
regardless of whether this particular scan exploited it.

## Step 4 — Check for exploitation attempts

Examine subsequent requests from the source IP for exploitation patterns
targeting enumerated plugins. Common signatures include requests to plugin
endpoints with malicious payloads, attempts to upload files via plugin upload
handlers, and SQL injection patterns against plugin AJAX endpoints.

## Step 5 — Containment and hardening

Block the source IP at the WAF. For longer-term hardening, disable username
enumeration by configuring WordPress to return 404 for author archives, remove
the WordPress version meta tag, and ensure all plugins are updated. Consider
requiring authentication for the `/wp-json/wp/v2/users` endpoint.

## Escalation criteria

Escalate to P2 if any enumerated plugin has a known unpatched vulnerability,
if exploitation attempts follow the scan, or if `xmlrpc.php` brute force
activity is observed from the same source. P3 for enumeration only.

## Common false positives

Authorised security scans, penetration testing engagements, and tools used by
the WordPress maintainers themselves can produce similar traffic. Verify the
source IP is not on an allowlist before responding.
