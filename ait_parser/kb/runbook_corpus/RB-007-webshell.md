---
id: RB-007
title: Web shell upload and access response
applies_to: webshell
mitre_ids: T1505.003, T1059.004, T1190
severity_guidance: P1 if a confirmed web shell is being accessed; equivalent to remote code execution as the web server user.
references: https://attack.mitre.org/techniques/T1505/003/, https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-258a
---

# Web shell upload and access response

This runbook applies when a server-side script (PHP, JSP, ASPX, or similar)
is uploaded to a web-accessible directory and then accessed. Web shells give
the attacker persistent code execution under the web server's account
without needing a separate connection — they appear as ordinary HTTP traffic
and can survive reboots. They are the most common persistence mechanism
following the exploitation of a web application vulnerability.

## Step 1 — Identify the web shell file

The triggering alert should include the path of the file that was accessed
or written. Common web shell indicators in the file content include calls
to `system()`, `exec()`, `passthru()`, `shell_exec()`, `eval()`, or `base64_decode()`.
The file is often placed in upload directories (`/wp-content/uploads/`, the
WordPress `/uploads/` folder, application-specific media folders), or in
directories the web server can write to that should not contain executable
scripts.

Compute the file's SHA-256 hash for incident records.

## Step 2 — Trace how the file got there

The web shell did not appear by itself — examine the access log for the
period immediately preceding the file's creation. Look for:

- POST requests with file upload payloads to known-vulnerable plugin
  endpoints (WordPress media library, theme editor, plugin upload).
- Exploitation of file upload vulnerabilities — requests with double
  extensions like `.php.jpg`, null-byte tricks, or content-type confusion.
- Directory traversal in file-write operations (`../../../var/www/html/shell.php`).
- Authenticated file uploads from accounts that should not have upload
  permissions, suggesting credential compromise.

## Step 3 — Identify who has accessed the shell

Search the access log for all subsequent requests to the web shell's URL.
The IPs that have accessed it are the attacker — record them all. Pay
particular attention to GET requests with command-execution parameters
(`?cmd=`, `?c=`, `?exec=`) or POST requests with command payloads. The
parameters often contain the actual commands the attacker has been running.

## Step 4 — Determine what the attacker has done

If access has occurred, the attacker has had arbitrary code execution as
the web server user (typically `www-data` or `apache`). Look for:

- Outbound network connections from the web server process.
- New files written by the web server account.
- Modifications to web application configuration files.
- Database access patterns that suggest data dumps (large SELECT queries,
  `mysqldump` invocations from the web server account).
- Privilege escalation attempts targeting the kernel or setuid binaries
  (see RB-005).

## Step 5 — Remove the web shell

Delete the web shell file. Block the IPs that have accessed it at the WAF.
However, removal alone is insufficient — assume additional persistence
mechanisms have been planted. The attacker may have placed multiple shells,
modified scheduled tasks, or stored credentials for later use.

## Step 6 — Full audit and remediation

Audit all files in web-accessible directories that were modified during or
after the attack window. Look particularly for files with the same hash
as the discovered shell, files with similar content patterns, and any
recently modified files in upload directories. Patch the underlying
vulnerability that allowed the upload. Plan to rebuild the host if there
is any indication of post-shell-access activity.

## Escalation criteria

P1 for any confirmed web shell access. P2 for a web shell file present
but never accessed (this can happen if the upload succeeded but the
attacker abandoned the access). Even an unaccessed web shell indicates a
successful exploitation of an upload vulnerability that requires patching.

## Common false positives

Legitimate file-management tools used by developers can have endpoint
patterns that superficially resemble web shells. Some PHP-based
administrative tools (phpMyAdmin, Adminer) include code-execution features
that are intentional. Verify against the asset inventory and configuration
management records before responding.
