# Security Policy

This project brokers credentials for security vendors' APIs. A defect here can expose the keys
to several security products at once, so reports are welcome and taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting: **Security → Report a vulnerability** on this
repository. That opens a private channel visible only to the maintainers, and it works without
either of us publishing an email address.

Useful to include, if you have it:

- what an attacker gains, and what access they need first
- affected version or commit
- a minimal reproduction
- your assessment of severity

You will get an acknowledgement within a week. If a report is confirmed, you will be told the
intended fix and timing, and credited in the release notes unless you would rather not be.

## Scope

In scope:

- disclosure of secret material through logs, exceptions, tracebacks, or error messages
- a secret name that escapes its provider's namespace or directory
- SQL injection through connector-supplied identifiers or values
- privilege assumptions in the example systemd units or documented database grants
- dependency confusion or entry-point hijacking in the backend discovery mechanism

Out of scope:

- vulnerabilities in PostgreSQL, HashiCorp Vault, Delinea Secret Server, or any vendor API —
  report those to their maintainers
- a deployment that reads secrets from a world-readable file, or otherwise ignores the guidance
  in the README
- anything requiring an attacker who already has code execution as the worker's user; at that
  point the credentials are theirs regardless

## Handling secrets in reports

If a reproduction involves real credentials, redact them. If you believe you have found live
credentials belonging to someone else, do not include them at all — say what you found and where,
and we will chase it down.
