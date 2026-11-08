# Security policy

## Reporting a vulnerability

Report privately through GitHub Security Advisories: on the repository page, Security, then "Report a vulnerability". Please do not open a public issue or pull request for a vulnerability, and do not include real credentials or customer data in a report; describe where they appear instead.

Expect an acknowledgement, then a discussion in the advisory. This is a volunteer project, so no response-time guarantee is made.

## Supported versions

The latest release. There is no tagged release yet; until there is, the default branch is the supported version.

## Scope

In scope:

- `jb` leaking a credential: in output, error messages, logs, files, the database or a `String()`/`%+v` rendering.
- Reading or writing outside what the config names; the read-only evidence path being writable.
- Config parsing that accepts input it should refuse (for example sending a key over clear HTTP to a non-loopback host).
- Dependency vulnerabilities that are reachable from `jb`.
- Anything that makes `jb` send traffic to a host other than the ones in your config, which [docs/POLICY.md](../docs/POLICY.md) forbids.

Out of scope: the security of the log store you point `jb` at, and findings that depend on an attacker who already has your API key or write access to your config file or evidence database.

## Handling secrets and evidence

`jb` must never leak credentials: keys come from the environment, are not written to config, and do not appear in errors. A report that shows otherwise is a vulnerability.

The evidence database holds the raw documents of your logs, which can contain personal data. Treat the `.duckdb` file as sensitive and do not attach it to an issue.
