# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 1.x | Yes |
| < 1.0 | No |

Fixes go into the latest 1.x release.

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub Security Advisories, using "Report a vulnerability" on
the repository's **Security** tab. Do not open a public issue, pull request or discussion for a security problem.

Include:

- the goose-web version (`goose-web version`), the Goose version, and the OS or Docker setup
- the steps to reproduce, and what an attacker gains
- any relevant configuration, with secrets removed

We aim to acknowledge reports within a few working days, agree on a fix and a disclosure date with you, and credit
you in the advisory unless you prefer otherwise.

## Scope

In scope: the goose-web gateway and its web UI. That covers the code in `goose_web/`, the installers in `scripts/`
and the container files in `docker/`. Examples:

- authentication or session bypass, CSRF, cross-site WebSocket hijacking, XSS
- a non-admin user escaping the policy firewall (`goose_web/policy.py`) or folder confinement, or reaching another
  user's profile through the gateway
- an MCP App frame breaking out of its sandbox
- the gateway running elevated or creating files owned by another account
- leaks of secrets or tokens through the API, logs or responses

Out of scope (report these upstream or to the relevant vendor):

- vulnerabilities in Goose itself, its extensions or MCP servers, or in LLM providers
- prompt injection that only does what the affected user's own policy and tool permissions already allow
- isolation limits that come from all profiles sharing one OS account. These are documented as accepted risks
  (see GW-01 in the assessment)
- findings that need admin rights, or code already running as the gateway's OS account
- missing TLS when the gateway is exposed without the recommended reverse proxy

## Security design and known risks

The threat model, verified controls, findings and the deployment hardening checklist are in
[docs/SECURITY-ASSESSMENT.md](docs/SECURITY-ASSESSMENT.md).
