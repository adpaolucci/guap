# Security Policy

## Architectural Security Boundaries

- **Single-Machine Local Execution:** `guap` exposes zero network-listening daemons. MCP runs exclusively over `stdio`, and `guap-llm` connects only to loopback (`127.0.0.1`, `::1`, `localhost`).
- **Tiered Autonomy:** AI tool calls cannot execute mutating actions directly; `guap_stage_fix` executes a non-destructive `dry_run` preview and writes a `pending` Approval Card requiring explicit human sign-off.
- **Clean-Room Prohibitions:** `guap` strictly forbids credential recovery, secret dumping, cross-process memory injection, and API hooking.

## Reporting Vulnerabilities

Report suspected security issues privately via GitHub Security Advisories on `https://github.com/adpaolucci/guap`.
