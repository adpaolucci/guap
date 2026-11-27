# GUAP — Generalized Utility & Administration Platform

**`guap`** is the flagship single-machine, pure-Rust offline AI + human IT administration appliance for the [GUAP ecosystem](https://guap.ca). It federates all **10 GUAP domain suites (`326` MCP tools)** behind **6 deterministic IT triage runbooks**, a **6-meta-tool (`~800`-token) lazy MCP gateway**, **SQLite human Approval Cards**, **SHA-256/512 Merkle custody receipts**, a **loopback-enforced local `llama-server` AI troubleshooting agent**, and **dual Win32 + Iced desktop consoles**.

---

## Architecture (7 Pure-Rust Crates)

| Crate | Purpose |
| --- | --- |
| `guap-catalog` | Dynamic discovery of sibling/portable/installed GUAP suites (`sys2rust`, `net2rust`, `forensics2rust`, `winctl2rust`, `fs2rust`, `chrome2rust`, `mail2rust`, `mail2mail`, `android2rust`, `robocopy2rust`), schema indexing, and bounded-timeout JSON-RPC `stdio` invocation |
| `guap-runbooks` | Six deterministic IT diagnostic runbooks (`health_and_security_posture`, `slowdown_and_startup_triage`, `crash_and_event_postmortem`, `storage_and_backup_audit`, `network_and_lan_triage`, `mail_browser_device_rescue`) with Merkle `CustodyManifest` output |
| `guap-router` | 6-meta-tool lazy MCP gateway (`guap_host_summary`, `guap_run_runbook`, `guap_find_tools`, `guap_call_readonly`, `guap_stage_fix`, `guap_manage_schedule`), Tiered Autonomy Policy Engine, SQLite Approval Cards, and deterministic Job Profiles |
| `guap-llm` | `#![forbid(unsafe_code)]` loopback-only (`127.0.0.1` / `localhost` / `::1`) OpenAI-compatible HTTP/1.1 client & multi-turn tool-calling agent loop for local `llama-server` |
| `guap-cli` | Unified `guap` CLI (`status`, `suites`, `tools`, `call`, `runbook`, `stage`, `approvals`, `job`, `custody`, `ask`, `mcp`) and standalone `guap-mcp` binary |
| `guap-win32` | Zero-GPU native Windows `SysListView32` console (`WinSafe` + ComCtl v6 manifest) |
| `guap-iced` | Cross-platform `iced 0.14` desktop console |

---

## Safety & Privacy Invariants

1. **Strictly Single-Machine & Loopback-Only:** Zero inbound network daemon, zero cloud SaaS dependency, and `guap-llm` physically refuses non-loopback endpoints so endpoint telemetry never leaves the machine.
2. **Tiered Autonomy (Human Approval Cards):** All ~267 read-only tools execute freely; mutating fixes run a non-destructive `dry_run` preview first and create a `pending` SQLite **Approval Card** that cannot execute without explicit human operator approval (`guap approvals approve <card_id>`).
3. **Cryptographic Custody:** Every runbook report and approved remediation emits a dual SHA-256 + SHA-512 Merkle `CustodyManifest`.
4. **Clean-Room Rust:** `#![forbid(unsafe_code)]` across all crates (with Win32 FFI isolated inside `guap-gui-win32`), zero credential extraction, and zero cross-process injection or API hooking.

---

## Quick Start

```powershell
# Inspect discovered suites, 326 indexed tools, and local AI readiness
cargo run -p guap-cli -- status

# Execute a deterministic IT triage runbook with Merkle custody receipt
cargo run -p guap-cli -- runbook run health_and_security_posture --format md

# Ask the local loopback llama-server AI administrator a question
cargo run -p guap-cli -- ask "Check overall system health and storage readiness"

# Launch the 6-meta-tool MCP stdio gateway
cargo run -p guap-cli -- mcp
```

## License

Apache License 2.0 (`LICENSE`).
