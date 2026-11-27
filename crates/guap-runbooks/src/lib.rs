#![forbid(unsafe_code)]

//! Six deterministic IT administration runbooks orchestrating read-only probes
//! across the 10 GUAP suites and emitting bounded `<1,500`-token structured digests
//! with SHA-256/SHA-512 Merkle `CustodyManifest` receipts.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use chrono::{DateTime, Utc};
use guap_catalog::{SuiteCatalog, ToolExecMode};
use guap_export::{
    CustodyLeaf, CustodyManifest, ExportFormat, ExportOptions, build_custody_manifest, export_table, sha256_hex,
    sha512_hex, write_custody_manifest_json,
};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RunbookError {
    #[error("unknown runbook '{0}'; run `guap runbook list` to view canonical IDs")]
    UnknownRunbook(String),

    #[error("export failed: {0}")]
    Export(#[from] guap_export::ExportError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunbookStepSpec {
    pub step_id: &'static str,
    pub title: &'static str,
    pub suite_hint: &'static str,
    pub preferred_tools: &'static [&'static str],
    pub fallback_query: &'static str,
    pub row_limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunbookSpec {
    pub id: &'static str,
    pub title: &'static str,
    pub domain: &'static str,
    pub summary: &'static str,
    pub steps: &'static [RunbookStepSpec],
}

pub const CORE_RUNBOOKS: &[RunbookSpec] = &[
    RunbookSpec {
        id: "health_and_security_posture",
        title: "Health & Security Posture",
        domain: "security",
        summary: "Audits Windows Defender/WSC security posture, critical services, loaded drivers, and mounted volume health.",
        steps: &[
            RunbookStepSpec {
                step_id: "defender_posture",
                title: "Endpoint Antivirus & Security Center Posture",
                suite_hint: "forensics2rust",
                preferred_tools: &["forensics2rust/posture.defender", "forensics2rust/posture.wsc"],
                fallback_query: "posture defender security",
                row_limit: 8,
            },
            RunbookStepSpec {
                step_id: "critical_services",
                title: "Windows Services & Driver State",
                suite_hint: "sys2rust",
                preferred_tools: &["sys2rust/hw_services", "sys2rust/hw_drivers"],
                fallback_query: "services drivers",
                row_limit: 10,
            },
            RunbookStepSpec {
                step_id: "volume_health",
                title: "Storage Volumes & SMART Telemetry",
                suite_hint: "fs2rust",
                preferred_tools: &["fs2rust/disk_smart_view", "fs2rust/drive_letter_view"],
                fallback_query: "smart drive disk",
                row_limit: 8,
            },
        ],
    },
    RunbookSpec {
        id: "slowdown_and_startup_triage",
        title: "Slowdown & Startup Triage",
        domain: "system",
        summary: "Identifies heavy processes, logon startup autoruns, scheduled tasks, and disk I/O bottlenecks.",
        steps: &[
            RunbookStepSpec {
                step_id: "active_processes",
                title: "Process CPU & Working Set Footprint",
                suite_hint: "sys2rust",
                preferred_tools: &["sys2rust/proc_top", "sys2rust/proc_list"],
                fallback_query: "proc process cpu",
                row_limit: 10,
            },
            RunbookStepSpec {
                step_id: "startup_autoruns",
                title: "Logon Autoruns & Scheduled Tasks",
                suite_hint: "sys2rust",
                preferred_tools: &["sys2rust/startup_entries", "sys2rust/hw_tasks"],
                fallback_query: "startup tasks autorun",
                row_limit: 10,
            },
            RunbookStepSpec {
                step_id: "disk_io_counters",
                title: "Disk & Per-Application I/O Activity",
                suite_hint: "fs2rust",
                preferred_tools: &["fs2rust/disk_counters_view", "fs2rust/app_read_write_counter"],
                fallback_query: "counters read write io",
                row_limit: 8,
            },
        ],
    },
    RunbookSpec {
        id: "crash_and_event_postmortem",
        title: "Crash & Event Postmortem",
        domain: "forensics",
        summary: "Correlates Windows Error Reporting (WER) crash records, minidumps, unexpected boot events, and system errors.",
        steps: &[
            RunbookStepSpec {
                step_id: "crash_reports",
                title: "WER Reports & Crash Minidumps",
                suite_hint: "forensics2rust",
                preferred_tools: &[
                    "forensics2rust/crash.wer_reports",
                    "forensics2rust/crash.wer",
                    "forensics2rust/crash.minidump",
                ],
                fallback_query: "crash wer minidump",
                row_limit: 10,
            },
            RunbookStepSpec {
                step_id: "system_evtx",
                title: "System & Boot/Shutdown EVTX Timeline",
                suite_hint: "forensics2rust",
                preferred_tools: &[
                    "forensics2rust/evtx.system_errors",
                    "forensics2rust/evtx.uptime",
                    "forensics2rust/evtx.legacy",
                ],
                fallback_query: "evtx uptime legacy error",
                row_limit: 10,
            },
            RunbookStepSpec {
                step_id: "recent_execution",
                title: "Recent Application Execution Prefetch",
                suite_hint: "forensics2rust",
                preferred_tools: &["forensics2rust/artifacts.prefetch", "forensics2rust/artifacts.executed"],
                fallback_query: "prefetch executed",
                row_limit: 8,
            },
        ],
    },
    RunbookSpec {
        id: "storage_and_backup_audit",
        title: "Storage & Backup Audit",
        domain: "storage",
        summary: "Inspects drive free space, NVMe/ATA SMART health, directory growth, and Robocopy backup validation readiness.",
        steps: &[
            RunbookStepSpec {
                step_id: "drives_and_smart",
                title: "Mounted Volumes & SMART Status",
                suite_hint: "fs2rust",
                preferred_tools: &["fs2rust/drive_letter_view", "fs2rust/disk_smart_view"],
                fallback_query: "drive smart disk",
                row_limit: 10,
            },
            RunbookStepSpec {
                step_id: "directory_footprint",
                title: "Directory Size & NTFS Stream Check",
                suite_hint: "fs2rust",
                preferred_tools: &["fs2rust/folders_report", "fs2rust/alternate_stream_view"],
                fallback_query: "folders report stream",
                row_limit: 8,
            },
            RunbookStepSpec {
                step_id: "backup_readiness",
                title: "Robocopy Backup Engine Readiness",
                suite_hint: "robocopy2rust",
                preferred_tools: &["robocopy2rust/robocopy2rust_validate"],
                fallback_query: "presets switch validate",
                row_limit: 6,
            },
        ],
    },
    RunbookSpec {
        id: "network_and_lan_triage",
        title: "Network & LAN Triage",
        domain: "network",
        summary: "Checks active TCP/UDP sockets, IPv4/IPv6 routes, DNS resolution health, and local LAN connectivity.",
        steps: &[
            RunbookStepSpec {
                step_id: "active_sockets",
                title: "Listening & Established TCP/UDP Sockets",
                suite_hint: "net2rust",
                preferred_tools: &["net2rust/sockets.ports", "net2rust/sockets.tcp"],
                fallback_query: "sockets ports tcp",
                row_limit: 12,
            },
            RunbookStepSpec {
                step_id: "routing_table",
                title: "Routing Table & Default Gateways",
                suite_hint: "net2rust",
                preferred_tools: &["net2rust/sockets.routes"],
                fallback_query: "routes gateway",
                row_limit: 8,
            },
            RunbookStepSpec {
                step_id: "dns_and_lan",
                title: "DNS Cache / Latency & LAN Neighbors",
                suite_hint: "net2rust",
                preferred_tools: &[
                    "net2rust/capture.dns",
                    "net2rust/lan.connect-log",
                    "net2rust/lan.ping-sweep",
                ],
                fallback_query: "dns lan arp",
                row_limit: 8,
            },
        ],
    },
    RunbookSpec {
        id: "mail_browser_device_rescue",
        title: "Mail, Browser & Device Rescue",
        domain: "rescue",
        summary: "Audits browser profile/cache health, PST/mailbox migration readiness, and connected Android ADB/MTP devices.",
        steps: &[
            RunbookStepSpec {
                step_id: "browser_profiles",
                title: "Chromium, Firefox & Edge Profile Discovery",
                suite_hint: "chrome2rust",
                preferred_tools: &["chrome2rust/chrome2rust_profiles", "chrome2rust/chrome2rust_sniff"],
                fallback_query: "profiles cache sniff",
                row_limit: 8,
            },
            RunbookStepSpec {
                step_id: "mail_readiness",
                title: "PST & Mailbox Engine Readiness",
                suite_hint: "mail2mail",
                preferred_tools: &["mail2mail/mail2mail_system_info", "mail2rust/mail2rust_sniff"],
                fallback_query: "system info pst",
                row_limit: 6,
            },
            RunbookStepSpec {
                step_id: "mobile_devices",
                title: "Android ADB / Fastboot Environment Check",
                suite_hint: "android2rust",
                preferred_tools: &[
                    "android2rust/android2rust_environment",
                    "android2rust/android2rust_presets",
                ],
                fallback_query: "environment presets adb",
                row_limit: 6,
            },
        ],
    },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostSummary {
    pub os: String,
    pub arch: String,
    pub family: String,
    pub cpu_logical_cores: usize,
    pub temp_dir_writable: bool,
    pub catalog_mode: String,
    pub discovered_suites_ready: usize,
    pub discovered_suites_total: usize,
    pub indexed_tools_total: usize,
    pub indexed_readonly_tools: usize,
    pub indexed_mutating_tools: usize,
    pub captured_at: DateTime<Utc>,
}

pub fn collect_host_summary(catalog: &SuiteCatalog) -> HostSummary {
    let cpu_logical_cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let temp_dir_writable = env::temp_dir().is_dir();
    HostSummary {
        os: env::consts::OS.to_string(),
        arch: env::consts::ARCH.to_string(),
        family: env::consts::FAMILY.to_string(),
        cpu_logical_cores,
        temp_dir_writable,
        catalog_mode: if catalog.is_offline() {
            "offline_synthetic".to_string()
        } else {
            "live".to_string()
        },
        discovered_suites_ready: catalog.ready_suite_count(),
        discovered_suites_total: catalog.suites().len(),
        indexed_tools_total: catalog.tools().len(),
        indexed_readonly_tools: catalog.total_readonly_tools(),
        indexed_mutating_tools: catalog.total_mutating_tools(),
        captured_at: Utc::now(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepFinding {
    pub step_id: String,
    pub title: String,
    pub suite_id: String,
    pub resolved_tool: Option<String>,
    pub status: String,
    pub row_count: usize,
    pub duration_ms: u64,
    pub highlights: Vec<Value>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunbookReport {
    pub runbook_id: String,
    pub title: String,
    pub domain: String,
    pub summary: String,
    pub executed_at: DateTime<Utc>,
    pub total_duration_ms: u64,
    pub host: HostSummary,
    pub findings: Vec<StepFinding>,
    pub custody: CustodyManifest,
    pub exported_report_path: Option<String>,
    pub exported_manifest_path: Option<String>,
}

impl RunbookReport {
    pub fn to_table_data(&self) -> TableData {
        let schema = runbook_findings_schema();
        let rows: Vec<Row> = self
            .findings
            .iter()
            .enumerate()
            .map(|(idx, f)| {
                let tool_label = f
                    .resolved_tool
                    .clone()
                    .unwrap_or_else(|| "(suite unavailable)".to_string());
                let summary_note = f
                    .note
                    .clone()
                    .unwrap_or_else(|| format!("Captured {} sample row(s)", f.row_count));
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(self.runbook_id.clone()),
                        CellValue::Text(f.step_id.clone()),
                        CellValue::Text(f.suite_id.clone()),
                        CellValue::Text(tool_label),
                        CellValue::Text(f.status.clone()),
                        CellValue::Uint(f.row_count as u64),
                        CellValue::Uint(f.duration_ms),
                        CellValue::Text(summary_note),
                    ],
                )
                .with_detail_json(serde_json::to_value(f).unwrap_or(Value::Null))
            })
            .collect();
        let total_rows = rows.len();
        TableData {
            schema,
            rows,
            total_rows,
        }
    }
}

pub fn find_runbook(runbook_id: &str) -> Option<&'static RunbookSpec> {
    CORE_RUNBOOKS
        .iter()
        .find(|r| r.id.eq_ignore_ascii_case(runbook_id.trim()))
}

pub struct RunbookEngine {
    catalog: Arc<SuiteCatalog>,
    last_findings: Mutex<Vec<(String, StepFinding)>>,
}

impl RunbookEngine {
    pub fn new(catalog: Arc<SuiteCatalog>) -> Self {
        Self {
            catalog,
            last_findings: Mutex::new(Vec::new()),
        }
    }

    pub fn catalog(&self) -> &Arc<SuiteCatalog> {
        &self.catalog
    }

    pub fn list_specs(&self) -> &'static [RunbookSpec] {
        CORE_RUNBOOKS
    }

    pub fn execute(
        &self,
        runbook_id: &str,
        export_dir: Option<&Path>,
        export_format: ExportFormat,
    ) -> Result<RunbookReport, RunbookError> {
        let spec = find_runbook(runbook_id).ok_or_else(|| RunbookError::UnknownRunbook(runbook_id.to_string()))?;
        let started = Instant::now();
        let host = collect_host_summary(&self.catalog);
        let mut findings = Vec::with_capacity(spec.steps.len() + 1);

        // Always prepend deterministic Step 0: Host Posture Snapshot
        findings.push(StepFinding {
            step_id: "host_posture".to_string(),
            title: "Local Host & Suite Readiness Snapshot".to_string(),
            suite_id: "guap".to_string(),
            resolved_tool: Some("guap/host_summary".to_string()),
            status: "ok".to_string(),
            row_count: 1,
            duration_ms: 0,
            highlights: vec![json!({
                "os": host.os,
                "arch": host.arch,
                "cores": host.cpu_logical_cores,
                "ready_suites": format!("{}/{}", host.discovered_suites_ready, host.discovered_suites_total),
                "indexed_tools": host.indexed_tools_total,
            })],
            note: Some(format!(
                "{}/{} suites ready ({} tools indexed)",
                host.discovered_suites_ready, host.discovered_suites_total, host.indexed_tools_total
            )),
        });

        for step in spec.steps {
            findings.push(self.run_step(step));
        }

        // Update cached findings table for Win32 / Iced inspection
        if let Ok(mut guard) = self.last_findings.lock() {
            guard.retain(|(rb, _)| rb != spec.id);
            for f in &findings {
                guard.push((spec.id.to_string(), f.clone()));
            }
        }

        let total_duration_ms = started.elapsed().as_millis() as u64;
        let executed_at = Utc::now();

        // Compute deterministic Merkle custody receipt over the report digest
        let digest_bytes = serde_json::to_vec_pretty(&json!({
            "runbook_id": spec.id,
            "executed_at": executed_at,
            "host": &host,
            "findings": &findings,
        }))
        .unwrap_or_default();

        let mut exported_report_path: Option<String> = None;
        let mut exported_manifest_path: Option<String> = None;
        let leaf_path = if let Some(dir) = export_dir {
            fs::create_dir_all(dir)?;
            let stamp = executed_at.format("%Y%m%dT%H%M%SZ");
            let report_file = dir.join(format!("{}_{}.{}", spec.id, stamp, export_format.extension()));
            let temp_report = RunbookReport {
                runbook_id: spec.id.to_string(),
                title: spec.title.to_string(),
                domain: spec.domain.to_string(),
                summary: spec.summary.to_string(),
                executed_at,
                total_duration_ms,
                host: host.clone(),
                findings: findings.clone(),
                custody: build_custody_manifest("guap.runbook", env!("CARGO_PKG_VERSION"), Vec::new()),
                exported_report_path: None,
                exported_manifest_path: None,
            };
            let table = temp_report.to_table_data();
            let rendered = export_table(
                &table,
                export_format,
                &ExportOptions {
                    title_override: Some(format!("GUAP Runbook — {}", spec.title)),
                    tool_version: env!("CARGO_PKG_VERSION").to_string(),
                    include_detail_json: export_format == ExportFormat::Json,
                    ..ExportOptions::default()
                },
            )?;
            fs::write(&report_file, &rendered)?;
            exported_report_path = Some(report_file.display().to_string());
            (report_file.display().to_string(), rendered)
        } else {
            (format!("memory://runbooks/{}", spec.id), digest_bytes)
        };

        let leaf = CustodyLeaf {
            index: 0,
            path: leaf_path.0,
            size_bytes: leaf_path.1.len() as u64,
            sha256: sha256_hex(&leaf_path.1),
            sha512: sha512_hex(&leaf_path.1),
        };
        let custody = build_custody_manifest(
            format!("guap.runbook.{}", spec.id),
            env!("CARGO_PKG_VERSION"),
            vec![leaf],
        );

        if let Some(ref report_path_str) = exported_report_path {
            let manifest_path = PathBuf::from(format!("{report_path_str}.custody.json"));
            write_custody_manifest_json(&custody, &manifest_path)?;
            exported_manifest_path = Some(manifest_path.display().to_string());
        }

        Ok(RunbookReport {
            runbook_id: spec.id.to_string(),
            title: spec.title.to_string(),
            domain: spec.domain.to_string(),
            summary: spec.summary.to_string(),
            executed_at,
            total_duration_ms,
            host,
            findings,
            custody,
            exported_report_path,
            exported_manifest_path,
        })
    }

    fn run_step(&self, step: &RunbookStepSpec) -> StepFinding {
        let t0 = Instant::now();
        let resolved = self.resolve_step_tool(step);
        let Some(tool_id) = resolved else {
            return StepFinding {
                step_id: step.step_id.to_string(),
                title: step.title.to_string(),
                suite_id: step.suite_hint.to_string(),
                resolved_tool: None,
                status: "skipped_unavailable".to_string(),
                row_count: 0,
                duration_ms: t0.elapsed().as_millis() as u64,
                highlights: Vec::new(),
                note: Some(format!(
                    "Suite '{}' is not installed or has no matching read-only tool yet",
                    step.suite_hint
                )),
            };
        };

        // Pass limit only if tool inputSchema accepts `limit`
        let supports_limit = self
            .catalog
            .resolve_tool(&tool_id)
            .ok()
            .and_then(|t| t.input_schema.get("properties"))
            .and_then(Value::as_object)
            .map(|p| p.contains_key("limit"))
            .unwrap_or(false);
        let call_args = if supports_limit {
            json!({ "limit": step.row_limit })
        } else {
            json!({})
        };

        match self.catalog.call_tool(&tool_id, &call_args, ToolExecMode::ReadOnly) {
            Ok(outcome) => {
                let (row_count, highlights) = compact_payload_highlights(&outcome.payload, 4);
                StepFinding {
                    step_id: step.step_id.to_string(),
                    title: step.title.to_string(),
                    suite_id: outcome.suite_id,
                    resolved_tool: Some(outcome.qualified_id),
                    status: if outcome.simulated { "ok_offline" } else { "ok" }.to_string(),
                    row_count,
                    duration_ms: t0.elapsed().as_millis() as u64,
                    highlights,
                    note: None,
                }
            }
            Err(err) => StepFinding {
                step_id: step.step_id.to_string(),
                title: step.title.to_string(),
                suite_id: step.suite_hint.to_string(),
                resolved_tool: Some(tool_id),
                status: "degraded".to_string(),
                row_count: 0,
                duration_ms: t0.elapsed().as_millis() as u64,
                highlights: Vec::new(),
                note: Some(truncate_str(&err.to_string(), 200)),
            },
        }
    }

    fn resolve_step_tool(&self, step: &RunbookStepSpec) -> Option<String> {
        for candidate in step.preferred_tools {
            if let Ok(tool) = self.catalog.resolve_tool(candidate)
                && tool.read_only
            {
                return Some(tool.qualified_id.clone());
            }
        }
        self.catalog
            .search_tools(step.fallback_query, None, Some(step.suite_hint), true, 1)
            .first()
            .map(|t| t.qualified_id.clone())
    }

    pub fn table_providers(engine: Arc<Self>) -> Vec<Arc<dyn TableProvider>> {
        vec![
            Arc::new(RunbooksCatalogProvider),
            Arc::new(RunbookFindingsProvider { engine }),
        ]
    }
}

fn compact_payload_highlights(payload: &Value, max_items: usize) -> (usize, Vec<Value>) {
    if let Some(rows) = payload.get("rows").and_then(Value::as_array) {
        let total = payload
            .get("total_rows")
            .and_then(Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(rows.len());
        let sample: Vec<Value> = rows
            .iter()
            .take(max_items)
            .map(|v| compact_json_value(v, 220))
            .collect();
        return (total, sample);
    }
    if let Some(arr) = payload.as_array() {
        let sample: Vec<Value> = arr.iter().take(max_items).map(|v| compact_json_value(v, 220)).collect();
        return (arr.len(), sample);
    }
    (1, vec![compact_json_value(payload, 320)])
}

fn compact_json_value(v: &Value, max_chars: usize) -> Value {
    let serialized = serde_json::to_string(v).unwrap_or_default();
    if serialized.len() <= max_chars {
        v.clone()
    } else {
        json!({ "summary": truncate_str(&serialized, max_chars) })
    }
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars).collect();
        out.push_str("...");
        out
    }
}

fn runbook_findings_schema() -> TableSchema {
    TableSchema::new(
        "runbooks.findings",
        "Runbook Diagnostic Findings",
        vec![
            ColumnDef::new("runbook_id", "Runbook", ColumnType::Text).with_width_hint(190),
            ColumnDef::new("step_id", "Step", ColumnType::Text).with_width_hint(150),
            ColumnDef::new("suite_id", "Suite", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("tool", "Resolved Tool", ColumnType::Text).with_width_hint(210),
            ColumnDef::new("status", "Status", ColumnType::Text).with_width_hint(110),
            ColumnDef::new("row_count", "Rows", ColumnType::Uint).with_width_hint(80),
            ColumnDef::new("duration_ms", "Duration", ColumnType::Duration).with_width_hint(95),
            ColumnDef::new("note", "Finding Summary", ColumnType::Text).with_width_hint(320),
        ],
    )
}

struct RunbooksCatalogProvider;

impl TableProvider for RunbooksCatalogProvider {
    fn tool_id(&self) -> &'static str {
        "runbooks.catalog"
    }

    fn description(&self) -> &'static str {
        "Six deterministic v1 IT administration and triage runbooks"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            "runbooks.catalog",
            "Deterministic IT Runbooks",
            vec![
                ColumnDef::new("runbook_id", "Runbook ID", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("title", "Title", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("domain", "Domain", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("steps", "Probes", ColumnType::Uint).with_width_hint(80),
                ColumnDef::new("summary", "Summary", ColumnType::Text).with_width_hint(420),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let schema = self.schema();
        let rows: Vec<Row> = CORE_RUNBOOKS
            .iter()
            .enumerate()
            .map(|(i, rb)| {
                let step_ids: Vec<&str> = rb.steps.iter().map(|s| s.step_id).collect();
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(rb.id.to_string()),
                        CellValue::Text(rb.title.to_string()),
                        CellValue::Text(rb.domain.to_string()),
                        CellValue::Uint((rb.steps.len() + 1) as u64),
                        CellValue::Text(rb.summary.to_string()),
                    ],
                )
                .with_detail_json(json!({
                    "id": rb.id,
                    "title": rb.title,
                    "domain": rb.domain,
                    "summary": rb.summary,
                    "steps": step_ids,
                }))
            })
            .collect();
        apply_query(&schema, &rows, req)
    }
}

struct RunbookFindingsProvider {
    engine: Arc<RunbookEngine>,
}

impl TableProvider for RunbookFindingsProvider {
    fn tool_id(&self) -> &'static str {
        "runbooks.findings"
    }

    fn description(&self) -> &'static str {
        "Captured diagnostic findings from executed IT runbooks"
    }

    fn schema(&self) -> TableSchema {
        runbook_findings_schema()
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let schema = self.schema();
        let cached = self.engine.last_findings.lock().map(|g| g.clone()).unwrap_or_default();
        let source_items: Vec<(String, StepFinding)> = if cached.is_empty() {
            // Seed with a lightweight host posture run on first view so GUIs are never empty!
            if let Ok(rep) = self
                .engine
                .execute("health_and_security_posture", None, ExportFormat::Json)
            {
                rep.findings
                    .into_iter()
                    .map(|f| ("health_and_security_posture".to_string(), f))
                    .collect()
            } else {
                Vec::new()
            }
        } else {
            cached
        };

        let rows: Vec<Row> = source_items
            .iter()
            .enumerate()
            .map(|(idx, (rb_id, f))| {
                let tool_label = f
                    .resolved_tool
                    .clone()
                    .unwrap_or_else(|| "(suite unavailable)".to_string());
                let summary_note = f
                    .note
                    .clone()
                    .unwrap_or_else(|| format!("Captured {} sample row(s)", f.row_count));
                Row::new(
                    (idx + 1) as u64,
                    vec![
                        CellValue::Text(rb_id.clone()),
                        CellValue::Text(f.step_id.clone()),
                        CellValue::Text(f.suite_id.clone()),
                        CellValue::Text(tool_label),
                        CellValue::Text(f.status.clone()),
                        CellValue::Uint(f.row_count as u64),
                        CellValue::Uint(f.duration_ms),
                        CellValue::Text(summary_note),
                    ],
                )
                .with_detail_json(serde_json::to_value(f).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&schema, &rows, req)
    }
}

#[cfg(test)]
mod tests {
    use guap_catalog::CatalogConfig;

    use super::*;

    #[test]
    fn executes_all_6_core_runbooks_offline_and_writes_merkle_custody_manifest() {
        let cat = Arc::new(SuiteCatalog::discover(CatalogConfig::offline()));
        let engine = RunbookEngine::new(cat);
        let tmp = tempfile::tempdir().unwrap();

        for spec in CORE_RUNBOOKS {
            let report = engine
                .execute(spec.id, Some(tmp.path()), ExportFormat::Markdown)
                .unwrap_or_else(|e| panic!("runbook '{}' failed: {e}", spec.id));
            assert_eq!(report.runbook_id, spec.id);
            assert_eq!(report.findings.len(), spec.steps.len() + 1);
            assert!(!report.custody.merkle_root_sha256.is_empty());
            assert!(!report.custody.merkle_root_sha512.is_empty());
            let md_path = PathBuf::from(report.exported_report_path.as_ref().unwrap());
            let custody_path = PathBuf::from(report.exported_manifest_path.as_ref().unwrap());
            assert!(md_path.is_file());
            assert!(custody_path.is_file());

            // Verify digest stays well below the 1,500-token (~6,000-byte) budget
            let serialized = serde_json::to_string(&report.findings).unwrap();
            assert!(
                serialized.len() < 6_000,
                "runbook '{}' digest exceeded compact token budget: {} bytes",
                spec.id,
                serialized.len()
            );
        }
    }
}
