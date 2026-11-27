#![forbid(unsafe_code)]

//! Six-Meta-Tool Lazy MCP Gateway (`~800` prompt tokens), Tiered Autonomy Policy Engine,
//! SQLite-backed **Approval Cards** (`dry_run` preview + human sign-off), deterministic
//! **Job Profiles**, and SHA-256/512 Merkle `CustodyManifest` audit logging.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::Utc;
use guap_catalog::{CatalogError, SuiteCatalog, ToolExecMode};
use guap_export::{
    CustodyLeaf, ExportFormat, build_custody_manifest, sha256_hex, sha512_hex, write_custody_manifest_json,
};
use guap_mcp::{ActionCommand, ActionRiskLevel, McpServerRegistry, McpToolError, PolicyMode};
use guap_runbooks::{CORE_RUNBOOKS, RunbookEngine, RunbookError, collect_host_summary};
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

pub const META_TOOL_COUNT: usize = 6;

#[derive(Debug, Error)]
pub enum RouterError {
    #[error("catalog error: {0}")]
    Catalog(#[from] CatalogError),

    #[error("runbook error: {0}")]
    Runbook(#[from] RunbookError),

    #[error("SQLite state error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("approval card '{0}' not found")]
    CardNotFound(String),

    #[error("approval card '{0}' cannot transition from status '{1}'")]
    InvalidCardState(String, String),

    #[error("job profile '{0}' not found")]
    JobNotFound(String),

    #[error("safety refusal: job profile '{0}' is not approved for execution")]
    JobNotApproved(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalCard {
    pub card_id: String,
    pub created_at: String,
    pub status: String,
    pub suite_id: String,
    pub tool_id: String,
    pub rationale: String,
    pub rollback_hint: String,
    pub arguments: Value,
    pub dry_run_preview: Value,
    pub execution_result: Option<Value>,
    pub custody_merkle_sha256: Option<String>,
    pub decided_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProfileStep {
    pub kind: String,
    pub target: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProfile {
    pub profile_id: String,
    pub name: String,
    pub schedule_hint: String,
    pub enabled: bool,
    pub approved: bool,
    pub steps: Vec<JobProfileStep>,
    pub last_run_at: Option<String>,
    pub last_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustodyAuditEntry {
    pub receipt_id: String,
    pub recorded_at: String,
    pub actor: String,
    pub operation: String,
    pub target_id: String,
    pub merkle_sha256: String,
    pub merkle_sha512: String,
    pub manifest_path: String,
}

#[derive(Debug, Clone)]
pub struct RouterConfig {
    pub state_dir: PathBuf,
    pub in_memory_db: bool,
    pub llm_endpoint: String,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            state_dir: default_state_dir(),
            in_memory_db: false,
            llm_endpoint: env::var("GUAP_LLM_ENDPOINT")
                .unwrap_or_else(|_| "http://127.0.0.1:9931/v1/chat/completions".to_string()),
        }
    }
}

impl RouterConfig {
    pub fn ephemeral(temp_dir: PathBuf) -> Self {
        Self {
            state_dir: temp_dir,
            in_memory_db: true,
            llm_endpoint: "http://127.0.0.1:9931/v1/chat/completions".to_string(),
        }
    }
}

pub fn default_state_dir() -> PathBuf {
    if let Ok(explicit) = env::var("GUAP_STATE_DIR") {
        return PathBuf::from(explicit);
    }
    if let Ok(exe) = env::current_exe()
        && let Some(dir) = exe.parent()
        && dir.join("guap-portable.marker").is_file()
    {
        return dir.join("state");
    }
    dirs::data_local_dir()
        .unwrap_or_else(env::temp_dir)
        .join("GUAP")
        .join("state")
}

pub struct RouterEngine {
    config: RouterConfig,
    catalog: Arc<SuiteCatalog>,
    runbooks: Arc<RunbookEngine>,
    conn: Mutex<Connection>,
}

impl RouterEngine {
    pub fn new(
        config: RouterConfig,
        catalog: Arc<SuiteCatalog>,
        runbooks: Arc<RunbookEngine>,
    ) -> Result<Self, RouterError> {
        fs::create_dir_all(&config.state_dir)?;
        let conn = if config.in_memory_db {
            Connection::open_in_memory()?
        } else {
            let db_path = config.state_dir.join("guap_state.sqlite");
            Connection::open(db_path)?
        };
        init_schema_and_defaults(&conn)?;
        Ok(Self {
            config,
            catalog,
            runbooks,
            conn: Mutex::new(conn),
        })
    }

    pub fn config(&self) -> &RouterConfig {
        &self.config
    }

    pub fn catalog(&self) -> &Arc<SuiteCatalog> {
        &self.catalog
    }

    pub fn runbooks(&self) -> &Arc<RunbookEngine> {
        &self.runbooks
    }

    pub fn reports_dir(&self) -> PathBuf {
        self.config.state_dir.join("reports")
    }

    pub fn receipts_dir(&self) -> PathBuf {
        self.config.state_dir.join("receipts")
    }

    /// Meta-Tool 1: `guap_host_summary`
    pub fn host_summary(&self) -> Result<Value, RouterError> {
        let host = collect_host_summary(&self.catalog);
        let pending_cards = self.count_pending_cards()?;
        let jobs = self.list_job_profiles()?;
        let runbook_ids: Vec<&str> = CORE_RUNBOOKS.iter().map(|r| r.id).collect();
        Ok(json!({
            "host": host,
            "llm_endpoint": self.config.llm_endpoint,
            "state_dir": self.config.state_dir.display().to_string(),
            "pending_approval_cards": pending_cards,
            "job_profiles_count": jobs.len(),
            "available_runbooks": runbook_ids,
        }))
    }

    /// Meta-Tool 2: `guap_run_runbook`
    pub fn run_runbook(&self, runbook_id: &str, persist_report: bool) -> Result<Value, RouterError> {
        let export_dir = if persist_report { Some(self.reports_dir()) } else { None };
        let report = self
            .runbooks
            .execute(runbook_id, export_dir.as_deref(), ExportFormat::Markdown)?;
        let manifest_path = report
            .exported_manifest_path
            .clone()
            .unwrap_or_else(|| format!("memory://runbooks/{}", report.runbook_id));
        self.record_custody_entry(
            "guap-router",
            "runbook",
            &report.runbook_id,
            &report.custody.merkle_root_sha256,
            &report.custody.merkle_root_sha512,
            &manifest_path,
        )?;
        Ok(json!({
            "runbook_id": report.runbook_id,
            "title": report.title,
            "executed_at": report.executed_at,
            "total_duration_ms": report.total_duration_ms,
            "findings": report.findings,
            "merkle_root_sha256": report.custody.merkle_root_sha256,
            "exported_report_path": report.exported_report_path,
        }))
    }

    /// Meta-Tool 3: `guap_find_tools`
    pub fn find_tools(
        &self,
        query: &str,
        domain: Option<&str>,
        suite: Option<&str>,
        read_only_only: bool,
        limit: usize,
    ) -> Value {
        let cap = limit.clamp(1, 5);
        let matches = self.catalog.search_tools(query, domain, suite, read_only_only, cap);
        let items: Vec<Value> = matches
            .into_iter()
            .map(|t| {
                json!({
                    "qualified_id": t.qualified_id,
                    "suite_id": t.suite_id,
                    "domain": t.domain,
                    "read_only": t.read_only,
                    "description": t.description,
                    "input_schema": t.input_schema,
                })
            })
            .collect();
        json!({
            "query": query,
            "returned": items.len(),
            "tools": items,
        })
    }

    /// Meta-Tool 4: `guap_call_readonly`
    pub fn call_readonly(
        &self,
        tool_ref: &str,
        arguments: &Value,
        max_rows: usize,
        max_bytes: usize,
    ) -> Result<Value, RouterError> {
        let row_cap = max_rows.clamp(1, 100);
        let byte_cap = max_bytes.clamp(512, 32_768);
        let outcome = self.catalog.call_tool(tool_ref, arguments, ToolExecMode::ReadOnly)?;
        let bounded = bound_payload(&outcome.payload, row_cap, byte_cap);
        Ok(json!({
            "qualified_id": outcome.qualified_id,
            "suite_id": outcome.suite_id,
            "simulated": outcome.simulated,
            "result": bounded,
        }))
    }

    /// Meta-Tool 5: `guap_stage_fix`
    /// Runs `DryRunPreview` first and creates a `pending` Approval Card.
    /// NEVER mutates host state without subsequent human `approve_card`.
    pub fn stage_fix(
        &self,
        tool_ref: &str,
        arguments: &Value,
        rationale: &str,
        rollback_hint: &str,
    ) -> Result<ApprovalCard, RouterError> {
        let preview = self
            .catalog
            .call_tool(tool_ref, arguments, ToolExecMode::DryRunPreview)?;
        let now = Utc::now();
        let card_hash = sha256_hex(
            format!(
                "{}:{}:{}",
                preview.qualified_id,
                now.timestamp_nanos_opt().unwrap_or(0),
                rationale
            )
            .as_bytes(),
        );
        let card_id = format!("card-{}", &card_hash[..10]);
        let created_at = now.to_rfc3339();
        let clean_rationale = if rationale.trim().is_empty() {
            format!("Proposed remediation via {}", preview.qualified_id)
        } else {
            rationale.trim().to_string()
        };
        let clean_rollback = if rollback_hint.trim().is_empty() {
            "Review pre-execution parameters and restore previous setting if needed".to_string()
        } else {
            rollback_hint.trim().to_string()
        };

        let card = ApprovalCard {
            card_id: card_id.clone(),
            created_at: created_at.clone(),
            status: "pending".to_string(),
            suite_id: preview.suite_id.clone(),
            tool_id: preview.qualified_id.clone(),
            rationale: clean_rationale.clone(),
            rollback_hint: clean_rollback.clone(),
            arguments: arguments.clone(),
            dry_run_preview: preview.payload.clone(),
            execution_result: None,
            custody_merkle_sha256: None,
            decided_at: None,
        };

        let args_str = serde_json::to_string(&card.arguments)?;
        let preview_str = serde_json::to_string(&card.dry_run_preview)?;
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT INTO approval_cards (
                card_id, created_at, status, suite_id, tool_id, rationale, rollback_hint,
                arguments_json, dry_run_preview_json
            ) VALUES (?1, ?2, 'pending', ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                card.card_id,
                card.created_at,
                card.suite_id,
                card.tool_id,
                card.rationale,
                card.rollback_hint,
                args_str,
                preview_str,
            ],
        )?;
        drop(conn);

        Ok(card)
    }

    /// Human-only action: explicitly approve and execute a `pending` Approval Card,
    /// writing a cryptographic Merkle `CustodyManifest` receipt to disk.
    pub fn approve_card(&self, card_id: &str, actor: &str) -> Result<ApprovalCard, RouterError> {
        let mut card = self.get_card(card_id)?;
        if card.status != "pending" {
            return Err(RouterError::InvalidCardState(card_id.to_string(), card.status));
        }

        let decided_at = Utc::now().to_rfc3339();
        let outcome_res = self
            .catalog
            .call_tool(&card.tool_id, &card.arguments, ToolExecMode::ApprovedMutating);

        let (new_status, exec_json) = match outcome_res {
            Ok(outcome) => ("executed".to_string(), outcome.payload),
            Err(err) => ("failed".to_string(), json!({ "error": err.to_string() })),
        };

        // Persist pre/post custody receipt + Merkle manifest
        let receipts_dir = self.receipts_dir();
        fs::create_dir_all(&receipts_dir)?;
        let receipt_path = receipts_dir.join(format!("{}.receipt.json", card.card_id));
        let receipt_bytes = serde_json::to_vec_pretty(&json!({
            "card_id": card.card_id,
            "approved_by": actor,
            "decided_at": decided_at,
            "tool_id": card.tool_id,
            "rationale": card.rationale,
            "rollback_hint": card.rollback_hint,
            "arguments": card.arguments,
            "dry_run_preview": card.dry_run_preview,
            "execution_result": exec_json,
            "status": new_status,
        }))?;
        fs::write(&receipt_path, &receipt_bytes)?;

        let leaf = CustodyLeaf {
            index: 0,
            path: receipt_path.display().to_string(),
            size_bytes: receipt_bytes.len() as u64,
            sha256: sha256_hex(&receipt_bytes),
            sha512: sha512_hex(&receipt_bytes),
        };
        let manifest = build_custody_manifest(
            format!("guap.approval.{}", card.card_id),
            env!("CARGO_PKG_VERSION"),
            vec![leaf],
        );
        let manifest_path = receipts_dir.join(format!("{}.custody.json", card.card_id));
        write_custody_manifest_json(&manifest, &manifest_path)
            .map_err(|e| RouterError::Io(std::io::Error::other(e)))?;

        let exec_str = serde_json::to_string(&exec_json)?;
        {
            let conn = self.conn.lock().expect("sqlite mutex poisoned");
            conn.execute(
                "UPDATE approval_cards
                 SET status = ?1, execution_result_json = ?2, custody_merkle_sha256 = ?3, decided_at = ?4
                 WHERE card_id = ?5",
                params![
                    new_status,
                    exec_str,
                    manifest.merkle_root_sha256,
                    decided_at,
                    card.card_id
                ],
            )?;
        }

        self.record_custody_entry(
            actor,
            &format!("approve_card:{new_status}"),
            &card.tool_id,
            &manifest.merkle_root_sha256,
            &manifest.merkle_root_sha512,
            &manifest_path.display().to_string(),
        )?;

        card.status = new_status;
        card.execution_result = Some(exec_json);
        card.custody_merkle_sha256 = Some(manifest.merkle_root_sha256);
        card.decided_at = Some(decided_at);
        Ok(card)
    }

    pub fn reject_card(&self, card_id: &str, actor: &str) -> Result<ApprovalCard, RouterError> {
        let mut card = self.get_card(card_id)?;
        if card.status != "pending" {
            return Err(RouterError::InvalidCardState(card_id.to_string(), card.status));
        }
        let decided_at = Utc::now().to_rfc3339();
        let reject_note = json!({ "rejected_by": actor, "decided_at": decided_at });
        let reject_str = serde_json::to_string(&reject_note)?;
        {
            let conn = self.conn.lock().expect("sqlite mutex poisoned");
            conn.execute(
                "UPDATE approval_cards SET status = 'rejected', execution_result_json = ?1, decided_at = ?2 WHERE card_id = ?3",
                params![reject_str, decided_at, card_id],
            )?;
        }
        card.status = "rejected".to_string();
        card.execution_result = Some(reject_note);
        card.decided_at = Some(decided_at);
        Ok(card)
    }

    pub fn get_card(&self, card_id: &str) -> Result<ApprovalCard, RouterError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let row = conn
            .query_row(
                "SELECT card_id, created_at, status, suite_id, tool_id, rationale, rollback_hint,
                        arguments_json, dry_run_preview_json, execution_result_json,
                        custody_merkle_sha256, decided_at
                 FROM approval_cards WHERE card_id = ?1",
                params![card_id],
                map_card_row,
            )
            .optional()?;
        row.ok_or_else(|| RouterError::CardNotFound(card_id.to_string()))
    }

    pub fn list_cards(&self, status_filter: Option<&str>) -> Result<Vec<ApprovalCard>, RouterError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut cards = Vec::new();
        if let Some(st) = status_filter {
            let mut stmt = conn.prepare(
                "SELECT card_id, created_at, status, suite_id, tool_id, rationale, rollback_hint,
                        arguments_json, dry_run_preview_json, execution_result_json,
                        custody_merkle_sha256, decided_at
                 FROM approval_cards WHERE status = ?1 ORDER BY created_at DESC",
            )?;
            let iter = stmt.query_map(params![st], map_card_row)?;
            for item in iter {
                cards.push(item?);
            }
        } else {
            let mut stmt = conn.prepare(
                "SELECT card_id, created_at, status, suite_id, tool_id, rationale, rollback_hint,
                        arguments_json, dry_run_preview_json, execution_result_json,
                        custody_merkle_sha256, decided_at
                 FROM approval_cards ORDER BY created_at DESC",
            )?;
            let iter = stmt.query_map([], map_card_row)?;
            for item in iter {
                cards.push(item?);
            }
        }
        Ok(cards)
    }

    pub fn count_pending_cards(&self) -> Result<usize, RouterError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM approval_cards WHERE status = 'pending'",
            [],
            |r| r.get(0),
        )?;
        Ok(n.max(0) as usize)
    }

    /// Meta-Tool 6: `guap_manage_schedule`
    pub fn list_job_profiles(&self) -> Result<Vec<JobProfile>, RouterError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT profile_id, name, schedule_hint, enabled, approved, steps_json, last_run_at, last_status
             FROM job_profiles ORDER BY profile_id ASC",
        )?;
        let iter = stmt.query_map([], map_job_row)?;
        let mut out = Vec::new();
        for r in iter {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn stage_job_profile(
        &self,
        profile_id: &str,
        name: &str,
        schedule_hint: &str,
        steps: Vec<JobProfileStep>,
    ) -> Result<JobProfile, RouterError> {
        let steps_json = serde_json::to_string(&steps)?;
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT OR REPLACE INTO job_profiles
             (profile_id, name, schedule_hint, enabled, approved, steps_json, last_run_at, last_status)
             VALUES (?1, ?2, ?3, 0, 0, ?4, NULL, 'staged_pending_approval')",
            params![profile_id, name, schedule_hint, steps_json],
        )?;
        Ok(JobProfile {
            profile_id: profile_id.to_string(),
            name: name.to_string(),
            schedule_hint: schedule_hint.to_string(),
            enabled: false,
            approved: false,
            steps,
            last_run_at: None,
            last_status: Some("staged_pending_approval".to_string()),
        })
    }

    pub fn approve_job_profile(&self, profile_id: &str) -> Result<JobProfile, RouterError> {
        {
            let conn = self.conn.lock().expect("sqlite mutex poisoned");
            let changed = conn.execute(
                "UPDATE job_profiles SET approved = 1, enabled = 1, last_status = 'approved' WHERE profile_id = ?1",
                params![profile_id],
            )?;
            if changed == 0 {
                return Err(RouterError::JobNotFound(profile_id.to_string()));
            }
        }
        self.get_job_profile(profile_id)
    }

    pub fn get_job_profile(&self, profile_id: &str) -> Result<JobProfile, RouterError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.query_row(
            "SELECT profile_id, name, schedule_hint, enabled, approved, steps_json, last_run_at, last_status
             FROM job_profiles WHERE profile_id = ?1",
            params![profile_id],
            map_job_row,
        )
        .optional()?
        .ok_or_else(|| RouterError::JobNotFound(profile_id.to_string()))
    }

    /// Deterministic unattended runner (`guap job run <profile_id>`):
    /// Refuses unapproved profiles and executes each step without needing an LLM.
    pub fn run_job_profile(&self, profile_id: &str) -> Result<Value, RouterError> {
        let job = self.get_job_profile(profile_id)?;
        if !job.approved {
            return Err(RouterError::JobNotApproved(profile_id.to_string()));
        }
        let mut step_results = Vec::with_capacity(job.steps.len());
        let mut overall_ok = true;
        for step in &job.steps {
            match step.kind.as_str() {
                "runbook" => match self.run_runbook(&step.target, true) {
                    Ok(val) => step_results.push(json!({ "step": step.target, "status": "ok", "output": val })),
                    Err(err) => {
                        overall_ok = false;
                        step_results.push(json!({ "step": step.target, "status": "error", "error": err.to_string() }));
                    }
                },
                "readonly_tool" => match self.call_readonly(&step.target, &step.arguments, 20, 8_192) {
                    Ok(val) => step_results.push(json!({ "step": step.target, "status": "ok", "output": val })),
                    Err(err) => {
                        overall_ok = false;
                        step_results.push(json!({ "step": step.target, "status": "error", "error": err.to_string() }));
                    }
                },
                other => {
                    overall_ok = false;
                    step_results.push(json!({
                        "step": step.target,
                        "status": "error",
                        "error": format!("unsupported deterministic step kind '{other}'")
                    }));
                }
            }
        }

        let now = Utc::now().to_rfc3339();
        let status_label = if overall_ok {
            "succeeded"
        } else {
            "completed_with_errors"
        };
        {
            let conn = self.conn.lock().expect("sqlite mutex poisoned");
            conn.execute(
                "UPDATE job_profiles SET last_run_at = ?1, last_status = ?2 WHERE profile_id = ?3",
                params![now, status_label, profile_id],
            )?;
        }

        Ok(json!({
            "profile_id": job.profile_id,
            "name": job.name,
            "ran_at": now,
            "status": status_label,
            "steps": step_results,
        }))
    }

    pub fn list_custody_entries(&self) -> Result<Vec<CustodyAuditEntry>, RouterError> {
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT receipt_id, recorded_at, actor, operation, target_id, merkle_sha256, merkle_sha512, manifest_path
             FROM custody_log ORDER BY recorded_at DESC",
        )?;
        let iter = stmt.query_map([], |r| {
            Ok(CustodyAuditEntry {
                receipt_id: r.get(0)?,
                recorded_at: r.get(1)?,
                actor: r.get(2)?,
                operation: r.get(3)?,
                target_id: r.get(4)?,
                merkle_sha256: r.get(5)?,
                merkle_sha512: r.get(6)?,
                manifest_path: r.get(7)?,
            })
        })?;
        let mut out = Vec::new();
        for item in iter {
            out.push(item?);
        }
        Ok(out)
    }

    fn record_custody_entry(
        &self,
        actor: &str,
        operation: &str,
        target_id: &str,
        merkle_sha256: &str,
        merkle_sha512: &str,
        manifest_path: &str,
    ) -> Result<(), RouterError> {
        let now = Utc::now();
        let receipt_id = format!(
            "rcpt-{}",
            &sha256_hex(format!("{now}:{operation}:{target_id}").as_bytes())[..10]
        );
        let conn = self.conn.lock().expect("sqlite mutex poisoned");
        conn.execute(
            "INSERT INTO custody_log
             (receipt_id, recorded_at, actor, operation, target_id, merkle_sha256, merkle_sha512, manifest_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                receipt_id,
                now.to_rfc3339(),
                actor,
                operation,
                target_id,
                merkle_sha256,
                merkle_sha512,
                manifest_path,
            ],
        )?;
        Ok(())
    }

    /// Build the 6-Meta-Tool MCP server registry (`PolicyMode::ReadOnlyOnly` safe by design:
    /// staging fixes creates pending Approval Cards without mutating the OS).
    pub fn build_mcp_registry(router: Arc<Self>) -> McpServerRegistry {
        let mut reg =
            McpServerRegistry::new(PolicyMode::ReadOnlyOnly).with_server_info("guap", env!("CARGO_PKG_VERSION"));
        for tool in Self::meta_tools(router) {
            reg.register_action(tool);
        }
        reg
    }

    /// Returns the 6 compact flagship meta-tools (~800 prompt tokens total).
    pub fn meta_tools(router: Arc<Self>) -> Vec<Arc<dyn ActionCommand>> {
        vec![
            Arc::new(HostSummaryMetaTool {
                router: Arc::clone(&router),
            }),
            Arc::new(RunRunbookMetaTool {
                router: Arc::clone(&router),
            }),
            Arc::new(FindToolsMetaTool {
                router: Arc::clone(&router),
            }),
            Arc::new(CallReadonlyMetaTool {
                router: Arc::clone(&router),
            }),
            Arc::new(StageFixMetaTool {
                router: Arc::clone(&router),
            }),
            Arc::new(ManageScheduleMetaTool { router }),
        ]
    }

    /// `TableProvider` views for `guap-win32` and `guap-iced`.
    pub fn table_providers(router: Arc<Self>) -> Vec<Arc<dyn TableProvider>> {
        vec![
            Arc::new(ApprovalCardsTableProvider {
                router: Arc::clone(&router),
            }),
            Arc::new(JobProfilesTableProvider {
                router: Arc::clone(&router),
            }),
            Arc::new(CustodyLogTableProvider { router }),
        ]
    }

    /// Human operator `ActionCommand`s exposed inside `guap-win32` desktop UI.
    pub fn gui_operator_actions(router: Arc<Self>) -> Vec<Arc<dyn ActionCommand>> {
        let mut actions = Self::meta_tools(Arc::clone(&router));
        actions.push(Arc::new(ApproveCardGuiAction {
            router: Arc::clone(&router),
        }));
        actions.push(Arc::new(RejectCardGuiAction { router }));
        actions
    }
}

fn init_schema_and_defaults(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS approval_cards (
            card_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL,
            suite_id TEXT NOT NULL,
            tool_id TEXT NOT NULL,
            rationale TEXT NOT NULL,
            rollback_hint TEXT NOT NULL,
            arguments_json TEXT NOT NULL,
            dry_run_preview_json TEXT NOT NULL,
            execution_result_json TEXT,
            custody_merkle_sha256 TEXT,
            decided_at TEXT
        );
        CREATE TABLE IF NOT EXISTS job_profiles (
            profile_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            schedule_hint TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            approved INTEGER NOT NULL DEFAULT 0,
            steps_json TEXT NOT NULL,
            last_run_at TEXT,
            last_status TEXT
        );
        CREATE TABLE IF NOT EXISTS custody_log (
            receipt_id TEXT PRIMARY KEY,
            recorded_at TEXT NOT NULL,
            actor TEXT NOT NULL,
            operation TEXT NOT NULL,
            target_id TEXT NOT NULL,
            merkle_sha256 TEXT NOT NULL,
            merkle_sha512 TEXT NOT NULL,
            manifest_path TEXT NOT NULL
        );",
    )?;

    let existing: i64 = conn.query_row("SELECT COUNT(*) FROM job_profiles", [], |r| r.get(0))?;
    if existing == 0 {
        let weekly_steps = serde_json::to_string(&vec![JobProfileStep {
            kind: "runbook".to_string(),
            target: "health_and_security_posture".to_string(),
            arguments: json!({}),
        }])
        .unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO job_profiles (profile_id, name, schedule_hint, enabled, approved, steps_json, last_status)
             VALUES ('weekly_health_audit', 'Weekly Endpoint Health & Security Posture', 'SUN 09:00', 1, 1, ?1, 'ready')",
            params![weekly_steps],
        )?;

        let storage_steps = serde_json::to_string(&vec![JobProfileStep {
            kind: "runbook".to_string(),
            target: "storage_and_backup_audit".to_string(),
            arguments: json!({}),
        }])
        .unwrap_or_else(|_| "[]".to_string());
        conn.execute(
            "INSERT INTO job_profiles (profile_id, name, schedule_hint, enabled, approved, steps_json, last_status)
             VALUES ('nightly_storage_audit', 'Nightly Storage, SMART & Backup Readiness Audit', 'DAILY 02:00', 1, 1, ?1, 'ready')",
            params![storage_steps],
        )?;
    }
    Ok(())
}

fn map_card_row(r: &rusqlite::Row<'_>) -> Result<ApprovalCard, rusqlite::Error> {
    let args_s: String = r.get(7)?;
    let prev_s: String = r.get(8)?;
    let exec_s: Option<String> = r.get(9)?;
    Ok(ApprovalCard {
        card_id: r.get(0)?,
        created_at: r.get(1)?,
        status: r.get(2)?,
        suite_id: r.get(3)?,
        tool_id: r.get(4)?,
        rationale: r.get(5)?,
        rollback_hint: r.get(6)?,
        arguments: serde_json::from_str(&args_s).unwrap_or(Value::Null),
        dry_run_preview: serde_json::from_str(&prev_s).unwrap_or(Value::Null),
        execution_result: exec_s.and_then(|s| serde_json::from_str(&s).ok()),
        custody_merkle_sha256: r.get(10)?,
        decided_at: r.get(11)?,
    })
}

fn map_job_row(r: &rusqlite::Row<'_>) -> Result<JobProfile, rusqlite::Error> {
    let enabled_i: i64 = r.get(3)?;
    let approved_i: i64 = r.get(4)?;
    let steps_s: String = r.get(5)?;
    Ok(JobProfile {
        profile_id: r.get(0)?,
        name: r.get(1)?,
        schedule_hint: r.get(2)?,
        enabled: enabled_i != 0,
        approved: approved_i != 0,
        steps: serde_json::from_str(&steps_s).unwrap_or_default(),
        last_run_at: r.get(6)?,
        last_status: r.get(7)?,
    })
}

fn bound_payload(payload: &Value, max_rows: usize, max_bytes: usize) -> Value {
    let mut candidate = payload.clone();
    if let Some(obj) = candidate.as_object_mut()
        && let Some(rows) = obj.get_mut("rows").and_then(Value::as_array_mut)
        && rows.len() > max_rows
    {
        let original_len = rows.len();
        rows.truncate(max_rows);
        obj.insert("truncated_from_rows".to_string(), json!(original_len));
        obj.insert("returned_rows".to_string(), json!(max_rows));
    }
    let encoded = serde_json::to_string(&candidate).unwrap_or_default();
    if encoded.len() <= max_bytes {
        candidate
    } else {
        let snippet: String = encoded.chars().take(max_bytes).collect();
        json!({
            "truncated": true,
            "original_bytes": encoded.len(),
            "excerpt": snippet,
        })
    }
}

// ============================================================================
// 6 Compact Flagship Meta-Tools
// ============================================================================

struct HostSummaryMetaTool {
    router: Arc<RouterEngine>,
}

impl ActionCommand for HostSummaryMetaTool {
    fn command_id(&self) -> &'static str {
        "guap_host_summary"
    }

    fn description(&self) -> &'static str {
        "Snapshot host OS/CPU, discovered GUAP suites, indexed tool counts, and pending Approval Cards"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::ReadOnly
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {}
        })
    }

    fn execute(&self, _args: &Value, _dry_run: bool) -> Result<Value, McpToolError> {
        self.router
            .host_summary()
            .map_err(|e| McpToolError::ExecutionFailed(e.to_string()))
    }
}

struct RunRunbookMetaTool {
    router: Arc<RouterEngine>,
}

impl ActionCommand for RunRunbookMetaTool {
    fn command_id(&self) -> &'static str {
        "guap_run_runbook"
    }

    fn description(&self) -> &'static str {
        "Run a deterministic IT triage runbook first and emit a <1,500-token digest + Merkle custody hash"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::ReadOnly
    }

    fn input_schema(&self) -> Value {
        let ids: Vec<&str> = CORE_RUNBOOKS.iter().map(|r| r.id).collect();
        json!({
            "type": "object",
            "properties": {
                "runbook_id": {
                    "type": "string",
                    "enum": ids,
                    "description": "Canonical runbook ID: health_and_security_posture (Defender/services/SMART), slowdown_and_startup_triage (boot/CPU/startup/IO), crash_and_event_postmortem (BSOD/WER/EVTX), storage_and_backup_audit (disk space/SMART/Robocopy backup), network_and_lan_triage (Wi-Fi/DNS/sockets/routes), mail_browser_device_rescue (Chrome/Edge profiles, PST/mail, Android ADB)"
                },
                "persist_report": {
                    "type": "boolean",
                    "default": true,
                    "description": "Write Markdown report and .custody.json Merkle manifest to state/reports/"
                }
            },
            "required": ["runbook_id"]
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let rb_id = args
            .get("runbook_id")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing string 'runbook_id'".to_string()))?;
        if dry_run {
            return Ok(json!({ "dry_run": true, "would_run_runbook": rb_id }));
        }
        let persist = args.get("persist_report").and_then(Value::as_bool).unwrap_or(true);
        self.router
            .run_runbook(rb_id, persist)
            .map_err(|e| McpToolError::ExecutionFailed(e.to_string()))
    }
}

struct FindToolsMetaTool {
    router: Arc<RouterEngine>,
}

impl ActionCommand for FindToolsMetaTool {
    fn command_id(&self) -> &'static str {
        "guap_find_tools"
    }

    fn description(&self) -> &'static str {
        "Search the 326-tool GUAP catalog by keyword/domain/suite and lazy-load 1..=5 JSON schemas"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::ReadOnly
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "query": { "type": "string", "description": "Keywords (e.g. 'smart disk', 'evtx logon', 'pst')" },
                "domain": { "type": "string", "description": "Optional domain filter (system, network, forensics, desktop, storage, browser, mail, mobile, backup)" },
                "suite": { "type": "string", "description": "Optional suite ID (e.g. sys2rust, net2rust, forensics2rust)" },
                "read_only_only": { "type": "boolean", "default": false },
                "limit": { "type": "integer", "minimum": 1, "maximum": 5, "default": 5 }
            },
            "required": ["query"]
        })
    }

    fn execute(&self, args: &Value, _dry_run: bool) -> Result<Value, McpToolError> {
        let query = args
            .get("query")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing string 'query'".to_string()))?;
        let domain = args.get("domain").and_then(Value::as_str);
        let suite = args.get("suite").and_then(Value::as_str);
        let ro_only = args.get("read_only_only").and_then(Value::as_bool).unwrap_or(false);
        let limit = args.get("limit").and_then(Value::as_u64).unwrap_or(5) as usize;
        Ok(self.router.find_tools(query, domain, suite, ro_only, limit))
    }
}

struct CallReadonlyMetaTool {
    router: Arc<RouterEngine>,
}

impl ActionCommand for CallReadonlyMetaTool {
    fn command_id(&self) -> &'static str {
        "guap_call_readonly"
    }

    fn description(&self) -> &'static str {
        "Execute any read-only GUAP suite tool ('<suite>/<tool>') with bounded row/byte output"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::ReadOnly
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "tool": { "type": "string", "description": "Qualified tool ID (e.g. 'fs2rust/disk_smart_view')" },
                "arguments": { "type": "object", "description": "JSON arguments matching the tool's input_schema" },
                "max_rows": { "type": "integer", "minimum": 1, "maximum": 100, "default": 25 }
            },
            "required": ["tool"]
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let tool = args
            .get("tool")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing string 'tool'".to_string()))?;
        if dry_run {
            let resolved = self
                .router
                .catalog
                .resolve_tool(tool)
                .map_err(|e| McpToolError::NotFound(e.to_string()))?;
            if !resolved.read_only {
                return Err(McpToolError::PolicyDenied(format!(
                    "tool '{}' is mutating; use guap_stage_fix instead",
                    resolved.qualified_id
                )));
            }
            return Ok(json!({ "dry_run": true, "qualified_id": resolved.qualified_id }));
        }
        let sub_args = args.get("arguments").unwrap_or(&Value::Null);
        let max_rows = args.get("max_rows").and_then(Value::as_u64).unwrap_or(25) as usize;
        self.router
            .call_readonly(tool, sub_args, max_rows, 12_000)
            .map_err(|e| match e {
                RouterError::Catalog(CatalogError::MutatingBlocked(msg)) => McpToolError::PolicyDenied(msg),
                RouterError::Catalog(CatalogError::ToolNotFound(msg)) => McpToolError::NotFound(msg),
                other => McpToolError::ExecutionFailed(other.to_string()),
            })
    }
}

struct StageFixMetaTool {
    router: Arc<RouterEngine>,
}

impl ActionCommand for StageFixMetaTool {
    fn command_id(&self) -> &'static str {
        "guap_stage_fix"
    }

    fn description(&self) -> &'static str {
        "Run a non-destructive dry_run preview of a mutating tool and stage a pending human Approval Card"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        // Staging a card never mutates the OS; human sign-off is required to execute it.
        ActionRiskLevel::ReadOnly
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "tool": { "type": "string", "description": "Mutating tool ID ('<suite>/<tool>')" },
                "arguments": { "type": "object", "description": "Proposed tool arguments" },
                "rationale": { "type": "string", "description": "Plain-language explanation of why this fix is needed" },
                "rollback_hint": { "type": "string", "description": "How to reverse or undo this change if needed" }
            },
            "required": ["tool", "rationale"]
        })
    }

    fn execute(&self, args: &Value, _dry_run: bool) -> Result<Value, McpToolError> {
        let tool = args
            .get("tool")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing string 'tool'".to_string()))?;
        let rationale = args
            .get("rationale")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing string 'rationale'".to_string()))?;
        let rollback_hint = args.get("rollback_hint").and_then(Value::as_str).unwrap_or("");
        let sub_args = args.get("arguments").cloned().unwrap_or_else(|| json!({}));

        let card = self
            .router
            .stage_fix(tool, &sub_args, rationale, rollback_hint)
            .map_err(|e| match e {
                RouterError::Catalog(CatalogError::NotMutating(msg)) => McpToolError::InvalidParams(msg),
                RouterError::Catalog(CatalogError::ToolNotFound(msg)) => McpToolError::NotFound(msg),
                other => McpToolError::ExecutionFailed(other.to_string()),
            })?;
        Ok(json!({
            "staged": true,
            "requires_human_approval": true,
            "approve_cli_command": format!("guap approvals approve {}", card.card_id),
            "card": card,
        }))
    }
}

struct ManageScheduleMetaTool {
    router: Arc<RouterEngine>,
}

impl ActionCommand for ManageScheduleMetaTool {
    fn command_id(&self) -> &'static str {
        "guap_manage_schedule"
    }

    fn description(&self) -> &'static str {
        "List, inspect, or stage deterministic local maintenance Job Profiles"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::ReadOnly
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["list", "inspect", "stage"],
                    "default": "list"
                },
                "profile_id": { "type": "string" },
                "name": { "type": "string" },
                "schedule_hint": { "type": "string", "description": "e.g. 'SUN 09:00' or 'DAILY 02:00'" },
                "runbook_id": { "type": "string", "description": "Runbook ID when action='stage'" }
            }
        })
    }

    fn execute(&self, args: &Value, _dry_run: bool) -> Result<Value, McpToolError> {
        let action = args.get("action").and_then(Value::as_str).unwrap_or("list");
        match action {
            "list" => {
                let profiles = self
                    .router
                    .list_job_profiles()
                    .map_err(|e| McpToolError::ExecutionFailed(e.to_string()))?;
                Ok(json!({ "profiles": profiles }))
            }
            "inspect" => {
                let id = args
                    .get("profile_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| McpToolError::InvalidParams("missing 'profile_id'".to_string()))?;
                let profile = self
                    .router
                    .get_job_profile(id)
                    .map_err(|e| McpToolError::NotFound(e.to_string()))?;
                Ok(json!({ "profile": profile }))
            }
            "stage" => {
                let id = args
                    .get("profile_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| McpToolError::InvalidParams("missing 'profile_id'".to_string()))?;
                let name = args.get("name").and_then(Value::as_str).unwrap_or(id);
                let sched = args.get("schedule_hint").and_then(Value::as_str).unwrap_or("MANUAL");
                let rb = args
                    .get("runbook_id")
                    .and_then(Value::as_str)
                    .unwrap_or("health_and_security_posture");
                let staged = self
                    .router
                    .stage_job_profile(
                        id,
                        name,
                        sched,
                        vec![JobProfileStep {
                            kind: "runbook".to_string(),
                            target: rb.to_string(),
                            arguments: json!({}),
                        }],
                    )
                    .map_err(|e| McpToolError::ExecutionFailed(e.to_string()))?;
                Ok(json!({
                    "staged": true,
                    "requires_human_approval": true,
                    "profile": staged
                }))
            }
            other => Err(McpToolError::InvalidParams(format!(
                "unknown schedule action '{other}'"
            ))),
        }
    }
}

// ============================================================================
// Desktop GUI Operator Actions & TableProviders
// ============================================================================

struct ApproveCardGuiAction {
    router: Arc<RouterEngine>,
}

impl ActionCommand for ApproveCardGuiAction {
    fn command_id(&self) -> &'static str {
        "router.approve_card"
    }

    fn description(&self) -> &'static str {
        "Human operator approval: execute a pending Approval Card and record Merkle custody receipt"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::PrivilegedMutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "card_id": { "type": "string" }
            },
            "required": ["card_id"]
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let card_id = args
            .get("card_id")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'card_id'".to_string()))?;
        if dry_run {
            let card = self
                .router
                .get_card(card_id)
                .map_err(|e| McpToolError::NotFound(e.to_string()))?;
            return Ok(json!({ "dry_run": true, "card": card }));
        }
        let updated = self
            .router
            .approve_card(card_id, "gui-operator")
            .map_err(|e| McpToolError::ExecutionFailed(e.to_string()))?;
        Ok(serde_json::to_value(updated)?)
    }
}

struct RejectCardGuiAction {
    router: Arc<RouterEngine>,
}

impl ActionCommand for RejectCardGuiAction {
    fn command_id(&self) -> &'static str {
        "router.reject_card"
    }

    fn description(&self) -> &'static str {
        "Reject a pending Approval Card without making any changes"
    }

    fn risk_level(&self) -> ActionRiskLevel {
        ActionRiskLevel::Mutating
    }

    fn input_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "card_id": { "type": "string" }
            },
            "required": ["card_id"]
        })
    }

    fn execute(&self, args: &Value, dry_run: bool) -> Result<Value, McpToolError> {
        let card_id = args
            .get("card_id")
            .and_then(Value::as_str)
            .ok_or_else(|| McpToolError::InvalidParams("missing 'card_id'".to_string()))?;
        if dry_run {
            return Ok(json!({ "dry_run": true, "would_reject": card_id }));
        }
        let updated = self
            .router
            .reject_card(card_id, "gui-operator")
            .map_err(|e| McpToolError::ExecutionFailed(e.to_string()))?;
        Ok(serde_json::to_value(updated)?)
    }
}

struct ApprovalCardsTableProvider {
    router: Arc<RouterEngine>,
}

impl TableProvider for ApprovalCardsTableProvider {
    fn tool_id(&self) -> &'static str {
        "router.approvals"
    }

    fn description(&self) -> &'static str {
        "Staged remediation Approval Cards with dry-run previews, rollback hints, and execution status"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            "router.approvals",
            "Staged Approval Cards",
            vec![
                ColumnDef::new("card_id", "Card ID", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("status", "Status", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("tool_id", "Target Tool", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("rationale", "Rationale", ColumnType::Text).with_width_hint(300),
                ColumnDef::new("rollback_hint", "Rollback Plan", ColumnType::Text).with_width_hint(240),
                ColumnDef::new("created_at", "Created At", ColumnType::Timestamp).with_width_hint(180),
            ],
        )
        .with_default_sort(5, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let schema = self.schema();
        let cards = self
            .router
            .list_cards(None)
            .map_err(|e| TableError::Provider(e.to_string()))?;
        let rows: Vec<Row> = cards
            .iter()
            .enumerate()
            .map(|(i, c)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(c.card_id.clone()),
                        CellValue::Text(c.status.clone()),
                        CellValue::Text(c.tool_id.clone()),
                        CellValue::Text(c.rationale.clone()),
                        CellValue::Text(c.rollback_hint.clone()),
                        CellValue::Text(c.created_at.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(c).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&schema, &rows, req)
    }
}

struct JobProfilesTableProvider {
    router: Arc<RouterEngine>,
}

impl TableProvider for JobProfilesTableProvider {
    fn tool_id(&self) -> &'static str {
        "router.jobs"
    }

    fn description(&self) -> &'static str {
        "Deterministic recurring IT maintenance Job Profiles"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            "router.jobs",
            "Deterministic Job Profiles",
            vec![
                ColumnDef::new("profile_id", "Profile ID", ColumnType::Text).with_width_hint(180),
                ColumnDef::new("name", "Name", ColumnType::Text).with_width_hint(280),
                ColumnDef::new("schedule", "Schedule", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("enabled", "Enabled", ColumnType::Bool).with_width_hint(85),
                ColumnDef::new("approved", "Approved", ColumnType::Bool).with_width_hint(90),
                ColumnDef::new("steps", "Steps", ColumnType::Uint).with_width_hint(70),
                ColumnDef::new("last_status", "Last Status", ColumnType::Text).with_width_hint(150),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let schema = self.schema();
        let jobs = self
            .router
            .list_job_profiles()
            .map_err(|e| TableError::Provider(e.to_string()))?;
        let rows: Vec<Row> = jobs
            .iter()
            .enumerate()
            .map(|(i, j)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(j.profile_id.clone()),
                        CellValue::Text(j.name.clone()),
                        CellValue::Text(j.schedule_hint.clone()),
                        CellValue::Bool(j.enabled),
                        CellValue::Bool(j.approved),
                        CellValue::Uint(j.steps.len() as u64),
                        CellValue::Text(j.last_status.clone().unwrap_or_else(|| "never".to_string())),
                    ],
                )
                .with_detail_json(serde_json::to_value(j).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&schema, &rows, req)
    }
}

struct CustodyLogTableProvider {
    router: Arc<RouterEngine>,
}

impl TableProvider for CustodyLogTableProvider {
    fn tool_id(&self) -> &'static str {
        "router.custody"
    }

    fn description(&self) -> &'static str {
        "Append-only SHA-256/SHA-512 Merkle custody audit ledger for runbooks and approved fixes"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            "router.custody",
            "Merkle Custody Audit Ledger",
            vec![
                ColumnDef::new("receipt_id", "Receipt ID", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("recorded_at", "Recorded At", ColumnType::Timestamp).with_width_hint(180),
                ColumnDef::new("actor", "Actor", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("operation", "Operation", ColumnType::Text).with_width_hint(160),
                ColumnDef::new("target_id", "Target", ColumnType::Text).with_width_hint(210),
                ColumnDef::new("merkle_sha256", "Merkle SHA-256", ColumnType::Text).with_width_hint(260),
            ],
        )
        .with_default_sort(1, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let schema = self.schema();
        let entries = self
            .router
            .list_custody_entries()
            .map_err(|e| TableError::Provider(e.to_string()))?;
        let rows: Vec<Row> = entries
            .iter()
            .enumerate()
            .map(|(i, e)| {
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(e.receipt_id.clone()),
                        CellValue::Text(e.recorded_at.clone()),
                        CellValue::Text(e.actor.clone()),
                        CellValue::Text(e.operation.clone()),
                        CellValue::Text(e.target_id.clone()),
                        CellValue::Text(e.merkle_sha256.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(e).unwrap_or(Value::Null))
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
    fn router_exposes_compact_6_meta_tools_and_enforces_approval_card_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        let cat = Arc::new(SuiteCatalog::discover(CatalogConfig::offline()));
        let rb = Arc::new(RunbookEngine::new(Arc::clone(&cat)));
        let router = Arc::new(RouterEngine::new(RouterConfig::ephemeral(tmp.path().to_path_buf()), cat, rb).unwrap());

        // 1. Verify MCP registry exposes exactly 6 meta-tools within compact prompt budget
        let mcp = RouterEngine::build_mcp_registry(Arc::clone(&router));
        let tools_json = mcp.list_tools();
        let arr = tools_json.as_array().unwrap();
        assert_eq!(arr.len(), META_TOOL_COUNT);
        let serialized_tools = serde_json::to_string(&tools_json).unwrap();
        assert!(
            serialized_tools.len() < 4_800,
            "6 meta-tools exceeded ~1,000-token budget: {} bytes",
            serialized_tools.len()
        );

        // 2. Verify guap_call_readonly blocks mutating tools over JSON-RPC
        let mut_attempt = mcp
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "guap_call_readonly",
                    "arguments": { "tool": "sys2rust/service_set_start_mode" }
                }
            }))
            .unwrap();
        assert_eq!(mut_attempt["error"]["code"], json!(-32003));

        // 3. Verify guap_stage_fix runs dry_run preview and creates pending Approval Card (no mutation!)
        let stage_resp = mcp
            .handle_jsonrpc_request(&json!({
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {
                    "name": "guap_stage_fix",
                    "arguments": {
                        "tool": "sys2rust/service_set_start_mode",
                        "arguments": { "target": "Fax" },
                        "rationale": "Disable unused Fax service",
                        "rollback_hint": "Restore Fax service start mode to Manual"
                    }
                }
            }))
            .unwrap();
        assert_eq!(stage_resp["result"]["isError"], json!(false));

        let pending = router.list_cards(Some("pending")).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].dry_run_preview["dry_run"], json!(true));
        assert!(pending[0].execution_result.is_none());

        // 4. Human approval executes the staged fix and writes a Merkle custody receipt
        let executed = router.approve_card(&pending[0].card_id, "unit-test-operator").unwrap();
        assert_eq!(executed.status, "executed");
        assert!(executed.custody_merkle_sha256.is_some());
        assert_eq!(router.count_pending_cards().unwrap(), 0);

        let custody_entries = router.list_custody_entries().unwrap();
        assert_eq!(custody_entries.len(), 1);

        // 5. Unapproved job profiles must be refused; seeded approved profile runs cleanly
        router
            .stage_job_profile("custom_unapproved", "Unapproved", "MANUAL", vec![])
            .unwrap();
        assert!(router.run_job_profile("custom_unapproved").is_err());

        let weekly = router.run_job_profile("weekly_health_audit").unwrap();
        assert_eq!(weekly["status"], json!("succeeded"));
    }
}
