#![forbid(unsafe_code)]

//! Federated suite discovery, MCP tool schema indexing, `TableProvider` views,
//! and bounded-timeout JSON-RPC 2.0 `stdio` client for the 10 GUAP domain suites.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, SystemTime};

use guap_mcp::MCP_PROTOCOL_VERSION;
use guap_table::{
    CellValue, ColumnDef, ColumnType, Row, SortDirection, TableData, TableError, TableProvider, TableQuery,
    TableSchema, apply_query,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;

/// Canonical metadata for each of the 10 federated GUAP suites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiteSpec {
    pub suite_id: &'static str,
    pub repo_dir: &'static str,
    pub portal: &'static str,
    pub domain: &'static str,
    pub mcp_bin: &'static str,
    pub mcp_prefix_args: &'static [&'static str],
    pub python_script_fallback: Option<&'static str>,
    pub supports_allow_mutating_flag: bool,
    pub supports_offline_flag: bool,
    pub expected_tools_hint: usize,
}

pub const KNOWN_SUITES: &[SuiteSpec] = &[
    SuiteSpec {
        suite_id: "sys2rust",
        repo_dir: "sys2rust",
        portal: "sys2rust",
        domain: "system",
        mcp_bin: "sys2rust-mcp",
        mcp_prefix_args: &[],
        python_script_fallback: None,
        supports_allow_mutating_flag: true,
        supports_offline_flag: true,
        expected_tools_hint: 70,
    },
    SuiteSpec {
        suite_id: "net2rust",
        repo_dir: "net2rust",
        portal: "net2rust",
        domain: "network",
        mcp_bin: "net2rust-mcp",
        mcp_prefix_args: &[],
        python_script_fallback: None,
        supports_allow_mutating_flag: true,
        supports_offline_flag: true,
        expected_tools_hint: 68,
    },
    SuiteSpec {
        suite_id: "forensics2rust",
        repo_dir: "forensics2rust",
        portal: "forensics2rust",
        domain: "forensics",
        mcp_bin: "forensics2rust",
        mcp_prefix_args: &["mcp"],
        python_script_fallback: None,
        supports_allow_mutating_flag: false,
        supports_offline_flag: false,
        expected_tools_hint: 45,
    },
    SuiteSpec {
        suite_id: "winctl2rust",
        repo_dir: "winctl2rust",
        portal: "winctl2rust",
        domain: "desktop",
        mcp_bin: "winctl2rust-mcp",
        mcp_prefix_args: &[],
        python_script_fallback: None,
        supports_allow_mutating_flag: true,
        supports_offline_flag: true,
        expected_tools_hint: 40,
    },
    SuiteSpec {
        suite_id: "fs2rust",
        repo_dir: "fs2rust",
        portal: "fs2rust",
        domain: "storage",
        mcp_bin: "fs2rust-mcp",
        mcp_prefix_args: &[],
        python_script_fallback: None,
        supports_allow_mutating_flag: true,
        supports_offline_flag: true,
        expected_tools_hint: 32,
    },
    SuiteSpec {
        suite_id: "chrome2rust",
        repo_dir: "chrome2rust",
        portal: "chrome2rust",
        domain: "browser",
        mcp_bin: "chrome2rust-mcp",
        mcp_prefix_args: &[],
        python_script_fallback: None,
        supports_allow_mutating_flag: false,
        supports_offline_flag: false,
        expected_tools_hint: 29,
    },
    SuiteSpec {
        suite_id: "mail2rust",
        repo_dir: "mail2rust",
        portal: "mail2rust",
        domain: "mail",
        mcp_bin: "mail2rust-mcp",
        mcp_prefix_args: &[],
        python_script_fallback: None,
        supports_allow_mutating_flag: true,
        supports_offline_flag: false,
        expected_tools_hint: 15,
    },
    SuiteSpec {
        suite_id: "android2rust",
        repo_dir: "android2rust",
        portal: "android2rust",
        domain: "mobile",
        mcp_bin: "android2rust-mcp",
        mcp_prefix_args: &[],
        python_script_fallback: None,
        supports_allow_mutating_flag: false,
        supports_offline_flag: false,
        expected_tools_hint: 13,
    },
    SuiteSpec {
        suite_id: "robocopy2rust",
        repo_dir: "robocopy2rust",
        portal: "robocopy2rust",
        domain: "backup",
        mcp_bin: "robocopy2rust-mcp",
        mcp_prefix_args: &[],
        python_script_fallback: None,
        supports_allow_mutating_flag: false,
        supports_offline_flag: false,
        expected_tools_hint: 9,
    },
    SuiteSpec {
        suite_id: "mail2mail",
        repo_dir: "all2pst",
        portal: "mail2mail",
        domain: "mail",
        mcp_bin: "mail2mcp",
        mcp_prefix_args: &[],
        python_script_fallback: Some("mail2mcp.py"),
        supports_allow_mutating_flag: false,
        supports_offline_flag: false,
        expected_tools_hint: 5,
    },
];

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("suite '{0}' not found in GUAP catalog")]
    SuiteNotFound(String),

    #[error("tool '{0}' not found in GUAP catalog")]
    ToolNotFound(String),

    #[error("tool '{0}' is ambiguous across suites ({1}); qualify as '<suite>/<tool>'")]
    AmbiguousTool(String, String),

    #[error("suite '{0}' has no discovered MCP executable on this host")]
    SuiteBinaryUnavailable(String),

    #[error("safety refusal: tool '{0}' is mutating and cannot be invoked through read-only gateway")]
    MutatingBlocked(String),

    #[error("safety refusal: tool '{0}' is read-only and does not require staging a fix")]
    NotMutating(String),

    #[error("downstream MCP timeout after {1}ms calling '{0}'")]
    Timeout(String, u64),

    #[error("downstream MCP execution failed for '{0}': {1}")]
    Execution(String, String),
}

/// Execution mode for catalog discovery and downstream calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CatalogMode {
    #[default]
    Live,
    Offline,
}

/// Configuration for `SuiteCatalog` discovery.
#[derive(Debug, Clone)]
pub struct CatalogConfig {
    pub mode: CatalogMode,
    /// Optional GUAP workspace or portable bundle root containing sibling suites.
    pub workspace_root: Option<PathBuf>,
    /// Per-call timeout for downstream `*-mcp` invocations.
    pub call_timeout: Duration,
    /// Pass `--offline` to downstream suites that support deterministic fixture mode.
    pub prefer_suite_offline_flag: bool,
}

impl Default for CatalogConfig {
    fn default() -> Self {
        Self {
            mode: CatalogMode::Live,
            workspace_root: detect_default_workspace_root(),
            call_timeout: Duration::from_secs(15),
            prefer_suite_offline_flag: false,
        }
    }
}

impl CatalogConfig {
    pub fn offline() -> Self {
        Self {
            mode: CatalogMode::Offline,
            workspace_root: None,
            call_timeout: Duration::from_secs(5),
            prefer_suite_offline_flag: true,
        }
    }
}

/// How to launch a discovered suite's MCP stdio server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpLaunchSpec {
    pub program: PathBuf,
    pub prefix_args: Vec<String>,
}

impl McpLaunchSpec {
    pub fn display_command(&self) -> String {
        if self.prefix_args.is_empty() {
            self.program.display().to_string()
        } else {
            format!("{} {}", self.program.display(), self.prefix_args.join(" "))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuiteAvailability {
    Ready,
    MetadataOnly,
    SyntheticOffline,
    Missing,
}

impl SuiteAvailability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::MetadataOnly => "metadata_only",
            Self::SyntheticOffline => "synthetic_offline",
            Self::Missing => "missing",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredSuite {
    pub suite_id: String,
    pub portal: String,
    pub domain: String,
    pub version: String,
    pub description: String,
    pub availability: SuiteAvailability,
    pub launch: Option<McpLaunchSpec>,
    pub supports_allow_mutating_flag: bool,
    pub supports_offline_flag: bool,
    pub readonly_count: usize,
    pub mutating_count: usize,
}

impl DiscoveredSuite {
    pub fn total_tools(&self) -> usize {
        self.readonly_count + self.mutating_count
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedTool {
    pub suite_id: String,
    pub portal: String,
    pub domain: String,
    pub tool_name: String,
    pub qualified_id: String,
    pub description: String,
    pub read_only: bool,
    pub destructive: bool,
    pub supports_dry_run_arg: bool,
    pub input_schema: Value,
    pub keywords: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolExecMode {
    ReadOnly,
    DryRunPreview,
    ApprovedMutating,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallOutcome {
    pub suite_id: String,
    pub tool_name: String,
    pub qualified_id: String,
    pub exec_mode: String,
    pub simulated: bool,
    pub payload: Value,
}

#[derive(Debug, Clone)]
pub struct SuiteCatalog {
    config: CatalogConfig,
    suites: Vec<DiscoveredSuite>,
    tools: Vec<IndexedTool>,
    by_qualified: BTreeMap<String, usize>,
    by_bare_name: BTreeMap<String, Vec<usize>>,
}

impl SuiteCatalog {
    pub fn discover(config: CatalogConfig) -> Self {
        match config.mode {
            CatalogMode::Offline => Self::build_offline(config),
            CatalogMode::Live => Self::build_live(config),
        }
    }

    pub fn config(&self) -> &CatalogConfig {
        &self.config
    }

    pub fn is_offline(&self) -> bool {
        self.config.mode == CatalogMode::Offline
    }

    pub fn suites(&self) -> &[DiscoveredSuite] {
        &self.suites
    }

    pub fn tools(&self) -> &[IndexedTool] {
        &self.tools
    }

    pub fn total_readonly_tools(&self) -> usize {
        self.tools.iter().filter(|t| t.read_only).count()
    }

    pub fn total_mutating_tools(&self) -> usize {
        self.tools.iter().filter(|t| !t.read_only).count()
    }

    pub fn ready_suite_count(&self) -> usize {
        self.suites
            .iter()
            .filter(|s| {
                matches!(
                    s.availability,
                    SuiteAvailability::Ready | SuiteAvailability::SyntheticOffline
                )
            })
            .count()
    }

    pub fn get_suite(&self, suite_id: &str) -> Option<&DiscoveredSuite> {
        self.suites
            .iter()
            .find(|s| s.suite_id.eq_ignore_ascii_case(suite_id) || s.portal.eq_ignore_ascii_case(suite_id))
    }

    /// Resolve either `<suite>/<tool>` or an unambiguous `<tool>` name.
    pub fn resolve_tool(&self, tool_ref: &str) -> Result<&IndexedTool, CatalogError> {
        let trimmed = tool_ref.trim();
        if let Some((suite_part, tool_part)) = trimmed.split_once('/') {
            let key = format!("{}/{}", suite_part.to_ascii_lowercase(), tool_part);
            if let Some(&idx) = self.by_qualified.get(&key) {
                return Ok(&self.tools[idx]);
            }
            // Case-insensitive fallback
            if let Some(found) = self.tools.iter().find(|t| {
                (t.suite_id.eq_ignore_ascii_case(suite_part) || t.portal.eq_ignore_ascii_case(suite_part))
                    && t.tool_name.eq_ignore_ascii_case(tool_part)
            }) {
                return Ok(found);
            }
            return Err(CatalogError::ToolNotFound(trimmed.to_string()));
        }

        if let Some(indices) = self.by_bare_name.get(trimmed) {
            if indices.len() == 1 {
                return Ok(&self.tools[indices[0]]);
            }
            let suites: Vec<String> = indices
                .iter()
                .map(|&i| format!("{}/{}", self.tools[i].suite_id, self.tools[i].tool_name))
                .collect();
            return Err(CatalogError::AmbiguousTool(trimmed.to_string(), suites.join(", ")));
        }

        // Case-insensitive bare match
        let matches: Vec<&IndexedTool> = self
            .tools
            .iter()
            .filter(|t| t.tool_name.eq_ignore_ascii_case(trimmed))
            .collect();
        match matches.len() {
            0 => Err(CatalogError::ToolNotFound(trimmed.to_string())),
            1 => Ok(matches[0]),
            _ => {
                let suites: Vec<String> = matches.iter().map(|t| t.qualified_id.clone()).collect();
                Err(CatalogError::AmbiguousTool(trimmed.to_string(), suites.join(", ")))
            }
        }
    }

    /// Ranked lazy schema search capped at `1..=10` tools so agents never blow prompt context.
    pub fn search_tools(
        &self,
        query: &str,
        domain_filter: Option<&str>,
        suite_filter: Option<&str>,
        read_only_only: bool,
        max_results: usize,
    ) -> Vec<&IndexedTool> {
        let cap = max_results.clamp(1, 10);
        let q_lower = query.trim().to_ascii_lowercase();
        let tokens: Vec<&str> = q_lower
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.' && c != '-')
            .filter(|t| !t.is_empty())
            .collect();

        let mut scored: Vec<(i64, usize)> = Vec::new();
        for (idx, tool) in self.tools.iter().enumerate() {
            if read_only_only && !tool.read_only {
                continue;
            }
            if let Some(dom) = domain_filter
                && !dom.trim().is_empty()
                && !tool.domain.eq_ignore_ascii_case(dom.trim())
            {
                continue;
            }
            if let Some(sf) = suite_filter
                && !sf.trim().is_empty()
                && !tool.suite_id.eq_ignore_ascii_case(sf.trim())
                && !tool.portal.eq_ignore_ascii_case(sf.trim())
            {
                continue;
            }

            if tokens.is_empty() {
                scored.push((1, idx));
                continue;
            }

            let name_l = tool.tool_name.to_ascii_lowercase();
            let qual_l = tool.qualified_id.to_ascii_lowercase();
            let desc_l = tool.description.to_ascii_lowercase();
            let suite_l = tool.suite_id.to_ascii_lowercase();
            let dom_l = tool.domain.to_ascii_lowercase();

            let mut score = 0i64;
            if name_l == q_lower || qual_l == q_lower {
                score += 500;
            } else if name_l.starts_with(&q_lower) {
                score += 200;
            } else if name_l.contains(&q_lower) {
                score += 120;
            }

            for tok in &tokens {
                if name_l == *tok {
                    score += 150;
                } else if name_l.contains(tok) {
                    score += 60;
                }
                if suite_l == *tok || dom_l == *tok {
                    score += 45;
                }
                if tool.keywords.iter().any(|k| k == tok) {
                    score += 40;
                } else if tool.keywords.iter().any(|k| k.contains(tok)) {
                    score += 20;
                }
                if desc_l.contains(tok) {
                    score += 15;
                }
            }

            if score > 0 {
                scored.push((score, idx));
            }
        }

        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        scored.into_iter().take(cap).map(|(_, idx)| &self.tools[idx]).collect()
    }

    /// Execute a downstream tool respecting `ToolExecMode` safety gates.
    pub fn call_tool(
        &self,
        tool_ref: &str,
        args: &Value,
        exec_mode: ToolExecMode,
    ) -> Result<ToolCallOutcome, CatalogError> {
        let tool = self.resolve_tool(tool_ref)?;
        match exec_mode {
            ToolExecMode::ReadOnly => {
                if !tool.read_only {
                    return Err(CatalogError::MutatingBlocked(tool.qualified_id.clone()));
                }
            }
            ToolExecMode::DryRunPreview | ToolExecMode::ApprovedMutating => {
                if tool.read_only {
                    return Err(CatalogError::NotMutating(tool.qualified_id.clone()));
                }
            }
        }

        let mut arg_obj: Map<String, Value> = match args {
            Value::Null => Map::new(),
            Value::Object(m) => m.clone(),
            _ => {
                return Err(CatalogError::Execution(
                    tool.qualified_id.clone(),
                    "arguments must be a JSON object".to_string(),
                ));
            }
        };

        // Strip any caller-supplied confirmation flags on read-only or preview calls
        match exec_mode {
            ToolExecMode::ReadOnly => {
                arg_obj.remove("confirm_destructive");
            }
            ToolExecMode::DryRunPreview => {
                arg_obj.insert("dry_run".to_string(), Value::Bool(true));
                arg_obj.insert("confirm_destructive".to_string(), Value::Bool(true));
            }
            ToolExecMode::ApprovedMutating => {
                arg_obj.insert("dry_run".to_string(), Value::Bool(false));
                arg_obj.insert("confirm_destructive".to_string(), Value::Bool(true));
            }
        }

        let exec_mode_label = match exec_mode {
            ToolExecMode::ReadOnly => "read_only",
            ToolExecMode::DryRunPreview => "dry_run_preview",
            ToolExecMode::ApprovedMutating => "approved_mutating",
        }
        .to_string();

        if self.config.mode == CatalogMode::Offline {
            return Ok(ToolCallOutcome {
                suite_id: tool.suite_id.clone(),
                tool_name: tool.tool_name.clone(),
                qualified_id: tool.qualified_id.clone(),
                exec_mode: exec_mode_label,
                simulated: true,
                payload: build_synthetic_call_payload(tool, &Value::Object(arg_obj), exec_mode),
            });
        }

        // CRITICAL SAFETY INVARIANT:
        // If staging a mutating fix (`DryRunPreview`) on a standalone suite tool whose inputSchema
        // does NOT advertise a native `dry_run` boolean property, NEVER spawn the child binary during
        // preview; return a deterministic non-executing preview plan instead!
        if exec_mode == ToolExecMode::DryRunPreview && !tool.supports_dry_run_arg {
            return Ok(ToolCallOutcome {
                suite_id: tool.suite_id.clone(),
                tool_name: tool.tool_name.clone(),
                qualified_id: tool.qualified_id.clone(),
                exec_mode: exec_mode_label,
                simulated: true,
                payload: json!({
                    "dry_run": true,
                    "simulated_preview": true,
                    "reason": "Downstream tool schema does not advertise native dry_run boolean; synthesized non-executing preview plan.",
                    "target_tool": tool.qualified_id,
                    "planned_arguments": arg_obj,
                }),
            });
        }

        let suite = self
            .get_suite(&tool.suite_id)
            .ok_or_else(|| CatalogError::SuiteNotFound(tool.suite_id.clone()))?;
        let launch = suite
            .launch
            .as_ref()
            .ok_or_else(|| CatalogError::SuiteBinaryUnavailable(suite.suite_id.clone()))?;

        let mut extra_flags: Vec<String> = Vec::new();
        if self.config.prefer_suite_offline_flag && suite.supports_offline_flag {
            extra_flags.push("--offline".to_string());
        }
        if matches!(exec_mode, ToolExecMode::DryRunPreview | ToolExecMode::ApprovedMutating)
            && suite.supports_allow_mutating_flag
        {
            extra_flags.push("--allow-mutating".to_string());
        }

        let payload = invoke_mcp_stdio_call(
            launch,
            &extra_flags,
            &tool.tool_name,
            &Value::Object(arg_obj),
            self.config.call_timeout,
        )
        .map_err(|err| match err {
            StdioCallError::Timeout(ms) => CatalogError::Timeout(tool.qualified_id.clone(), ms),
            StdioCallError::Other(msg) => CatalogError::Execution(tool.qualified_id.clone(), msg),
        })?;

        Ok(ToolCallOutcome {
            suite_id: tool.suite_id.clone(),
            tool_name: tool.tool_name.clone(),
            qualified_id: tool.qualified_id.clone(),
            exec_mode: exec_mode_label,
            simulated: false,
            payload,
        })
    }

    pub fn table_providers(catalog: Arc<Self>) -> Vec<Arc<dyn TableProvider>> {
        vec![
            Arc::new(SuitesTableProvider {
                catalog: Arc::clone(&catalog),
            }),
            Arc::new(ToolsTableProvider { catalog }),
        ]
    }

    fn finalize_indexes(mut suites: Vec<DiscoveredSuite>, tools: Vec<IndexedTool>, config: CatalogConfig) -> Self {
        let mut by_qualified = BTreeMap::new();
        let mut by_bare_name: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for (idx, tool) in tools.iter().enumerate() {
            by_qualified.insert(tool.qualified_id.to_ascii_lowercase(), idx);
            by_bare_name.entry(tool.tool_name.clone()).or_default().push(idx);
        }
        for suite in &mut suites {
            suite.readonly_count = tools
                .iter()
                .filter(|t| t.suite_id == suite.suite_id && t.read_only)
                .count();
            suite.mutating_count = tools
                .iter()
                .filter(|t| t.suite_id == suite.suite_id && !t.read_only)
                .count();
        }
        Self {
            config,
            suites,
            tools,
            by_qualified,
            by_bare_name,
        }
    }

    fn build_live(config: CatalogConfig) -> Self {
        let mut suites = Vec::with_capacity(KNOWN_SUITES.len());
        let mut all_tools = Vec::new();

        for spec in KNOWN_SUITES {
            let meta = read_suite_metadata(config.workspace_root.as_deref(), spec);
            let version = meta
                .as_ref()
                .and_then(|m| m.get("version").and_then(Value::as_str))
                .unwrap_or("0.1.0")
                .to_string();
            let description = meta
                .as_ref()
                .and_then(|m| m.get("description").and_then(Value::as_str))
                .unwrap_or(spec.domain)
                .to_string();

            let launch = locate_suite_mcp_binary(config.workspace_root.as_deref(), spec);
            let mut discovered_tools: Vec<IndexedTool> = Vec::new();
            let mut availability = SuiteAvailability::Missing;

            if let Some(ref launch_spec) = launch
                && let Ok(raw_tools) = probe_suite_tools(launch_spec)
            {
                for raw in raw_tools {
                    if let Some(indexed) = parse_raw_tool(spec, &raw) {
                        discovered_tools.push(indexed);
                    }
                }
                availability = SuiteAvailability::Ready;
            }

            if discovered_tools.is_empty()
                && let Some(ref meta_val) = meta
            {
                discovered_tools = parse_metadata_v2_tools(spec, meta_val);
                if availability == SuiteAvailability::Missing {
                    availability = SuiteAvailability::MetadataOnly;
                }
            }

            all_tools.extend(discovered_tools);
            suites.push(DiscoveredSuite {
                suite_id: spec.suite_id.to_string(),
                portal: spec.portal.to_string(),
                domain: spec.domain.to_string(),
                version,
                description,
                availability,
                launch,
                supports_allow_mutating_flag: spec.supports_allow_mutating_flag,
                supports_offline_flag: spec.supports_offline_flag,
                readonly_count: 0,
                mutating_count: 0,
            });
        }

        Self::finalize_indexes(suites, all_tools, config)
    }

    fn build_offline(config: CatalogConfig) -> Self {
        let mut suites = Vec::with_capacity(KNOWN_SUITES.len());
        let mut tools = Vec::new();

        for spec in KNOWN_SUITES {
            suites.push(DiscoveredSuite {
                suite_id: spec.suite_id.to_string(),
                portal: spec.portal.to_string(),
                domain: spec.domain.to_string(),
                version: if spec.suite_id == "mail2rust" {
                    "3.5.0".to_string()
                } else if spec.suite_id == "mail2mail" {
                    "2.3.0".to_string()
                } else if spec.suite_id == "chrome2rust" {
                    "0.2.2".to_string()
                } else {
                    "0.1.0".to_string()
                },
                description: format!("Synthetic offline fixture for {} ({})", spec.suite_id, spec.domain),
                availability: SuiteAvailability::SyntheticOffline,
                launch: None,
                supports_allow_mutating_flag: spec.supports_allow_mutating_flag,
                supports_offline_flag: spec.supports_offline_flag,
                readonly_count: 0,
                mutating_count: 0,
            });
            tools.extend(synthetic_tools_for_suite(spec));
        }

        Self::finalize_indexes(suites, tools, config)
    }
}

fn detect_default_workspace_root() -> Option<PathBuf> {
    if let Ok(explicit) = env::var("GUAP_WORKSPACE_ROOT") {
        let p = PathBuf::from(explicit);
        if p.is_dir() {
            return Some(p);
        }
    }
    if let Ok(exe) = env::current_exe() {
        for ancestor in exe.ancestors().skip(1) {
            if ancestor.join("guap-kit").is_dir() || ancestor.join("sys2rust").is_dir() {
                return Some(ancestor.to_path_buf());
            }
        }
    }
    if let Ok(cwd) = env::current_dir() {
        for ancestor in cwd.ancestors() {
            if ancestor.join("guap-kit").is_dir() || ancestor.join("sys2rust").is_dir() {
                return Some(ancestor.to_path_buf());
            }
        }
    }
    None
}

fn exe_filename(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

fn file_mtime(path: &Path) -> SystemTime {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or(SystemTime::UNIX_EPOCH)
}

fn locate_suite_mcp_binary(workspace_root: Option<&Path>, spec: &SuiteSpec) -> Option<McpLaunchSpec> {
    let bin_file = exe_filename(spec.mcp_bin);
    let prefix_args: Vec<String> = spec.mcp_prefix_args.iter().map(|s| (*s).to_string()).collect();

    // 1. Portable sibling directory next to running `guap` binary
    if let Ok(current_exe) = env::current_exe()
        && let Some(exe_dir) = current_exe.parent()
    {
        for candidate in [
            exe_dir.join(&bin_file),
            exe_dir.join("suites").join(spec.suite_id).join(&bin_file),
            exe_dir.join("suites").join(spec.repo_dir).join(&bin_file),
        ] {
            if candidate.is_file() {
                return Some(McpLaunchSpec {
                    program: candidate,
                    prefix_args,
                });
            }
        }
    }

    // 2. Sibling workspace build outputs (pick newest mtime between debug and release!)
    if let Some(root) = workspace_root {
        let repo_path = root.join(spec.repo_dir);
        let debug_bin = repo_path.join("target").join("debug").join(&bin_file);
        let release_bin = repo_path.join("target").join("release").join(&bin_file);
        let chosen = match (debug_bin.is_file(), release_bin.is_file()) {
            (true, true) => {
                if file_mtime(&debug_bin) >= file_mtime(&release_bin) {
                    Some(debug_bin)
                } else {
                    Some(release_bin)
                }
            }
            (true, false) => Some(debug_bin),
            (false, true) => Some(release_bin),
            (false, false) => None,
        };
        if let Some(program) = chosen {
            return Some(McpLaunchSpec { program, prefix_args });
        }

        // Python fallback for `all2pst` (`mail2mcp.py`)
        if let Some(py_script) = spec.python_script_fallback {
            let script_path = repo_path.join(py_script);
            if script_path.is_file()
                && let Some(py_exe) = find_on_path(if cfg!(windows) { "python.exe" } else { "python3" })
                    .or_else(|| find_on_path("python"))
            {
                return Some(McpLaunchSpec {
                    program: py_exe,
                    prefix_args: vec![script_path.display().to_string()],
                });
            }
        }
    }

    // 3. Installed binary on PATH
    if let Some(path_bin) = find_on_path(&bin_file) {
        return Some(McpLaunchSpec {
            program: path_bin,
            prefix_args,
        });
    }

    None
}

fn find_on_path(file_name: &str) -> Option<PathBuf> {
    let path_os = env::var_os("PATH")?;
    for dir in env::split_paths(&path_os) {
        let candidate = dir.join(file_name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn read_suite_metadata(workspace_root: Option<&Path>, spec: &SuiteSpec) -> Option<Value> {
    let root = workspace_root?;
    let meta_path = root.join(spec.repo_dir).join("metadata.json");
    let raw = fs::read_to_string(meta_path).ok()?;
    serde_json::from_str::<Value>(&raw).ok()
}

fn probe_suite_tools(launch: &McpLaunchSpec) -> Result<Vec<Value>, String> {
    if let Ok(tools) = probe_suite_tools_cli(launch, Duration::from_millis(2500)) {
        return Ok(tools);
    }
    probe_suite_tools_stdio(launch, Duration::from_secs(4))
}

fn probe_suite_tools_stdio(launch: &McpLaunchSpec, timeout: Duration) -> Result<Vec<Value>, String> {
    let mut cmd = Command::new(&launch.program);
    cmd.args(&launch.prefix_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| format!("spawn failed ({}): {e}", launch.display_command()))?;
    let mut stdin = child.stdin.take().ok_or_else(|| "missing child stdin".to_string())?;
    let stdout = child.stdout.take().ok_or_else(|| "missing child stdout".to_string())?;

    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "guap-catalog", "version": env!("CARGO_PKG_VERSION") }
        }
    });
    let notif = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
    let list_req = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {} });
    let lines = format!("{init_req}\n{notif}\n{list_req}\n");
    let _ = stdin.write_all(lines.as_bytes()).and_then(|_| stdin.flush());
    drop(stdin);

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line_res in reader.lines() {
            let Ok(line) = line_res else { break };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<Value>(trimmed)
                && val.get("id") == Some(&json!(2))
            {
                let _ = tx.send(Ok(val));
                return;
            }
        }
        let _ = tx.send(Err("EOF before tools/list response".to_string()));
    });

    let res = rx.recv_timeout(timeout);
    let _ = child.kill();
    let _ = child.wait();

    let resp = res
        .map_err(|_| format!("timed out probing tools/list on {}", launch.display_command()))?
        .map_err(|e| format!("tools/list failed on {}: {e}", launch.display_command()))?;

    resp.get("result")
        .and_then(|r| r.get("tools"))
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| "missing result.tools array in JSON-RPC response".to_string())
}

fn probe_suite_tools_cli(launch: &McpLaunchSpec, timeout: Duration) -> Result<Vec<Value>, String> {
    let launch_clone = launch.clone();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut cmd = Command::new(&launch_clone.program);
        cmd.args(&launch_clone.prefix_args)
            .arg("--tools")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let child_res = cmd.spawn();
        let _ = tx.send(child_res);
    });

    let mut child = rx
        .recv_timeout(timeout)
        .map_err(|_| format!("timed out spawning --tools on {}", launch.display_command()))?
        .map_err(|e| format!("failed spawning {}: {e}", launch.display_command()))?;

    let (out_tx, out_rx) = mpsc::channel();
    let mut stdout = child.stdout.take().ok_or_else(|| "missing stdout".to_string())?;
    thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = std::io::Read::read_to_end(&mut stdout, &mut buf);
        let _ = out_tx.send(buf);
    });

    let Ok(stdout_bytes) = out_rx.recv_timeout(timeout) else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("timed out reading --tools on {}", launch.display_command()));
    };
    let status = child.wait().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err("non-zero exit from --tools".to_string());
    }

    let parsed: Value = serde_json::from_slice(&stdout_bytes)
        .map_err(|e| format!("invalid JSON from --tools on {}: {e}", launch.display_command()))?;

    if let Some(arr) = parsed.as_array() {
        return Ok(arr.clone());
    }
    if let Some(arr) = parsed.get("tools").and_then(Value::as_array) {
        return Ok(arr.clone());
    }
    Err("expected JSON array or { tools: [...] }".to_string())
}

fn infer_read_only(spec: &SuiteSpec, tool_name: &str, raw: &Value) -> (bool, bool) {
    if spec.suite_id == "forensics2rust" || spec.suite_id == "chrome2rust" {
        return (true, false);
    }
    if let Some(ann) = raw.get("annotations").and_then(Value::as_object) {
        let ro = ann.get("readOnlyHint").and_then(Value::as_bool);
        let destr = ann.get("destructiveHint").and_then(Value::as_bool);
        if let Some(r) = ro {
            return (r, destr.unwrap_or(!r));
        }
        if let Some(d) = destr {
            return (!d, d);
        }
    }
    if let Some(props) = raw
        .get("inputSchema")
        .and_then(|s| s.get("properties"))
        .and_then(Value::as_object)
        && props.contains_key("confirm_destructive")
    {
        return (false, true);
    }

    let lower = tool_name.to_ascii_lowercase();
    let mutating_verbs = [
        "convert",
        "split",
        "merge",
        "execute",
        "run_job",
        "edit",
        "strip",
        "toggle",
        "kill",
        "terminate",
        "delete",
        "remove",
        "update",
        "changer",
        "set_",
        "write",
        "extract",
        "WOL",
        "wake",
    ];
    let read_only_hints = [
        "sniff",
        "validate",
        "audit",
        "inspect",
        "list",
        "view",
        "status",
        "report",
        "custody",
        "environment",
        "presets",
        "parse",
        "decode",
        "profiles",
        "dry_run",
        "preview",
        "info",
        "classify",
    ];
    if read_only_hints.iter().any(|h| lower.contains(h)) {
        return (true, false);
    }
    if mutating_verbs.iter().any(|v| lower.contains(&v.to_ascii_lowercase())) {
        return (false, true);
    }
    (true, false)
}

fn parse_raw_tool(spec: &SuiteSpec, raw: &Value) -> Option<IndexedTool> {
    let obj = raw.as_object()?;
    let tool_name = obj.get("name")?.as_str()?.trim().to_string();
    if tool_name.is_empty() {
        return None;
    }
    let description = obj
        .get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let input_schema = obj
        .get("inputSchema")
        .cloned()
        .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
    let supports_dry_run_arg = input_schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|p| p.contains_key("dry_run"))
        .unwrap_or(false);
    let (read_only, destructive) = infer_read_only(spec, &tool_name, raw);
    let keywords = extract_keywords(&tool_name, &description, spec.domain);

    Some(IndexedTool {
        suite_id: spec.suite_id.to_string(),
        portal: spec.portal.to_string(),
        domain: spec.domain.to_string(),
        qualified_id: format!("{}/{tool_name}", spec.suite_id),
        tool_name,
        description,
        read_only,
        destructive,
        supports_dry_run_arg,
        input_schema,
        keywords,
    })
}

fn parse_metadata_v2_tools(spec: &SuiteSpec, meta: &Value) -> Vec<IndexedTool> {
    let mut out = Vec::new();
    if let Some(tools) = meta.get("tools").and_then(Value::as_array) {
        for item in tools {
            let Some(id) = item.get("id").or_else(|| item.get("name")).and_then(Value::as_str) else {
                continue;
            };
            let desc = item
                .get("summary")
                .or_else(|| item.get("description"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let read_only = item.get("readOnly").and_then(Value::as_bool).unwrap_or(true);
            let keywords = extract_keywords(id, &desc, spec.domain);
            out.push(IndexedTool {
                suite_id: spec.suite_id.to_string(),
                portal: spec.portal.to_string(),
                domain: spec.domain.to_string(),
                qualified_id: format!("{}/{id}", spec.suite_id),
                tool_name: id.to_string(),
                description: desc,
                read_only,
                destructive: !read_only,
                supports_dry_run_arg: !read_only,
                input_schema: json!({ "type": "object", "properties": {} }),
                keywords,
            });
        }
    }
    if let Some(actions) = meta.get("actions").and_then(Value::as_array) {
        for item in actions {
            let Some(id) = item.get("id").or_else(|| item.get("name")).and_then(Value::as_str) else {
                continue;
            };
            let desc = item
                .get("summary")
                .or_else(|| item.get("description"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let keywords = extract_keywords(id, &desc, spec.domain);
            out.push(IndexedTool {
                suite_id: spec.suite_id.to_string(),
                portal: spec.portal.to_string(),
                domain: spec.domain.to_string(),
                qualified_id: format!("{}/{id}", spec.suite_id),
                tool_name: id.to_string(),
                description: desc,
                read_only: false,
                destructive: true,
                supports_dry_run_arg: true,
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "dry_run": { "type": "boolean", "default": false },
                        "confirm_destructive": { "type": "boolean", "default": false }
                    }
                }),
                keywords,
            });
        }
    }
    out
}

fn extract_keywords(tool_name: &str, description: &str, domain: &str) -> Vec<String> {
    let mut kws = Vec::new();
    kws.push(domain.to_ascii_lowercase());
    for part in tool_name.split(|c: char| !c.is_ascii_alphanumeric()) {
        if part.len() >= 2 {
            let p = part.to_ascii_lowercase();
            if !kws.contains(&p) {
                kws.push(p);
            }
        }
    }
    for word in description.split(|c: char| !c.is_ascii_alphanumeric()) {
        if word.len() >= 4 {
            let w = word.to_ascii_lowercase();
            if !kws.contains(&w) && kws.len() < 16 {
                kws.push(w);
            }
        }
    }
    kws
}

enum StdioCallError {
    Timeout(u64),
    Other(String),
}

fn invoke_mcp_stdio_call(
    launch: &McpLaunchSpec,
    extra_flags: &[String],
    tool_name: &str,
    arguments: &Value,
    timeout: Duration,
) -> Result<Value, StdioCallError> {
    let mut cmd = Command::new(&launch.program);
    cmd.args(&launch.prefix_args)
        .args(extra_flags)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| StdioCallError::Other(format!("spawn failed ({}): {e}", launch.display_command())))?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| StdioCallError::Other("missing child stdin".to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| StdioCallError::Other("missing child stdout".to_string()))?;

    let init_req = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "guap-appliance", "version": env!("CARGO_PKG_VERSION") }
        }
    });
    let notif = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    });
    let call_req = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": arguments
        }
    });

    let payload_lines = format!("{init_req}\n{notif}\n{call_req}\n");
    if let Err(e) = stdin.write_all(payload_lines.as_bytes()).and_then(|_| stdin.flush()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(StdioCallError::Other(format!("stdin write failed: {e}")));
    }
    // Close stdin so single-session stdio servers exit cleanly after replying to id=2
    drop(stdin);

    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line_res in reader.lines() {
            let Ok(line) = line_res else {
                break;
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<Value>(trimmed)
                && val.get("id") == Some(&json!(2))
            {
                let _ = tx.send(Ok(val));
                return;
            }
        }
        let _ = tx.send(Err("EOF before receiving JSON-RPC response id=2".to_string()));
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(resp)) => {
            let _ = child.kill();
            let _ = child.wait();
            if let Some(err_obj) = resp.get("error") {
                let msg = err_obj
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown JSON-RPC error");
                return Err(StdioCallError::Other(msg.to_string()));
            }
            let result = resp.get("result").cloned().unwrap_or(Value::Null);
            if result.get("isError").and_then(Value::as_bool) == Some(true) {
                let text = extract_mcp_text_content(&result).unwrap_or_else(|| result.to_string());
                return Err(StdioCallError::Other(text));
            }
            if let Some(text) = extract_mcp_text_content(&result)
                && let Ok(parsed_json) = serde_json::from_str::<Value>(&text)
            {
                return Ok(parsed_json);
            }
            Ok(result)
        }
        Ok(Err(msg)) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(StdioCallError::Other(msg))
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(StdioCallError::Timeout(timeout.as_millis() as u64))
        }
    }
}

fn extract_mcp_text_content(result: &Value) -> Option<String> {
    let arr = result.get("content")?.as_array()?;
    for item in arr {
        if item.get("type").and_then(Value::as_str) == Some("text")
            && let Some(text) = item.get("text").and_then(Value::as_str)
        {
            return Some(text.to_string());
        }
    }
    None
}

fn synthetic_tools_for_suite(spec: &SuiteSpec) -> Vec<IndexedTool> {
    let entries: &[(&str, &str, bool)] = match spec.suite_id {
        "sys2rust" => &[
            (
                "hw_services",
                "Inspect Windows services, startup mode, and binary paths",
                true,
            ),
            ("hw_drivers", "Enumerate loaded kernel and filesystem drivers", true),
            ("hw_tasks", "Inspect OS scheduled tasks and triggers", true),
            ("hw_battery", "Read battery health, wear level, and power state", true),
            ("startup_entries", "Audit logon startup items and autorun entries", true),
            (
                "proc_top",
                "Inspect active processes, CPU time, and working set memory",
                true,
            ),
            (
                "service_set_start_mode",
                "Change service start mode with reversible snapshot",
                false,
            ),
        ],
        "net2rust" => &[
            ("sockets.ports", "List active TCP/UDP sockets and owning PIDs", true),
            ("sockets.routes", "Inspect IPv4/IPv6 routing table and gateways", true),
            (
                "lan.ping-sweep",
                "Probe LAN gateway and local subnet reachability",
                true,
            ),
            (
                "capture.dns",
                "Inspect recent DNS resolution latency and NXDOMAIN responses",
                true,
            ),
            (
                "sockets.close-tcp",
                "Close an established TCP socket (requires confirmation)",
                false,
            ),
        ],
        "forensics2rust" => &[
            (
                "posture.defender",
                "Inspect Microsoft Defender & WSC security posture",
                true,
            ),
            (
                "evtx.system_errors",
                "Query critical and error System/Application EVTX events",
                true,
            ),
            (
                "crash.wer_reports",
                "List Windows Error Reporting and minidump crash records",
                true,
            ),
            (
                "artifacts.prefetch",
                "Inspect recent application execution Prefetch timeline",
                true,
            ),
        ],
        "fs2rust" => &[
            (
                "drive_letter_view",
                "Inspect mounted volumes, free capacity, and filesystems",
                true,
            ),
            (
                "disk_smart_view",
                "Read ATA/NVMe SMART temperature and health attributes",
                true,
            ),
            (
                "folders_report",
                "Summarize largest directories and storage growth",
                true,
            ),
            ("bulk_file_changer", "Batch-update file timestamps or attributes", false),
        ],
        "winctl2rust" => &[
            (
                "audio_view",
                "List CoreAudio playback/capture endpoints and mute state",
                true,
            ),
            ("desktop_hotkeys", "Audit registered global desktop hotkeys", true),
            (
                "cmd_atnow_tasks",
                "Schedule or manage local maintenance task entries",
                false,
            ),
        ],
        "chrome2rust" => &[
            (
                "chrome2rust_profiles",
                "Discover Chromium, Firefox, and Edge user profiles",
                true,
            ),
            (
                "chrome2rust_cache_list",
                "List browser disk cache entries read-only",
                true,
            ),
        ],
        "mail2rust" => &[
            (
                "mail2rust_sniff",
                "Detect PST/OST/MBOX/EML archive format and health",
                true,
            ),
            (
                "mail2rust_validate_pst",
                "Validate MS-PST B-tree and block CRC integrity",
                true,
            ),
            (
                "mail2rust_convert",
                "Convert mailbox archive across PST/MBOX/EML",
                false,
            ),
        ],
        "android2rust" => &[
            (
                "android2rust_environment",
                "Verify local ADB/Fastboot binaries and connected devices",
                true,
            ),
            (
                "android2rust_dry_run",
                "Preview ADB/Fastboot command plan without execution",
                true,
            ),
        ],
        "robocopy2rust" => &[
            (
                "robocopy2rust_validate",
                "Validate backup source/destination and 85+ Robocopy switches",
                true,
            ),
            (
                "robocopy2rust_execute",
                "Execute Robocopy backup job with /L preview guardrail",
                false,
            ),
        ],
        "mail2mail" => &[
            (
                "mail2mail_system_info",
                "Check Python & Outlook MAPI availability for mailbox migration",
                true,
            ),
            (
                "mail2mail_classify",
                "Classify mailbox archive format from header magic",
                true,
            ),
        ],
        _ => &[],
    };

    entries
        .iter()
        .map(|(name, desc, read_only)| IndexedTool {
            suite_id: spec.suite_id.to_string(),
            portal: spec.portal.to_string(),
            domain: spec.domain.to_string(),
            qualified_id: format!("{}/{name}", spec.suite_id),
            tool_name: (*name).to_string(),
            description: (*desc).to_string(),
            read_only: *read_only,
            destructive: !*read_only,
            supports_dry_run_arg: !*read_only,
            input_schema: if *read_only {
                json!({
                    "type": "object",
                    "properties": {
                        "filter": { "type": "string" },
                        "limit": { "type": "integer", "minimum": 1 }
                    }
                })
            } else {
                json!({
                    "type": "object",
                    "properties": {
                        "target": { "type": "string" },
                        "dry_run": { "type": "boolean", "default": false },
                        "confirm_destructive": { "type": "boolean", "default": false }
                    }
                })
            },
            keywords: extract_keywords(name, desc, spec.domain),
        })
        .collect()
}

fn build_synthetic_call_payload(tool: &IndexedTool, args: &Value, exec_mode: ToolExecMode) -> Value {
    match exec_mode {
        ToolExecMode::ReadOnly => json!({
            "tool_id": tool.tool_name,
            "suite_id": tool.suite_id,
            "title": format!("{} ({})", tool.tool_name, tool.suite_id),
            "total_rows": 2,
            "returned_rows": 2,
            "rows": [
                {
                    "row_id": 1,
                    "item": format!("{}:primary", tool.tool_name),
                    "status": "healthy",
                    "severity": "info",
                    "detail": format!("Synthetic offline sample row 1 for {}", tool.qualified_id)
                },
                {
                    "row_id": 2,
                    "item": format!("{}:secondary", tool.tool_name),
                    "status": "warning",
                    "severity": "low",
                    "detail": format!("Synthetic offline sample row 2 for {}", tool.qualified_id)
                }
            ]
        }),
        ToolExecMode::DryRunPreview => json!({
            "dry_run": true,
            "would_apply": true,
            "target_tool": tool.qualified_id,
            "preview_summary": format!("Dry-run preview succeeded for {} with zero system changes", tool.qualified_id),
            "arguments": args
        }),
        ToolExecMode::ApprovedMutating => json!({
            "dry_run": false,
            "applied": true,
            "target_tool": tool.qualified_id,
            "execution_summary": format!("Approved action {} applied cleanly in synthetic offline mode", tool.qualified_id),
            "arguments": args
        }),
    }
}

struct SuitesTableProvider {
    catalog: Arc<SuiteCatalog>,
}

impl TableProvider for SuitesTableProvider {
    fn tool_id(&self) -> &'static str {
        "catalog.suites"
    }

    fn description(&self) -> &'static str {
        "Discovered GUAP domain suites, versions, availability status, and MCP tool counts"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            "catalog.suites",
            "Discovered GUAP Suites",
            vec![
                ColumnDef::new("suite_id", "Suite", ColumnType::Text).with_width_hint(140),
                ColumnDef::new("domain", "Domain", ColumnType::Text).with_width_hint(110),
                ColumnDef::new("version", "Version", ColumnType::Text).with_width_hint(90),
                ColumnDef::new("status", "Status", ColumnType::Text).with_width_hint(130),
                ColumnDef::new("total_tools", "Total Tools", ColumnType::Uint).with_width_hint(100),
                ColumnDef::new("readonly_tools", "Read-Only", ColumnType::Uint).with_width_hint(100),
                ColumnDef::new("mutating_tools", "Mutating", ColumnType::Uint).with_width_hint(100),
                ColumnDef::new("binary", "MCP Launch Target", ColumnType::Text).with_width_hint(320),
            ],
        )
        .with_default_sort(4, SortDirection::Desc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let schema = self.schema();
        let rows: Vec<Row> = self
            .catalog
            .suites()
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let cmd = s
                    .launch
                    .as_ref()
                    .map(McpLaunchSpec::display_command)
                    .unwrap_or_else(|| "(offline / not built)".to_string());
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(s.suite_id.clone()),
                        CellValue::Text(s.domain.clone()),
                        CellValue::Text(s.version.clone()),
                        CellValue::Text(s.availability.as_str().to_string()),
                        CellValue::Uint(s.total_tools() as u64),
                        CellValue::Uint(s.readonly_count as u64),
                        CellValue::Uint(s.mutating_count as u64),
                        CellValue::Text(cmd),
                    ],
                )
                .with_detail_json(serde_json::to_value(s).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&schema, &rows, req)
    }
}

struct ToolsTableProvider {
    catalog: Arc<SuiteCatalog>,
}

impl TableProvider for ToolsTableProvider {
    fn tool_id(&self) -> &'static str {
        "catalog.tools"
    }

    fn description(&self) -> &'static str {
        "Indexed MCP tools across all 10 federated GUAP suites with safety classification and JSON schemas"
    }

    fn schema(&self) -> TableSchema {
        TableSchema::new(
            "catalog.tools",
            "Federated GUAP Tool Index",
            vec![
                ColumnDef::new("qualified_id", "Qualified ID", ColumnType::Text).with_width_hint(220),
                ColumnDef::new("suite_id", "Suite", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("domain", "Domain", ColumnType::Text).with_width_hint(100),
                ColumnDef::new("access", "Access Tier", ColumnType::Text).with_width_hint(120),
                ColumnDef::new("dry_run", "Dry-Run Arg", ColumnType::Bool).with_width_hint(95),
                ColumnDef::new("description", "Description", ColumnType::Text).with_width_hint(420),
            ],
        )
        .with_default_sort(0, SortDirection::Asc)
    }

    fn query(&self, req: &TableQuery) -> Result<TableData, TableError> {
        let schema = self.schema();
        let rows: Vec<Row> = self
            .catalog
            .tools()
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let access = if t.read_only { "read_only" } else { "approval_required" };
                Row::new(
                    (i + 1) as u64,
                    vec![
                        CellValue::Text(t.qualified_id.clone()),
                        CellValue::Text(t.suite_id.clone()),
                        CellValue::Text(t.domain.clone()),
                        CellValue::Text(access.to_string()),
                        CellValue::Bool(t.supports_dry_run_arg),
                        CellValue::Text(t.description.clone()),
                    ],
                )
                .with_detail_json(serde_json::to_value(t).unwrap_or(Value::Null))
            })
            .collect();
        apply_query(&schema, &rows, req)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_catalog_discovers_all_10_suites_and_enforces_safety_gates() {
        let cat = Arc::new(SuiteCatalog::discover(CatalogConfig::offline()));
        assert_eq!(cat.suites().len(), 10);
        assert_eq!(cat.ready_suite_count(), 10);
        assert!(cat.total_readonly_tools() >= 20);
        assert!(cat.total_mutating_tools() >= 5);

        // Ranked search caps results and respects read_only_only
        let matches = cat.search_tools("smart disk", None, None, true, 5);
        assert!(!matches.is_empty());
        assert_eq!(matches[0].qualified_id, "fs2rust/disk_smart_view");

        // Read-only call succeeds on read-only tool
        let ro = cat
            .call_tool("fs2rust/disk_smart_view", &json!({}), ToolExecMode::ReadOnly)
            .expect("read-only tool succeeds");
        assert!(ro.simulated);
        assert_eq!(ro.exec_mode, "read_only");

        // Read-only gateway MUST block mutating tool!
        let err = cat
            .call_tool(
                "sys2rust/service_set_start_mode",
                &json!({ "confirm_destructive": true }),
                ToolExecMode::ReadOnly,
            )
            .expect_err("mutating tool must be refused in ReadOnly mode");
        assert!(err.to_string().contains("safety refusal"));

        // DryRunPreview succeeds on mutating tool
        let preview = cat
            .call_tool(
                "sys2rust/service_set_start_mode",
                &json!({ "target": "Spooler" }),
                ToolExecMode::DryRunPreview,
            )
            .expect("dry run preview succeeds");
        assert_eq!(preview.payload["dry_run"], json!(true));

        // TableProviders work cleanly
        let providers = SuiteCatalog::table_providers(cat);
        assert_eq!(providers.len(), 2);
        let suites_data = providers[0].query(&TableQuery::default()).unwrap();
        assert_eq!(suites_data.total_rows, 10);
    }
}
