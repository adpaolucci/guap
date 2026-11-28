#![forbid(unsafe_code)]

mod bundle;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use guap_catalog::{CatalogConfig, CatalogMode, SuiteCatalog};
use guap_export::{ExportFormat, ExportOptions, export_table};
use guap_llm::{DEFAULT_LLAMA_ENDPOINT, LlmClientConfig, LocalAdminAgent, probe_local_llama_server};
use guap_router::{RouterConfig, RouterEngine};
use guap_runbooks::{CORE_RUNBOOKS, RunbookEngine};
use guap_table::TableQuery;
use serde_json::{Value, json};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "guap",
    version,
    about = "GUAP — Generalized Utility & Administration Platform (Single-Machine Offline AI + IT Appliance)"
)]
pub struct Cli {
    /// Run against deterministic synthetic offline fixtures (zero child process spawning)
    #[arg(long, global = true)]
    pub offline: bool,

    /// Override GUAP sibling suites workspace or portable directory
    #[arg(long, global = true, value_name = "PATH")]
    pub workspace_root: Option<PathBuf>,

    /// Override state directory for SQLite Approval Cards, Job Profiles, and custody manifests
    #[arg(long, global = true, value_name = "PATH")]
    pub state_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Display host posture, local llama-server readiness, discovered suites, and pending Approval Cards
    Status {
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// List all 10 federated GUAP domain suites and their discovered MCP binaries
    Suites {
        /// Output format: md, json, csv, tsv, html
        #[arg(long, default_value = "md")]
        format: String,
        /// Emit machine-readable JSON (overrides --format)
        #[arg(long)]
        json: bool,
    },
    /// Search or browse the 326-tool federated GUAP catalog
    Tools {
        /// Keyword search query
        #[arg(short, long)]
        search: Option<String>,
        /// Filter by domain (system, network, forensics, desktop, storage, browser, mail, mobile, backup)
        #[arg(long)]
        domain: Option<String>,
        /// Filter by suite ID (e.g. sys2rust, net2rust, forensics2rust)
        #[arg(long)]
        suite: Option<String>,
        /// Show only read-only tools
        #[arg(long)]
        readonly: bool,
        /// Maximum results when searching (1..=10)
        #[arg(long, default_value_t = 5)]
        limit: usize,
        /// Emit JSON output including inputSchema
        #[arg(long)]
        json: bool,
    },
    /// Call any read-only tool across the 10 GUAP suites
    Call {
        /// Qualified tool reference (`<suite>/<tool>` or unambiguous `<tool>`)
        tool: String,
        /// JSON object arguments
        #[arg(long, default_value = "{}")]
        args: String,
        /// Maximum rows returned
        #[arg(long, default_value_t = 25)]
        max_rows: usize,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// List or execute the 6 deterministic IT triage runbooks
    Runbook {
        #[command(subcommand)]
        action: RunbookCommand,
    },
    /// Stage a mutating remediation via non-destructive dry-run preview (creates a pending Approval Card)
    Stage {
        /// Mutating tool reference (`<suite>/<tool>`)
        tool: String,
        /// Why this remediation is proposed
        #[arg(long)]
        rationale: String,
        /// How to undo or roll back this change
        #[arg(long, default_value = "")]
        rollback: String,
        /// JSON object arguments
        #[arg(long, default_value = "{}")]
        args: String,
        /// Emit pure JSON without trailing human helper text
        #[arg(long)]
        json: bool,
    },
    /// Review, approve, or reject staged remediation Approval Cards
    Approvals {
        #[command(subcommand)]
        action: ApprovalsCommand,
    },
    /// Manage or execute deterministic local maintenance Job Profiles
    Job {
        #[command(subcommand)]
        action: JobCommand,
    },
    /// View the append-only SHA-256/512 Merkle custody audit ledger
    Custody {
        #[arg(long)]
        json: bool,
    },
    /// Ask the local loopback llama-server AI administrator a diagnostic question
    Ask {
        /// Natural-language diagnostic question or task
        question: String,
        /// Loopback OpenAI-compatible chat completions endpoint
        #[arg(long, default_value = DEFAULT_LLAMA_ENDPOINT)]
        endpoint: String,
        /// Model ID (defaults to 'auto' to pick the loaded local GGUF)
        #[arg(long, default_value = "auto")]
        model: String,
        /// Maximum tool-calling turns
        #[arg(long, default_value_t = 6)]
        max_steps: usize,
        /// Enable full model reasoning traces instead of fast mode
        #[arg(long)]
        thinking: bool,
        /// Emit full session JSON trace
        #[arg(long)]
        json: bool,
    },
    /// Run the 6-meta-tool MCP JSON-RPC 2.0 stdio server (or print tool schemas with --tools)
    Mcp {
        /// Print the 6 flagship MCP meta-tool schemas as JSON and exit
        #[arg(long)]
        tools: bool,
    },
    /// Create or cryptographically verify a self-contained `guap-portable` USB/folder bundle
    Bundle {
        #[command(subcommand)]
        action: BundleCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum BundleCommand {
    /// Assemble a portable folder/USB bundle containing guap binaries, discovered suite MCPs, and a Merkle manifest
    Create {
        /// Destination portable bundle directory
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// Optional directory containing compiled guap/guap-mcp/guap-win32/guap-iced binaries
        #[arg(long, value_name = "DIR")]
        bin_dir: Option<PathBuf>,
        /// Optional CPU/Vulkan llama-server binary to bundle into llm/
        #[arg(long, value_name = "FILE")]
        llama_server: Option<PathBuf>,
        /// Optional quantized .gguf model to bundle into llm/models/
        #[arg(long, value_name = "FILE")]
        gguf: Option<PathBuf>,
        /// Include optional CUDA GPU backend DLLs (ggml-cuda.dll) when bundling llama-server
        #[arg(long)]
        include_cuda: bool,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Verify every artifact and the SHA-256/SHA-512 Merkle roots of a portable bundle
    Verify {
        /// Portable bundle directory containing portable-manifest.custody.json
        #[arg(long, default_value = ".", value_name = "DIR")]
        dir: PathBuf,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum RunbookCommand {
    /// List all 6 deterministic v1 IT triage runbooks
    List {
        #[arg(long)]
        json: bool,
    },
    /// Execute a deterministic runbook and emit findings + Merkle custody manifest
    Run {
        /// Runbook ID (e.g. health_and_security_posture)
        runbook_id: String,
        /// Output format: md, json, csv, html
        #[arg(long, default_value = "md")]
        format: String,
        /// Optional output directory for persisted report + .custody.json manifest
        #[arg(long, value_name = "DIR")]
        out_dir: Option<PathBuf>,
        /// Emit machine-readable JSON (overrides --format)
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum ApprovalsCommand {
    /// List Approval Cards (optionally filtered by status: pending, executed, rejected, failed)
    List {
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Inspect full dry-run preview, arguments, and rollback plan for a Card
    Inspect {
        card_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Explicitly approve and execute a pending Card, writing a Merkle custody receipt
    Approve {
        card_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Reject a pending Card without applying changes
    Reject {
        card_id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum JobCommand {
    /// List registered deterministic Job Profiles
    List {
        #[arg(long)]
        json: bool,
    },
    /// Approve a staged Job Profile for deterministic execution
    Approve {
        profile_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Execute an approved deterministic Job Profile without invoking an LLM
    Run {
        profile_id: String,
        #[arg(long)]
        json: bool,
    },
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn build_stack(cli: &Cli) -> anyhow::Result<Arc<RouterEngine>> {
    let mut cat_cfg = if cli.offline {
        CatalogConfig::offline()
    } else {
        CatalogConfig::default()
    };
    if let Some(ref root) = cli.workspace_root {
        cat_cfg.workspace_root = Some(root.clone());
    }
    if cli.offline {
        cat_cfg.mode = CatalogMode::Offline;
    } else if matches!(cli.command, Commands::Bundle { .. }) {
        cat_cfg.prefer_release_binaries = true;
    }

    let catalog = Arc::new(SuiteCatalog::discover(cat_cfg));
    let runbooks = Arc::new(RunbookEngine::new(Arc::clone(&catalog)));

    let mut router_cfg = RouterConfig::default();
    if let Some(ref sd) = cli.state_dir {
        router_cfg.state_dir = sd.clone();
    }
    Ok(Arc::new(RouterEngine::new(router_cfg, catalog, runbooks)?))
}

fn main() -> anyhow::Result<()> {
    let _ = ctrlc::set_handler(|| {
        std::process::exit(130);
    });
    let cli = Cli::parse();
    init_tracing();
    run_cli(&cli)
}

pub fn run_cli(cli: &Cli) -> anyhow::Result<()> {
    if let Commands::Bundle {
        action: BundleCommand::Verify { dir, json: as_json },
    } = &cli.command
    {
        let report = bundle::verify_portable_bundle(dir)?;
        if *as_json {
            let mut val = serde_json::to_value(&report)?;
            if let Some(obj) = val.as_object_mut() {
                obj.insert("ok".to_string(), json!(report.verified));
            }
            println!("{}", serde_json::to_string_pretty(&val)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        if !report.verified {
            anyhow::bail!(
                "portable bundle integrity check FAILED ({} mismatch(es))",
                report.mismatches.len()
            );
        }
        return Ok(());
    }

    let router = build_stack(cli)?;
    match &cli.command {
        Commands::Status { json: as_json } => {
            let summary = router.host_summary()?;
            let llm_probe = if cli.offline {
                guap_llm::LlmServerProbe {
                    reachable: false,
                    endpoint: router.config().llm_endpoint.clone(),
                    loaded_models: Vec::new(),
                    error: Some("skipped in --offline mode".to_string()),
                }
            } else {
                probe_local_llama_server(&router.config().llm_endpoint, Duration::from_secs(2))
            };
            if *as_json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "appliance": summary,
                        "local_llm": llm_probe,
                        "suites": router.catalog().suites(),
                    }))?
                );
            } else {
                let host = &summary["host"];
                println!("GUAP Appliance v{}", env!("CARGO_PKG_VERSION"));
                println!(
                    "  Host:           {} ({}) · {} logical cores",
                    host["os"].as_str().unwrap_or(""),
                    host["arch"].as_str().unwrap_or(""),
                    host["cpu_logical_cores"].as_u64().unwrap_or(0)
                );
                println!(
                    "  Suites Ready:   {}/{} ({} total tools: {} read-only, {} approval-gated)",
                    host["discovered_suites_ready"].as_u64().unwrap_or(0),
                    host["discovered_suites_total"].as_u64().unwrap_or(0),
                    host["indexed_tools_total"].as_u64().unwrap_or(0),
                    host["indexed_readonly_tools"].as_u64().unwrap_or(0),
                    host["indexed_mutating_tools"].as_u64().unwrap_or(0)
                );
                println!(
                    "  Pending Cards:  {} (State: {})",
                    summary["pending_approval_cards"].as_u64().unwrap_or(0),
                    summary["state_dir"].as_str().unwrap_or("")
                );
                if llm_probe.reachable {
                    println!(
                        "  Local AI:       ONLINE at {} (models: {})",
                        llm_probe.endpoint,
                        if llm_probe.loaded_models.is_empty() {
                            "default".to_string()
                        } else {
                            llm_probe.loaded_models.join(", ")
                        }
                    );
                } else {
                    println!(
                        "  Local AI:       OFFLINE at {} ({})",
                        llm_probe.endpoint,
                        llm_probe.error.unwrap_or_else(|| "not running".to_string())
                    );
                }
            }
        }
        Commands::Suites { format, json: as_json } => {
            let fmt = if *as_json {
                ExportFormat::Json
            } else {
                ExportFormat::parse(format)?
            };
            let providers = SuiteCatalog::table_providers(Arc::clone(router.catalog()));
            let data = providers[0].query(&TableQuery::default())?;
            let bytes = export_table(&data, fmt, &ExportOptions::default())?;
            print!("{}", String::from_utf8_lossy(&bytes));
        }
        Commands::Tools {
            search,
            domain,
            suite,
            readonly,
            limit,
            json: as_json,
        } => {
            if let Some(q) = search {
                let matches = router
                    .catalog()
                    .search_tools(q, domain.as_deref(), suite.as_deref(), *readonly, *limit);
                if *as_json {
                    println!("{}", serde_json::to_string_pretty(&matches)?);
                } else {
                    for t in matches {
                        let tier = if t.read_only { "RO" } else { "APPROVAL" };
                        println!("[{tier}] {:<36} ({}) — {}", t.qualified_id, t.domain, t.description);
                    }
                }
            } else {
                let providers = SuiteCatalog::table_providers(Arc::clone(router.catalog()));
                let data = providers[1].query(&TableQuery {
                    limit: Some(50),
                    ..TableQuery::default()
                })?;
                let fmt = if *as_json {
                    ExportFormat::Json
                } else {
                    ExportFormat::Markdown
                };
                let bytes = export_table(&data, fmt, &ExportOptions::default())?;
                print!("{}", String::from_utf8_lossy(&bytes));
            }
        }
        Commands::Call {
            tool,
            args,
            max_rows,
            json: _,
        } => {
            let parsed_args: Value = serde_json::from_str(args)?;
            let out = router.call_readonly(tool, &parsed_args, *max_rows, 16_384)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Commands::Runbook { action } => match action {
            RunbookCommand::List { json: as_json } => {
                if *as_json {
                    let list: Vec<Value> = CORE_RUNBOOKS
                        .iter()
                        .map(|r| {
                            json!({
                                "id": r.id,
                                "title": r.title,
                                "domain": r.domain,
                                "summary": r.summary,
                                "steps": r.steps.len() + 1,
                            })
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&list)?);
                } else {
                    for r in CORE_RUNBOOKS {
                        println!("{:<30} [{}] — {}", r.id, r.domain, r.summary);
                    }
                }
            }
            RunbookCommand::Run {
                runbook_id,
                format,
                out_dir,
                json: as_json,
            } => {
                let fmt = if *as_json {
                    ExportFormat::Json
                } else {
                    ExportFormat::parse(format)?
                };
                let target_dir = out_dir.clone().unwrap_or_else(|| router.reports_dir());
                let report = router.runbooks().execute(runbook_id, Some(&target_dir), fmt)?;
                if fmt == ExportFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    let table = report.to_table_data();
                    let rendered = export_table(&table, fmt, &ExportOptions::default())?;
                    print!("{}", String::from_utf8_lossy(&rendered));
                    println!(
                        "\nCustody Merkle SHA-256: {}\nSaved Report:           {}",
                        report.custody.merkle_root_sha256,
                        report.exported_report_path.as_deref().unwrap_or("(memory)")
                    );
                }
            }
        },
        Commands::Stage {
            tool,
            rationale,
            rollback,
            args,
            json: as_json,
        } => {
            let parsed_args: Value = serde_json::from_str(args)?;
            let card = router.stage_fix(tool, &parsed_args, rationale, rollback)?;
            println!("{}", serde_json::to_string_pretty(&card)?);
            if !*as_json {
                println!("\nTo approve and execute: guap approvals approve {}", card.card_id);
            }
        }
        Commands::Approvals { action } => match action {
            ApprovalsCommand::List { status, json: as_json } => {
                let cards = router.list_cards(status.as_deref())?;
                if *as_json {
                    println!("{}", serde_json::to_string_pretty(&cards)?);
                } else if cards.is_empty() {
                    println!("No Approval Cards found.");
                } else {
                    for c in cards {
                        println!(
                            "{:<16} [{:<8}] {:<34} — {}",
                            c.card_id, c.status, c.tool_id, c.rationale
                        );
                    }
                }
            }
            ApprovalsCommand::Inspect { card_id, json: _ } => {
                let card = router.get_card(card_id)?;
                println!("{}", serde_json::to_string_pretty(&card)?);
            }
            ApprovalsCommand::Approve { card_id, json: _ } => {
                let card = router.approve_card(card_id, "cli-operator")?;
                println!("{}", serde_json::to_string_pretty(&card)?);
            }
            ApprovalsCommand::Reject { card_id, json: _ } => {
                let card = router.reject_card(card_id, "cli-operator")?;
                println!("{}", serde_json::to_string_pretty(&card)?);
            }
        },
        Commands::Job { action } => match action {
            JobCommand::List { json: as_json } => {
                let jobs = router.list_job_profiles()?;
                if *as_json {
                    println!("{}", serde_json::to_string_pretty(&jobs)?);
                } else {
                    for j in jobs {
                        println!(
                            "{:<24} [approved={:<5}] {:<12} — {}",
                            j.profile_id, j.approved, j.schedule_hint, j.name
                        );
                    }
                }
            }
            JobCommand::Approve { profile_id, json: _ } => {
                let job = router.approve_job_profile(profile_id)?;
                println!("{}", serde_json::to_string_pretty(&job)?);
            }
            JobCommand::Run { profile_id, json: _ } => {
                let res = router.run_job_profile(profile_id)?;
                println!("{}", serde_json::to_string_pretty(&res)?);
            }
        },
        Commands::Custody { json: as_json } => {
            let entries = router.list_custody_entries()?;
            if *as_json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else if entries.is_empty() {
                println!("Custody ledger is currently empty.");
            } else {
                for e in entries {
                    println!(
                        "{:<16} {} {:<18} {:<30} sha256:{}...",
                        e.receipt_id,
                        e.recorded_at,
                        e.operation,
                        e.target_id,
                        &e.merkle_sha256[..16.min(e.merkle_sha256.len())]
                    );
                }
            }
        }
        Commands::Ask {
            question,
            endpoint,
            model,
            max_steps,
            thinking,
            json: as_json,
        } => {
            let agent = LocalAdminAgent::new(
                LlmClientConfig {
                    chat_endpoint: endpoint.clone(),
                    model: model.clone(),
                    max_steps: *max_steps,
                    timeout: Duration::from_secs(120),
                    fast_mode: !*thinking,
                },
                Arc::clone(&router),
            );
            let session = agent.ask(question)?;
            if *as_json {
                println!("{}", serde_json::to_string_pretty(&session)?);
            } else {
                println!(
                    "[GUAP Local AI · model={} · steps={} · tool_calls={} · pending_cards={}]\n\n{}",
                    session.model,
                    session.steps_taken,
                    session.tool_calls.len(),
                    session.pending_approval_cards,
                    session.answer
                );
            }
        }
        Commands::Mcp { tools } => {
            let reg = RouterEngine::build_mcp_registry(router);
            if *tools {
                println!("{}", serde_json::to_string_pretty(&reg.list_tools())?);
                return Ok(());
            }
            reg.serve_stdio()?;
        }
        Commands::Bundle { action } => match action {
            BundleCommand::Create {
                out,
                bin_dir,
                llama_server,
                gguf,
                include_cuda,
                json: as_json,
            } => {
                let summary = bundle::create_portable_bundle(
                    router.catalog(),
                    out,
                    bin_dir.as_deref(),
                    llama_server.as_deref(),
                    gguf.as_deref(),
                    *include_cuda,
                )?;
                if *as_json {
                    let mut val = serde_json::to_value(&summary)?;
                    if let Some(obj) = val.as_object_mut() {
                        obj.insert("ok".to_string(), json!(true));
                    }
                    println!("{}", serde_json::to_string_pretty(&val)?);
                } else {
                    println!("{}", serde_json::to_string_pretty(&summary)?);
                }
            }
            BundleCommand::Verify { .. } => unreachable!("handled before build_stack"),
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_and_runs_offline_status_runbook_and_approval_flow() {
        let tmp = tempfile::tempdir().unwrap();
        let state_str = tmp.path().display().to_string();

        let status_cli =
            Cli::try_parse_from(["guap", "--offline", "--state-dir", &state_str, "status", "--json"]).unwrap();
        run_cli(&status_cli).unwrap();

        let suites_cli =
            Cli::try_parse_from(["guap", "--offline", "--state-dir", &state_str, "suites", "--json"]).unwrap();
        run_cli(&suites_cli).unwrap();

        let rb_cli = Cli::try_parse_from([
            "guap",
            "--offline",
            "--state-dir",
            &state_str,
            "runbook",
            "run",
            "health_and_security_posture",
            "--format",
            "md",
        ])
        .unwrap();
        run_cli(&rb_cli).unwrap();

        let stage_cli = Cli::try_parse_from([
            "guap",
            "--offline",
            "--state-dir",
            &state_str,
            "stage",
            "sys2rust/service_set_start_mode",
            "--rationale",
            "unit test stage",
            "--json",
        ])
        .unwrap();
        run_cli(&stage_cli).unwrap();

        let approve_parsed = Cli::try_parse_from([
            "guap",
            "--offline",
            "--state-dir",
            &state_str,
            "approvals",
            "approve",
            "card-1",
            "--json",
        ])
        .unwrap();
        assert!(matches!(
            approve_parsed.command,
            Commands::Approvals {
                action: ApprovalsCommand::Approve { json: true, .. }
            }
        ));

        let mcp_tools_cli =
            Cli::try_parse_from(["guap", "--offline", "--state-dir", &state_str, "mcp", "--tools"]).unwrap();
        run_cli(&mcp_tools_cli).unwrap();

        let bundle_dir = tmp.path().join("portable_test");
        let bundle_dir_str = bundle_dir.display().to_string();
        let create_cli = Cli::try_parse_from([
            "guap",
            "--offline",
            "--state-dir",
            &state_str,
            "bundle",
            "create",
            "--out",
            &bundle_dir_str,
            "--json",
        ])
        .unwrap();
        run_cli(&create_cli).unwrap();

        let verify_cli = Cli::try_parse_from(["guap", "bundle", "verify", "--dir", &bundle_dir_str, "--json"]).unwrap();
        run_cli(&verify_cli).unwrap();
    }

    #[test]
    fn bundle_verify_succeeds_without_state_dir_on_readonly_state() {
        let tmp = tempfile::tempdir().unwrap();
        let state_str = tmp.path().join("create_state").display().to_string();
        let bundle_dir = tmp.path().join("portable_ro_test");
        let bundle_dir_str = bundle_dir.display().to_string();

        let create_cli = Cli::try_parse_from([
            "guap",
            "--offline",
            "--state-dir",
            &state_str,
            "bundle",
            "create",
            "--out",
            &bundle_dir_str,
            "--json",
        ])
        .unwrap();
        run_cli(&create_cli).unwrap();

        let verify_cli = Cli::try_parse_from(["guap", "bundle", "verify", "--dir", &bundle_dir_str]).unwrap();
        run_cli(&verify_cli).unwrap();
    }
}
