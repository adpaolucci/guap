#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use guap_catalog::{CatalogConfig, SuiteCatalog};
use guap_router::{RouterConfig, RouterEngine};
use guap_runbooks::RunbookEngine;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "guap-mcp",
    version,
    about = "GUAP Flagship 6-Meta-Tool Lazy MCP JSON-RPC 2.0 stdio server"
)]
struct Args {
    /// Print registered MCP meta-tools as JSON and exit
    #[arg(long)]
    tools: bool,

    /// Run in deterministic offline synthetic fixture mode
    #[arg(long)]
    offline: bool,

    /// Optional sibling workspace root override
    #[arg(long, value_name = "PATH")]
    workspace_root: Option<PathBuf>,

    /// Optional state directory override
    #[arg(long, value_name = "PATH")]
    state_dir: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();

    let mut cat_cfg = if args.offline {
        CatalogConfig::offline()
    } else {
        CatalogConfig::default()
    };
    if let Some(root) = args.workspace_root {
        cat_cfg.workspace_root = Some(root);
    }

    let catalog = Arc::new(SuiteCatalog::discover(cat_cfg));
    let runbooks = Arc::new(RunbookEngine::new(Arc::clone(&catalog)));
    let mut router_cfg = RouterConfig::default();
    if let Some(sd) = args.state_dir {
        router_cfg.state_dir = sd;
    }
    let router = Arc::new(RouterEngine::new(router_cfg, catalog, runbooks)?);
    let registry = RouterEngine::build_mcp_registry(router);

    if args.tools {
        println!("{}", serde_json::to_string_pretty(&registry.list_tools())?);
        return Ok(());
    }
    registry.serve_stdio()
}
