#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#![forbid(unsafe_code)]
#![allow(linker_messages)]

use std::path::PathBuf;
use std::sync::Arc;

use guap_catalog::{CatalogConfig, SuiteCatalog};
use guap_gui_win32::{Win32TableHostConfig, run_win32_suite};
use guap_mcp::ActionCommand;
use guap_router::{RouterConfig, RouterEngine};
use guap_runbooks::RunbookEngine;
use guap_table::TableProvider;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaunchArgs {
    pub offline: bool,
    pub light: bool,
    pub tool: Option<String>,
    pub workspace_root: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchAction {
    Help,
    Version,
    Run(LaunchArgs),
}

pub fn parse_launch_args_from<I>(args: I) -> Result<LaunchAction, String>
where
    I: IntoIterator<Item = String>,
{
    let mut parsed = LaunchArgs::default();
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--help" | "-h" => return Ok(LaunchAction::Help),
            "--version" | "-V" => return Ok(LaunchAction::Version),
            "--offline" => parsed.offline = true,
            "--light" => parsed.light = true,
            "--tool" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value after --tool <TOOL_ID>".to_string())?;
                if value.trim().is_empty() {
                    return Err("--tool value must not be empty".to_string());
                }
                parsed.tool = Some(value);
            }
            "--workspace-root" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value after --workspace-root <PATH>".to_string())?;
                parsed.workspace_root = Some(PathBuf::from(value));
            }
            "--state-dir" => {
                let value = iter
                    .next()
                    .ok_or_else(|| "missing value after --state-dir <PATH>".to_string())?;
                parsed.state_dir = Some(PathBuf::from(value));
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    Ok(LaunchAction::Run(parsed))
}

fn help_text() -> &'static str {
    "guap-win32 — Native Zero-GPU Win32 Console for the GUAP Flagship IT Appliance\n\n\
     USAGE:\n    guap-win32 [OPTIONS]\n\n\
     OPTIONS:\n    \
     --offline                Use deterministic offline synthetic suite fixtures\n    \
     --workspace-root <PATH>  Override sibling GUAP suites root directory\n    \
     --state-dir <PATH>       Override SQLite state & custody directory\n    \
     --light                  Start with light theme instead of dark mode\n    \
     --tool <TOOL_ID>         Select initial tab (e.g. catalog.suites, router.approvals)\n    \
     -h, --help               Print help and exit\n    \
     -V, --version            Print version and exit"
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

fn default_host_config(dark_mode: bool) -> Win32TableHostConfig {
    Win32TableHostConfig {
        app_title: "GUAP — Generalized Utility & Administration Platform (Win32)".to_string(),
        dark_mode,
        show_hex_pane: false,
        default_export_dir: None,
    }
}

type ProvidersAndActions = (Vec<Arc<dyn TableProvider>>, Vec<Arc<dyn ActionCommand>>);

pub fn collect_providers_and_actions(args: &LaunchArgs) -> anyhow::Result<ProvidersAndActions> {
    let mut cat_cfg = if args.offline {
        CatalogConfig::offline()
    } else {
        CatalogConfig::default()
    };
    if let Some(ref root) = args.workspace_root {
        cat_cfg.workspace_root = Some(root.clone());
    }
    let catalog = Arc::new(SuiteCatalog::discover(cat_cfg));
    let runbooks = Arc::new(RunbookEngine::new(Arc::clone(&catalog)));

    let mut router_cfg = RouterConfig::default();
    if let Some(ref sd) = args.state_dir {
        router_cfg.state_dir = sd.clone();
    }
    let router = Arc::new(RouterEngine::new(
        router_cfg,
        Arc::clone(&catalog),
        Arc::clone(&runbooks),
    )?);

    let mut providers: Vec<Arc<dyn TableProvider>> = SuiteCatalog::table_providers(catalog)
        .into_iter()
        .chain(RunbookEngine::table_providers(runbooks))
        .chain(RouterEngine::table_providers(Arc::clone(&router)))
        .collect();

    if let Some(ref id) = args.tool {
        let pos = providers
            .iter()
            .position(|p| p.tool_id() == id)
            .ok_or_else(|| anyhow::anyhow!("unknown tool_id '{id}'"))?;
        providers.swap(0, pos);
    }

    let actions = RouterEngine::gui_operator_actions(router);
    Ok((providers, actions))
}

fn main() -> anyhow::Result<()> {
    let action = match parse_launch_args_from(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(err) => {
            eprintln!("{err}\n\n{}", help_text());
            std::process::exit(2);
        }
    };

    match action {
        LaunchAction::Help => {
            println!("{}", help_text());
            Ok(())
        }
        LaunchAction::Version => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        LaunchAction::Run(args) => {
            init_tracing();
            let (providers, actions) = collect_providers_and_actions(&args)?;
            run_win32_suite(default_host_config(!args.light), providers, actions)
        }
    }
}

#[cfg(test)]
mod tests {
    use guap_gui_win32::Win32GridState;

    use super::*;

    #[test]
    fn win32_grid_state_loads_all_7_appliance_tabs_and_8_operator_actions() {
        let tmp = tempfile::tempdir().unwrap();
        let args = LaunchArgs {
            offline: true,
            light: false,
            tool: Some("runbooks.catalog".to_string()),
            workspace_root: None,
            state_dir: Some(tmp.path().to_path_buf()),
        };

        let (providers, actions) = collect_providers_and_actions(&args).unwrap();
        assert_eq!(providers.len(), 7);
        assert_eq!(actions.len(), 8);
        assert_eq!(providers[0].tool_id(), "runbooks.catalog");

        let tab_ids: Vec<String> = providers.iter().map(|p| p.tool_id().to_string()).collect();
        let mut state = Win32GridState::new(default_host_config(true), providers, actions);
        assert_eq!(state.active_tool_id(), Some("runbooks.catalog"));

        for id in &tab_ids {
            assert!(state.select_tool_by_id(id), "failed selecting '{id}'");
            assert!(state.last_error.is_none(), "'{id}' query error: {:?}", state.last_error);
            assert!(!state.columns().is_empty());
        }

        assert!(state.select_tool_by_id("catalog.suites"));
        assert_eq!(state.row_count(), 10);
        state.set_filter("sys2rust".to_string());
        assert_eq!(state.row_count(), 1);
        state.set_filter(String::new());
        let _ = state.toggle_sort(0);
        assert!(state.last_error.is_none());

        type RunSuiteFn =
            fn(Win32TableHostConfig, Vec<Arc<dyn TableProvider>>, Vec<Arc<dyn ActionCommand>>) -> anyhow::Result<()>;
        let _fn_ptr: RunSuiteFn = run_win32_suite;
    }
}
