#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::sync::Arc;

use guap_catalog::{CatalogConfig, SuiteCatalog};
use guap_gui_iced::{IcedSuiteConfig, run_iced_suite};
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
    "guap-iced — Cross-Platform Iced 0.14 Console for the GUAP Flagship IT Appliance\n\n\
     USAGE:\n    guap-iced [OPTIONS]\n\n\
     OPTIONS:\n    \
     --offline                Use deterministic offline synthetic suite fixtures\n    \
     --workspace-root <PATH>  Override sibling GUAP suites root directory\n    \
     --state-dir <PATH>       Override SQLite state & custody directory\n    \
     --light                  Start with light theme instead of dark mode\n    \
     --tool <TOOL_ID>         Select initial tab (e.g. catalog.suites, runbooks.findings)\n    \
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

fn default_suite_config(dark_mode: bool) -> IcedSuiteConfig {
    IcedSuiteConfig {
        app_title: "GUAP — Generalized Utility & Administration Platform (Iced)".to_string(),
        dark_mode,
        window_size: (1380.0, 840.0),
    }
}

pub fn collect_providers(args: &LaunchArgs) -> Result<Vec<Arc<dyn TableProvider>>, String> {
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
    let router = Arc::new(
        RouterEngine::new(router_cfg, Arc::clone(&catalog), Arc::clone(&runbooks)).map_err(|e| e.to_string())?,
    );

    let mut providers: Vec<Arc<dyn TableProvider>> = SuiteCatalog::table_providers(catalog)
        .into_iter()
        .chain(RunbookEngine::table_providers(runbooks))
        .chain(RouterEngine::table_providers(router))
        .collect();

    if let Some(ref id) = args.tool {
        let pos = providers
            .iter()
            .position(|p| p.tool_id() == id)
            .ok_or_else(|| format!("unknown tool_id '{id}'"))?;
        providers.swap(0, pos);
    }

    Ok(providers)
}

fn main() -> iced::Result {
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
            let providers = match collect_providers(&args) {
                Ok(p) => p,
                Err(err) => {
                    eprintln!("{err}");
                    std::process::exit(2);
                }
            };
            run_iced_suite(default_suite_config(!args.light), providers)
        }
    }
}

#[cfg(test)]
mod tests {
    use guap_gui_iced::{DataGridMessage, IcedDataGrid};

    use super::*;

    #[test]
    fn iced_data_grid_switches_across_all_7_appliance_tabs_headless() {
        let tmp = tempfile::tempdir().unwrap();
        let args = LaunchArgs {
            offline: true,
            light: false,
            tool: Some("catalog.suites".to_string()),
            workspace_root: None,
            state_dir: Some(tmp.path().to_path_buf()),
        };

        let providers = collect_providers(&args).unwrap();
        assert_eq!(providers.len(), 7);
        let tab_ids: Vec<String> = providers.iter().map(|p| p.tool_id().to_string()).collect();

        let mut grid = IcedDataGrid::new(providers).with_dark_mode(true).with_page_size(50);
        for id in &tab_ids {
            let _ = grid.update(DataGridMessage::SelectTool(id.clone()));
            assert_eq!(grid.active_tool_id(), Some(id.as_str()));
            assert!(grid.last_error().is_none(), "'{id}' error: {:?}", grid.last_error());
            assert!(!grid.columns().is_empty());
        }

        let _ = grid.update(DataGridMessage::SelectTool("catalog.suites".to_string()));
        assert_eq!(grid.total_rows(), 10);
        let _ = grid.update(DataGridMessage::FilterChanged("net2rust".to_string()));
        assert_eq!(grid.total_rows(), 1);
        let _ = grid.update(DataGridMessage::FilterChanged(String::new()));
        let _ = grid.update(DataGridMessage::ToggleDarkMode);
        assert!(!grid.dark_mode());
    }
}
