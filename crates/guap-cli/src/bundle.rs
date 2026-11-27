use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use guap_catalog::{KNOWN_SUITES, SuiteCatalog};
use guap_export::{
    CustodyLeaf, CustodyManifest, build_custody_manifest, compute_merkle_root_sha256, compute_merkle_root_sha512,
    sha256_hex, sha512_hex, write_custody_manifest_json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSummary {
    pub output_dir: String,
    pub copied_artifacts: usize,
    pub total_bytes: u64,
    pub suites_bundled: Vec<String>,
    pub merkle_root_sha256: String,
    pub merkle_root_sha512: String,
    pub custody_manifest_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleVerifyReport {
    pub bundle_dir: String,
    pub verified: bool,
    pub checked_files: usize,
    pub mismatches: Vec<String>,
    pub expected_merkle_sha256: String,
    pub actual_merkle_sha256: String,
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

/// Assemble a self-contained `guap-portable` folder/USB layout with a cryptographic
/// SHA-256 + SHA-512 Merkle `CustodyManifest` (`portable-manifest.custody.json`).
pub fn create_portable_bundle(
    catalog: &SuiteCatalog,
    out_dir: &Path,
    guap_bin_dir: Option<&Path>,
    llama_server_bin: Option<&Path>,
    gguf_model: Option<&Path>,
) -> anyhow::Result<BundleSummary> {
    fs::create_dir_all(out_dir.join("suites"))?;
    fs::create_dir_all(out_dir.join("llm").join("models"))?;
    fs::create_dir_all(out_dir.join("state"))?;

    let mut staged_rel_paths: Vec<PathBuf> = Vec::new();

    // 1. Marker file activating portable relative `state/` directory automatically
    let marker_rel = PathBuf::from("guap-portable.marker");
    fs::write(
        out_dir.join(&marker_rel),
        format!("guap-portable v{}\n", env!("CARGO_PKG_VERSION")),
    )?;
    staged_rel_paths.push(marker_rel);

    // 2. Copy flagship `guap`, `guap-mcp`, `guap-win32`, `guap-iced` binaries when present
    let resolved_bin_dir = match guap_bin_dir {
        Some(d) => Some(d.to_path_buf()),
        None => std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf)),
    };
    if let Some(ref bdir) = resolved_bin_dir {
        for base in ["guap", "guap-mcp", "guap-win32", "guap-iced"] {
            let fname = exe_name(base);
            let src = bdir.join(&fname);
            if src.is_file() {
                let rel = PathBuf::from(&fname);
                fs::copy(&src, out_dir.join(&rel))
                    .with_context(|| format!("failed copying {} into bundle", src.display()))?;
                staged_rel_paths.push(rel);
            }
        }
    }

    // 3. Copy discovered suite MCP binaries (and Python modules for `mail2mail` when present)
    let mut suites_bundled = Vec::new();
    for suite in catalog.suites() {
        let Some(ref launch) = suite.launch else {
            continue;
        };
        if suite.suite_id == "mail2mail" {
            // For `mail2mail`, `prefix_args[0]` is `<repo>/mail2mcp.py` when running from source
            if let Some(script_str) = launch.prefix_args.first() {
                let script_path = PathBuf::from(script_str);
                if let Some(src_dir) = script_path.parent()
                    && src_dir.is_dir()
                {
                    let dst_suite_dir = out_dir.join("suites").join("mail2mail");
                    fs::create_dir_all(&dst_suite_dir)?;
                    if let Ok(entries) = fs::read_dir(src_dir) {
                        let mut py_files: Vec<PathBuf> = entries
                            .flatten()
                            .map(|e| e.path())
                            .filter(|p| {
                                p.is_file()
                                    && p.extension()
                                        .and_then(|x| x.to_str())
                                        .map(|x| x == "py")
                                        .unwrap_or(false)
                            })
                            .collect();
                        py_files.sort();
                        for py in py_files {
                            if let Some(name) = py.file_name() {
                                let rel = PathBuf::from("suites").join("mail2mail").join(name);
                                fs::copy(&py, out_dir.join(&rel))?;
                                staged_rel_paths.push(rel);
                            }
                        }
                        suites_bundled.push(suite.suite_id.clone());
                    }
                }
            }
            continue;
        }

        if launch.program.is_file()
            && let Some(fname) = launch.program.file_name()
        {
            let dst_suite_dir = out_dir.join("suites").join(&suite.suite_id);
            fs::create_dir_all(&dst_suite_dir)?;
            let rel = PathBuf::from("suites").join(&suite.suite_id).join(fname);
            fs::copy(&launch.program, out_dir.join(&rel))
                .with_context(|| format!("failed copying suite binary {}", launch.program.display()))?;
            staged_rel_paths.push(rel);
            suites_bundled.push(suite.suite_id.clone());
        }
    }

    // 4. Optional offline `llama-server` + `guap-admin` GGUF drop-in
    if let Some(srv) = llama_server_bin {
        if !srv.is_file() {
            bail!("--llama-server file does not exist: {}", srv.display());
        }
        let fname = exe_name("llama-server");
        let rel = PathBuf::from("llm").join(fname);
        fs::copy(srv, out_dir.join(&rel))?;
        staged_rel_paths.push(rel);
    }
    if let Some(gguf) = gguf_model {
        if !gguf.is_file() {
            bail!("--gguf file does not exist: {}", gguf.display());
        }
        let fname = gguf
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("invalid --gguf filename"))?;
        let rel = PathBuf::from("llm").join("models").join(fname);
        fs::copy(gguf, out_dir.join(&rel))?;
        staged_rel_paths.push(rel);
    }

    let llm_readme_rel = PathBuf::from("llm").join("README.txt");
    fs::write(
        out_dir.join(&llm_readme_rel),
        "GUAP Portable Offline LLM Runtime\n\
         ==================================\n\
         Place `llama-server.exe` (CPU or Vulkan build) in `llm/` and a quantized `.gguf`\n\
         (e.g. `guap-admin-v0.1-q4_k_m.gguf` or `gemma-4-E4B-it-Q4_K_XL.gguf`) in `llm/models/`.\n\
         When `guap ask` runs and `127.0.0.1:9931` is not already active, `guap` automatically\n\
         spawns the bundled `llama-server` on an ephemeral loopback port (`127.0.0.1`) and\n\
         terminates it cleanly on exit.\n",
    )?;
    staged_rel_paths.push(llm_readme_rel);

    // 5. Write portable `mcp.json` and `portable-info.json`
    let mcp_rel = PathBuf::from("mcp.json");
    let mcp_cmd = format!("./{}", exe_name("guap-mcp"));
    fs::write(
        out_dir.join(&mcp_rel),
        serde_json::to_vec_pretty(&json!({
            "mcpServers": {
                "guap": {
                    "command": mcp_cmd,
                    "args": []
                }
            }
        }))?,
    )?;
    staged_rel_paths.push(mcp_rel);

    let info_rel = PathBuf::from("portable-info.json");
    let known_ids: Vec<&str> = KNOWN_SUITES.iter().map(|s| s.suite_id).collect();
    fs::write(
        out_dir.join(&info_rel),
        serde_json::to_vec_pretty(&json!({
            "bundle": "guap-portable",
            "version": env!("CARGO_PKG_VERSION"),
            "suites_bundled": suites_bundled,
            "known_suites": known_ids,
        }))?,
    )?;
    staged_rel_paths.push(info_rel);

    // 6. Deterministic sort + dual SHA-256 / SHA-512 Merkle CustodyManifest
    staged_rel_paths.sort();
    staged_rel_paths.dedup();

    let mut leaves = Vec::with_capacity(staged_rel_paths.len());
    for (idx, rel) in staged_rel_paths.iter().enumerate() {
        let bytes = fs::read(out_dir.join(rel))?;
        let norm_rel = rel.to_string_lossy().replace('\\', "/");
        leaves.push(CustodyLeaf {
            index: idx,
            path: norm_rel,
            size_bytes: bytes.len() as u64,
            sha256: sha256_hex(&bytes),
            sha512: sha512_hex(&bytes),
        });
    }

    let manifest = build_custody_manifest("guap.portable.bundle", env!("CARGO_PKG_VERSION"), leaves);
    let manifest_path = out_dir.join("portable-manifest.custody.json");
    write_custody_manifest_json(&manifest, &manifest_path)?;

    Ok(BundleSummary {
        output_dir: out_dir.display().to_string(),
        copied_artifacts: manifest.artifact_count,
        total_bytes: manifest.total_bytes,
        suites_bundled,
        merkle_root_sha256: manifest.merkle_root_sha256,
        merkle_root_sha512: manifest.merkle_root_sha512,
        custody_manifest_path: manifest_path.display().to_string(),
    })
}

/// Cryptographically verify every file and the dual SHA-256/SHA-512 Merkle roots of a `guap-portable` directory.
pub fn verify_portable_bundle(bundle_dir: &Path) -> anyhow::Result<BundleVerifyReport> {
    let manifest_path = bundle_dir.join("portable-manifest.custody.json");
    let raw = fs::read_to_string(&manifest_path)
        .with_context(|| format!("missing custody manifest at {}", manifest_path.display()))?;
    let manifest: CustodyManifest = serde_json::from_str(&raw)?;

    let mut mismatches = Vec::new();
    let mut sha256_leaves = Vec::with_capacity(manifest.leaves.len());
    let mut sha512_leaves = Vec::with_capacity(manifest.leaves.len());

    for leaf in &manifest.leaves {
        let target = bundle_dir.join(Path::new(&leaf.path));
        match fs::read(&target) {
            Ok(bytes) => {
                let actual_256 = sha256_hex(&bytes);
                let actual_512 = sha512_hex(&bytes);
                if bytes.len() as u64 != leaf.size_bytes || actual_256 != leaf.sha256 || actual_512 != leaf.sha512 {
                    mismatches.push(format!("{}: hash or size mismatch", leaf.path));
                }
                sha256_leaves.push(actual_256);
                sha512_leaves.push(actual_512);
            }
            Err(_) => {
                mismatches.push(format!("{}: file missing", leaf.path));
                sha256_leaves.push(String::new());
                sha512_leaves.push(String::new());
            }
        }
    }

    let actual_merkle_256 = compute_merkle_root_sha256(&sha256_leaves);
    let actual_merkle_512 = compute_merkle_root_sha512(&sha512_leaves);
    if actual_merkle_256 != manifest.merkle_root_sha256 {
        mismatches.push("SHA-256 Merkle root mismatch".to_string());
    }
    if actual_merkle_512 != manifest.merkle_root_sha512 {
        mismatches.push("SHA-512 Merkle root mismatch".to_string());
    }

    Ok(BundleVerifyReport {
        bundle_dir: bundle_dir.display().to_string(),
        verified: mismatches.is_empty(),
        checked_files: manifest.leaves.len(),
        mismatches,
        expected_merkle_sha256: manifest.merkle_root_sha256,
        actual_merkle_sha256: actual_merkle_256,
    })
}
