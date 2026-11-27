#![forbid(unsafe_code)]

//! Loopback-enforced offline `llama-server` HTTP/1.1 client and 6-meta-tool
//! OpenAI-compatible IT administration agent loop (`#![forbid(unsafe_code)]`,
//! zero external HTTP crate dependencies).

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use guap_mcp::McpServerRegistry;
use guap_router::RouterEngine;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

pub const DEFAULT_LLAMA_ENDPOINT: &str = "http://127.0.0.1:9931/v1/chat/completions";

#[derive(Debug, Error)]
pub enum LlmError {
    #[error("privacy refusal: endpoint '{0}' is not a loopback address (GUAP requires 127.0.0.1 / ::1 / localhost)")]
    NonLoopbackEndpoint(String),

    #[error("invalid endpoint URL '{0}'")]
    InvalidEndpoint(String),

    #[error("local llama-server unreachable at {0}: {1}")]
    Unreachable(String, String),

    #[error("HTTP {0} from local llama-server: {1}")]
    HttpStatus(u16, String),

    #[error("malformed response from local llama-server: {0}")]
    MalformedResponse(String),
}

#[derive(Debug, Clone)]
pub struct LlmClientConfig {
    pub chat_endpoint: String,
    pub model: String,
    pub max_steps: usize,
    pub timeout: Duration,
    /// Pass `chat_template_kwargs: { "enable_thinking": false }` for snappy local tool turns.
    pub fast_mode: bool,
}

impl Default for LlmClientConfig {
    fn default() -> Self {
        Self {
            chat_endpoint: std::env::var("GUAP_LLM_ENDPOINT").unwrap_or_else(|_| DEFAULT_LLAMA_ENDPOINT.to_string()),
            model: std::env::var("GUAP_LLM_MODEL").unwrap_or_else(|_| "auto".to_string()),
            max_steps: 6,
            timeout: Duration::from_secs(90),
            fast_mode: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmServerProbe {
    pub reachable: bool,
    pub endpoint: String,
    pub loaded_models: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallTrace {
    pub step: usize,
    pub tool_name: String,
    pub arguments: Value,
    pub succeeded: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSessionResult {
    pub model: String,
    pub steps_taken: usize,
    pub tool_calls: Vec<ToolCallTrace>,
    pub pending_approval_cards: usize,
    pub answer: String,
}

#[derive(Debug, Clone)]
struct ParsedLoopbackUrl {
    host: String,
    port: u16,
    path: String,
}

fn parse_loopback_http_url(raw: &str) -> Result<ParsedLoopbackUrl, LlmError> {
    let trimmed = raw.trim();
    let rest = trimmed
        .strip_prefix("http://")
        .ok_or_else(|| LlmError::InvalidEndpoint(trimmed.to_string()))?;

    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or_else(|| LlmError::InvalidEndpoint(trimmed.to_string()))?;
        let h = &bracketed[..end];
        let after = &bracketed[end + 1..];
        let p = if let Some(port_str) = after.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|_| LlmError::InvalidEndpoint(trimmed.to_string()))?
        } else {
            80
        };
        (h.to_string(), p)
    } else if let Some((h, p_str)) = authority.rsplit_once(':') {
        let p = p_str
            .parse::<u16>()
            .map_err(|_| LlmError::InvalidEndpoint(trimmed.to_string()))?;
        (h.to_string(), p)
    } else {
        (authority.to_string(), 80)
    };

    let is_loopback = host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1";
    if !is_loopback {
        return Err(LlmError::NonLoopbackEndpoint(trimmed.to_string()));
    }

    Ok(ParsedLoopbackUrl {
        host,
        port,
        path: path.to_string(),
    })
}

fn derive_models_url(chat_endpoint: &str) -> String {
    if let Some(prefix) = chat_endpoint.strip_suffix("/chat/completions") {
        format!("{prefix}/models")
    } else if let Some(prefix) = chat_endpoint.strip_suffix('/') {
        format!("{prefix}/v1/models")
    } else {
        format!("{chat_endpoint}/models")
    }
}

fn http_request(
    method: &str,
    url: &ParsedLoopbackUrl,
    body: Option<&[u8]>,
    timeout: Duration,
) -> Result<(u16, Vec<u8>), LlmError> {
    let addr_spec = if url.host.contains(':') {
        format!("[{}]:{}", url.host, url.port)
    } else {
        format!("{}:{}", url.host, url.port)
    };

    let addrs: Vec<SocketAddr> = addr_spec
        .to_socket_addrs()
        .map_err(|e| LlmError::Unreachable(addr_spec.clone(), e.to_string()))?
        .filter(|a| a.ip().is_loopback())
        .collect();
    let target = addrs
        .first()
        .copied()
        .ok_or_else(|| LlmError::NonLoopbackEndpoint(addr_spec.clone()))?;

    let mut stream = TcpStream::connect_timeout(&target, Duration::from_secs(3).min(timeout))
        .map_err(|e| LlmError::Unreachable(addr_spec.clone(), e.to_string()))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    let payload = body.unwrap_or(&[]);
    let req_head = if body.is_some() {
        format!(
            "{method} {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            url.path,
            url.host,
            url.port,
            payload.len()
        )
    } else {
        format!(
            "{method} {} HTTP/1.1\r\nHost: {}:{}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
            url.path, url.host, url.port
        )
    };

    stream
        .write_all(req_head.as_bytes())
        .and_then(|_| {
            if !payload.is_empty() {
                stream.write_all(payload)
            } else {
                Ok(())
            }
        })
        .and_then(|_| stream.flush())
        .map_err(|e| LlmError::Unreachable(addr_spec.clone(), e.to_string()))?;

    let mut raw = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let mut expected_total: Option<usize> = None;
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&chunk[..n]);
                if expected_total.is_none()
                    && let Some(hdr_end) = raw.windows(4).position(|w| w == b"\r\n\r\n")
                {
                    let hdr_str = String::from_utf8_lossy(&raw[..hdr_end]);
                    for line in hdr_str.lines() {
                        let lower = line.to_ascii_lowercase();
                        if let Some(rest) = lower.strip_prefix("content-length:")
                            && let Ok(cl) = rest.trim().parse::<usize>()
                        {
                            expected_total = Some(hdr_end + 4 + cl);
                            break;
                        }
                    }
                }
                if let Some(total) = expected_total
                    && raw.len() >= total
                {
                    raw.truncate(total);
                    break;
                }
            }
            Err(e) => {
                if let Some(total) = expected_total
                    && raw.len() >= total
                {
                    raw.truncate(total);
                    break;
                }
                return Err(LlmError::Unreachable(addr_spec, e.to_string()));
            }
        }
    }

    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), LlmError> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| LlmError::MalformedResponse("missing HTTP header terminator".to_string()))?;
    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let body_bytes = &raw[header_end + 4..];

    let mut lines = header_str.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| LlmError::MalformedResponse("empty status line".to_string()))?;
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| LlmError::MalformedResponse(format!("invalid status line '{status_line}'")))?;

    let is_chunked = lines.any(|line| {
        let lower = line.to_ascii_lowercase();
        lower.starts_with("transfer-encoding:") && lower.contains("chunked")
    });

    let decoded = if is_chunked {
        decode_chunked_body(body_bytes)?
    } else {
        body_bytes.to_vec()
    };
    Ok((status_code, decoded))
}

fn decode_chunked_body(mut input: &[u8]) -> Result<Vec<u8>, LlmError> {
    let mut out = Vec::new();
    while let Some(crlf) = input.windows(2).position(|w| w == b"\r\n") {
        let len_str = String::from_utf8_lossy(&input[..crlf]);
        let hex_part = len_str.split(';').next().unwrap_or("").trim();
        let chunk_len = usize::from_str_radix(hex_part, 16)
            .map_err(|_| LlmError::MalformedResponse(format!("invalid chunk size '{hex_part}'")))?;
        input = &input[crlf + 2..];
        if chunk_len == 0 {
            break;
        }
        if input.len() < chunk_len {
            return Err(LlmError::MalformedResponse("truncated chunked body".to_string()));
        }
        out.extend_from_slice(&input[..chunk_len]);
        input = &input[chunk_len..];
        if input.starts_with(b"\r\n") {
            input = &input[2..];
        }
    }
    Ok(out)
}

/// Probe whether local `llama-server` is online and list loaded model IDs.
pub fn probe_local_llama_server(chat_endpoint: &str, timeout: Duration) -> LlmServerProbe {
    let models_url = derive_models_url(chat_endpoint);
    let parsed = match parse_loopback_http_url(&models_url) {
        Ok(u) => u,
        Err(e) => {
            return LlmServerProbe {
                reachable: false,
                endpoint: chat_endpoint.to_string(),
                loaded_models: Vec::new(),
                error: Some(e.to_string()),
            };
        }
    };

    match http_request("GET", &parsed, None, timeout) {
        Ok((code, body)) if (200..300).contains(&code) => {
            let mut models = Vec::new();
            if let Ok(val) = serde_json::from_slice::<Value>(&body)
                && let Some(arr) = val.get("data").and_then(Value::as_array)
            {
                for item in arr {
                    if let Some(id) = item.get("id").and_then(Value::as_str) {
                        models.push(id.to_string());
                    }
                }
            }
            LlmServerProbe {
                reachable: true,
                endpoint: chat_endpoint.to_string(),
                loaded_models: models,
                error: None,
            }
        }
        Ok((code, body)) => LlmServerProbe {
            reachable: false,
            endpoint: chat_endpoint.to_string(),
            loaded_models: Vec::new(),
            error: Some(format!("HTTP {code}: {}", String::from_utf8_lossy(&body))),
        },
        Err(err) => LlmServerProbe {
            reachable: false,
            endpoint: chat_endpoint.to_string(),
            loaded_models: Vec::new(),
            error: Some(err.to_string()),
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundledLlamaSpec {
    pub server_bin: PathBuf,
    pub model_gguf: PathBuf,
}

/// Discover a portable bundled `llama-server` + `.gguf` inside `<portable_root>/llm/`.
pub fn discover_bundled_llama_in_dir(portable_root: &Path) -> Option<BundledLlamaSpec> {
    let llm_dir = portable_root.join("llm");
    let bin_name = if cfg!(windows) {
        "llama-server.exe"
    } else {
        "llama-server"
    };
    let server_bin = llm_dir.join(bin_name);
    if !server_bin.is_file() {
        return None;
    }

    let models_dir = llm_dir.join("models");
    let mut ggufs: Vec<PathBuf> = Vec::new();
    for search_dir in [&models_dir, &llm_dir] {
        if let Ok(entries) = fs::read_dir(search_dir) {
            for ent in entries.flatten() {
                let p = ent.path();
                if p.is_file()
                    && p.extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e.eq_ignore_ascii_case("gguf"))
                        .unwrap_or(false)
                {
                    ggufs.push(p);
                }
            }
        }
    }
    ggufs.sort();
    ggufs.dedup();
    if ggufs.is_empty() {
        return None;
    }

    for pref in ["guap-admin", "gemma-4-e4b", "nemotron-3.5-bolt", "qwen3.5"] {
        if let Some(found) = ggufs.iter().find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.to_ascii_lowercase().contains(pref))
                .unwrap_or(false)
        }) {
            return Some(BundledLlamaSpec {
                server_bin,
                model_gguf: found.clone(),
            });
        }
    }

    Some(BundledLlamaSpec {
        server_bin,
        model_gguf: ggufs.remove(0),
    })
}

struct BundledLlamaGuard {
    child: Child,
    endpoint: String,
}

impl Drop for BundledLlamaGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_ephemeral_bundled_llama(
    spec: &BundledLlamaSpec,
    ready_timeout: Duration,
) -> Result<BundledLlamaGuard, LlmError> {
    let port = TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .unwrap_or(19931);
    let endpoint = format!("http://127.0.0.1:{port}/v1/chat/completions");

    let child = Command::new(&spec.server_bin)
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "-m",
            &spec.model_gguf.display().to_string(),
            "-c",
            "16384",
            "--jinja",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| LlmError::Unreachable(endpoint.clone(), format!("failed spawning bundled llama-server: {e}")))?;

    let guard = BundledLlamaGuard {
        child,
        endpoint: endpoint.clone(),
    };
    let deadline = Instant::now() + ready_timeout;
    while Instant::now() < deadline {
        let probe = probe_local_llama_server(&guard.endpoint, Duration::from_millis(800));
        if probe.reachable {
            return Ok(guard);
        }
        thread::sleep(Duration::from_millis(250));
    }
    Err(LlmError::Unreachable(
        endpoint,
        "bundled llama-server did not become ready within timeout".to_string(),
    ))
}

pub struct LocalAdminAgent {
    config: LlmClientConfig,
    router: Arc<RouterEngine>,
    mcp: McpServerRegistry,
}

impl LocalAdminAgent {
    pub fn new(config: LlmClientConfig, router: Arc<RouterEngine>) -> Self {
        let mcp = RouterEngine::build_mcp_registry(Arc::clone(&router));
        Self { config, router, mcp }
    }

    pub fn ask(&self, question: &str) -> Result<AgentSessionResult, LlmError> {
        let mut active_endpoint = self.config.chat_endpoint.clone();
        let mut initial_probe = probe_local_llama_server(&active_endpoint, Duration::from_secs(2));
        let _bundled_guard = if !initial_probe.reachable {
            if let Ok(exe) = env::current_exe()
                && let Some(exe_dir) = exe.parent()
                && let Some(spec) = discover_bundled_llama_in_dir(exe_dir)
            {
                let guard = start_ephemeral_bundled_llama(&spec, Duration::from_secs(30))?;
                active_endpoint = guard.endpoint.clone();
                initial_probe = probe_local_llama_server(&active_endpoint, Duration::from_secs(2));
                Some(guard)
            } else {
                None
            }
        } else {
            None
        };

        let parsed_url = parse_loopback_http_url(&active_endpoint)?;
        let resolved_model = self.select_model_id(&initial_probe);
        let openai_tools = self.build_openai_tools_spec();

        let system_prompt = "You are GUAP, a strictly local, privacy-preserving IT administration assistant running on this machine.\n\
            Follow these rules:\n\
            1. Prefer running `guap_run_runbook` or `guap_host_summary` first for system triage.\n\
            2. Use `guap_find_tools` to discover specific read-only or remediation tools across the 10 GUAP suites before calling `guap_call_readonly` or `guap_stage_fix`.\n\
            3. NEVER claim you modified the system directly: any fix MUST be staged via `guap_stage_fix` with a clear `rationale` and `rollback_hint`, which creates a human Approval Card (`guap approvals approve <card_id>`).\n\
            4. Be concise, cite concrete findings, and list any staged Approval Card IDs.";

        let mut messages: Vec<Value> = vec![
            json!({ "role": "system", "content": system_prompt }),
            json!({ "role": "user", "content": question }),
        ];

        let mut traces = Vec::new();
        let max_steps = self.config.max_steps.clamp(1, 12);

        for step in 1..=max_steps {
            let mut req_body = json!({
                "model": resolved_model,
                "messages": messages,
                "tools": openai_tools,
                "tool_choice": "auto",
                "temperature": 0.1
            });
            if self.config.fast_mode
                && let Some(obj) = req_body.as_object_mut()
            {
                obj.insert("chat_template_kwargs".to_string(), json!({ "enable_thinking": false }));
            }

            let body_bytes = serde_json::to_vec(&req_body).map_err(|e| LlmError::MalformedResponse(e.to_string()))?;
            let (status, resp_bytes) = http_request("POST", &parsed_url, Some(&body_bytes), self.config.timeout)?;
            if !(200..300).contains(&status) {
                return Err(LlmError::HttpStatus(
                    status,
                    String::from_utf8_lossy(&resp_bytes).to_string(),
                ));
            }

            let parsed: Value = serde_json::from_slice(&resp_bytes)
                .map_err(|e| LlmError::MalformedResponse(format!("invalid JSON: {e}")))?;
            let message = parsed
                .get("choices")
                .and_then(Value::as_array)
                .and_then(|c| c.first())
                .and_then(|c| c.get("message"))
                .cloned()
                .ok_or_else(|| LlmError::MalformedResponse("missing choices[0].message".to_string()))?;

            let tool_calls = message
                .get("tool_calls")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            if tool_calls.is_empty() {
                let content = message
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_string();
                let pending = self.router.count_pending_cards().unwrap_or(0);
                return Ok(AgentSessionResult {
                    model: resolved_model,
                    steps_taken: step,
                    tool_calls: traces,
                    pending_approval_cards: pending,
                    answer: content,
                });
            }

            messages.push(message);

            for tc in tool_calls {
                let call_id = tc.get("id").and_then(Value::as_str).unwrap_or("call_1").to_string();
                let fn_obj = tc.get("function").cloned().unwrap_or(Value::Null);
                let fn_name = fn_obj.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                let raw_args = fn_obj.get("arguments").cloned().unwrap_or_else(|| json!("{}"));
                let parsed_args = match raw_args {
                    Value::String(s) => serde_json::from_str::<Value>(&s).unwrap_or_else(|_| json!({})),
                    Value::Object(_) => raw_args,
                    _ => json!({}),
                };

                let (succeeded, tool_output) = match self.mcp.dispatch(&fn_name, &parsed_args) {
                    Ok(val) => (true, val),
                    Err(rpc_err) => (false, json!({ "error": rpc_err.message, "code": rpc_err.code })),
                };

                traces.push(ToolCallTrace {
                    step,
                    tool_name: fn_name.clone(),
                    arguments: parsed_args,
                    succeeded,
                });

                messages.push(json!({
                    "role": "tool",
                    "tool_call_id": call_id,
                    "name": fn_name,
                    "content": serde_json::to_string(&tool_output).unwrap_or_default(),
                }));
            }
        }

        let pending = self.router.count_pending_cards().unwrap_or(0);
        Ok(AgentSessionResult {
            model: resolved_model,
            steps_taken: max_steps,
            tool_calls: traces,
            pending_approval_cards: pending,
            answer:
                "Reached maximum local tool-calling step limit; inspect captured findings and staged Approval Cards."
                    .to_string(),
        })
    }

    fn select_model_id(&self, probe: &LlmServerProbe) -> String {
        if !self.config.model.trim().is_empty() && !self.config.model.eq_ignore_ascii_case("auto") {
            return self.config.model.clone();
        }
        let chat_models: Vec<String> = probe
            .loaded_models
            .iter()
            .filter(|m| !m.to_ascii_lowercase().contains("embed"))
            .cloned()
            .collect();
        for pref in ["guap-admin", "gemma-4-e4b", "nemotron-3.5-bolt", "qwen3.5"] {
            if let Some(found) = chat_models.iter().find(|m| m.to_ascii_lowercase().contains(pref)) {
                return found.clone();
            }
        }
        chat_models
            .into_iter()
            .next()
            .unwrap_or_else(|| "guap-admin-local".to_string())
    }

    fn build_openai_tools_spec(&self) -> Value {
        let mcp_tools = self.mcp.list_tools();
        let mut out = Vec::new();
        if let Some(arr) = mcp_tools.as_array() {
            for item in arr {
                let Some(name) = item.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let desc = item.get("description").and_then(Value::as_str).unwrap_or("");
                let params = item
                    .get("inputSchema")
                    .cloned()
                    .unwrap_or_else(|| json!({ "type": "object", "properties": {} }));
                out.push(json!({
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": desc,
                        "parameters": params,
                    }
                }));
            }
        }
        Value::Array(out)
    }
}

#[cfg(test)]
mod tests {
    use guap_catalog::{CatalogConfig, SuiteCatalog};
    use guap_router::RouterConfig;
    use guap_runbooks::RunbookEngine;

    use super::*;

    #[test]
    fn discovers_bundled_portable_llama_and_prefers_guap_admin_gguf() {
        let tmp = tempfile::tempdir().unwrap();
        let llm_dir = tmp.path().join("llm");
        let models_dir = llm_dir.join("models");
        fs::create_dir_all(&models_dir).unwrap();

        let bin_name = if cfg!(windows) {
            "llama-server.exe"
        } else {
            "llama-server"
        };
        fs::write(llm_dir.join(bin_name), b"stub-llama-server").unwrap();
        fs::write(models_dir.join("other-model-q4.gguf"), b"gguf-1").unwrap();
        fs::write(models_dir.join("guap-admin-v0.1-q4_k_m.gguf"), b"gguf-2").unwrap();

        let spec = discover_bundled_llama_in_dir(tmp.path()).expect("should discover bundled llama");
        assert!(
            spec.model_gguf
                .file_name()
                .unwrap()
                .to_string_lossy()
                .contains("guap-admin")
        );
    }

    #[test]
    fn rejects_any_non_loopback_endpoint() {
        let err = parse_loopback_http_url("http://api.openai.com/v1/chat/completions")
            .expect_err("external host must be blocked");
        assert!(err.to_string().contains("privacy refusal"));

        let err_ip = parse_loopback_http_url("http://192.168.1.50:9931/v1/chat/completions")
            .expect_err("LAN IP must be blocked");
        assert!(err_ip.to_string().contains("privacy refusal"));

        assert!(parse_loopback_http_url("http://127.0.0.1:9931/v1/chat/completions").is_ok());
        assert!(parse_loopback_http_url("http://localhost:9931/v1/chat/completions").is_ok());
    }

    fn drain_http_request(stream: &mut TcpStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut buf = Vec::with_capacity(4096);
        let mut tmp = [0u8; 2048];
        let mut needed: Option<usize> = None;
        loop {
            match stream.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if needed.is_none()
                        && let Some(hdr_end) = buf.windows(4).position(|w| w == b"\r\n\r\n")
                    {
                        let hdr = String::from_utf8_lossy(&buf[..hdr_end]);
                        let cl = hdr
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse::<usize>().ok())
                            })
                            .unwrap_or(0);
                        needed = Some(hdr_end + 4 + cl);
                    }
                    if let Some(total) = needed
                        && buf.len() >= total
                    {
                        break;
                    }
                }
            }
        }
    }

    #[test]
    fn executes_multi_turn_tool_loop_and_stages_approval_card_over_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_handle = thread::spawn(move || {
            // Request 1: GET /v1/models
            if let Ok((mut s1, _)) = listener.accept() {
                drain_http_request(&mut s1);
                let body = serde_json::to_vec(&json!({
                    "data": [{ "id": "mock-gemma-4-e4b" }]
                }))
                .unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = s1.write_all(resp.as_bytes());
                let _ = s1.write_all(&body);
                let _ = s1.flush();
            }

            // Request 2: Turn 1 chat completion -> requests guap_stage_fix
            if let Ok((mut s2, _)) = listener.accept() {
                drain_http_request(&mut s2);
                let body = serde_json::to_vec(&json!({
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": null,
                            "tool_calls": [{
                                "id": "call_stage_1",
                                "type": "function",
                                "function": {
                                    "name": "guap_stage_fix",
                                    "arguments": "{\"tool\":\"sys2rust/service_set_start_mode\",\"arguments\":{\"target\":\"Fax\"},\"rationale\":\"Disable unused Fax service\",\"rollback_hint\":\"Set back to Manual\"}"
                                }
                            }]
                        }
                    }]
                }))
                .unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = s2.write_all(resp.as_bytes());
                let _ = s2.write_all(&body);
                let _ = s2.flush();
            }

            // Request 3: Turn 2 chat completion -> final summary
            if let Ok((mut s3, _)) = listener.accept() {
                drain_http_request(&mut s3);
                let body = serde_json::to_vec(&json!({
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": "I ran a dry-run preview and staged an Approval Card to disable the Fax service."
                        }
                    }]
                }))
                .unwrap();
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                let _ = s3.write_all(resp.as_bytes());
                let _ = s3.write_all(&body);
                let _ = s3.flush();
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        let cat = Arc::new(SuiteCatalog::discover(CatalogConfig::offline()));
        let rb = Arc::new(RunbookEngine::new(Arc::clone(&cat)));
        let router = Arc::new(RouterEngine::new(RouterConfig::ephemeral(tmp.path().to_path_buf()), cat, rb).unwrap());

        let agent = LocalAdminAgent::new(
            LlmClientConfig {
                chat_endpoint: format!("http://127.0.0.1:{port}/v1/chat/completions"),
                model: "auto".to_string(),
                max_steps: 4,
                timeout: Duration::from_secs(5),
                fast_mode: true,
            },
            Arc::clone(&router),
        );

        let result = agent.ask("Please stage disabling the unused Fax service.").unwrap();
        server_handle.join().unwrap();

        assert_eq!(result.model, "mock-gemma-4-e4b");
        assert_eq!(result.steps_taken, 2);
        assert_eq!(result.tool_calls.len(), 1);
        assert!(result.tool_calls[0].succeeded);
        assert_eq!(result.pending_approval_cards, 1);
        assert!(result.answer.contains("Approval Card"));
    }
}
