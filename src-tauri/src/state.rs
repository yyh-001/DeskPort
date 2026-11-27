//! Shared runtime state and the `AppStateSnapshot` contract sent to the UI.
//!
//! All snapshot fields are camelCase because this is the exact JSON the
//! Track B frontend consumes; keep it in sync with the construction sheet.

use crate::config::{self, secret_preview, ServerConfig, TunnelConfig, TunnelMode};
use crate::db::{ClientRecord, OAuthDb, TokenRecord};
use crate::tools::TOOL_NAMES;
use anyhow::{Context, Result};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::oneshot;

const MAX_SERVER_LOGS: usize = 400;
const MAX_TUNNEL_LOGS: usize = 400;
const MAX_LOG_LINE: usize = 6_000;

pub type Emitter = Arc<dyn Fn() + Send + Sync>;

#[derive(Debug, Default)]
pub struct ServerRuntime {
    pub status: String,
    pub started_at: Option<i64>,
    pub port: u16,
    pub logs: Vec<String>,
    pub shutdown: Option<oneshot::Sender<()>>,
}

#[derive(Debug, Default)]
pub struct TunnelRuntime {
    pub mode: TunnelMode,
    pub status: String,
    pub pid: Option<u32>,
    pub public_url: Option<String>,
    pub error: Option<String>,
    pub logs: Vec<String>,
}

impl ServerRuntime {
    fn new(port: u16) -> Self {
        Self {
            status: "stopped".to_string(),
            started_at: None,
            port,
            logs: Vec::new(),
            shutdown: None,
        }
    }
}

impl TunnelRuntime {
    fn new(mode: TunnelMode) -> Self {
        Self {
            mode,
            status: "stopped".to_string(),
            pid: None,
            public_url: None,
            error: None,
            logs: Vec::new(),
        }
    }
}

pub struct AppState {
    pub data_dir: PathBuf,
    pub db: OAuthDb,
    config: Mutex<ServerConfig>,
    tunnel_config: Mutex<TunnelConfig>,
    server: Mutex<ServerRuntime>,
    tunnel: Mutex<TunnelRuntime>,
    installing_cloudflared: AtomicBool,
    emitter: Mutex<Option<Emitter>>,
}

impl AppState {
    pub fn open(data_dir: impl Into<PathBuf>) -> Result<Arc<Self>> {
        let data_dir = data_dir.into();
        fs::create_dir_all(&data_dir)
            .with_context(|| format!("create data dir {}", data_dir.display()))?;
        fs::create_dir_all(config::bin_dir(&data_dir))?;

        let config_path = config::config_path(&data_dir);
        let (config, config_warnings) = config::load_server_config(&data_dir);
        if !config_path.exists() {
            config::save_server_config(&data_dir, &config)?;
        }
        let tunnel_path = config::tunnel_path(&data_dir);
        let (tunnel_config, tunnel_warnings) = config::load_tunnel_config(&data_dir);
        if !tunnel_path.exists() {
            config::save_tunnel_config(&data_dir, &tunnel_config)?;
        }
        let db = OAuthDb::open(&config::db_path(&data_dir))?;

        let state = Arc::new(Self {
            data_dir,
            db,
            config: Mutex::new(config.clone()),
            tunnel_config: Mutex::new(tunnel_config.clone()),
            server: Mutex::new(ServerRuntime::new(config.port)),
            tunnel: Mutex::new(TunnelRuntime::new(tunnel_config.mode)),
            installing_cloudflared: AtomicBool::new(false),
            emitter: Mutex::new(None),
        });

        // A config file that exists but cannot be parsed used to fall back to
        // defaults silently, so edits made in an editor looked ignored. Surface
        // the reason in the log panel; the frontend shows it on first paint.
        for warning in config_warnings {
            state.push_server_log(warning);
        }
        for warning in tunnel_warnings {
            state.push_tunnel_log(warning);
        }

        Ok(state)
    }

    fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
        mutex.lock().unwrap_or_else(|err| err.into_inner())
    }

    pub fn set_emitter(&self, emitter: Emitter) {
        *Self::lock(&self.emitter) = Some(emitter);
    }

    /// Tell the frontend something changed. Never panics if no window exists
    /// (tests, CLI runs).
    pub fn notify(&self) {
        if let Some(emitter) = Self::lock(&self.emitter).clone() {
            emitter();
        }
    }

    pub fn config(&self) -> ServerConfig {
        Self::lock(&self.config).clone()
    }

    pub fn replace_config(&self, mut config: ServerConfig) {
        config.normalize();
        *Self::lock(&self.config) = config;
    }

    pub fn tunnel_config(&self) -> TunnelConfig {
        Self::lock(&self.tunnel_config).clone()
    }

    pub fn replace_tunnel_config(&self, mut config: TunnelConfig) {
        config.normalize();
        let mode = config.mode;
        *Self::lock(&self.tunnel_config) = config;
        Self::lock(&self.tunnel).mode = mode;
    }

    // -- logging ----------------------------------------------------------

    pub fn push_server_log(&self, message: impl AsRef<str>) {
        {
            let mut server = Self::lock(&self.server);
            push_log(&mut server.logs, message.as_ref(), MAX_SERVER_LOGS);
        }
        self.notify();
    }

    pub fn push_tunnel_log(&self, message: impl AsRef<str>) {
        let tunnel_config = self.tunnel_config();
        let secrets = tunnel_config.secrets();
        let sanitized = crate::tunnel::sanitize(message.as_ref(), &secrets);
        {
            let mut tunnel = Self::lock(&self.tunnel);
            push_log(&mut tunnel.logs, &sanitized, MAX_TUNNEL_LOGS);
        }
        self.notify();
    }

    pub fn clear_logs(&self) {
        Self::lock(&self.server).logs.clear();
        Self::lock(&self.tunnel).logs.clear();
        self.notify();
    }

    // -- server -----------------------------------------------------------

    pub fn server_running(&self) -> bool {
        Self::lock(&self.server).status == "running"
    }

    pub fn server_begin_start(&self, port: u16) -> Option<oneshot::Receiver<()>> {
        let mut server = Self::lock(&self.server);
        if server.status == "running" {
            return None;
        }
        let (tx, rx) = oneshot::channel();
        server.shutdown = Some(tx);
        server.port = port;
        server.status = "running".to_string();
        server.started_at = Some(config::now_ms());
        drop(server);
        self.push_server_log(format!("Starting MCP server on http://127.0.0.1:{port}"));
        Some(rx)
    }

    pub fn server_mark_stopped(&self, message: impl AsRef<str>) {
        {
            let mut server = Self::lock(&self.server);
            let was_running = server.status == "running";
            server.status = "stopped".to_string();
            server.started_at = None;
            server.shutdown = None;
            if was_running {
                push_log(&mut server.logs, message.as_ref(), MAX_SERVER_LOGS);
            }
        }
        self.notify();
    }

    pub fn server_shutdown(&self) {
        let sender = Self::lock(&self.server).shutdown.take();
        if let Some(sender) = sender {
            let _ = sender.send(());
        }
        {
            let mut server = Self::lock(&self.server);
            let was_running = server.status == "running";
            server.status = "stopped".to_string();
            server.started_at = None;
            if was_running {
                push_log(&mut server.logs, "MCP server stopped", MAX_SERVER_LOGS);
            }
        }
        self.notify();
    }

    pub fn server_port(&self) -> u16 {
        Self::lock(&self.server).port
    }

    // -- tunnel -----------------------------------------------------------

    pub fn tunnel_status(&self) -> String {
        Self::lock(&self.tunnel).status.clone()
    }

    pub fn tunnel_begin_start(&self, mode: TunnelMode) {
        {
            let mut tunnel = Self::lock(&self.tunnel);
            tunnel.mode = mode;
            tunnel.status = "starting".to_string();
            tunnel.pid = None;
            tunnel.public_url = None;
            tunnel.error = None;
        }
        self.notify();
    }

    pub fn tunnel_set_pid(&self, pid: u32) {
        Self::lock(&self.tunnel).pid = Some(pid);
        self.notify();
    }

    pub fn tunnel_set_public_url_if_empty(&self, url: String) {
        let url = url.trim().trim_end_matches('/').to_string();
        if url.is_empty() {
            return;
        }
        {
            let mut tunnel = Self::lock(&self.tunnel);
            // Late output from an already-stopped process must not revive it.
            if matches!(tunnel.status.as_str(), "stopped" | "error") {
                return;
            }
            if tunnel.public_url.is_none() {
                tunnel.public_url = Some(url);
            }
        }
        self.notify();
    }

    pub fn tunnel_mark_running(&self) {
        {
            let mut tunnel = Self::lock(&self.tunnel);
            if tunnel.status == "stopped" {
                return;
            }
            tunnel.status = "running".to_string();
            tunnel.error = None;
        }
        self.notify();
    }

    pub fn tunnel_mark_error(&self, message: impl AsRef<str>) {
        {
            let mut tunnel = Self::lock(&self.tunnel);
            tunnel.status = "error".to_string();
            tunnel.error = Some(message.as_ref().to_string());
        }
        self.notify();
    }

    pub fn tunnel_pid(&self) -> Option<u32> {
        Self::lock(&self.tunnel).pid
    }

    pub fn tunnel_exited(&self, pid: u32, code: Option<i32>) {
        let mut tunnel = Self::lock(&self.tunnel);
        if tunnel.pid != Some(pid) {
            // A newer tunnel already replaced this process.
            return;
        }
        tunnel.pid = None;
        tunnel.public_url = None;
        if tunnel.error.is_none() {
            tunnel.status = "stopped".to_string();
        } else {
            tunnel.status = "error".to_string();
        }
        let message = match code {
            Some(code) => format!("Tunnel process exited with code {code}"),
            None => "Tunnel process exited".to_string(),
        };
        push_log(&mut tunnel.logs, &message, MAX_TUNNEL_LOGS);
        drop(tunnel);
        self.notify();
    }

    pub fn tunnel_stop_mark(&self, message: impl AsRef<str>) {
        {
            let mut tunnel = Self::lock(&self.tunnel);
            tunnel.status = "stopped".to_string();
            tunnel.pid = None;
            tunnel.public_url = None;
            tunnel.error = None;
            push_log(&mut tunnel.logs, message.as_ref(), MAX_TUNNEL_LOGS);
        }
        self.notify();
    }

    // -- cloudflared installer -------------------------------------------

    pub fn installing_cloudflared(&self) -> bool {
        self.installing_cloudflared.load(Ordering::SeqCst)
    }

    /// Returns false when another install is already running.
    pub fn begin_install(&self) -> bool {
        !self.installing_cloudflared.swap(true, Ordering::SeqCst)
    }

    pub fn end_install(&self) {
        self.installing_cloudflared.store(false, Ordering::SeqCst);
        self.notify();
    }

    // -- snapshot ---------------------------------------------------------

    pub fn snapshot(&self) -> AppStateSnapshot {
        let config = self.config();
        let tunnel_config = self.tunnel_config();
        let port = self.server_port();
        let now = config::now_ms();

        let server = {
            let runtime = Self::lock(&self.server);
            ServerView {
                status: if runtime.status.is_empty() {
                    "stopped".to_string()
                } else {
                    runtime.status.clone()
                },
                started_at: runtime.started_at,
                local_url: format!("http://127.0.0.1:{port}/mcp"),
                logs: runtime.logs.clone(),
            }
        };

        let tunnel = {
            let runtime = Self::lock(&self.tunnel);
            let public_url = runtime.public_url.clone();
            TunnelView {
                mode: tunnel_config.mode,
                status: if runtime.status.is_empty() {
                    "stopped".to_string()
                } else {
                    runtime.status.clone()
                },
                pid: runtime.pid,
                mcp_url: public_url
                    .as_deref()
                    .map(|url| format!("{}/mcp", url.trim_end_matches('/'))),
                public_url,
                error: runtime.error.clone(),
                logs: runtime.logs.clone(),
            }
        };

        let clients = self.db.list_clients().unwrap_or_default();
        let tokens = self.db.list_tokens().unwrap_or_default();

        let binaries = crate::tunnel::detect_binaries(&self.data_dir);

        AppStateSnapshot {
            version: config::VERSION.to_string(),
            platform: config::platform().to_string(),
            data_dir: self.data_dir.to_string_lossy().to_string(),
            tools: TOOL_NAMES.iter().map(|name| name.to_string()).collect(),
            config,
            tunnel_config: TunnelConfigView {
                mode: tunnel_config.mode,
                has_cloudflare_token: !tunnel_config.cloudflare_token.is_empty(),
                cloudflare_token_preview: secret_preview(&tunnel_config.cloudflare_token),
                fixed_url: tunnel_config.fixed_url.clone(),
                has_ngrok_auth_token: !tunnel_config.ngrok_auth_token.is_empty(),
                ngrok_auth_token_preview: secret_preview(&tunnel_config.ngrok_auth_token),
                ngrok_domain: tunnel_config.ngrok_domain.clone(),
            },
            binaries: TunnelBinaries {
                cloudflared_installed: binaries.cloudflared.is_some(),
                cloudflared_path: binaries
                    .cloudflared
                    .as_ref()
                    .map(|path| path.to_string_lossy().to_string()),
                ngrok_installed: binaries.ngrok.is_some(),
                ngrok_path: binaries
                    .ngrok
                    .as_ref()
                    .map(|path| path.to_string_lossy().to_string()),
                installing_cloudflared: self.installing_cloudflared(),
            },
            server,
            tunnel,
            oauth: OAuthView {
                client_count: clients.len(),
                active_token_count: self.db.count_active_tokens(now).unwrap_or_else(|_| {
                    tokens.iter().filter(|token| !token.is_expired(now)).count()
                }),
                clients: clients.iter().map(client_view).collect(),
                tokens: tokens.iter().map(|token| token_view(token, now)).collect(),
            },
            now,
        }
    }
}

fn push_log(buffer: &mut Vec<String>, message: &str, max: usize) {
    for line in message.lines() {
        let clean = line.replace('\r', "");
        let clean = clean.trim_end();
        if clean.is_empty() {
            continue;
        }
        let clean: String = clean.chars().take(MAX_LOG_LINE).collect();
        buffer.push(format!("[{}] {clean}", config::clock()));
    }
    if buffer.len() > max {
        let excess = buffer.len() - max;
        buffer.drain(0..excess);
    }
}

fn client_view(client: &ClientRecord) -> OAuthClientView {
    OAuthClientView {
        client_id: client.client_id.clone(),
        client_name: client.client_name.clone(),
        created_at: client.created_at,
    }
}

fn token_view(token: &TokenRecord, now: i64) -> OAuthTokenView {
    OAuthTokenView {
        token_id: token.token.clone(),
        token_prefix: secret_preview(&token.token),
        token_type: token.token_type.clone(),
        client_id: token.client_id.clone(),
        scope: token.scope.clone(),
        expires_at: token.expires_at,
        created_at: token.created_at,
        expired: token.is_expired(now),
    }
}

// ---------------------------------------------------------------------------
// Snapshot DTOs (camelCase — shared contract with the frontend)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelConfigView {
    pub mode: TunnelMode,
    pub has_cloudflare_token: bool,
    pub cloudflare_token_preview: String,
    pub fixed_url: String,
    pub has_ngrok_auth_token: bool,
    pub ngrok_auth_token_preview: String,
    pub ngrok_domain: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelBinaries {
    pub cloudflared_installed: bool,
    pub cloudflared_path: Option<String>,
    pub ngrok_installed: bool,
    pub ngrok_path: Option<String>,
    pub installing_cloudflared: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerView {
    pub status: String,
    pub started_at: Option<i64>,
    pub local_url: String,
    pub logs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunnelView {
    pub mode: TunnelMode,
    pub status: String,
    pub pid: Option<u32>,
    pub public_url: Option<String>,
    pub mcp_url: Option<String>,
    pub error: Option<String>,
    pub logs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthClientView {
    pub client_id: String,
    pub client_name: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthTokenView {
    pub token_id: String,
    pub token_prefix: String,
    pub token_type: String,
    pub client_id: Option<String>,
    pub scope: String,
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub expired: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OAuthView {
    pub client_count: usize,
    pub active_token_count: usize,
    pub clients: Vec<OAuthClientView>,
    pub tokens: Vec<OAuthTokenView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppStateSnapshot {
    pub version: String,
    pub platform: String,
    pub data_dir: String,
    pub tools: Vec<String>,
    pub config: ServerConfig,
    pub tunnel_config: TunnelConfigView,
    pub binaries: TunnelBinaries,
    pub server: ServerView,
    pub tunnel: TunnelView,
    pub oauth: OAuthView,
    pub now: i64,
}

pub fn data_dir_from_app(app: &tauri::AppHandle) -> PathBuf {
    use tauri::Manager;
    if let Some(custom) = std::env::var_os("DESKPORT_DATA_DIR") {
        return PathBuf::from(custom);
    }
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| config::home_dir().join(".deskport"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn state() -> (tempfile::TempDir, Arc<AppState>) {
        let dir = tempfile::tempdir().unwrap();
        let state = AppState::open(dir.path()).unwrap();
        (dir, state)
    }

    #[test]
    fn snapshot_matches_the_shared_contract() {
        let (_dir, state) = state();
        let value = serde_json::to_value(state.snapshot()).unwrap();
        let object = value.as_object().expect("snapshot object");

        for key in [
            "version",
            "platform",
            "dataDir",
            "tools",
            "config",
            "tunnelConfig",
            "binaries",
            "server",
            "tunnel",
            "oauth",
            "now",
        ] {
            assert!(object.contains_key(key), "missing {key}");
        }
        assert_eq!(value["version"], config::VERSION);
        assert_eq!(value["tools"].as_array().unwrap().len(), 11);
        assert_eq!(value["config"]["restrictToWorkspaces"], true);
        assert_eq!(value["config"]["port"], 3334);
        assert_eq!(value["config"]["defaultShell"], "auto");
        assert_eq!(value["config"]["defaultTimeoutSec"], 60);
        assert_eq!(value["config"]["maxOutputChars"], 20000);
        assert_eq!(value["server"]["status"], "stopped");
        assert_eq!(value["server"]["localUrl"], "http://127.0.0.1:3334/mcp");
        assert_eq!(value["tunnel"]["status"], "stopped");
        assert!(value["tunnel"]["mcpUrl"].is_null());
        assert_eq!(value["tunnelConfig"]["mode"], "quick");
        assert_eq!(value["binaries"]["installingCloudflared"], false);
        assert_eq!(value["oauth"]["clientCount"], 0);
        assert_eq!(value["oauth"]["activeTokenCount"], 0);
        assert!(value["oauth"]["clients"].as_array().unwrap().is_empty());
        assert!(value["oauth"]["tokens"].as_array().unwrap().is_empty());
    }

    #[test]
    fn first_run_persists_a_safe_config() {
        let (dir, _state) = state();
        assert!(config::config_path(dir.path()).exists());
        let raw = fs::read_to_string(config::config_path(dir.path())).unwrap();
        assert!(raw.contains("\"restrictToWorkspaces\": true"));
        assert!(config::tunnel_path(dir.path()).exists());
    }

    #[test]
    fn tunnel_view_builds_mcp_url() {
        let (_dir, state) = state();
        state.tunnel_begin_start(TunnelMode::Quick);
        state.tunnel_set_pid(4242);
        state.tunnel_set_public_url_if_empty("https://demo.trycloudflare.com/".into());
        state.tunnel_mark_running();
        let snapshot = state.snapshot();
        assert_eq!(snapshot.tunnel.status, "running");
        assert_eq!(snapshot.tunnel.pid, Some(4242));
        assert_eq!(
            snapshot.tunnel.mcp_url.as_deref(),
            Some("https://demo.trycloudflare.com/mcp")
        );
        state.tunnel_exited(4242, Some(0));
        let snapshot = state.snapshot();
        assert_eq!(snapshot.tunnel.status, "stopped");
        assert!(snapshot.tunnel.mcp_url.is_none());
    }

    #[test]
    fn stale_tunnel_exit_does_not_clobber_new_process() {
        let (_dir, state) = state();
        state.tunnel_begin_start(TunnelMode::Quick);
        state.tunnel_set_pid(7);
        state.tunnel_mark_running();
        state.tunnel_exited(9, Some(0));
        assert_eq!(state.snapshot().tunnel.status, "running");
    }

    #[test]
    fn token_secrets_are_masked_in_tunnel_logs() {
        let (_dir, state) = state();
        let mut config = state.tunnel_config();
        config.cloudflare_token = "super-secret-cloudflare-token".into();
        state.replace_tunnel_config(config);
        state.push_tunnel_log("starting with --token super-secret-cloudflare-token");
        let snapshot = state.snapshot();
        let joined = snapshot.tunnel.logs.join("\n");
        assert!(!joined.contains("super-secret-cloudflare-token"));
        assert!(joined.contains("***"));
    }

    #[test]
    fn oauth_views_are_rendered_from_the_database() {
        let (_dir, state) = state();
        state
            .db
            .save_client(&ClientRecord {
                client_id: "dp_abc".into(),
                client_secret: Some("secret".into()),
                client_name: "Claude".into(),
                redirect_uris: vec![],
                grant_types: vec![],
                response_types: vec![],
                token_endpoint_auth_method: "none".into(),
                created_at: 1,
            })
            .unwrap();
        state
            .db
            .save_token(&TokenRecord {
                token: "abcdefghijklmnopqrstuvwxyz0123456789".into(),
                token_type: "access".into(),
                client_id: Some("dp_abc".into()),
                scope: "mcp:tools".into(),
                expires_at: Some(config::now_ms() + 60_000),
                created_at: 2,
            })
            .unwrap();

        let snapshot = state.snapshot();
        assert_eq!(snapshot.oauth.client_count, 1);
        assert_eq!(snapshot.oauth.active_token_count, 1);
        assert_eq!(snapshot.oauth.clients[0].client_name, "Claude");
        let token = &snapshot.oauth.tokens[0];
        assert!(token.token_prefix.starts_with("abcdefgh"));
        assert!(token.token_prefix.ends_with("6789"));
        assert!(!token.expired);
    }

    #[test]
    fn every_view_exposes_exactly_the_contract_keys() {
        fn keys(value: &Value) -> Vec<String> {
            let mut keys: Vec<String> =
                value.as_object().expect("object").keys().cloned().collect();
            keys.sort();
            keys
        }

        let (_dir, state) = state();
        state
            .db
            .save_client(&ClientRecord {
                client_id: "dp_contract".into(),
                client_secret: None,
                client_name: "Contract".into(),
                redirect_uris: vec![],
                grant_types: vec![],
                response_types: vec![],
                token_endpoint_auth_method: "none".into(),
                created_at: 1,
            })
            .unwrap();
        state
            .db
            .save_token(&TokenRecord {
                token: "token-abcdefghijklmnop".into(),
                token_type: "access".into(),
                client_id: Some("dp_contract".into()),
                scope: "mcp:tools".into(),
                expires_at: None,
                created_at: 2,
            })
            .unwrap();

        let value = serde_json::to_value(state.snapshot()).unwrap();
        assert_eq!(
            keys(&value),
            vec![
                "binaries",
                "config",
                "dataDir",
                "now",
                "oauth",
                "platform",
                "server",
                "tools",
                "tunnel",
                "tunnelConfig",
                "version"
            ]
        );
        assert_eq!(
            keys(&value["config"]),
            vec![
                "defaultShell",
                "defaultTimeoutSec",
                "defaultWorkspace",
                "maxOutputChars",
                "port",
                "restrictToWorkspaces",
                "workspaces"
            ]
        );
        assert_eq!(
            keys(&value["config"]["workspaces"][0]),
            vec!["id", "name", "path"]
        );
        assert_eq!(
            keys(&value["tunnelConfig"]),
            vec![
                "cloudflareTokenPreview",
                "fixedUrl",
                "hasCloudflareToken",
                "hasNgrokAuthToken",
                "mode",
                "ngrokAuthTokenPreview",
                "ngrokDomain"
            ]
        );
        assert_eq!(
            keys(&value["binaries"]),
            vec![
                "cloudflaredInstalled",
                "cloudflaredPath",
                "installingCloudflared",
                "ngrokInstalled",
                "ngrokPath"
            ]
        );
        assert_eq!(
            keys(&value["server"]),
            vec!["localUrl", "logs", "startedAt", "status"]
        );
        assert_eq!(
            keys(&value["tunnel"]),
            vec![
                "error",
                "logs",
                "mcpUrl",
                "mode",
                "pid",
                "publicUrl",
                "status"
            ]
        );
        assert_eq!(
            keys(&value["oauth"]),
            vec!["activeTokenCount", "clientCount", "clients", "tokens"]
        );
        assert_eq!(
            keys(&value["oauth"]["clients"][0]),
            vec!["clientId", "clientName", "createdAt"]
        );
        assert_eq!(
            keys(&value["oauth"]["tokens"][0]),
            vec![
                "clientId",
                "createdAt",
                "expired",
                "expiresAt",
                "scope",
                "tokenId",
                "tokenPrefix",
                "tokenType"
            ]
        );
    }

    #[test]
    fn track_b_can_read_the_snapshot_shape_as_json() {
        let (_dir, state) = state();
        let value: Value = serde_json::from_str(&serde_json::to_string(&state.snapshot()).unwrap())
            .expect("snapshot round trip");
        assert_eq!(value["config"]["workspaces"].as_array().unwrap().len(), 1);
        assert_eq!(value["config"]["workspaces"][0]["id"], "default");
    }

    #[test]
    fn corrupt_config_warning_reaches_the_log_panel() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(config::config_path(dir.path()), b"{ broken json").unwrap();
        let state = AppState::open(dir.path()).unwrap();
        let logs = state.snapshot().server.logs.join("\n");
        assert!(logs.contains("config.json"), "{logs}");
        assert!(logs.contains("Failed to parse"), "{logs}");
        // A broken file is reported, never silently overwritten.
        let raw = fs::read_to_string(config::config_path(dir.path())).unwrap();
        assert_eq!(raw, "{ broken json");
    }
}
