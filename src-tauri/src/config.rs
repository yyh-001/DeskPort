//! Configuration model, on-disk persistence and small platform helpers.
//!
//! Two files live inside the app data directory:
//! * `config.json`  — user visible [`ServerConfig`]
//! * `tunnel.json`  — [`TunnelConfig`] (contains secrets, `0600` on Unix)

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub const DEFAULT_PORT: u16 = 3334;
pub const DEFAULT_TIMEOUT_SEC: u64 = 60;
pub const DEFAULT_MAX_OUTPUT_CHARS: usize = 20_000;
pub const MIN_TIMEOUT_SEC: u64 = 5;
pub const MAX_TIMEOUT_SEC: u64 = 300;
pub const MIN_OUTPUT_CHARS: usize = 2_000;
pub const MAX_OUTPUT_CHARS: usize = 100_000;

const CONFIG_FILE: &str = "config.json";
const TUNNEL_FILE: &str = "tunnel.json";
const DB_FILE: &str = "oauth.db";

// ---------------------------------------------------------------------------
// Workspace / server configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceItem {
    pub id: String,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ShellKind {
    #[default]
    Auto,
    Bash,
    Powershell,
    Cmd,
    Zsh,
    Sh,
}

impl ShellKind {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(ShellKind::Auto),
            "bash" => Some(ShellKind::Bash),
            "powershell" => Some(ShellKind::Powershell),
            "cmd" => Some(ShellKind::Cmd),
            "zsh" => Some(ShellKind::Zsh),
            "sh" => Some(ShellKind::Sh),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_workspace_id")]
    pub default_workspace: String,
    #[serde(default = "default_true")]
    pub restrict_to_workspaces: bool,
    #[serde(default = "default_workspaces")]
    pub workspaces: Vec<WorkspaceItem>,
    #[serde(default)]
    pub default_shell: ShellKind,
    #[serde(default = "default_timeout_sec")]
    pub default_timeout_sec: u64,
    #[serde(default = "default_max_output_chars")]
    pub max_output_chars: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        let workspaces = default_workspaces();
        Self {
            port: DEFAULT_PORT,
            default_workspace: workspaces
                .first()
                .map(|w| w.id.clone())
                .unwrap_or_else(default_workspace_id),
            restrict_to_workspaces: true,
            workspaces,
            default_shell: ShellKind::Auto,
            default_timeout_sec: DEFAULT_TIMEOUT_SEC,
            max_output_chars: DEFAULT_MAX_OUTPUT_CHARS,
        }
    }
}

impl ServerConfig {
    /// Clamp values and repair structural problems so the rest of the app can
    /// rely on a well-formed configuration.
    pub fn normalize(&mut self) {
        if self.port == 0 {
            self.port = DEFAULT_PORT;
        }
        self.default_timeout_sec = self
            .default_timeout_sec
            .clamp(MIN_TIMEOUT_SEC, MAX_TIMEOUT_SEC);
        self.max_output_chars = self
            .max_output_chars
            .clamp(MIN_OUTPUT_CHARS, MAX_OUTPUT_CHARS);

        let mut seen: Vec<String> = Vec::new();
        let mut workspaces: Vec<WorkspaceItem> = Vec::new();
        for raw in std::mem::take(&mut self.workspaces) {
            let id = raw.id.trim().to_string();
            let path = raw.path.trim().to_string();
            if id.is_empty() || path.is_empty() {
                continue;
            }
            let key = id.to_ascii_lowercase();
            if seen.contains(&key) {
                continue;
            }
            seen.push(key);
            let name = if raw.name.trim().is_empty() {
                id.clone()
            } else {
                raw.name.trim().to_string()
            };
            workspaces.push(WorkspaceItem { id, name, path });
        }
        if workspaces.is_empty() {
            workspaces = default_workspaces();
        }
        self.workspaces = workspaces;

        if !self
            .workspaces
            .iter()
            .any(|w| w.id == self.default_workspace)
        {
            self.default_workspace = self.workspaces[0].id.clone();
        }
    }

    pub fn default_workspace(&self) -> Option<&WorkspaceItem> {
        self.workspaces
            .iter()
            .find(|w| w.id == self.default_workspace)
            .or_else(|| self.workspaces.first())
    }
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

fn default_true() -> bool {
    true
}

fn default_workspace_id() -> String {
    "default".to_string()
}

fn default_timeout_sec() -> u64 {
    DEFAULT_TIMEOUT_SEC
}

fn default_max_output_chars() -> usize {
    DEFAULT_MAX_OUTPUT_CHARS
}

fn default_workspaces() -> Vec<WorkspaceItem> {
    vec![default_workspace_item()]
}

/// First-run workspace: the user's `Desktop` when present, otherwise `$HOME`.
pub fn default_workspace_item() -> WorkspaceItem {
    let home = home_dir();
    let desktop = home.join("Desktop");
    let (path, name) = if desktop.is_dir() {
        (desktop, "Desktop")
    } else {
        (home, "Home")
    };
    WorkspaceItem {
        id: default_workspace_id(),
        name: name.to_string(),
        path: path.to_string_lossy().to_string(),
    }
}

pub fn home_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

// ---------------------------------------------------------------------------
// Tunnel configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum TunnelMode {
    #[default]
    Quick,
    Named,
    Ngrok,
}

impl TunnelMode {
    pub fn as_str(self) -> &'static str {
        match self {
            TunnelMode::Quick => "quick",
            TunnelMode::Named => "named",
            TunnelMode::Ngrok => "ngrok",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct TunnelConfig {
    pub mode: TunnelMode,
    pub cloudflare_token: String,
    pub fixed_url: String,
    pub ngrok_auth_token: String,
    pub ngrok_domain: String,
}

impl TunnelConfig {
    pub fn normalize(&mut self) {
        self.cloudflare_token = self.cloudflare_token.trim().to_string();
        self.ngrok_auth_token = self.ngrok_auth_token.trim().to_string();
        self.fixed_url = self.fixed_url.trim().trim_end_matches('/').to_string();
        self.ngrok_domain = self
            .ngrok_domain
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
    }

    pub fn secrets(&self) -> Vec<&str> {
        let mut out = Vec::new();
        if !self.cloudflare_token.is_empty() {
            out.push(self.cloudflare_token.as_str());
        }
        if !self.ngrok_auth_token.is_empty() {
            out.push(self.ngrok_auth_token.as_str());
        }
        out
    }
}

/// Partial update sent by the UI. Token fields are only honoured when they
/// contain a value, so a blank input never wipes a stored secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TunnelConfigPatch {
    #[serde(default)]
    pub mode: Option<TunnelMode>,
    #[serde(default)]
    pub cloudflare_token: Option<String>,
    #[serde(default)]
    pub fixed_url: Option<String>,
    #[serde(default)]
    pub ngrok_auth_token: Option<String>,
    #[serde(default)]
    pub ngrok_domain: Option<String>,
}

impl TunnelConfigPatch {
    pub fn apply(self, current: &mut TunnelConfig) {
        if let Some(mode) = self.mode {
            current.mode = mode;
        }
        if let Some(token) = self.cloudflare_token {
            let token = token.trim();
            if !token.is_empty() {
                current.cloudflare_token = token.to_string();
            }
        }
        if let Some(token) = self.ngrok_auth_token {
            let token = token.trim();
            if !token.is_empty() {
                current.ngrok_auth_token = token.to_string();
            }
        }
        if let Some(url) = self.fixed_url {
            current.fixed_url = url.trim().trim_end_matches('/').to_string();
        }
        if let Some(domain) = self.ngrok_domain {
            current.ngrok_domain = domain
                .trim()
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_string();
        }
        current.normalize();
    }
}

/// `abcdefgh...wxyz` style preview, never the full secret.
pub fn secret_preview(secret: &str) -> String {
    let chars: Vec<char> = secret.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    if chars.len() <= 12 {
        return format!("{}...", chars.iter().collect::<String>());
    }
    let head: String = chars[..8].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}...{tail}")
}

// ---------------------------------------------------------------------------
// Paths, load & save
// ---------------------------------------------------------------------------

pub fn config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CONFIG_FILE)
}

pub fn tunnel_path(data_dir: &Path) -> PathBuf {
    data_dir.join(TUNNEL_FILE)
}

pub fn db_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DB_FILE)
}

pub fn bin_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("bin")
}

/// Why a JSON file could not be turned into a config value.
enum JsonLoadError {
    /// File does not exist yet — first run, not an error worth reporting.
    NotFound,
    Io(std::io::Error),
    Parse(serde_json::Error),
}

/// Read and parse a JSON config file, tolerating a UTF-8 BOM.
///
/// Windows Notepad writes `EF BB BF` when saving as UTF-8, and `serde_json`
/// rejects that prefix. Stripping it here keeps a hand-edited file working.
fn read_json_stripping_bom<T: serde::de::DeserializeOwned>(
    path: &Path,
) -> std::result::Result<T, JsonLoadError> {
    const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(JsonLoadError::NotFound)
        }
        Err(err) => return Err(JsonLoadError::Io(err)),
    };
    let body = bytes.strip_prefix(UTF8_BOM).unwrap_or(&bytes);
    serde_json::from_slice::<T>(body).map_err(JsonLoadError::Parse)
}

/// One-line warning for a failed load, or `None` when the file is simply absent.
fn load_warning(file: &str, path: &Path, err: &JsonLoadError) -> Option<String> {
    match err {
        JsonLoadError::NotFound => None,
        JsonLoadError::Io(err) => Some(format!(
            "Failed to read {file} ({}): {err}. Falling back to defaults.",
            path.display()
        )),
        JsonLoadError::Parse(err) => {
            let detail = err.to_string().replace(['\n', '\r'], " ");
            let mut detail: String = detail.chars().take(200).collect();
            if detail.chars().count() >= 200 {
                detail.push('…');
            }
            Some(format!(
                "Failed to parse {file} ({}): {detail}. Falling back to defaults — \
                 check the JSON syntax (a UTF-8 BOM is handled, trailing commas are not).",
                path.display()
            ))
        }
    }
}

/// Load `config.json` together with human-readable warnings for the caller to
/// surface (a missing file is not a warning, a broken one is).
pub fn load_server_config(data_dir: &Path) -> (ServerConfig, Vec<String>) {
    let path = config_path(data_dir);
    match read_json_stripping_bom::<ServerConfig>(&path) {
        Ok(mut config) => {
            config.normalize();
            (config, Vec::new())
        }
        Err(err) => {
            let warnings = load_warning(CONFIG_FILE, &path, &err).into_iter().collect();
            let mut config = ServerConfig::default();
            config.normalize();
            (config, warnings)
        }
    }
}

pub fn save_server_config(data_dir: &Path, config: &ServerConfig) -> Result<()> {
    let mut normalized = config.clone();
    normalized.normalize();
    let bytes = serde_json::to_vec_pretty(&normalized).context("serialize config.json")?;
    write_atomic(&config_path(data_dir), &bytes, Some(0o600))
}

/// Tunnel counterpart of [`load_server_config`].
pub fn load_tunnel_config(data_dir: &Path) -> (TunnelConfig, Vec<String>) {
    let path = tunnel_path(data_dir);
    match read_json_stripping_bom::<TunnelConfig>(&path) {
        Ok(mut config) => {
            config.normalize();
            (config, Vec::new())
        }
        Err(err) => {
            let warnings = load_warning(TUNNEL_FILE, &path, &err).into_iter().collect();
            let mut config = TunnelConfig::default();
            config.normalize();
            (config, warnings)
        }
    }
}

pub fn save_tunnel_config(data_dir: &Path, config: &TunnelConfig) -> Result<()> {
    let mut normalized = config.clone();
    normalized.normalize();
    let bytes = serde_json::to_vec_pretty(&normalized).context("serialize tunnel.json")?;
    write_atomic(&tunnel_path(data_dir), &bytes, Some(0o600))
}

fn write_atomic(path: &Path, bytes: &[u8], unix_mode: Option<u32>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create directory {}", parent.display()))?;
    }
    let mut tmp = path.to_path_buf();
    tmp.set_extension(format!("tmp{}", std::process::id()));
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;

    #[cfg(unix)]
    if let Some(mode) = unix_mode {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = unix_mode;

    if fs::rename(&tmp, path).is_err() {
        // Windows cannot rename over an existing file.
        let _ = fs::remove_file(path);
        fs::rename(&tmp, path).with_context(|| format!("replace {}", path.display()))?;
    }
    Ok(())
}

pub fn platform() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "windows"
    }
    #[cfg(target_os = "macos")]
    {
        "macos"
    }
    #[cfg(target_os = "linux")]
    {
        "linux"
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        "unknown"
    }
}

pub fn clock() -> String {
    chrono::Local::now().format("%H:%M:%S").to_string()
}

pub fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[test]
    fn default_config_is_safe() {
        let cfg = ServerConfig::default();
        assert_eq!(cfg.port, 3334);
        assert!(cfg.restrict_to_workspaces);
        assert_eq!(cfg.default_shell, ShellKind::Auto);
        assert_eq!(cfg.default_timeout_sec, 60);
        assert_eq!(cfg.max_output_chars, 20_000);
        assert_eq!(cfg.workspaces.len(), 1);
        assert_eq!(cfg.workspaces[0].id, "default");
        assert!(!cfg.workspaces[0].path.is_empty());
        assert_eq!(cfg.default_workspace, "default");
    }

    #[test]
    fn normalize_clamps_and_repairs() {
        let mut cfg = ServerConfig {
            port: 0,
            default_workspace: "missing".into(),
            restrict_to_workspaces: false,
            workspaces: vec![
                WorkspaceItem {
                    id: "  ".into(),
                    name: "bad".into(),
                    path: "/tmp".into(),
                },
                WorkspaceItem {
                    id: "work".into(),
                    name: "  ".into(),
                    path: "/tmp/work".into(),
                },
                WorkspaceItem {
                    id: "WORK".into(),
                    name: "dupe".into(),
                    path: "/tmp/dupe".into(),
                },
            ],
            default_shell: ShellKind::Powershell,
            default_timeout_sec: 9999,
            max_output_chars: 1,
        };
        cfg.normalize();
        assert_eq!(cfg.port, DEFAULT_PORT);
        assert_eq!(cfg.default_timeout_sec, MAX_TIMEOUT_SEC);
        assert_eq!(cfg.max_output_chars, MIN_OUTPUT_CHARS);
        assert_eq!(cfg.workspaces.len(), 1);
        assert_eq!(cfg.workspaces[0].id, "work");
        assert_eq!(cfg.workspaces[0].name, "work");
        assert_eq!(cfg.default_workspace, "work");
    }

    #[test]
    fn missing_and_corrupt_config_fall_back_to_defaults() {
        let dir = temp_dir();
        let (cfg, _) = load_server_config(dir.path());
        assert_eq!(cfg.port, 3334);
        assert!(cfg.restrict_to_workspaces);

        fs::write(config_path(dir.path()), b"{ not json").unwrap();
        let (cfg, _) = load_server_config(dir.path());
        assert_eq!(cfg.port, 3334);
        assert_eq!(cfg.workspaces.len(), 1);
    }

    #[test]
    fn config_round_trip() {
        let dir = temp_dir();
        let cfg = ServerConfig {
            port: 4123,
            default_shell: ShellKind::Zsh,
            workspaces: vec![WorkspaceItem {
                id: "docs".into(),
                name: "Docs".into(),
                path: "/tmp/docs".into(),
            }],
            default_workspace: "docs".into(),
            ..Default::default()
        };
        save_server_config(dir.path(), &cfg).unwrap();
        let (loaded, _) = load_server_config(dir.path());
        assert_eq!(loaded.port, 4123);
        assert_eq!(loaded.default_shell, ShellKind::Zsh);
        assert_eq!(loaded.workspaces[0].id, "docs");
    }

    #[test]
    fn tunnel_patch_keeps_blank_secrets() {
        let mut cfg = TunnelConfig {
            mode: TunnelMode::Named,
            cloudflare_token: "cf-secret".into(),
            ngrok_auth_token: "ng-secret".into(),
            ..Default::default()
        };
        let patch = TunnelConfigPatch {
            mode: Some(TunnelMode::Ngrok),
            cloudflare_token: Some("   ".into()),
            ngrok_auth_token: None,
            ngrok_domain: Some("https://demo.ngrok-free.app/".into()),
            fixed_url: Some("https://mcp.example.com/".into()),
        };
        patch.apply(&mut cfg);
        assert_eq!(cfg.mode, TunnelMode::Ngrok);
        assert_eq!(cfg.cloudflare_token, "cf-secret");
        assert_eq!(cfg.ngrok_auth_token, "ng-secret");
        assert_eq!(cfg.ngrok_domain, "demo.ngrok-free.app");
        assert_eq!(cfg.fixed_url, "https://mcp.example.com");
    }

    #[test]
    fn secret_preview_never_leaks_full_token() {
        assert_eq!(secret_preview(""), "");
        assert_eq!(secret_preview("short"), "short...");
        let token = "eyJhabcdefghijklmnopqrstuvwxyz3f9a";
        let preview = secret_preview(token);
        assert!(preview.starts_with("eyJhabcd"));
        assert!(preview.ends_with("3f9a"));
        assert!(!preview.contains("klmnop"));
    }

    #[test]
    fn tunnel_config_is_saved_with_owner_only_permissions() {
        let dir = temp_dir();
        let cfg = TunnelConfig {
            cloudflare_token: "abc".into(),
            ..Default::default()
        };
        save_tunnel_config(dir.path(), &cfg).unwrap();
        let (loaded, _) = load_tunnel_config(dir.path());
        assert_eq!(loaded.cloudflare_token, "abc");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(tunnel_path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// Windows Notepad prepends this when saving as UTF-8.
    fn with_utf8_bom(json: &str) -> Vec<u8> {
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(json.as_bytes());
        bytes
    }

    #[test]
    fn bom_config_is_parsed() {
        let dir = temp_dir();
        let json = r#"{
            "port": 4123,
            "defaultWorkspace": "work",
            "restrictToWorkspaces": true,
            "workspaces": [
                { "id": "work", "name": "Work", "path": "/tmp/work" },
                { "id": "docs", "name": "Docs", "path": "/tmp/docs" }
            ],
            "defaultShell": "bash",
            "defaultTimeoutSec": 45,
            "maxOutputChars": 30000
        }"#;
        fs::write(config_path(dir.path()), with_utf8_bom(json)).unwrap();

        let (cfg, warnings) = load_server_config(dir.path());
        assert!(
            warnings.is_empty(),
            "BOM must not be reported: {warnings:?}"
        );
        assert_eq!(cfg.port, 4123);
        assert_eq!(cfg.default_workspace, "work");
        assert_eq!(cfg.default_shell, ShellKind::Bash);
        assert_eq!(cfg.default_timeout_sec, 45);
        assert_eq!(cfg.max_output_chars, 30000);
        assert_eq!(cfg.workspaces.len(), 2);
        assert_eq!(cfg.workspaces[0].id, "work");
        assert_eq!(cfg.workspaces[0].name, "Work");
        assert_eq!(cfg.workspaces[1].id, "docs");
        assert_eq!(cfg.workspaces[1].path, "/tmp/docs");
    }

    #[test]
    fn bom_tunnel_config_is_parsed() {
        let dir = temp_dir();
        let json = r#"{
            "mode": "named",
            "cloudflareToken": "cf-token",
            "fixedUrl": "https://mcp.example.com/"
        }"#;
        fs::write(tunnel_path(dir.path()), with_utf8_bom(json)).unwrap();

        let (cfg, warnings) = load_tunnel_config(dir.path());
        assert!(
            warnings.is_empty(),
            "BOM must not be reported: {warnings:?}"
        );
        assert_eq!(cfg.mode, TunnelMode::Named);
        assert_eq!(cfg.cloudflare_token, "cf-token");
        assert_eq!(cfg.fixed_url, "https://mcp.example.com");
    }

    #[test]
    fn corrupt_config_falls_back_with_warning() {
        let dir = temp_dir();
        fs::write(config_path(dir.path()), b"{ not json").unwrap();

        let (cfg, warnings) = load_server_config(dir.path());
        assert_eq!(cfg.port, DEFAULT_PORT);
        assert_eq!(cfg.workspaces.len(), 1);
        assert_eq!(warnings.len(), 1, "expected exactly one warning");
        assert!(warnings[0].contains("config.json"), "{}", warnings[0]);
        assert!(warnings[0].contains("parse"), "{}", warnings[0]);
    }

    #[test]
    fn missing_config_reports_no_warning() {
        let dir = temp_dir();
        let (cfg, warnings) = load_server_config(dir.path());
        assert_eq!(cfg.port, DEFAULT_PORT);
        assert!(
            warnings.is_empty(),
            "first run is not an error: {warnings:?}"
        );

        let (tunnel, warnings) = load_tunnel_config(dir.path());
        assert_eq!(tunnel.mode, TunnelMode::Quick);
        assert!(
            warnings.is_empty(),
            "first run is not an error: {warnings:?}"
        );
    }
}
