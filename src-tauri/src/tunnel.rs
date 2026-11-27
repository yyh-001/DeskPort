//! Tunnel lifecycle: Cloudflare Quick / Named, ngrok, and the one-click
//! `cloudflared` installer.
//!
//! Secrets are never echoed: every log line passes through [`sanitize`] and is
//! additionally scrubbed by [`crate::state::AppState::push_tunnel_log`].

use crate::config::{self, TunnelMode};
use crate::state::AppState;
use regex::Regex;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

const USER_AGENT: &str = concat!("DeskPort/", env!("CARGO_PKG_VERSION"));
const MAX_DOWNLOAD_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Binaries {
    pub cloudflared: Option<PathBuf>,
    pub ngrok: Option<PathBuf>,
}

pub fn detect_binaries(data_dir: &Path) -> Binaries {
    Binaries {
        cloudflared: find_cloudflared(data_dir),
        ngrok: find_ngrok(data_dir),
    }
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

pub fn find_cloudflared(data_dir: &Path) -> Option<PathBuf> {
    let mut candidates = vec![config::bin_dir(data_dir).join(exe_name("cloudflared"))];
    if cfg!(windows) {
        candidates.extend(
            [
                "C:\\Program Files\\cloudflared\\cloudflared.exe",
                "C:\\Program Files (x86)\\cloudflared\\cloudflared.exe",
                "C:\\ProgramData\\cloudflared\\cloudflared.exe",
            ]
            .iter()
            .map(PathBuf::from),
        );
    } else if cfg!(target_os = "macos") {
        candidates.extend(
            [
                "/opt/homebrew/bin/cloudflared",
                "/usr/local/bin/cloudflared",
            ]
            .iter()
            .map(PathBuf::from),
        );
    } else {
        candidates.extend(
            [
                "/usr/local/bin/cloudflared",
                "/usr/bin/cloudflared",
                "/snap/bin/cloudflared",
            ]
            .iter()
            .map(PathBuf::from),
        );
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .or_else(|| crate::tools::which("cloudflared"))
}

pub fn find_ngrok(data_dir: &Path) -> Option<PathBuf> {
    let mut candidates = vec![config::bin_dir(data_dir).join(exe_name("ngrok"))];
    if cfg!(windows) {
        if let Some(local) = std::env::var_os("LOCALAPPDATA") {
            let local = PathBuf::from(local);
            candidates.push(local.join("Microsoft/WinGet/Links/ngrok.exe"));
            candidates.push(local.join("ngrok/ngrok.exe"));
        }
        candidates.push(PathBuf::from("C:\\Program Files\\ngrok\\ngrok.exe"));
    } else if cfg!(target_os = "macos") {
        candidates.extend(
            ["/opt/homebrew/bin/ngrok", "/usr/local/bin/ngrok"]
                .iter()
                .map(PathBuf::from),
        );
    } else {
        candidates.extend(
            ["/usr/local/bin/ngrok", "/usr/bin/ngrok", "/snap/bin/ngrok"]
                .iter()
                .map(PathBuf::from),
        );
    }
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .or_else(|| crate::tools::which("ngrok"))
}

/// Replace every occurrence of a configured secret with `***`.
pub fn sanitize(text: &str, secrets: &[&str]) -> String {
    let mut out = text.to_string();
    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
        if out.contains(secret) {
            out = out.replace(secret, "***");
        }
    }
    out
}

/// Start the tunnel selected by the persisted configuration.
pub fn start(state: &Arc<AppState>) -> Result<(), String> {
    let current = state.tunnel_status();
    if current == "running" || current == "starting" {
        return Ok(());
    }

    let tunnel_config = state.tunnel_config();
    let mode = tunnel_config.mode;
    let port = state.server_port();
    let binaries = detect_binaries(&state.data_dir);

    let (exe, args, preset_url) = match mode {
        TunnelMode::Quick => {
            let exe = binaries.cloudflared.clone().ok_or_else(|| {
                "cloudflared is not installed. Use the install button to download it.".to_string()
            })?;
            (
                exe,
                vec![
                    "tunnel".to_string(),
                    "--url".to_string(),
                    format!("http://127.0.0.1:{port}"),
                ],
                None,
            )
        }
        TunnelMode::Named => {
            let exe = binaries.cloudflared.clone().ok_or_else(|| {
                "cloudflared is not installed. Use the install button to download it.".to_string()
            })?;
            if tunnel_config.cloudflare_token.is_empty() {
                return Err("Cloudflare Named Tunnel requires a tunnel token".to_string());
            }
            (
                exe,
                vec![
                    "tunnel".to_string(),
                    "run".to_string(),
                    "--token".to_string(),
                    tunnel_config.cloudflare_token.clone(),
                ],
                Some(tunnel_config.fixed_url.clone()).filter(|url| !url.is_empty()),
            )
        }
        TunnelMode::Ngrok => {
            let exe = binaries
                .ngrok
                .clone()
                .ok_or_else(|| "ngrok is not installed or not in PATH".to_string())?;
            if tunnel_config.ngrok_auth_token.is_empty() {
                return Err("ngrok requires an authtoken".to_string());
            }
            if tunnel_config.ngrok_domain.is_empty() {
                return Err("ngrok requires a fixed domain (e.g. demo.ngrok-free.app)".to_string());
            }
            let domain = tunnel_config
                .ngrok_domain
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .to_string();
            (
                exe,
                vec![
                    "http".to_string(),
                    format!("--domain={domain}"),
                    format!("http://127.0.0.1:{port}"),
                    "--log".to_string(),
                    "stdout".to_string(),
                ],
                Some(format!("https://{domain}")),
            )
        }
    };

    state.tunnel_begin_start(mode);
    state.push_tunnel_log(format!(
        "Starting {} tunnel -> http://127.0.0.1:{port} with {}",
        mode.as_str(),
        exe.display()
    ));

    let mut command = Command::new(&exe);
    command
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if mode == TunnelMode::Ngrok {
        command.env("NGROK_AUTHTOKEN", &tunnel_config.ngrok_auth_token);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child: Child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            let message = format!("Failed to start {}: {err}", exe.display());
            state.push_tunnel_log(&message);
            state.tunnel_mark_error(message.clone());
            return Err(message);
        }
    };

    let pid = child.id();
    state.tunnel_set_pid(pid);
    if let Some(url) = preset_url {
        state.tunnel_set_public_url_if_empty(url);
    }

    let secrets = tunnel_config
        .secrets()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if let Some(stdout) = child.stdout.take() {
        spawn_pump(stdout, Arc::clone(state), mode, port, secrets.clone());
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_pump(stderr, Arc::clone(state), mode, port, secrets);
    }

    let monitor_state = Arc::clone(state);
    std::thread::spawn(move || {
        let status = child.wait();
        let code = status.ok().and_then(|status| status.code());
        if code != Some(0) && monitor_state.tunnel_pid() == Some(pid) {
            monitor_state.push_tunnel_log(format!(
                "Tunnel process exited unexpectedly (code {code:?})"
            ));
            monitor_state.tunnel_mark_error(format!(
                "Tunnel process exited with code {}",
                code.map(|code| code.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }
        monitor_state.tunnel_exited(pid, code);
    });

    Ok(())
}

fn spawn_pump<R: Read + Send + 'static>(
    reader: R,
    state: Arc<AppState>,
    mode: TunnelMode,
    port: u16,
    secrets: Vec<String>,
) {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut buffer = Vec::new();
        loop {
            buffer.clear();
            match reader.read_until(b'\n', &mut buffer) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
            let line = String::from_utf8_lossy(&buffer).trim_end().to_string();
            if line.is_empty() {
                continue;
            }
            let secret_refs: Vec<&str> = secrets.iter().map(String::as_str).collect();
            let safe = sanitize(&line, &secret_refs);
            state.push_tunnel_log(&safe);

            match mode {
                TunnelMode::Quick => {
                    if let Some(url) = extract_quick_url(&safe) {
                        state.tunnel_set_public_url_if_empty(url);
                        if state.tunnel_status() != "running" {
                            state.tunnel_mark_running();
                        }
                    }
                }
                TunnelMode::Named => {
                    if let Some(url) = extract_ingress_url(&safe, port) {
                        state.tunnel_set_public_url_if_empty(url);
                        state.tunnel_mark_running();
                    } else if safe.contains("Registered tunnel connection") {
                        state.tunnel_mark_running();
                    }
                }
                TunnelMode::Ngrok => {
                    let lower = safe.to_ascii_lowercase();
                    if lower.contains("started tunnel")
                        || lower.contains("client session established")
                        || lower.contains("url=https://")
                    {
                        state.tunnel_mark_running();
                    }
                }
            }
        }
    });
}

/// `https://random-words.trycloudflare.com` from a Quick Tunnel log line.
pub fn extract_quick_url(line: &str) -> Option<String> {
    let regex = Regex::new(r"https://[a-z0-9-]+\.trycloudflare\.com").ok()?;
    regex.find(line).map(|found| found.as_str().to_string())
}

/// Index of the `}` that closes the object starting at `payload[0]`.
fn matching_json_end(payload: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;
    for (index, ch) in payload.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '"' if !in_string => in_string = true,
            '"' => in_string = false,
            '{' if !in_string => depth += 1,
            '}' if !in_string => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// Cloudflare logs the resolved ingress configuration; pick the hostname whose
/// service points at our local port.
pub fn extract_ingress_url(line: &str, port: u16) -> Option<String> {
    let index = line.find("config=")?;
    let rest = &line[index + 7..];
    let start = rest.find('{')?;
    let payload = &rest[start..];
    let end = matching_json_end(payload)?;
    let unescaped = payload[..=end].replace("\\\"", "\"");
    let value: serde_json::Value = serde_json::from_str(&unescaped).ok()?;
    let ingress = value.get("ingress")?.as_array()?;
    for rule in ingress {
        let Some(hostname) = rule.get("hostname").and_then(|value| value.as_str()) else {
            continue;
        };
        let service = rule
            .get("service")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if service.contains(&format!(":{port}")) && !hostname.is_empty() {
            return Some(format!("https://{hostname}"));
        }
    }
    None
}

pub fn stop(state: &Arc<AppState>) {
    state.push_tunnel_log("Stopping tunnel");
    let pid = state.tunnel_pid();
    if let Some(pid) = pid {
        kill_tree(pid);
    }
    state.tunnel_stop_mark("Tunnel stopped");
}

#[cfg(windows)]
fn kill_tree(pid: u32) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(unix)]
fn kill_tree(pid: u32) {
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
}

// ---------------------------------------------------------------------------
// One-click cloudflared install
// ---------------------------------------------------------------------------

pub fn install_url() -> Result<&'static str, String> {
    let url = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => {
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe"
        }
        ("windows", "aarch64") => {
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-arm64.exe"
        }
        ("macos", "aarch64") => {
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-arm64.tgz"
        }
        ("macos", "x86_64") => {
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz"
        }
        ("linux", "x86_64") => {
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"
        }
        ("linux", "aarch64") => {
            "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"
        }
        (os, arch) => {
            return Err(format!(
                "No official cloudflared build for {os}/{arch}; install it manually."
            ))
        }
    };
    Ok(url)
}

/// Download `cloudflared` into `<dataDir>/bin`. Blocking — call from a worker
/// thread (the Tauri command wraps it in `spawn_blocking`).
pub fn install_cloudflared(state: &Arc<AppState>) -> Result<PathBuf, String> {
    if !state.begin_install() {
        return Err("cloudflared is already being installed".to_string());
    }
    let result = install_cloudflared_inner(state);
    state.end_install();
    match &result {
        Ok(path) => {
            state.push_tunnel_log(format!("cloudflared installed at {}", path.display()));
        }
        Err(err) => {
            state.push_tunnel_log(format!("cloudflared install failed: {err}"));
        }
    }
    result
}

fn install_cloudflared_inner(state: &Arc<AppState>) -> Result<PathBuf, String> {
    let url = install_url()?;
    let bin_dir = config::bin_dir(&state.data_dir);
    fs::create_dir_all(&bin_dir)
        .map_err(|err| format!("Cannot create {}: {err}", bin_dir.display()))?;
    let destination = bin_dir.join(exe_name("cloudflared"));
    let temp = bin_dir.join(format!("cloudflared.download.{}", std::process::id()));

    state.push_tunnel_log(format!("Downloading cloudflared from {url}"));
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(20))
        .timeout_read(Duration::from_secs(180))
        .timeout_write(Duration::from_secs(60))
        .user_agent(USER_AGENT)
        .build();
    let response = agent
        .get(url)
        .call()
        .map_err(|err| format!("Download failed: {err}"))?;
    let reader = response.into_reader().take(MAX_DOWNLOAD_BYTES);

    if url.ends_with(".tgz") {
        extract_cloudflared_from_tgz(reader, &temp)?;
    } else {
        let mut file = fs::File::create(&temp)
            .map_err(|err| format!("Cannot write {}: {err}", temp.display()))?;
        let mut reader = reader;
        std::io::copy(&mut reader, &mut file)
            .map_err(|err| format!("Download interrupted: {err}"))?;
        file.flush()
            .map_err(|err| format!("Cannot flush {}: {err}", temp.display()))?;
    }

    let size = fs::metadata(&temp).map(|meta| meta.len()).unwrap_or(0);
    if size < 1024 {
        let _ = fs::remove_file(&temp);
        return Err("Downloaded cloudflared binary looks empty".to_string());
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&temp, fs::Permissions::from_mode(0o755));
    }

    if fs::rename(&temp, &destination).is_err() {
        let _ = fs::remove_file(&destination);
        fs::rename(&temp, &destination)
            .map_err(|err| format!("Cannot install {}: {err}", destination.display()))?;
    }
    Ok(destination)
}

fn extract_cloudflared_from_tgz(reader: impl Read, destination: &Path) -> Result<(), String> {
    let mut bytes = Vec::new();
    let mut reader = reader;
    reader
        .read_to_end(&mut bytes)
        .map_err(|err| format!("Download interrupted: {err}"))?;
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|err| format!("Invalid cloudflared archive: {err}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|err| format!("Invalid archive entry: {err}"))?;
        let path = entry
            .path()
            .map_err(|err| format!("Invalid archive path: {err}"))?
            .to_path_buf();
        let is_binary = path
            .file_name()
            .map(|name| name == "cloudflared")
            .unwrap_or(false);
        if !is_binary {
            continue;
        }
        let mut file = fs::File::create(destination)
            .map_err(|err| format!("Cannot write {}: {err}", destination.display()))?;
        std::io::copy(&mut entry, &mut file)
            .map_err(|err| format!("Cannot extract cloudflared: {err}"))?;
        file.flush()
            .map_err(|err| format!("Cannot flush {}: {err}", destination.display()))?;
        return Ok(());
    }
    Err("cloudflared binary was not found inside the archive".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_removes_every_secret() {
        let text = "run --token abc123 and NGROK=xyz789 abc123";
        let clean = sanitize(text, &["abc123", "xyz789", ""]);
        assert_eq!(clean, "run --token *** and NGROK=*** ***");
        assert!(!clean.contains("abc123"));
        assert!(!clean.contains("xyz789"));
    }

    #[test]
    fn quick_tunnel_url_is_detected() {
        let line = "2026-02-01T10:00:00Z INF +--------------------------------------------------------------------------------------------+";
        assert!(extract_quick_url(line).is_none());
        let line = "INF |  https://funny-otter-deskport.trycloudflare.com  |";
        assert_eq!(
            extract_quick_url(line).as_deref(),
            Some("https://funny-otter-deskport.trycloudflare.com")
        );
    }

    #[test]
    fn named_tunnel_ingress_is_parsed() {
        let ingress = r#"{"ingress":[{"hostname":"mcp.example.com","service":"http://127.0.0.1:3334"},{"service":"http_status:404"}]}"#;
        let line = format!("INF Updated to new configuration config={ingress} version=1");
        assert_eq!(
            extract_ingress_url(&line, 3334).as_deref(),
            Some("https://mcp.example.com")
        );
        assert!(extract_ingress_url(&line, 9999).is_none());

        let escaped = format!("INF config=\"{}\" version=1", ingress.replace('"', "\\\""));
        assert_eq!(
            extract_ingress_url(&escaped, 3334).as_deref(),
            Some("https://mcp.example.com")
        );
    }

    #[test]
    fn install_url_matches_the_platform() {
        let url = install_url();
        if cfg!(any(
            target_os = "windows",
            target_os = "macos",
            target_os = "linux"
        )) {
            let url = url.expect("supported platform");
            assert!(url.starts_with(
                "https://github.com/cloudflare/cloudflared/releases/latest/download/"
            ));
            match std::env::consts::OS {
                "windows" => assert!(url.ends_with(".exe")),
                "macos" => assert!(url.ends_with(".tgz")),
                _ => assert!(!url.ends_with(".tgz") && !url.ends_with(".exe")),
            }
        }
    }

    #[test]
    fn detection_never_panics_and_prefers_the_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let binaries = detect_binaries(dir.path());
        let local = dir.path().join("bin").join(exe_name("cloudflared"));
        if let Some(found) = binaries.cloudflared {
            assert!(found.is_file());
        }
        assert!(!local.exists());
    }
}
