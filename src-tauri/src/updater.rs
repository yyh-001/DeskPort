//! In-app software update checker and installer backed by GitHub Releases.
//!
//! Uses `ureq` directly against `yyh-001/DeskPort` so updates work for both
//! NSIS/MSI installers and portable executables without requiring a separate
//! signing pipeline.

use crate::config::VERSION;
use crate::state::AppState;
use crate::tunnel;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::Emitter;

const GITHUB_OWNER_REPO: &str = "yyh-001/DeskPort";
const LATEST_RELEASE_API: &str =
    "https://api.github.com/repos/yyh-001/DeskPort/releases/latest";
const RELEASES_URL: &str = "https://github.com/yyh-001/DeskPort/releases";
const ALLOWED_DOWNLOAD_PREFIX: &str =
    "https://github.com/yyh-001/DeskPort/releases/download/";
const ALLOWED_PAGE_PREFIX: &str = "https://github.com/yyh-001/DeskPort/";
const USER_AGENT: &str = concat!("DeskPort/", env!("CARGO_PKG_VERSION"));
const MAX_UPDATE_BYTES: u64 = 256 * 1024 * 1024;
const MIN_UPDATE_BYTES: u64 = 64 * 1024;

static UPDATING: AtomicBool = AtomicBool::new(false);

struct UpdateGuard;

impl UpdateGuard {
    fn acquire() -> Result<Self, String> {
        if UPDATING
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err("已有更新任务正在进行中".to_string());
        }
        Ok(Self)
    }
}

impl Drop for UpdateGuard {
    fn drop(&mut self) {
        UPDATING.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallMode {
    Installer,
    Portable,
    Dmg,
    AppImage,
    Manual,
}

impl InstallMode {
    pub fn as_str(self) -> &'static str {
        match self {
            InstallMode::Installer => "installer",
            InstallMode::Portable => "portable",
            InstallMode::Dmg => "dmg",
            InstallMode::AppImage => "appimage",
            InstallMode::Manual => "manual",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "installer" => InstallMode::Installer,
            "portable" => InstallMode::Portable,
            "dmg" => InstallMode::Dmg,
            "appimage" => InstallMode::AppImage,
            _ => InstallMode::Manual,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateCheckResult {
    pub current_version: String,
    pub latest_version: String,
    pub has_update: bool,
    pub release_name: String,
    pub release_notes: String,
    pub release_url: String,
    pub published_at: Option<String>,
    pub asset_name: Option<String>,
    pub download_url: Option<String>,
    pub asset_size: Option<u64>,
    pub install_mode: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateProgressEvent {
    pub stage: String,
    pub downloaded: u64,
    pub total: Option<u64>,
    pub percent: Option<u8>,
    pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    html_url: Option<String>,
    #[serde(default)]
    published_at: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseAsset {
    pub name: String,
    pub browser_download_url: String,
    #[serde(default)]
    pub size: u64,
}

pub fn parse_semver(raw: &str) -> Option<(u64, u64, u64, bool)> {
    let trimmed = raw.trim().trim_start_matches(['v', 'V']);
    if trimmed.is_empty() {
        return None;
    }
    let without_build = trimmed.split('+').next().unwrap_or(trimmed);
    let (core, has_prerelease) = match without_build.split_once('-') {
        Some((core, pre)) if !pre.is_empty() => (core, true),
        Some((core, _)) => (core, false),
        None => (without_build, false),
    };
    let mut parts = core.split('.');
    let major = parts.next()?.parse::<u64>().ok()?;
    let minor = parts.next()?.parse::<u64>().ok()?;
    let patch = match parts.next() {
        Some(value) => value.parse::<u64>().ok()?,
        None => 0,
    };
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch, has_prerelease))
}

pub fn is_newer_version(current: &str, latest: &str) -> bool {
    let Some((c_maj, c_min, c_pat, c_pre)) = parse_semver(current) else {
        return false;
    };
    let Some((l_maj, l_min, l_pat, l_pre)) = parse_semver(latest) else {
        return false;
    };
    match (l_maj, l_min, l_pat).cmp(&(c_maj, c_min, c_pat)) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => c_pre && !l_pre,
    }
}

pub fn detect_install_mode(
    current_exe: &Path,
    os: &str,
    appimage_env: Option<&str>,
) -> InstallMode {
    match os {
        "windows" => {
            let has_uninstaller = current_exe
                .parent()
                .map(|dir| dir.join("uninstall.exe").is_file())
                .unwrap_or(false);
            if has_uninstaller {
                InstallMode::Installer
            } else {
                InstallMode::Portable
            }
        }
        "macos" => {
            let normalized = current_exe.to_string_lossy().replace('\\', "/");
            if normalized.contains(".app/Contents/MacOS") {
                InstallMode::Dmg
            } else {
                InstallMode::Portable
            }
        }
        "linux" => {
            if appimage_env.is_some_and(|val| !val.trim().is_empty()) {
                InstallMode::AppImage
            } else if current_exe.parent().is_some_and(|dir| {
                let path = dir.to_string_lossy();
                !path.starts_with("/usr") && !path.starts_with("/opt")
            }) {
                InstallMode::Portable
            } else {
                InstallMode::Manual
            }
        }
        _ => InstallMode::Manual,
    }
}

pub fn current_install_mode() -> InstallMode {
    let exe = std::env::current_exe().unwrap_or_default();
    let appimage = std::env::var("APPIMAGE").ok();
    detect_install_mode(&exe, std::env::consts::OS, appimage.as_deref())
}

pub fn select_asset<'a>(
    assets: &'a [ReleaseAsset],
    os: &str,
    arch: &str,
    mode: InstallMode,
) -> Option<&'a ReleaseAsset> {
    let find = |pred: &dyn Fn(&str) -> bool| -> Option<&'a ReleaseAsset> {
        assets.iter().find(|asset| pred(&asset.name))
    };

    match os {
        "windows" => {
            let is_setup = |n: &str| {
                let l = n.to_ascii_lowercase();
                l.ends_with("-setup.exe") && (l.contains("x64") || !l.contains("arm64"))
            };
            let is_msi = |n: &str| n.to_ascii_lowercase().ends_with(".msi");
            let is_portable = |n: &str| n.eq_ignore_ascii_case("deskport_windows_x64.exe");
            match mode {
                InstallMode::Installer => find(&is_setup)
                    .or_else(|| find(&is_msi))
                    .or_else(|| find(&is_portable)),
                _ => find(&is_portable).or_else(|| find(&is_setup)),
            }
        }
        "macos" => {
            let arch_tag = if arch == "aarch64" { "aarch64" } else { "x64" };
            let dmg_suffix = format!("_{arch_tag}.dmg");
            let portable_name = format!("deskport_darwin_{arch_tag}");
            let is_dmg = |n: &str| n.ends_with(&dmg_suffix);
            let is_portable = |n: &str| n == portable_name;
            match mode {
                InstallMode::Dmg => find(&is_dmg).or_else(|| find(&is_portable)),
                _ => find(&is_portable).or_else(|| find(&is_dmg)),
            }
        }
        "linux" => {
            let is_appimage = |n: &str| n.ends_with(".AppImage");
            let is_portable = |n: &str| n == "deskport_linux_x64";
            let is_deb = |n: &str| n.ends_with(".deb");
            match mode {
                InstallMode::AppImage => find(&is_appimage),
                InstallMode::Portable => find(&is_portable).or_else(|| find(&is_appimage)),
                _ => find(&is_deb).or_else(|| find(&is_appimage)),
            }
        }
        _ => None,
    }
}

pub fn validate_download_url(url: &str) -> Result<(), String> {
    let trimmed = url.trim();
    if trimmed.is_empty()
        || !trimmed.starts_with(ALLOWED_DOWNLOAD_PREFIX)
        || trimmed.chars().any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err(format!(
            "下载地址不在 {GITHUB_OWNER_REPO} 官方发布白名单中"
        ));
    }
    Ok(())
}

pub fn validate_release_page_url(url: &str) -> Result<(), String> {
    let trimmed = url.trim();
    if trimmed.is_empty()
        || (!trimmed.starts_with(ALLOWED_PAGE_PREFIX) && trimmed != RELEASES_URL)
        || trimmed.chars().any(|ch| ch.is_control() || ch.is_whitespace())
    {
        return Err("发布页链接无效".to_string());
    }
    Ok(())
}

fn sanitize_asset_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || trimmed.len() > 160
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.contains("..")
        || trimmed.contains('\0')
    {
        return Err("更新文件名不合法".to_string());
    }
    Ok(trimmed.to_string())
}

pub fn check_for_updates() -> Result<UpdateCheckResult, String> {
    let mode = current_install_mode();
    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(15))
        .build();

    let response = agent
        .get(LATEST_RELEASE_API)
        .set("User-Agent", USER_AGENT)
        .set("Accept", "application/vnd.github+json")
        .call();

    let release: GithubRelease = match response {
        Ok(resp) => serde_json::from_reader(resp.into_reader().take(2 * 1024 * 1024))
            .map_err(|err| format!("解析版本信息失败: {err}"))?,
        Err(ureq::Error::Status(404, _)) => {
            return Ok(UpdateCheckResult {
                current_version: VERSION.to_string(),
                latest_version: VERSION.to_string(),
                has_update: false,
                release_name: String::new(),
                release_notes: String::new(),
                release_url: RELEASES_URL.to_string(),
                published_at: None,
                asset_name: None,
                download_url: None,
                asset_size: None,
                install_mode: mode.as_str().to_string(),
            });
        }
        Err(ureq::Error::Status(403 | 429, _)) => {
            return Err("GitHub API 请求频率受限，请稍后再试或前往 Releases 页面查看".to_string());
        }
        Err(ureq::Error::Status(code, _)) => {
            return Err(format!("检查更新失败（HTTP {code}）"));
        }
        Err(ureq::Error::Transport(err)) => {
            return Err(format!("无法连接 GitHub 检查更新: {err}"));
        }
    };

    let latest_version = release
        .tag_name
        .trim()
        .trim_start_matches(['v', 'V'])
        .to_string();
    let has_update = !release.draft && !release.prerelease && is_newer_version(VERSION, &latest_version);

    let asset = select_asset(&release.assets, std::env::consts::OS, std::env::consts::ARCH, mode);
    let release_url = release
        .html_url
        .filter(|url| validate_release_page_url(url).is_ok())
        .unwrap_or_else(|| RELEASES_URL.to_string());

    Ok(UpdateCheckResult {
        current_version: VERSION.to_string(),
        latest_version: if latest_version.is_empty() {
            VERSION.to_string()
        } else {
            latest_version
        },
        has_update,
        release_name: release
            .name
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| release.tag_name.clone()),
        release_notes: release.body.unwrap_or_default(),
        release_url,
        published_at: release.published_at,
        asset_name: asset.map(|a| a.name.clone()),
        download_url: asset.map(|a| a.browser_download_url.clone()),
        asset_size: asset.map(|a| a.size),
        install_mode: mode.as_str().to_string(),
    })
}

fn emit_progress(
    app: &tauri::AppHandle,
    stage: &str,
    downloaded: u64,
    total: Option<u64>,
    message: impl Into<String>,
) {
    let percent = total.and_then(|t| {
        if t > 0 {
            Some(((downloaded.min(t) * 100) / t) as u8)
        } else {
            None
        }
    });
    let _ = app.emit(
        "update-progress",
        UpdateProgressEvent {
            stage: stage.to_string(),
            downloaded,
            total,
            percent,
            message: message.into(),
        },
    );
}

fn verify_binary_header(path: &Path, asset_name: &str) -> Result<(), String> {
    let mut file =
        fs::File::open(path).map_err(|err| format!("无法校验下载文件: {err}"))?;
    let mut magic = [0u8; 8];
    let n = file
        .read(&mut magic)
        .map_err(|err| format!("读取下载文件头失败: {err}"))?;
    if n < 4 {
        return Err("下载文件过小或已损坏".to_string());
    }

    let lower = asset_name.to_ascii_lowercase();
    if lower.ends_with(".exe") && &magic[..2] != b"MZ" {
        return Err("下载的 Windows 可执行文件校验失败".to_string());
    }
    if lower.ends_with(".msi") && magic[..4] != [0xD0, 0xCF, 0x11, 0xE0] {
        return Err("下载的 MSI 安装包校验失败".to_string());
    }
    if cfg!(target_os = "linux")
        && (lower.ends_with(".appimage") || lower.starts_with("deskport_linux"))
        && magic[..4] != [0x7F, b'E', b'L', b'F']
    {
        return Err("下载的 Linux 可执行文件校验失败".to_string());
    }
    Ok(())
}

fn download_to_path(
    app: &tauri::AppHandle,
    download_url: &str,
    destination: &Path,
) -> Result<u64, String> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("无法创建下载目录 {}: {err}", parent.display()))?;
    }

    let agent = ureq::AgentBuilder::new()
        .timeout(Duration::from_secs(300))
        .build();
    let response = agent
        .get(download_url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|err| format!("下载更新失败: {err}"))?;

    let total = response
        .header("Content-Length")
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0 && *v <= MAX_UPDATE_BYTES);

    emit_progress(app, "downloading", 0, total, "正在下载更新…");

    let mut file = fs::File::create(destination)
        .map_err(|err| format!("无法写入更新文件 {}: {err}", destination.display()))?;
    let mut reader = response.into_reader().take(MAX_UPDATE_BYTES + 1);
    let mut buffer = [0u8; 64 * 1024];
    let mut downloaded: u64 = 0;
    let mut last_emit = Instant::now();
    let mut last_percent: Option<u8> = None;

    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|err| format!("下载中断: {err}"))?;
        if read == 0 {
            break;
        }
        downloaded += read as u64;
        if downloaded > MAX_UPDATE_BYTES {
            let _ = fs::remove_file(destination);
            return Err("更新文件超出大小限制".to_string());
        }
        file.write_all(&buffer[..read])
            .map_err(|err| format!("写入更新文件失败: {err}"))?;

        let percent = total.and_then(|t| {
            if t > 0 {
                Some(((downloaded.min(t) * 100) / t) as u8)
            } else {
                None
            }
        });
        let should_emit = last_emit.elapsed() >= Duration::from_millis(150)
            || (percent.is_some() && percent != last_percent);
        if should_emit {
            last_emit = Instant::now();
            last_percent = percent;
            emit_progress(app, "downloading", downloaded, total, "正在下载更新…");
        }
    }
    file.flush()
        .map_err(|err| format!("刷新更新文件失败: {err}"))?;

    if downloaded < MIN_UPDATE_BYTES {
        let _ = fs::remove_file(destination);
        return Err("下载的更新文件不完整".to_string());
    }

    emit_progress(app, "downloading", downloaded, total.or(Some(downloaded)), "下载完成");
    Ok(downloaded)
}

pub fn install_update(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    download_url: &str,
    asset_name: &str,
    install_mode: &str,
) -> Result<(), String> {
    validate_download_url(download_url)?;
    let safe_name = sanitize_asset_name(asset_name)?;
    let _guard = UpdateGuard::acquire()?;
    let mode = InstallMode::parse(install_mode);

    let result = install_update_inner(app, state, download_url, &safe_name, mode);
    if let Err(ref err) = result {
        emit_progress(app, "error", 0, None, err.clone());
    }
    result
}

fn install_update_inner(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    download_url: &str,
    safe_name: &str,
    mode: InstallMode,
) -> Result<(), String> {
    match mode {
        InstallMode::Installer => {
            let dest = std::env::temp_dir().join(format!("deskport-update-{safe_name}"));
            let _ = fs::remove_file(&dest);
            let total = download_to_path(app, download_url, &dest)?;
            verify_binary_header(&dest, safe_name)?;
            emit_progress(app, "installing", total, Some(total), "正在启动安装程序…");
            state.push_server_log(format!("Launching installer update: {safe_name}"));

            tunnel::stop(state);
            state.server_shutdown();

            if safe_name.to_ascii_lowercase().ends_with(".msi") {
                Command::new("msiexec")
                    .arg("/i")
                    .arg(&dest)
                    .spawn()
                    .map_err(|err| format!("无法启动 MSI 安装程序: {err}"))?;
            } else {
                Command::new(&dest)
                    .spawn()
                    .map_err(|err| format!("无法启动安装程序: {err}"))?;
            }

            emit_progress(app, "done", total, Some(total), "安装程序已启动，即将退出当前版本");
            std::thread::sleep(Duration::from_millis(300));
            app.exit(0);
            Ok(())
        }
        InstallMode::Portable | InstallMode::AppImage => {
            let target_path = if cfg!(target_os = "linux") && mode == InstallMode::AppImage {
                std::env::var_os("APPIMAGE")
                    .map(PathBuf::from)
                    .filter(|p| !p.as_os_str().is_empty())
                    .ok_or_else(|| "无法定位当前 AppImage 路径".to_string())?
            } else {
                std::env::current_exe()
                    .map_err(|err| format!("无法获取当前程序路径: {err}"))?
            };

            let temp_path = target_path.with_extension("new");
            let _ = fs::remove_file(&temp_path);
            let total = download_to_path(app, download_url, &temp_path).map_err(|err| {
                format!("{err}（若当前目录无写权限，可点击「查看详情」手动下载）")
            })?;
            verify_binary_header(&temp_path, safe_name)?;

            emit_progress(app, "installing", total, Some(total), "正在替换并重启应用…");
            state.push_server_log(format!("Applying portable update: {safe_name}"));

            apply_self_replace(app, state, &target_path, &temp_path, total)
        }
        InstallMode::Dmg | InstallMode::Manual => {
            if cfg!(target_os = "macos") && safe_name.ends_with(".dmg") {
                let dest = std::env::temp_dir().join(format!("deskport-update-{safe_name}"));
                let _ = fs::remove_file(&dest);
                let total = download_to_path(app, download_url, &dest)?;
                emit_progress(app, "done", total, Some(total), "已下载磁盘映像，正在打开…");
                Command::new("open")
                    .arg(&dest)
                    .spawn()
                    .map_err(|err| format!("无法打开 DMG: {err}"))?;
                Ok(())
            } else {
                open_release_page(Some(RELEASES_URL.to_string()))
            }
        }
    }
}

#[cfg(windows)]
fn apply_self_replace(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    target_path: &Path,
    temp_path: &Path,
    total: u64,
) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let pid = std::process::id();
    let script = r#"
$target = $env:DESKPORT_UPD_TARGET
$newFile = $env:DESKPORT_UPD_NEW
$bakFile = "$target.bak"
$pidToWait = [int]$env:DESKPORT_UPD_PID
for ($i = 0; $i -lt 60; $i++) {
  if (-not (Get-Process -Id $pidToWait -ErrorAction SilentlyContinue)) { break }
  Start-Sleep -Milliseconds 250
}
for ($i = 0; $i -lt 20; $i++) {
  try {
    if (Test-Path -LiteralPath $bakFile) { Remove-Item -LiteralPath $bakFile -Force -ErrorAction SilentlyContinue }
    if (Test-Path -LiteralPath $target) { Move-Item -LiteralPath $target -Destination $bakFile -Force }
    Move-Item -LiteralPath $newFile -Destination $target -Force
    Remove-Item -LiteralPath $bakFile -Force -ErrorAction SilentlyContinue
    Start-Process -FilePath $target
    exit 0
  } catch {
    if ((-not (Test-Path -LiteralPath $target)) -and (Test-Path -LiteralPath $bakFile)) {
      Move-Item -LiteralPath $bakFile -Destination $target -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 250
  }
}
exit 1
"#;

    tunnel::stop(state);
    state.server_shutdown();

    Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .env("DESKPORT_UPD_PID", pid.to_string())
        .env("DESKPORT_UPD_NEW", temp_path)
        .env("DESKPORT_UPD_TARGET", target_path)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|err| format!("无法启动更新替换脚本: {err}"))?;

    emit_progress(app, "done", total, Some(total), "正在重启以完成更新…");
    std::thread::sleep(Duration::from_millis(250));
    app.exit(0);
    Ok(())
}

#[cfg(unix)]
fn apply_self_replace(
    app: &tauri::AppHandle,
    state: &Arc<AppState>,
    target_path: &Path,
    temp_path: &Path,
    total: u64,
) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(temp_path, fs::Permissions::from_mode(0o755))
        .map_err(|err| format!("无法设置执行权限: {err}"))?;
    fs::rename(temp_path, target_path)
        .map_err(|err| format!("无法替换程序文件 {}: {err}", target_path.display()))?;

    tunnel::stop(state);
    state.server_shutdown();

    Command::new(target_path)
        .spawn()
        .map_err(|err| format!("更新已写入但无法自动重启: {err}"))?;

    emit_progress(app, "done", total, Some(total), "正在重启以完成更新…");
    std::thread::sleep(Duration::from_millis(250));
    app.exit(0);
    Ok(())
}

pub fn open_release_page(url: Option<String>) -> Result<(), String> {
    let target = url
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| RELEASES_URL.to_string());
    validate_release_page_url(&target)?;

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        Command::new("cmd")
            .args(["/C", "start", "", &target])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map(|_| ())
            .map_err(|err| format!("无法打开浏览器: {err}"))
    }
    #[cfg(target_os = "macos")]
    {
        Command::new("open")
            .arg(&target)
            .spawn()
            .map(|_| ())
            .map_err(|err| format!("无法打开浏览器: {err}"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        Command::new("xdg-open")
            .arg(&target)
            .spawn()
            .map(|_| ())
            .map_err(|err| format!("无法打开浏览器: {err}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_assets() -> Vec<ReleaseAsset> {
        vec![
            ReleaseAsset {
                name: "DeskPort_0.2.0_x64-setup.exe".into(),
                browser_download_url:
                    "https://github.com/yyh-001/DeskPort/releases/download/v0.2.0/DeskPort_0.2.0_x64-setup.exe"
                        .into(),
                size: 10_000_000,
            },
            ReleaseAsset {
                name: "DeskPort_0.2.0_x64_en-US.msi".into(),
                browser_download_url:
                    "https://github.com/yyh-001/DeskPort/releases/download/v0.2.0/DeskPort_0.2.0_x64_en-US.msi"
                        .into(),
                size: 12_000_000,
            },
            ReleaseAsset {
                name: "deskport_windows_x64.exe".into(),
                browser_download_url:
                    "https://github.com/yyh-001/DeskPort/releases/download/v0.2.0/deskport_windows_x64.exe"
                        .into(),
                size: 7_500_000,
            },
            ReleaseAsset {
                name: "DeskPort_0.2.0_aarch64.dmg".into(),
                browser_download_url:
                    "https://github.com/yyh-001/DeskPort/releases/download/v0.2.0/DeskPort_0.2.0_aarch64.dmg"
                        .into(),
                size: 9_000_000,
            },
            ReleaseAsset {
                name: "DeskPort_0.2.0_x64.dmg".into(),
                browser_download_url:
                    "https://github.com/yyh-001/DeskPort/releases/download/v0.2.0/DeskPort_0.2.0_x64.dmg"
                        .into(),
                size: 9_500_000,
            },
            ReleaseAsset {
                name: "deskport_darwin_aarch64".into(),
                browser_download_url:
                    "https://github.com/yyh-001/DeskPort/releases/download/v0.2.0/deskport_darwin_aarch64"
                        .into(),
                size: 7_000_000,
            },
            ReleaseAsset {
                name: "deskport_darwin_x64".into(),
                browser_download_url:
                    "https://github.com/yyh-001/DeskPort/releases/download/v0.2.0/deskport_darwin_x64"
                        .into(),
                size: 7_100_000,
            },
            ReleaseAsset {
                name: "DeskPort_0.2.0_amd64.AppImage".into(),
                browser_download_url:
                    "https://github.com/yyh-001/DeskPort/releases/download/v0.2.0/DeskPort_0.2.0_amd64.AppImage"
                        .into(),
                size: 80_000_000,
            },
            ReleaseAsset {
                name: "DeskPort_0.2.0_amd64.deb".into(),
                browser_download_url:
                    "https://github.com/yyh-001/DeskPort/releases/download/v0.2.0/DeskPort_0.2.0_amd64.deb"
                        .into(),
                size: 8_000_000,
            },
            ReleaseAsset {
                name: "deskport_linux_x64".into(),
                browser_download_url:
                    "https://github.com/yyh-001/DeskPort/releases/download/v0.2.0/deskport_linux_x64"
                        .into(),
                size: 7_200_000,
            },
        ]
    }

    #[test]
    fn semver_comparison_handles_v_prefix_and_prereleases() {
        assert!(is_newer_version("0.1.0", "0.2.0"));
        assert!(is_newer_version("0.1.0", "v0.1.1"));
        assert!(is_newer_version("0.2.0-beta.1", "0.2.0"));
        assert!(!is_newer_version("0.1.0", "0.1.0"));
        assert!(!is_newer_version("0.2.0", "0.1.9"));
        assert!(!is_newer_version("0.2.0", "0.2.0-rc.1"));
        assert!(!is_newer_version("0.1.0", "not-a-version"));
    }

    #[test]
    fn install_mode_detection_works_across_platforms() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("deskport.exe");
        fs::write(&exe, b"stub").unwrap();
        assert_eq!(
            detect_install_mode(&exe, "windows", None),
            InstallMode::Portable
        );

        fs::write(dir.path().join("uninstall.exe"), b"stub").unwrap();
        assert_eq!(
            detect_install_mode(&exe, "windows", None),
            InstallMode::Installer
        );

        assert_eq!(
            detect_install_mode(
                Path::new("/Applications/DeskPort.app/Contents/MacOS/deskport"),
                "macos",
                None
            ),
            InstallMode::Dmg
        );
        assert_eq!(
            detect_install_mode(Path::new("/Users/me/bin/deskport"), "macos", None),
            InstallMode::Portable
        );
        assert_eq!(
            detect_install_mode(
                Path::new("/tmp/.mount_Desk/usr/bin/deskport"),
                "linux",
                Some("/home/me/DeskPort.AppImage")
            ),
            InstallMode::AppImage
        );
        assert_eq!(
            detect_install_mode(Path::new("/usr/bin/deskport"), "linux", None),
            InstallMode::Manual
        );
    }

    #[test]
    fn asset_selection_matches_platform_and_mode() {
        let assets = sample_assets();
        assert_eq!(
            select_asset(&assets, "windows", "x86_64", InstallMode::Installer)
                .unwrap()
                .name,
            "DeskPort_0.2.0_x64-setup.exe"
        );
        assert_eq!(
            select_asset(&assets, "windows", "x86_64", InstallMode::Portable)
                .unwrap()
                .name,
            "deskport_windows_x64.exe"
        );
        assert_eq!(
            select_asset(&assets, "macos", "aarch64", InstallMode::Dmg)
                .unwrap()
                .name,
            "DeskPort_0.2.0_aarch64.dmg"
        );
        assert_eq!(
            select_asset(&assets, "macos", "x86_64", InstallMode::Portable)
                .unwrap()
                .name,
            "deskport_darwin_x64"
        );
        assert_eq!(
            select_asset(&assets, "linux", "x86_64", InstallMode::AppImage)
                .unwrap()
                .name,
            "DeskPort_0.2.0_amd64.AppImage"
        );
        assert_eq!(
            select_asset(&assets, "linux", "x86_64", InstallMode::Portable)
                .unwrap()
                .name,
            "deskport_linux_x64"
        );
        assert_eq!(
            select_asset(&assets, "linux", "x86_64", InstallMode::Manual)
                .unwrap()
                .name,
            "DeskPort_0.2.0_amd64.deb"
        );
    }

    #[test]
    fn url_and_asset_name_validation_rejects_untrusted_targets() {
        assert!(validate_download_url(
            "https://github.com/yyh-001/DeskPort/releases/download/v0.2.0/deskport_windows_x64.exe"
        )
        .is_ok());
        assert!(validate_download_url("https://evil.example.com/payload.exe").is_err());
        assert!(validate_download_url("http://github.com/yyh-001/DeskPort/releases/download/v0.2.0/a.exe").is_err());
        assert!(validate_release_page_url("https://github.com/yyh-001/DeskPort/releases/tag/v0.2.0").is_ok());
        assert!(validate_release_page_url("javascript:alert(1)").is_err());
        assert!(sanitize_asset_name("../evil.exe").is_err());
        assert!(sanitize_asset_name("deskport_windows_x64.exe").is_ok());
    }
}
