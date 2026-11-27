//! DeskPort application shell: window, tray, cleanup and the 15 IPC commands.

mod config;
mod db;
mod mcp_server;
mod state;
mod tools;
mod tunnel;
mod updater;

use crate::config::{ServerConfig, TunnelConfigPatch};
use crate::state::{data_dir_from_app, AppState};
use serde::Serialize;
use std::process::Command;
use std::sync::Arc;
use tauri::menu::MenuBuilder;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Emitter, Manager, RunEvent, State, WindowEvent};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::DialogExt;

#[derive(Debug, Serialize)]
struct RevokeResult {
    deleted: usize,
}

#[derive(Debug, Serialize)]
struct InstallResult {
    path: String,
}

// ---------------------------------------------------------------------------
// Commands (names and payloads are the shared frontend contract)
// ---------------------------------------------------------------------------

#[tauri::command]
fn get_state(state: State<'_, Arc<AppState>>) -> state::AppStateSnapshot {
    state.snapshot()
}

#[tauri::command]
fn start_server(state: State<'_, Arc<AppState>>) -> state::AppStateSnapshot {
    let state = state.inner().clone();
    if let Err(err) = start_server_inner(&state) {
        state.push_server_log(err);
    }
    state.snapshot()
}

#[tauri::command]
fn stop_server(state: State<'_, Arc<AppState>>) -> state::AppStateSnapshot {
    let state = state.inner().clone();
    state.server_shutdown();
    state.snapshot()
}

#[tauri::command]
fn restart_server(state: State<'_, Arc<AppState>>) -> state::AppStateSnapshot {
    let state = state.inner().clone();
    state.server_shutdown();
    // Give the old listener a moment to release the port, then retry briefly.
    let mut last_error = None;
    for (attempt, delay_ms) in [180u64, 250, 350].into_iter().enumerate() {
        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
        match start_server_inner(&state) {
            Ok(()) => {
                last_error = None;
                break;
            }
            Err(err) => {
                if attempt == 2 {
                    last_error = Some(err);
                }
            }
        }
    }
    if let Some(err) = last_error {
        state.push_server_log(err);
    }
    state.snapshot()
}

#[tauri::command]
fn start_tunnel(state: State<'_, Arc<AppState>>) -> state::AppStateSnapshot {
    let state = state.inner().clone();
    if let Err(err) = tunnel::start(&state) {
        state.tunnel_mark_error(err);
    }
    state.snapshot()
}

#[tauri::command]
fn stop_tunnel(state: State<'_, Arc<AppState>>) -> state::AppStateSnapshot {
    let state = state.inner().clone();
    tunnel::stop(&state);
    state.snapshot()
}

#[tauri::command]
fn start_all(state: State<'_, Arc<AppState>>) -> state::AppStateSnapshot {
    let state = state.inner().clone();
    start_all_inner(&state);
    state.snapshot()
}

#[tauri::command]
fn stop_all(state: State<'_, Arc<AppState>>) -> state::AppStateSnapshot {
    let state = state.inner().clone();
    stop_all_inner(&state);
    state.snapshot()
}

#[tauri::command]
fn clear_logs(state: State<'_, Arc<AppState>>) -> state::AppStateSnapshot {
    let state = state.inner().clone();
    state.clear_logs();
    state.snapshot()
}

#[tauri::command]
fn save_config(config: ServerConfig, state: State<'_, Arc<AppState>>) -> state::AppStateSnapshot {
    let state = state.inner().clone();
    let mut config = config;
    config.normalize();
    if let Err(err) = config::save_server_config(&state.data_dir, &config) {
        state.push_server_log(format!("Failed to save config.json: {err}"));
    }
    let port_changed = state.config().port != config.port;
    state.replace_config(config);
    if port_changed && state.server_running() {
        state.push_server_log("Port changed. Restart the MCP server to apply it.");
    }
    state.notify();
    state.snapshot()
}

#[tauri::command]
fn save_tunnel_config(
    patch: TunnelConfigPatch,
    state: State<'_, Arc<AppState>>,
) -> state::AppStateSnapshot {
    let state = state.inner().clone();
    let mut current = state.tunnel_config();
    patch.apply(&mut current);
    if let Err(err) = config::save_tunnel_config(&state.data_dir, &current) {
        state.push_tunnel_log(format!("Failed to save tunnel.json: {err}"));
    }
    state.replace_tunnel_config(current);
    state.notify();
    state.snapshot()
}

#[tauri::command]
fn revoke_token(token_id: Option<String>, state: State<'_, Arc<AppState>>) -> RevokeResult {
    let state = state.inner().clone();
    let deleted = match token_id.as_deref() {
        Some(token) if !token.is_empty() => state.db.revoke_token(token).unwrap_or(0),
        _ => state.db.revoke_all().unwrap_or(0),
    };
    state.push_server_log(format!("Revoked {deleted} OAuth token(s)"));
    state.notify();
    RevokeResult { deleted }
}

#[tauri::command]
async fn pick_folder(app: tauri::AppHandle) -> Result<Option<String>, String> {
    let folder =
        tauri::async_runtime::spawn_blocking(move || app.dialog().file().blocking_pick_folder())
            .await
            .map_err(|err| format!("Folder picker failed: {err}"))?;
    Ok(folder
        .and_then(|path| path.into_path().ok())
        .map(|path| path.to_string_lossy().to_string()))
}

#[tauri::command]
async fn install_cloudflared(state: State<'_, Arc<AppState>>) -> Result<InstallResult, String> {
    let state = state.inner().clone();
    let installed =
        tauri::async_runtime::spawn_blocking(move || tunnel::install_cloudflared(&state))
            .await
            .map_err(|err| format!("Install task failed: {err}"))?;
    installed.map(|path| InstallResult {
        path: path.to_string_lossy().to_string(),
    })
}

#[tauri::command]
fn open_data_dir(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    let dir = state.data_dir.clone();
    std::fs::create_dir_all(&dir)
        .map_err(|err| format!("Cannot create {}: {err}", dir.display()))?;

    #[cfg(target_os = "windows")]
    let mut command = {
        let mut command = Command::new("explorer");
        command.arg(&dir);
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = Command::new("open");
        command.arg(&dir);
        command
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut command = Command::new("xdg-open");
        command.arg(&dir);
        command
    };

    command
        .spawn()
        .map(|_| ())
        .map_err(|err| format!("Cannot open {}: {err}", dir.display()))
}

#[tauri::command]
async fn check_update() -> Result<updater::UpdateCheckResult, String> {
    tauri::async_runtime::spawn_blocking(updater::check_for_updates)
        .await
        .map_err(|err| format!("Update check failed: {err}"))?
}

#[tauri::command]
async fn install_update(
    app: tauri::AppHandle,
    state: State<'_, Arc<AppState>>,
    download_url: String,
    asset_name: String,
    install_mode: String,
) -> Result<(), String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        updater::install_update(&app, &state, &download_url, &asset_name, &install_mode)
    })
    .await
    .map_err(|err| format!("Update task failed: {err}"))?
}

#[tauri::command]
fn open_release_page(url: Option<String>) -> Result<(), String> {
    updater::open_release_page(url)
}

// ---------------------------------------------------------------------------
// Internal lifecycle helpers (shared by IPC commands and the tray menu)
// ---------------------------------------------------------------------------

fn start_server_inner(state: &Arc<AppState>) -> Result<(), String> {
    if state.server_running() {
        return Ok(());
    }
    let port = state.config().port;
    let listener = std::net::TcpListener::bind(("127.0.0.1", port)).map_err(|err| {
        format!("Cannot listen on 127.0.0.1:{port}: {err} (is another DeskPort instance running?)")
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("Cannot configure listener: {err}"))?;

    let shutdown = state
        .server_begin_start(port)
        .ok_or_else(|| "MCP server is already running".to_string())?;

    let task_state = Arc::clone(state);
    tauri::async_runtime::spawn(async move {
        let listener = match tokio::net::TcpListener::from_std(listener) {
            Ok(listener) => listener,
            Err(err) => {
                task_state.push_server_log(format!("Cannot adopt TCP listener: {err}"));
                task_state.server_mark_stopped("MCP server failed to start");
                return;
            }
        };
        if let Err(err) = mcp_server::serve(listener, Arc::clone(&task_state), shutdown).await {
            task_state.push_server_log(err);
        }
        task_state.server_mark_stopped("MCP server stopped");
    });

    state.notify();
    Ok(())
}

fn stop_all_inner(state: &Arc<AppState>) {
    tunnel::stop(state);
    state.server_shutdown();
}

fn start_all_inner(state: &Arc<AppState>) {
    if let Err(err) = start_server_inner(state) {
        state.push_server_log(err);
        return;
    }
    if let Err(err) = tunnel::start(state) {
        state.tunnel_mark_error(err);
    }
}

fn mcp_url_for_clipboard(state: &AppState) -> String {
    let snapshot = state.snapshot();
    if snapshot.tunnel.status == "running" {
        if let Some(url) = snapshot.tunnel.mcp_url {
            return url;
        }
    }
    snapshot.server.local_url
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

// ---------------------------------------------------------------------------
// Tray
// ---------------------------------------------------------------------------

fn setup_tray(app: &mut tauri::App, state: Arc<AppState>) -> tauri::Result<()> {
    let menu = MenuBuilder::new(app)
        .text("show", "显示 DeskPort")
        .text("copy-url", "复制 MCP URL")
        .text("toggle", "启动 / 停止全部")
        .text("check-update", "检查更新")
        .separator()
        .text("quit", "退出 DeskPort")
        .build()?;

    let mut builder = TrayIconBuilder::with_id("deskport-tray")
        .tooltip("DeskPort")
        .menu(&menu);
    if let Some(icon) = app.default_window_icon().cloned() {
        builder = builder.icon(icon);
    }

    let menu_state = Arc::clone(&state);
    builder
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "show" => show_main_window(app),
            "copy-url" => {
                let url = mcp_url_for_clipboard(&menu_state);
                let _ = app.clipboard().write_text(url);
            }
            "toggle" => {
                let tunnel_busy =
                    matches!(menu_state.tunnel_status().as_str(), "running" | "starting");
                if menu_state.server_running() || tunnel_busy {
                    stop_all_inner(&menu_state);
                } else {
                    start_all_inner(&menu_state);
                }
            }
            "check-update" => {
                show_main_window(app);
                let _ = app.emit("trigger-check-update", ());
            }
            "quit" => {
                tunnel::stop(&menu_state);
                menu_state.server_shutdown();
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let data_dir = data_dir_from_app(app.handle());
            let state = AppState::open(&data_dir)?;
            app.manage(Arc::clone(&state));

            let handle = app.handle().clone();
            state.set_emitter(Arc::new(move || {
                let _ = handle.emit("state-changed", ());
            }));

            setup_tray(app, Arc::clone(&state))?;

            if let Some(window) = app.get_webview_window("main") {
                let window_handle = window.clone();
                window.on_window_event(move |event| {
                    if let WindowEvent::CloseRequested { api, .. } = event {
                        // Closing the window keeps the MCP server and tunnel
                        // alive in the tray; only "退出 DeskPort" quits.
                        api.prevent_close();
                        let _ = window_handle.hide();
                    }
                });
            }

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            start_all,
            stop_all,
            start_server,
            stop_server,
            restart_server,
            start_tunnel,
            stop_tunnel,
            clear_logs,
            save_config,
            save_tunnel_config,
            revoke_token,
            pick_folder,
            install_cloudflared,
            open_data_dir,
            check_update,
            install_update,
            open_release_page,
        ]);

    let app = builder
        .build(tauri::generate_context!())
        .expect("failed to initialize DeskPort");

    app.run(|app_handle, event| {
        if let RunEvent::Exit = event {
            if let Some(state) = app_handle.try_state::<Arc<AppState>>() {
                let state = state.inner().clone();
                tunnel::stop(&state);
                state.server_shutdown();
            }
        }
    });
}
