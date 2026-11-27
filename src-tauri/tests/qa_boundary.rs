//! Independent QA acceptance suite for DeskPort v1.0.
//!
//! These tests live outside the library crate and re-include the production
//! modules so the public IPC surface stays untouched. Every test is prefixed
//! `qa_` to keep the added boundary coverage separable from the in-crate unit
//! tests. Business code is never modified by this file.
//!
//! Coverage map (construction sheet section 7):
//! 1. workspace allow-list traversal / prefix spoof / case variants
//! 2. OAuth 2.1 + PKCE discovery, registration, consent XSS, redirect
//!    validation, PKCE failure, replay, refresh and revocation
//! 3. MCP Streamable HTTP auth, protocol flow, all 11 tools, batch, errors
//! 4. tunnel log secret redaction
//! 5. corrupt/missing config safe fallback

#![allow(dead_code)]

#[path = "../src/config.rs"]
mod config;
#[path = "../src/db.rs"]
mod db;
#[path = "../src/mcp_server.rs"]
mod mcp_server;
#[path = "../src/state.rs"]
mod state;
#[path = "../src/tools.rs"]
mod tools;
#[path = "../src/tunnel.rs"]
mod tunnel;

use axum::body::Body;
use axum::http::{header, HeaderMap, Request, StatusCode};
use base64::Engine;
use config::{ServerConfig, WorkspaceItem};
use db::TokenRecord;
use http_body_util::BodyExt;
use mcp_server::router;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use state::AppState;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tower::ServiceExt;

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

/// Data dir + one whitelisted workspace (`<root>/ws`) + an outside sibling
/// (`<root>/outside.txt` and `<root>/ws-evil/secret.txt`) for escape probes.
struct Fixture {
    _root: TempDir,
    _data: TempDir,
    state: Arc<AppState>,
    ws: std::path::PathBuf,
    outside_file: std::path::PathBuf,
    evil_file: std::path::PathBuf,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let data = tempfile::tempdir().unwrap();
    let ws = root.path().join("ws");
    let evil = root.path().join("ws-evil");
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&evil).unwrap();
    let outside_file = root.path().join("outside.txt");
    fs::write(&outside_file, "top secret outside").unwrap();
    let evil_file = evil.join("secret.txt");
    fs::write(&evil_file, "sibling prefix secret").unwrap();

    let mut state = AppState::open(data.path()).unwrap();
    let mut cfg = state.config();
    cfg.workspaces = vec![WorkspaceItem {
        id: "work".into(),
        name: "Work".into(),
        path: ws.to_string_lossy().to_string(),
    }];
    cfg.default_workspace = "work".into();
    cfg.restrict_to_workspaces = true;
    Arc::get_mut(&mut state).unwrap().replace_config(cfg);
    let state = state.clone();

    Fixture {
        _root: root,
        _data: data,
        state,
        ws,
        outside_file,
        evil_file,
    }
}

fn cfg_for(f: &Fixture) -> ServerConfig {
    f.state.config()
}

struct HttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl HttpResponse {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

async fn send(
    state: &Arc<AppState>,
    method: &str,
    path: &str,
    content_type: &str,
    body: &str,
    extra: &[(&str, &str)],
) -> HttpResponse {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::HOST, "127.0.0.1:3334");
    if !content_type.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    for (key, value) in extra {
        builder = builder.header(*key, *value);
    }
    let request = builder.body(Body::from(body.to_string())).unwrap();
    let response = router(Arc::clone(state)).oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    HttpResponse {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).to_string(),
    }
}

async fn rpc(state: &Arc<AppState>, body: Value, token: Option<&str>) -> HttpResponse {
    let owned;
    let mut extra: Vec<(&str, &str)> = Vec::new();
    if let Some(token) = token {
        owned = format!("Bearer {token}");
        extra.push((header::AUTHORIZATION.as_str(), owned.as_str()));
    }
    send(
        state,
        "POST",
        "/mcp",
        "application/json",
        &body.to_string(),
        &extra,
    )
    .await
}

fn seed_access_token(state: &AppState, token: &str, expires_at: i64) {
    state
        .db
        .save_token(&TokenRecord {
            token: token.to_string(),
            token_type: "access".into(),
            client_id: Some("dp_qa".into()),
            scope: "mcp:tools".into(),
            expires_at: Some(expires_at),
            created_at: config::now_ms(),
        })
        .unwrap();
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| {
            format!(
                "{key}={}",
                url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>()
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

async fn register_client(state: &Arc<AppState>, name: &str) -> String {
    let response = send(
        state,
        "POST",
        "/oauth/register",
        "application/json",
        &json!({"client_name": name, "redirect_uris": ["http://127.0.0.1:53682/callback"]})
            .to_string(),
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.body);
    response.json()["client_id"].as_str().unwrap().to_string()
}

struct Tokens {
    access: String,
    refresh: String,
}

/// Runs the complete registration -> consent -> PKCE exchange flow.
async fn full_flow(state: &Arc<AppState>) -> Tokens {
    let client_id = register_client(state, "QA Client").await;
    let verifier = "qa-verifier-abcdefghijklmnopqrstuvwxyz-0123456789";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let redirect_uri = "http://127.0.0.1:53682/callback";

    let approval = send(
        state,
        "POST",
        "/oauth/authorize",
        "application/x-www-form-urlencoded",
        &form(&[
            ("decision", "approve"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("state", "qa-state"),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("scope", "mcp:tools"),
        ]),
        &[],
    )
    .await;
    assert_eq!(approval.status, StatusCode::FOUND, "{}", approval.body);
    let location = approval.headers[header::LOCATION]
        .to_str()
        .unwrap()
        .to_string();
    assert!(location.starts_with(redirect_uri), "{location}");
    let parsed = url::Url::parse(&location).unwrap();
    let query: std::collections::HashMap<String, String> =
        parsed.query_pairs().into_owned().collect();
    assert_eq!(query.get("state").map(String::as_str), Some("qa-state"));
    let code = query.get("code").cloned().expect("auth code");

    let granted = send(
        state,
        "POST",
        "/oauth/token",
        "application/x-www-form-urlencoded",
        &form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect_uri),
            ("client_id", &client_id),
            ("code_verifier", verifier),
        ]),
        &[],
    )
    .await;
    assert_eq!(granted.status, StatusCode::OK, "{}", granted.body);
    let body = granted.json();
    Tokens {
        access: body["access_token"].as_str().unwrap().to_string(),
        refresh: body["refresh_token"].as_str().unwrap().to_string(),
    }
}

fn tool_text(response: &HttpResponse) -> String {
    response.json()["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn tool_is_error(response: &HttpResponse) -> bool {
    response.json()["result"]["isError"] == Value::Bool(true)
}

// ---------------------------------------------------------------------------
// 1. Workspace allow-list / path traversal
// ---------------------------------------------------------------------------

#[test]
fn qa_path_whitelist_blocks_traversal_and_prefix_spoof() {
    let f = fixture();
    let cfg = cfg_for(&f);

    for raw in [
        "../outside.txt",
        f.outside_file.to_string_lossy().as_ref(),
        "../ws-evil/secret.txt",
        f.evil_file.to_string_lossy().as_ref(),
        "missing/../../outside.txt",
    ] {
        let err = tools::resolve_path(&cfg, None, raw).unwrap_err();
        assert!(
            err.contains("Access denied"),
            "escape {raw} was not denied: {err}"
        );
    }

    let legit = tools::resolve_path(&cfg, Some("work"), "nested/deeper/file.txt").unwrap();
    let canonical_ws = f.ws.canonicalize().unwrap();
    assert!(
        tools::is_within(&canonical_ws, &legit),
        "legit sub path resolved outside: {}",
        legit.display()
    );
}

#[cfg(windows)]
#[test]
fn qa_path_whitelist_windows_case_and_separator_variants() {
    let f = fixture();
    let cfg = cfg_for(&f);

    // Windows allow-listing must ignore case for a valid sub path.
    let upper = f.ws.to_string_lossy().to_uppercase();
    let probe = Path::new(&upper).join("Case.txt");
    assert!(
        tools::resolve_path(&cfg, None, &probe.to_string_lossy()).is_ok(),
        "case-variant of a whitelisted root must be accepted on Windows"
    );

    // ... but must not let a case variant of a sibling prefix through.
    let evil_upper = f.evil_file.to_string_lossy().to_uppercase();
    let err = tools::resolve_path(&cfg, None, &evil_upper).unwrap_err();
    assert!(err.contains("Access denied"), "{err}");

    // Forward slashes and mixed case inside the root are fine.
    let mixed = format!(
        "{}/Mixed/Case.txt",
        f.ws.to_string_lossy().replace('\\', "/")
    );
    assert!(tools::resolve_path(&cfg, None, &mixed).is_ok(), "{mixed}");
}

#[test]
fn qa_tools_path_guard_end_to_end() {
    let f = fixture();
    let cfg = cfg_for(&f);

    let denied = tools::call(&cfg, "read_file", &json!({"filePath": "../outside.txt"}));
    assert!(denied.is_error, "{}", denied.text);
    assert!(denied.text.contains("Access denied"), "{}", denied.text);

    let denied_abs = tools::call(
        &cfg,
        "read_file",
        &json!({"filePath": f.outside_file.to_string_lossy()}),
    );
    assert!(denied_abs.is_error, "{}", denied_abs.text);

    let denied_prefix = tools::call(
        &cfg,
        "read_file",
        &json!({"filePath": f.evil_file.to_string_lossy()}),
    );
    assert!(denied_prefix.is_error, "{}", denied_prefix.text);

    // Legit sub path still works end-to-end.
    let written = tools::call(
        &cfg,
        "write_file",
        &json!({"filePath": "nested/inside.txt", "content": "inside only"}),
    );
    assert!(!written.is_error, "{}", written.text);
    let read = tools::call(&cfg, "read_file", &json!({"filePath": "nested/inside.txt"}));
    assert!(!read.is_error, "{}", read.text);
    assert!(read.text.contains("inside only"));
}

#[test]
fn qa_path_whitelist_disabled_allows_outside_path() {
    let f = fixture();
    let mut cfg = cfg_for(&f);
    cfg.restrict_to_workspaces = false;
    let resolved =
        tools::resolve_path(&cfg, None, f.outside_file.to_string_lossy().as_ref()).unwrap();
    assert!(resolved.ends_with("outside.txt"));
}

// ---------------------------------------------------------------------------
// 2. OAuth 2.1 + PKCE
// ---------------------------------------------------------------------------

#[tokio::test]
async fn qa_oauth_discovery_documents_are_rfc_compliant() {
    let f = fixture();
    let state = Arc::clone(&f.state);

    let resource = send(
        &state,
        "GET",
        "/.well-known/oauth-protected-resource",
        "",
        "",
        &[],
    )
    .await;
    assert_eq!(resource.status, StatusCode::OK);
    let body = resource.json();
    assert_eq!(body["resource"], "http://127.0.0.1:3334/mcp");
    assert_eq!(body["resource_name"], "DeskPort");
    assert_eq!(body["authorization_servers"][0], "http://127.0.0.1:3334");
    assert_eq!(body["bearer_methods_supported"][0], "header");
    assert_eq!(body["scopes_supported"][0], "mcp:tools");

    let nested = send(
        &state,
        "GET",
        "/.well-known/oauth-protected-resource/mcp",
        "",
        "",
        &[],
    )
    .await;
    assert_eq!(nested.status, StatusCode::OK);
    assert_eq!(nested.json()["resource"], "http://127.0.0.1:3334/mcp");

    let metadata = send(
        &state,
        "GET",
        "/.well-known/oauth-authorization-server",
        "",
        "",
        &[],
    )
    .await;
    assert_eq!(metadata.status, StatusCode::OK);
    let body = metadata.json();
    assert_eq!(
        body["authorization_endpoint"],
        "http://127.0.0.1:3334/oauth/authorize"
    );
    assert_eq!(body["token_endpoint"], "http://127.0.0.1:3334/oauth/token");
    assert_eq!(
        body["registration_endpoint"],
        "http://127.0.0.1:3334/oauth/register"
    );
    assert_eq!(
        body["code_challenge_methods_supported"],
        json!(["S256", "plain"])
    );
    assert_eq!(
        body["grant_types_supported"],
        json!(["authorization_code", "refresh_token"])
    );
}

#[tokio::test]
async fn qa_oauth_registration_issues_unique_dp_credentials() {
    let f = fixture();
    let state = Arc::clone(&f.state);
    let first = register_client(&state, "Claude").await;
    let second = register_client(&state, "Cursor").await;
    assert!(first.starts_with("dp_"));
    assert_eq!(first.len(), 27);
    assert_ne!(first, second);

    let clients = state.snapshot().oauth;
    assert_eq!(clients.client_count, 2);
    assert!(clients
        .clients
        .iter()
        .all(|c| c.client_id.starts_with("dp_")));
}

#[tokio::test]
async fn qa_oauth_authorize_page_escapes_xss_payloads() {
    let f = fixture();
    let state = Arc::clone(&f.state);
    let malicious = "<script>alert(\"xss\")</script><img src=x onerror=alert(1)>";
    let client_id = register_client(&state, malicious).await;

    let path = format!(
        "/oauth/authorize?client_id={client_id}&redirect_uri=http%3A%2F%2F127.0.0.1%3A53682%2Fcallback&state=%3C%2Fscript%3E&code_challenge=abc&code_challenge_method=S256&scope=%3Cb%3Eevil%3C%2Fb%3E"
    );
    let page = send(&state, "GET", &path, "", "", &[]).await;
    assert_eq!(page.status, StatusCode::OK);
    assert_eq!(
        page.headers[header::CONTENT_TYPE].to_str().unwrap(),
        "text/html; charset=utf-8"
    );
    assert!(page
        .body
        .contains("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"));
    assert!(!page.body.contains("<script>alert"));
    assert!(!page.body.contains("<img src=x onerror"));
    assert!(page.body.contains("&lt;b&gt;evil&lt;/b&gt;"));
    assert!(page.body.contains("Work"));
    assert!(page.body.contains("已开启"));
    assert!(page.body.contains("允许连接"));
    assert_eq!(page.headers["x-content-type-options"], "nosniff");
    assert!(page.headers.contains_key("content-security-policy"));
}

#[tokio::test]
async fn qa_oauth_rejects_scriptable_redirect_uris() {
    let f = fixture();
    let state = Arc::clone(&f.state);
    let client_id = register_client(&state, "Evil").await;

    for bad in [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "file:///C:/Windows/win.ini",
        "vbscript:msgbox(1)",
    ] {
        let get = send(
            &state,
            "GET",
            &format!(
                "/oauth/authorize?client_id={client_id}&redirect_uri={}",
                url::form_urlencoded::byte_serialize(bad.as_bytes()).collect::<String>()
            ),
            "",
            "",
            &[],
        )
        .await;
        assert_eq!(get.status, StatusCode::BAD_REQUEST, "GET {bad}");
        assert!(get.headers.get(header::LOCATION).is_none(), "GET {bad}");

        let post = send(
            &state,
            "POST",
            "/oauth/authorize",
            "application/x-www-form-urlencoded",
            &form(&[
                ("decision", "approve"),
                ("client_id", &client_id),
                ("redirect_uri", bad),
            ]),
            &[],
        )
        .await;
        assert_eq!(post.status, StatusCode::BAD_REQUEST, "POST {bad}");
        assert!(post.headers.get(header::LOCATION).is_none(), "POST {bad}");
    }
}

#[tokio::test]
async fn qa_oauth_pkce_wrong_verifier_replay_and_refresh() {
    let f = fixture();
    let state = Arc::clone(&f.state);
    let client_id = register_client(&state, "PKCE Client").await;
    let verifier = "qa-verifier-wrong-and-right-check-0123456789";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let redirect_uri = "http://127.0.0.1:53682/callback";

    let approval = send(
        &state,
        "POST",
        "/oauth/authorize",
        "application/x-www-form-urlencoded",
        &form(&[
            ("decision", "approve"),
            ("client_id", &client_id),
            ("redirect_uri", redirect_uri),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
            ("scope", "mcp:tools"),
        ]),
        &[],
    )
    .await;
    assert_eq!(approval.status, StatusCode::FOUND);
    let location = approval.headers[header::LOCATION].to_str().unwrap();
    let parsed = url::Url::parse(location).unwrap();
    let query: std::collections::HashMap<String, String> =
        parsed.query_pairs().into_owned().collect();
    let code = query.get("code").cloned().unwrap();

    // Wrong verifier is rejected but must not burn the fresh code.
    let wrong = send(
        &state,
        "POST",
        "/oauth/token",
        "application/x-www-form-urlencoded",
        &form(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", "definitely-the-wrong-verifier-0123456789"),
        ]),
        &[],
    )
    .await;
    assert_eq!(wrong.status, StatusCode::BAD_REQUEST);
    assert_eq!(wrong.json()["error"], "invalid_grant");

    let good_body = form(&[
        ("grant_type", "authorization_code"),
        ("code", &code),
        ("redirect_uri", redirect_uri),
        ("client_id", &client_id),
        ("code_verifier", verifier),
    ]);
    let granted = send(
        &state,
        "POST",
        "/oauth/token",
        "application/x-www-form-urlencoded",
        &good_body,
        &[],
    )
    .await;
    assert_eq!(granted.status, StatusCode::OK, "{}", granted.body);
    let tokens = granted.json();
    let access = tokens["access_token"].as_str().unwrap().to_string();
    let refresh = tokens["refresh_token"].as_str().unwrap().to_string();
    assert_eq!(tokens["token_type"], "Bearer");
    assert_eq!(tokens["expires_in"], 604800);
    assert_eq!(access.len(), 64);
    assert_eq!(refresh.len(), 64);

    // Auth code replay is rejected.
    let replay = send(
        &state,
        "POST",
        "/oauth/token",
        "application/x-www-form-urlencoded",
        &good_body,
        &[],
    )
    .await;
    assert_eq!(replay.status, StatusCode::BAD_REQUEST);
    assert_eq!(replay.json()["error"], "invalid_grant");

    // Refresh grant issues a new access token and keeps the refresh token.
    let refreshed = send(
        &state,
        "POST",
        "/oauth/token",
        "application/x-www-form-urlencoded",
        &form(&[("grant_type", "refresh_token"), ("refresh_token", &refresh)]),
        &[],
    )
    .await;
    assert_eq!(refreshed.status, StatusCode::OK, "{}", refreshed.body);
    assert_eq!(refreshed.json()["refresh_token"], refresh);
    assert_ne!(refreshed.json()["access_token"], access);

    // JSON bodies are supported as well.
    let json_refresh = send(
        &state,
        "POST",
        "/oauth/token",
        "application/json",
        &json!({"grant_type": "refresh_token", "refresh_token": refresh}).to_string(),
        &[],
    )
    .await;
    assert_eq!(json_refresh.status, StatusCode::OK);
}

#[tokio::test]
async fn qa_oauth_deny_redirects_with_access_denied() {
    let f = fixture();
    let state = Arc::clone(&f.state);
    let response = send(
        &state,
        "POST",
        "/oauth/authorize",
        "application/x-www-form-urlencoded",
        &form(&[
            ("decision", "deny"),
            ("redirect_uri", "http://127.0.0.1:53682/callback"),
            ("state", "deny-state"),
        ]),
        &[],
    )
    .await;
    assert_eq!(response.status, StatusCode::FOUND);
    let location = response.headers[header::LOCATION].to_str().unwrap();
    assert!(location.contains("error=access_denied"), "{location}");
    assert!(location.contains("state=deny-state"), "{location}");
}

#[tokio::test]
async fn qa_oauth_revoked_and_expired_tokens_are_rejected() {
    let f = fixture();
    let state = Arc::clone(&f.state);
    let tokens = full_flow(&state).await;

    let ok = rpc(
        &state,
        json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
        Some(&tokens.access),
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK);

    // Revoke just the access token.
    assert_eq!(state.db.revoke_token(&tokens.access).unwrap(), 1);
    let revoked = rpc(
        &state,
        json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
        Some(&tokens.access),
    )
    .await;
    assert_eq!(revoked.status, StatusCode::UNAUTHORIZED);
    assert!(revoked.headers.contains_key(header::WWW_AUTHENTICATE));

    // Revoked refresh token cannot mint a new access token.
    assert_eq!(state.db.revoke_token(&tokens.refresh).unwrap(), 1);
    let refresh = send(
        &state,
        "POST",
        "/oauth/token",
        "application/x-www-form-urlencoded",
        &form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &tokens.refresh),
        ]),
        &[],
    )
    .await;
    assert_eq!(refresh.status, StatusCode::BAD_REQUEST);
    assert_eq!(refresh.json()["error"], "invalid_grant");

    // Expired access token is rejected and purged.
    let expired = "qa-expired-access-token";
    seed_access_token(&state, expired, config::now_ms() - 1_000);
    let expired_response = rpc(
        &state,
        json!({"jsonrpc":"2.0","id":3,"method":"ping"}),
        Some(expired),
    )
    .await;
    assert_eq!(expired_response.status, StatusCode::UNAUTHORIZED);
    assert!(state
        .db
        .find_token(expired, "access", config::now_ms())
        .unwrap()
        .is_none());
}

// ---------------------------------------------------------------------------
// 3. MCP Streamable HTTP
// ---------------------------------------------------------------------------

#[tokio::test]
async fn qa_mcp_requires_bearer_and_returns_www_authenticate() {
    let f = fixture();
    let state = Arc::clone(&f.state);
    let body = json!({"jsonrpc":"2.0","id":1,"method":"ping"});

    let missing = rpc(&state, body.clone(), None).await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    let challenge = missing.headers[header::WWW_AUTHENTICATE]
        .to_str()
        .unwrap()
        .to_string();
    assert!(challenge.contains("Bearer"), "{challenge}");
    assert!(challenge.contains("resource_metadata="), "{challenge}");
    assert!(
        challenge.contains("/.well-known/oauth-protected-resource"),
        "{challenge}"
    );

    let bogus = rpc(&state, body.clone(), Some("bogus-token")).await;
    assert_eq!(bogus.status, StatusCode::UNAUTHORIZED);
    assert!(bogus.headers.contains_key(header::WWW_AUTHENTICATE));

    let revoked_token = "qa-revoked-token";
    seed_access_token(&state, revoked_token, config::now_ms() + 60_000);
    state.db.revoke_token(revoked_token).unwrap();
    let revoked = rpc(&state, body, Some(revoked_token)).await;
    assert_eq!(revoked.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn qa_mcp_initialize_notifications_ping_and_exact_tool_list() {
    let f = fixture();
    let state = Arc::clone(&f.state);
    let token = "qa-protocol-token";
    seed_access_token(&state, token, config::now_ms() + 3_600_000);

    let init = rpc(
        &state,
        json!({
            "jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"qa","version":"1"}}
        }),
        Some(token),
    )
    .await;
    assert_eq!(init.status, StatusCode::OK);
    let result = init.json();
    assert_eq!(result["result"]["protocolVersion"], "2025-06-18");
    assert!(result["result"]["capabilities"]["tools"].is_object());
    assert_eq!(result["result"]["serverInfo"]["name"], "DeskPort");
    assert_eq!(result["result"]["serverInfo"]["version"], "0.1.0");
    assert!(result["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("list_workspaces"));

    let notification = rpc(
        &state,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        Some(token),
    )
    .await;
    assert_eq!(notification.status, StatusCode::ACCEPTED);
    assert!(notification.body.is_empty());

    let ping = rpc(
        &state,
        json!({"jsonrpc":"2.0","id":2,"method":"ping"}),
        Some(token),
    )
    .await;
    assert_eq!(ping.status, StatusCode::OK);
    assert_eq!(ping.json()["result"], json!({}));

    let list = rpc(
        &state,
        json!({"jsonrpc":"2.0","id":3,"method":"tools/list"}),
        Some(token),
    )
    .await;
    assert_eq!(list.status, StatusCode::OK);
    let tools = list.json()["result"]["tools"].as_array().unwrap().clone();
    assert_eq!(tools.len(), 11);
    let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        vec![
            "list_workspaces",
            "list_files",
            "search_files",
            "read_file",
            "read_files",
            "write_file",
            "write_files",
            "edit_file",
            "edit_files",
            "delete_file",
            "bash",
        ]
    );
    for tool in &tools {
        assert!(tool["description"].is_string());
        assert_eq!(tool["inputSchema"]["type"], "object");
        assert!(tool["annotations"].is_object());
    }
}

#[tokio::test]
async fn qa_mcp_tools_call_full_read_write_edit_search_delete_and_bash() {
    let f = fixture();
    let state = Arc::clone(&f.state);
    let token = "qa-tools-token";
    seed_access_token(&state, token, config::now_ms() + 3_600_000);

    let call = |name: &'static str, arguments: Value| {
        let state = Arc::clone(&state);
        async move {
            rpc(
                &state,
                json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":name,"arguments":arguments}}),
                Some(token),
            )
            .await
        }
    };

    let workspaces = call("list_workspaces", json!({})).await;
    assert!(!tool_is_error(&workspaces), "{}", workspaces.body);
    let text = tool_text(&workspaces);
    assert!(text.contains("\"work\""), "{text}");
    assert!(text.contains("Work"), "{text}");

    let written = call(
        "write_files",
        json!({"files":[
            {"filePath":"qa/a.txt","content":"alpha"},
            {"filePath":"qa/b.txt","content":"beta"}
        ]}),
    )
    .await;
    assert!(!tool_is_error(&written), "{}", written.body);
    assert!(tool_text(&written).contains("2/2"));

    let read = call("read_files", json!({"filePaths":["qa/a.txt","qa/b.txt"]})).await;
    assert!(!tool_is_error(&read), "{}", read.body);
    assert!(tool_text(&read).contains("alpha"));
    assert!(tool_text(&read).contains("beta"));

    let edited = call(
        "edit_files",
        json!({"edits":[
            {"filePath":"qa/a.txt","target":"alpha","replacement":"ALPHA"},
            {"filePath":"qa/b.txt","target":"beta","replacement":"BETA"}
        ]}),
    )
    .await;
    assert!(!tool_is_error(&edited), "{}", edited.body);
    assert!(tool_text(&edited).contains("2/2"));

    let searched = call("search_files", json!({"query":"ALPHA"})).await;
    assert!(!tool_is_error(&searched), "{}", searched.body);
    assert!(tool_text(&searched).contains("qa/a.txt"));

    let listed = call("list_files", json!({"dirPath":"qa","depth":2})).await;
    assert!(!tool_is_error(&listed), "{}", listed.body);
    assert!(tool_text(&listed).contains("a.txt"));

    let bash = call("bash", json!({"command":"echo deskport-qa-bash-ok"})).await;
    assert!(!tool_is_error(&bash), "{}", bash.body);
    assert!(tool_text(&bash).contains("deskport-qa-bash-ok"));
    assert!(tool_text(&bash).contains("\"exitCode\": 0"));

    // Timeout path: must be killed and reported, not hang.
    let started = Instant::now();
    let timed_out = call("bash", json!({"command":"sleep 30","timeoutSec":5})).await;
    assert!(started.elapsed() < Duration::from_secs(25));
    assert!(tool_is_error(&timed_out), "{}", timed_out.body);
    assert!(
        tool_text(&timed_out).contains("\"timedOut\": true"),
        "{}",
        timed_out.body
    );

    let deleted = call("delete_file", json!({"filePath":"qa/a.txt"})).await;
    assert!(!tool_is_error(&deleted), "{}", deleted.body);
    assert!(!f.ws.join("qa/a.txt").exists());

    // Allow-list is enforced through the MCP layer too.
    let denied = call("read_file", json!({"filePath":"../outside.txt"})).await;
    assert!(tool_is_error(&denied), "{}", denied.body);
    assert!(tool_text(&denied).contains("Access denied"));
}

#[tokio::test]
async fn qa_mcp_batch_unknown_method_and_parse_error() {
    let f = fixture();
    let state = Arc::clone(&f.state);
    let token = "qa-batch-token";
    seed_access_token(&state, token, config::now_ms() + 3_600_000);

    let batch = rpc(
        &state,
        json!([
            {"jsonrpc":"2.0","id":1,"method":"ping"},
            {"jsonrpc":"2.0","method":"notifications/initialized"},
            {"jsonrpc":"2.0","id":2,"method":"resources/list"},
            {"jsonrpc":"2.0","id":3,"method":"tools/list"}
        ]),
        Some(token),
    )
    .await;
    assert_eq!(batch.status, StatusCode::OK);
    let responses = batch.json();
    let responses = responses.as_array().unwrap();
    assert_eq!(responses.len(), 3);
    assert_eq!(responses[1]["error"]["code"], -32601);
    assert!(responses[1]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("resources/list"));
    assert_eq!(
        responses[2]["result"]["tools"].as_array().unwrap().len(),
        11
    );

    let invalid = send(
        &state,
        "POST",
        "/mcp",
        "application/json",
        "{not valid json",
        &[(header::AUTHORIZATION.as_str(), "Bearer qa-batch-token")],
    )
    .await;
    assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
    let body = invalid.json();
    assert_eq!(body["error"]["code"], -32700);

    let unknown = rpc(
        &state,
        json!({"jsonrpc":"2.0","id":9,"method":"completion/complete"}),
        Some(token),
    )
    .await;
    assert_eq!(unknown.json()["error"]["code"], -32601);

    let get = send(
        &state,
        "GET",
        "/mcp",
        "",
        "",
        &[(header::AUTHORIZATION.as_str(), "Bearer qa-batch-token")],
    )
    .await;
    assert_eq!(get.status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(get.headers[header::ALLOW]
        .to_str()
        .unwrap()
        .contains("POST"));

    let options = send(&state, "OPTIONS", "/mcp", "", "", &[]).await;
    assert_eq!(options.status, StatusCode::NO_CONTENT);
    assert_eq!(options.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
}

// ---------------------------------------------------------------------------
// 4. Log redaction
// ---------------------------------------------------------------------------

#[test]
fn qa_tunnel_logs_never_contain_plaintext_secrets() {
    let f = fixture();
    let state = &f.state;

    let cloudflare_token = "cf-super-secret-token-0123456789abcdef";
    let ngrok_token = "2nGrokSecretAuthToken0123456789abcdef";
    let mut tunnel = state.tunnel_config();
    tunnel.cloudflare_token = cloudflare_token.into();
    tunnel.ngrok_auth_token = ngrok_token.into();
    state.replace_tunnel_config(tunnel);

    state.push_tunnel_log(format!(
        "starting tunnel --token {cloudflare_token} --authtoken {ngrok_token}"
    ));
    state.push_tunnel_log(format!("reconnecting with {cloudflare_token}"));

    let snapshot = state.snapshot();
    let logs = snapshot.tunnel.logs.join("\n");
    assert!(!logs.contains(cloudflare_token), "{logs}");
    assert!(!logs.contains(ngrok_token), "{logs}");
    assert!(logs.contains("***"), "{logs}");

    assert!(snapshot.tunnel_config.has_cloudflare_token);
    assert!(snapshot.tunnel_config.has_ngrok_auth_token);
    assert!(!snapshot
        .tunnel_config
        .cloudflare_token_preview
        .contains(cloudflare_token));
    assert!(!snapshot
        .tunnel_config
        .ngrok_auth_token_preview
        .contains(ngrok_token));
    assert_eq!(
        snapshot.tunnel_config.cloudflare_token_preview,
        "cf-super...cdef"
    );
}

// ---------------------------------------------------------------------------
// 5. Corrupt / missing configuration fallback
// ---------------------------------------------------------------------------

#[test]
fn qa_missing_config_falls_back_to_safe_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let (cfg, _) = config::load_server_config(dir.path());
    assert!(cfg.restrict_to_workspaces);
    assert_eq!(cfg.port, 3334);
    assert_eq!(cfg.default_shell, config::ShellKind::Auto);
    assert!(!cfg.workspaces.is_empty());

    // AppState::open persists the safe first-run file.
    let state = AppState::open(dir.path()).unwrap();
    assert!(dir.path().join("config.json").exists());
    let snapshot = state.snapshot();
    assert!(snapshot.config.restrict_to_workspaces);
    assert_eq!(snapshot.config.default_workspace, "default");
}

#[test]
fn qa_corrupt_config_and_tunnel_files_do_not_crash() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("config.json"), b"{ this is not json").unwrap();
    fs::write(dir.path().join("tunnel.json"), b"<xml>broken</xml>").unwrap();
    fs::create_dir_all(dir.path().join("bin")).unwrap();

    let (cfg, _) = config::load_server_config(dir.path());
    assert!(cfg.restrict_to_workspaces, "unsafe fallback");
    assert_eq!(cfg.port, 3334);
    assert!(!cfg.workspaces.is_empty());

    let (tunnel, _) = config::load_tunnel_config(dir.path());
    assert_eq!(tunnel.mode, config::TunnelMode::Quick);
    assert!(tunnel.cloudflare_token.is_empty());
    assert!(tunnel.ngrok_auth_token.is_empty());

    let state = AppState::open(dir.path()).unwrap();
    let snapshot = state.snapshot();
    assert!(snapshot.config.restrict_to_workspaces);
    assert_eq!(snapshot.tunnel.status, "stopped");
    assert!(snapshot.tunnel.error.is_none());
}

#[test]
fn qa_tunnel_patch_blank_tokens_preserve_existing_secrets() {
    let mut current = config::TunnelConfig {
        mode: config::TunnelMode::Named,
        cloudflare_token: "keep-me".into(),
        fixed_url: "https://example.test".into(),
        ngrok_auth_token: "keep-ngrok".into(),
        ngrok_domain: "example.ngrok.app".into(),
    };
    let patch = config::TunnelConfigPatch {
        mode: Some(config::TunnelMode::Ngrok),
        cloudflare_token: Some("   ".into()),
        ngrok_auth_token: Some(String::new()),
        ..Default::default()
    };
    patch.apply(&mut current);
    assert_eq!(current.mode, config::TunnelMode::Ngrok);
    assert_eq!(current.cloudflare_token, "keep-me");
    assert_eq!(current.ngrok_auth_token, "keep-ngrok");
    assert_eq!(current.fixed_url, "https://example.test");
}

// ---------------------------------------------------------------------------
// 6. Frontend contract snapshot (camelCase keys the UI reads)
// ---------------------------------------------------------------------------

#[test]
fn qa_snapshot_exposes_the_camel_case_frontend_contract() {
    let f = fixture();
    let value = serde_json::to_value(f.state.snapshot()).unwrap();
    let object = value.as_object().unwrap();

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
        assert!(object.contains_key(key), "missing snapshot key {key}");
    }
    assert_eq!(value["config"]["restrictToWorkspaces"], true);
    assert_eq!(value["config"]["defaultWorkspace"], "work");
    assert_eq!(value["config"]["defaultShell"], "auto");
    assert!(value["server"]["localUrl"]
        .as_str()
        .unwrap()
        .starts_with("http://127.0.0.1:"));
    assert!(value["tunnel"]["status"].is_string());
    assert!(value["tunnel"].get("error").is_some());
    assert!(value["tunnelConfig"].get("hasCloudflareToken").is_some());
    assert!(value["tunnelConfig"]
        .get("cloudflareTokenPreview")
        .is_some());
    assert!(value["binaries"].get("cloudflaredInstalled").is_some());
    assert!(value["oauth"].get("activeTokenCount").is_some());
    assert_eq!(value["tools"].as_array().unwrap().len(), 11);
}
