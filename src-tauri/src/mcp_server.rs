//! Streamable HTTP MCP endpoint plus the OAuth 2.1 authorization-server half.
//!
//! The HTTP surface is a single fallback handler so CORS, status codes and the
//! `Allow` header stay explicit and easy to audit:
//!
//! * `GET  /`                                     service descriptor
//! * `GET  /.well-known/oauth-protected-resource`  RFC 9728
//! * `GET  /.well-known/oauth-authorization-server` RFC 8414
//! * `POST /oauth/register`                       RFC 7591 dynamic registration
//! * `GET|POST /oauth/authorize`                  consent page + approval
//! * `POST /oauth/token`                          code / refresh grants
//! * `GET|POST|DELETE /mcp`                       JSON-RPC 2.0 (bearer protected)

use crate::config::{self, ServerConfig, WorkspaceItem, VERSION};
use crate::db::{ClientRecord, CodeRecord, TokenRecord};
use crate::state::AppState;
use crate::tools;
use axum::body::{to_bytes, Body};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode};

type Resp = Response<Body>;
use axum::Router;
use base64::Engine;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const ACCESS_TOKEN_TTL_SECS: i64 = 7 * 24 * 60 * 60;
const AUTH_CODE_TTL_MS: i64 = 5 * 60 * 1000;
const SCOPE: &str = "mcp:tools";
const MCP_PROTOCOL_VERSIONS: [&str; 3] = ["2024-11-05", "2025-03-26", "2025-06-18"];
const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";

const INSTRUCTIONS: &str = "You are connected to the user's machine through DeskPort, a local MCP bridge. \
Use list_workspaces to discover the allowed folders. \
Prefer list_files(depth=2) to inspect a project in one call, search_files instead of spawning grep/find, \
and read_files / write_files / edit_files to batch multiple files in a single round-trip. \
Chain related shell commands with && in one bash call. Only touch paths inside the allowed workspaces.";

// ---------------------------------------------------------------------------
// Router & transport
// ---------------------------------------------------------------------------

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .fallback(handle)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(state)
}

pub async fn serve(
    listener: TcpListener,
    state: Arc<AppState>,
    shutdown: oneshot::Receiver<()>,
) -> Result<(), String> {
    state.push_server_log(format!(
        "MCP server listening on http://127.0.0.1:{}",
        listener.local_addr().map(|addr| addr.port()).unwrap_or(0)
    ));
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async move {
            let _ = shutdown.await;
        })
        .await
        .map_err(|err| format!("MCP server error: {err}"))
}

async fn handle(State(state): State<Arc<AppState>>, request: Request<Body>) -> Resp {
    let response = dispatch(state, request).await;
    with_cors(response)
}

async fn dispatch(state: Arc<AppState>, request: Request<Body>) -> Resp {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let normalized_path = if path.len() > 1 {
        let trimmed = path.trim_end_matches('/');
        if trimmed.is_empty() {
            "/"
        } else {
            trimmed
        }
    } else {
        path.as_str()
    };
    let query = request.uri().query().unwrap_or("").to_string();
    let base = base_url(request.headers(), state.server_port());

    if method == Method::OPTIONS {
        return empty_response(StatusCode::NO_CONTENT);
    }

    let headers = request.headers().clone();
    let body = if method == Method::POST {
        match to_bytes(request.into_body(), MAX_BODY_BYTES).await {
            Ok(bytes) => bytes.to_vec(),
            Err(_) => {
                return json_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "invalid_request",
                    "Body too large",
                )
            }
        }
    } else {
        Vec::new()
    };

    match (method.as_str(), normalized_path) {
        ("GET", "/") => json_response(
            StatusCode::OK,
            &json!({
                "status": "ok",
                "service": "DeskPort",
                "version": VERSION,
                "mcp_endpoint": format!("{base}/mcp"),
            }),
        ),
        ("GET", "/.well-known/oauth-protected-resource")
        | ("GET", "/.well-known/oauth-protected-resource/mcp") => {
            state.push_server_log(format!("OAuth discovery: GET {path}"));
            json_response(
                StatusCode::OK,
                &json!({
                    "resource": format!("{base}/mcp"),
                    "resource_name": "DeskPort",
                    "authorization_servers": [base.clone()],
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": [SCOPE],
                }),
            )
        }
        ("GET", "/.well-known/oauth-authorization-server")
        | ("GET", "/.well-known/oauth-authorization-server/mcp")
        | ("GET", "/.well-known/openid-configuration")
        | ("GET", "/.well-known/openid-configuration/mcp")
        | ("GET", "/mcp/.well-known/openid-configuration") => {
            state.push_server_log(format!("OAuth discovery: GET {path}"));
            json_response(
                StatusCode::OK,
                &json!({
                    "issuer": base,
                    "service_documentation": base,
                    "authorization_endpoint": format!("{base}/oauth/authorize"),
                    "token_endpoint": format!("{base}/oauth/token"),
                    "registration_endpoint": format!("{base}/oauth/register"),
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "code_challenge_methods_supported": ["S256", "plain"],
                    "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
                    "scopes_supported": [SCOPE],
                    "client_id_metadata_document_supported": true,
                }),
            )
        }
        ("POST", "/oauth/register") => register_client(&state, &body),
        ("GET", "/oauth/authorize") => authorize_page(&state, &query),
        ("POST", "/oauth/authorize") => authorize_decision(&state, &headers, &body),
        ("POST", "/oauth/token") => issue_token(&state, &headers, &body),
        (_, "/mcp") => mcp_endpoint(&state, &method, &headers, &body, &base),
        _ => {
            state.push_server_log(format!("HTTP 404: {method} {path}"));
            json_error(StatusCode::NOT_FOUND, "not_found", "Unknown endpoint")
        }
    }
}

fn base_url(headers: &HeaderMap, port: u16) -> String {
    let scheme = header_value(headers, "x-forwarded-proto")
        .and_then(|value| value.split(',').next().map(str::trim).map(str::to_string))
        .filter(|value| value == "http" || value == "https")
        .unwrap_or_else(|| "http".to_string());
    let host = header_value(headers, "x-forwarded-host")
        .or_else(|| header_value(headers, "host"))
        .and_then(|value| value.split(',').next().map(str::trim).map(str::to_string))
        .filter(|value| is_safe_host(value));
    match host {
        Some(host) => format!("{scheme}://{host}"),
        None => format!("http://127.0.0.1:{port}"),
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn is_safe_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && host
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | ':' | '[' | ']' | '_'))
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn with_cors(mut response: Resp) -> Resp {
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, POST, DELETE, OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("Mcp-Session-Id"),
    );
    response
}

fn json_response(status: StatusCode, value: &Value) -> Resp {
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(Body::from(body))
        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn json_error(status: StatusCode, error: &str, description: &str) -> Resp {
    json_response(
        status,
        &json!({ "error": error, "error_description": description }),
    )
}

fn empty_response(status: StatusCode) -> Resp {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .unwrap_or_default()
}

fn html_response(status: StatusCode, html: String) -> Resp {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header("X-Content-Type-Options", "nosniff")
        .header("Referrer-Policy", "no-referrer")
        .header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
        )
        .body(Body::from(html))
        .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

fn redirect_response(location: String) -> Resp {
    match HeaderValue::from_str(&location) {
        Ok(value) => Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, value)
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::empty())
            .unwrap_or_else(|_| empty_response(StatusCode::INTERNAL_SERVER_ERROR)),
        Err(_) => json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "redirect_uri cannot be represented as a Location header",
        ),
    }
}

// ---------------------------------------------------------------------------
// Request parsing
// ---------------------------------------------------------------------------

fn parse_params(content_type: &str, body: &[u8]) -> HashMap<String, String> {
    let content_type = content_type.to_ascii_lowercase();
    let looks_json = body.first() == Some(&b'{');
    if content_type.contains("application/json") || looks_json {
        if let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(body) {
            return map
                .into_iter()
                .map(|(key, value)| {
                    let value = match value {
                        Value::String(text) => text,
                        other => other.to_string(),
                    };
                    (key, value)
                })
                .collect();
        }
    }
    url::form_urlencoded::parse(body)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn parse_query(query: &str) -> HashMap<String, String> {
    url::form_urlencoded::parse(query.as_bytes())
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect()
}

fn random_hex(bytes: usize) -> String {
    let mut buffer = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buffer);
    buffer.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 16);
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Only `http`, `https` and custom app schemes may receive an authorization
/// redirect. Anything scriptable is rejected before it can be embedded.
fn validate_redirect_uri(raw: &str) -> Result<url::Url, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("Missing redirect_uri".to_string());
    }
    let url = url::Url::parse(raw).map_err(|err| format!("Invalid redirect_uri: {err}"))?;
    let scheme = url.scheme().to_ascii_lowercase();
    if matches!(
        scheme.as_str(),
        "javascript" | "data" | "vbscript" | "file" | "about" | "blob" | "jar"
    ) {
        return Err(format!("Unsupported redirect_uri scheme: {scheme}"));
    }
    if scheme.len() < 2 {
        return Err("Invalid redirect_uri scheme".to_string());
    }
    if (scheme == "http" || scheme == "https") && url.host_str().is_none() {
        return Err("redirect_uri must include a host".to_string());
    }
    Ok(url)
}

// ---------------------------------------------------------------------------
// OAuth: dynamic client registration
// ---------------------------------------------------------------------------

fn register_client(state: &AppState, body: &[u8]) -> Resp {
    let payload: Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));
    let client_name = payload
        .get("client_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(|name| name.chars().take(80).collect::<String>())
        .unwrap_or_else(|| "MCP Client".to_string());
    let redirect_uris: Vec<String> = payload
        .get("redirect_uris")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .take(10)
                .map(|uri| uri.chars().take(2048).collect::<String>())
                .collect()
        })
        .unwrap_or_default();

    let token_endpoint_auth_method = payload
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|method| matches!(*method, "none" | "client_secret_post" | "client_secret_basic"))
        .unwrap_or("none")
        .to_string();

    let client = ClientRecord {
        client_id: format!("dp_{}", random_hex(12)),
        client_secret: Some(random_hex(24)),
        client_name,
        redirect_uris,
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        response_types: vec!["code".into()],
        token_endpoint_auth_method,
        created_at: config::now_ms(),
    };

    if let Err(err) = state.db.save_client(&client) {
        state.push_server_log(format!("Failed to register OAuth client: {err}"));
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Could not persist the client",
        );
    }

    state.push_server_log(format!(
        "Registered dynamic OAuth client {} ({})",
        client.client_name, client.client_id
    ));

    json_response(
        StatusCode::CREATED,
        &json!({
            "client_id": client.client_id,
            "client_secret": client.client_secret,
            "client_id_issued_at": config::now_ms() / 1000,
            "client_secret_expires_at": 0,
            "client_name": client.client_name,
            "redirect_uris": client.redirect_uris,
            "grant_types": client.grant_types,
            "response_types": client.response_types,
            "token_endpoint_auth_method": client.token_endpoint_auth_method,
        }),
    )
}

// ---------------------------------------------------------------------------
// OAuth: consent page
// ---------------------------------------------------------------------------

fn authorize_page(state: &AppState, query: &str) -> Resp {
    let params = parse_query(query);
    let redirect_uri = params.get("redirect_uri").cloned().unwrap_or_default();
    if let Err(err) = validate_redirect_uri(&redirect_uri) {
        return json_error(StatusCode::BAD_REQUEST, "invalid_request", &err);
    }
    let client_id = params.get("client_id").cloned().unwrap_or_default();
    let client = state.db.get_client(&client_id).ok().flatten();
    let client_name = client
        .as_ref()
        .map(|client| client.client_name.clone())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            if client_id.is_empty() {
                "Unknown App".to_string()
            } else {
                client_id.clone()
            }
        });

    let config = state.config();
    let scope = params
        .get("scope")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| SCOPE.to_string());

    state.push_server_log(format!("OAuth authorize page opened for {client_name}"));

    let html = render_authorize_page(&AuthorizePage {
        client_name: &client_name,
        client_id: &client_id,
        redirect_uri: &redirect_uri,
        state: params.get("state").map(String::as_str).unwrap_or(""),
        code_challenge: params
            .get("code_challenge")
            .map(String::as_str)
            .unwrap_or(""),
        code_challenge_method: params
            .get("code_challenge_method")
            .map(String::as_str)
            .unwrap_or("S256"),
        scope: &scope,
        workspaces: &config.workspaces,
        restrict_to_workspaces: config.restrict_to_workspaces,
    });
    html_response(StatusCode::OK, html)
}

struct AuthorizePage<'a> {
    client_name: &'a str,
    client_id: &'a str,
    redirect_uri: &'a str,
    state: &'a str,
    code_challenge: &'a str,
    code_challenge_method: &'a str,
    scope: &'a str,
    workspaces: &'a [WorkspaceItem],
    restrict_to_workspaces: bool,
}

fn render_authorize_page(page: &AuthorizePage<'_>) -> String {
    let workspaces = if page.workspaces.is_empty() {
        "<li class=\"ws-empty\">未配置任何工作区</li>".to_string()
    } else {
        page.workspaces
            .iter()
            .map(|workspace| {
                let name = escape_html(&workspace.name);
                let path = escape_html(&workspace.path);
                format!(
                    "<li class=\"ws\">\
                       <svg class=\"ws-ico\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">\
                         <path d=\"M3.5 7.6a2 2 0 0 1 2-2h3.9l2.1 2.6h7a2 2 0 0 1 2 2v7.2a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z\"/>\
                       </svg>\
                       <div class=\"ws-info\">\
                         <span class=\"ws-name\">{name}</span>\
                         <span class=\"ws-path\" title=\"{path}\">{path}</span>\
                       </div>\
                     </li>"
                )
            })
            .collect::<Vec<_>>()
            .join("")
    };

    let whitelist_pill = if page.restrict_to_workspaces {
        "<span class=\"pill ok\"><i class=\"dot\"></i>白名单已开启</span>"
    } else {
        "<span class=\"pill warn\"><i class=\"dot\"></i>白名单已关闭</span>"
    };

    let unrestricted_warn = if page.restrict_to_workspaces {
        ""
    } else {
        "<div class=\"warn-box\">白名单已关闭，该应用可访问本机任意路径</div>"
    };

    let client_id_display = if page.client_id.is_empty() {
        "—"
    } else {
        page.client_id
    };

    format!(
        r##"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>DeskPort · 授权连接</title>
<style>
  :root {{
    color-scheme: dark light;
    --canvas:#09090B; --card:#111113; --surface:#18181B; --inset:#0D0D10;
    --line:rgba(255,255,255,.08); --line-strong:rgba(255,255,255,.14);
    --fg:#F4F4F5; --fg2:#A1A1AA; --fg3:#71717A;
    --green:#10B981; --green-soft:rgba(16,185,129,.12); --green-line:rgba(16,185,129,.26);
    --amber:#F59E0B; --amber-soft:rgba(245,158,11,.10); --amber-line:rgba(245,158,11,.28);
    --primary-bg:#F4F4F5; --primary-fg:#09090B; --primary-hover:#E4E4E7;
    --ambient:rgba(255,255,255,.045);
    --shadow:0 24px 72px rgba(0,0,0,.58);
  }}
  @media (prefers-color-scheme: light) {{
    :root {{
      --canvas:#FAFAFA; --card:#FFFFFF; --surface:#F4F4F5; --inset:#F7F7F8;
      --line:rgba(0,0,0,.075); --line-strong:rgba(0,0,0,.14);
      --fg:#18181B; --fg2:#52525B; --fg3:#71717A;
      --green:#059669; --green-soft:rgba(5,150,105,.09); --green-line:rgba(5,150,105,.24);
      --amber:#B45309; --amber-soft:rgba(180,83,9,.08); --amber-line:rgba(180,83,9,.22);
      --primary-bg:#18181B; --primary-fg:#FFFFFF; --primary-hover:#27272A;
      --ambient:rgba(24,24,27,.03);
      --shadow:0 20px 56px rgba(16,24,40,.10);
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{
    margin:0; min-height:100vh; position:relative;
    background:var(--canvas); color:var(--fg);
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,"PingFang SC","Microsoft YaHei",sans-serif;
    font-size:13.5px; line-height:1.5;
    display:flex; align-items:center; justify-content:center;
    padding:24px 16px; -webkit-font-smoothing:antialiased;
  }}
  body::before {{
    content:""; position:fixed; inset:0; pointer-events:none;
    background:radial-gradient(640px 320px at 50% -120px, var(--ambient), transparent 70%);
  }}
  .card {{
    position:relative; width:100%; max-width:400px;
    background:var(--card); border:1px solid var(--line);
    border-radius:18px; padding:26px 24px 20px; box-shadow:var(--shadow);
  }}
  .head {{ text-align:center; margin-bottom:20px; }}
  .logo {{
    display:inline-flex; align-items:center; justify-content:center;
    width:38px; height:38px; border-radius:11px; margin-bottom:10px;
    background:var(--surface); border:1px solid var(--line-strong);
  }}
  .eyebrow {{
    font-size:11px; font-weight:600; letter-spacing:.04em;
    color:var(--fg3); margin-bottom:6px;
  }}
  h1 {{
    margin:0 0 6px; font-size:17.5px; font-weight:600;
    letter-spacing:-.015em; line-height:1.35; word-break:break-word;
  }}
  h1 span {{ color:var(--fg); }}
  .sub {{ margin:0; font-size:12.5px; color:var(--fg2); }}
  .box {{
    border:1px solid var(--line); border-radius:12px;
    background:var(--inset); overflow:hidden; margin-bottom:12px;
  }}
  .box-head {{
    display:flex; align-items:center; justify-content:space-between; gap:8px;
    padding:9px 12px; border-bottom:1px solid var(--line);
    font-size:11.5px; font-weight:600; color:var(--fg2);
  }}
  .pill {{
    display:inline-flex; align-items:center; gap:5px;
    padding:2px 8px; border-radius:999px; font-size:10.5px; font-weight:500;
  }}
  .pill .dot {{ width:5px; height:5px; border-radius:50%; background:currentColor; }}
  .pill.ok {{ color:var(--green); background:var(--green-soft); border:1px solid var(--green-line); }}
  .pill.warn {{ color:var(--amber); background:var(--amber-soft); border:1px solid var(--amber-line); }}
  .ws-list {{
    list-style:none; margin:0; padding:4px 0;
    max-height:160px; overflow-y:auto;
  }}
  .ws {{
    display:flex; align-items:center; gap:9px;
    padding:7px 12px;
  }}
  .ws + .ws {{ border-top:1px solid var(--line); }}
  .ws-ico {{
    width:15px; height:15px; flex:0 0 auto;
    fill:none; stroke:var(--fg3); stroke-width:1.7;
    stroke-linecap:round; stroke-linejoin:round;
  }}
  .ws-info {{ flex:1; min-width:0; display:flex; flex-direction:column; gap:1px; }}
  .ws-name {{ font-size:12.5px; font-weight:600; color:var(--fg); white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .ws-path {{
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    font-size:11px; color:var(--fg3);
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
  }}
  .ws-empty {{ padding:12px; text-align:center; font-size:12px; color:var(--fg3); }}
  .warn-box {{
    margin-bottom:12px; padding:8px 11px; border-radius:10px;
    background:var(--amber-soft); border:1px solid var(--amber-line);
    color:var(--amber); font-size:11.5px; font-weight:500; text-align:center;
  }}
  .details {{
    margin-bottom:18px; border:1px solid var(--line);
    border-radius:10px; background:var(--inset);
  }}
  .details summary {{
    list-style:none; cursor:pointer; user-select:none;
    display:flex; align-items:center; justify-content:space-between;
    padding:8px 12px; font-size:11.5px; color:var(--fg2); font-weight:500;
  }}
  .details summary::-webkit-details-marker {{ display:none; }}
  .summary-right {{ display:inline-flex; align-items:center; gap:6px; color:var(--fg3); font-size:11px; }}
  .chev {{
    width:12px; height:12px; fill:none; stroke:currentColor; stroke-width:1.8;
    stroke-linecap:round; stroke-linejoin:round; transition:transform .16s ease;
  }}
  .details[open] .chev {{ transform:rotate(180deg); }}
  .details-body {{
    padding:8px 12px 10px; border-top:1px solid var(--line);
    display:flex; flex-direction:column; gap:6px;
  }}
  .kv {{ display:flex; align-items:baseline; justify-content:space-between; gap:12px; font-size:11.5px; }}
  .kv span {{ color:var(--fg3); flex:0 0 auto; }}
  .kv code {{
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    font-size:11px; color:var(--fg2); word-break:break-all; text-align:right;
  }}
  .actions {{ display:flex; gap:9px; }}
  button {{
    height:40px; border-radius:10px; font-size:13px; font-weight:600;
    cursor:pointer; border:1px solid transparent; font-family:inherit;
    transition:background-color .14s ease, border-color .14s ease, transform .06s ease;
  }}
  button:active {{ transform:translateY(1px); }}
  .deny {{
    flex:0 0 100px; background:transparent; color:var(--fg2); border-color:var(--line);
  }}
  .deny:hover {{ background:var(--surface); border-color:var(--line-strong); color:var(--fg); }}
  .approve {{ flex:1; background:var(--primary-bg); color:var(--primary-fg); }}
  .approve:hover {{ background:var(--primary-hover); }}
  footer {{
    margin-top:16px; text-align:center; color:var(--fg3);
    font-size:11px; letter-spacing:.01em;
  }}
</style>
</head>
<body>
  <main class="card">
    <div class="head">
      <div class="logo" aria-hidden="true">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
          <rect x="3.2" y="3.2" width="17.6" height="17.6" rx="5.2" stroke="currentColor" stroke-width="1.6"/>
          <rect x="8.1" y="8.1" width="7.8" height="7.8" rx="2.1" fill="#10B981"/>
        </svg>
      </div>
      <div class="eyebrow">DeskPort</div>
      <h1>允许 <span>{client_name}</span> 连接？</h1>
      <p class="sub">授权后可访问开放工作区中的文件与 Shell 工具</p>
    </div>

    <div class="box">
      <div class="box-head">
        <span>开放工作区</span>
        {whitelist_pill}
      </div>
      <ul class="ws-list">{workspaces}</ul>
    </div>

    {unrestricted_warn}

    <details class="details">
      <summary>
        <span>连接详情</span>
        <span class="summary-right">11 个工具 <svg class="chev" viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9.5 6 6 6-6"/></svg></span>
      </summary>
      <div class="details-body">
        <div class="kv"><span>客户端 ID</span><code>{client_id}</code></div>
        <div class="kv"><span>权限范围</span><code>{scope}</code></div>
      </div>
    </details>

    <form method="POST" action="/oauth/authorize" class="actions">
      <input type="hidden" name="client_id" value="{client_id_attr}">
      <input type="hidden" name="redirect_uri" value="{redirect_uri_attr}">
      <input type="hidden" name="state" value="{state_attr}">
      <input type="hidden" name="code_challenge" value="{challenge_attr}">
      <input type="hidden" name="code_challenge_method" value="{method_attr}">
      <input type="hidden" name="scope" value="{scope_attr}">
      <button type="submit" name="decision" value="deny" class="deny">拒绝</button>
      <button type="submit" name="decision" value="approve" class="approve">允许连接</button>
    </form>

    <footer>仅授权给信任的应用 · 可随时在 DeskPort 吊销 · v{version}</footer>
  </main>
</body>
</html>"##,
        client_name = escape_html(page.client_name),
        client_id = escape_html(client_id_display),
        scope = escape_html(page.scope),
        whitelist_pill = whitelist_pill,
        workspaces = workspaces,
        unrestricted_warn = unrestricted_warn,
        client_id_attr = escape_html(page.client_id),
        redirect_uri_attr = escape_html(page.redirect_uri),
        state_attr = escape_html(page.state),
        challenge_attr = escape_html(page.code_challenge),
        method_attr = escape_html(page.code_challenge_method),
        scope_attr = escape_html(page.scope),
        version = VERSION,
    )
}

// ---------------------------------------------------------------------------
// OAuth: consent decision
// ---------------------------------------------------------------------------

fn authorize_decision(state: &AppState, headers: &HeaderMap, body: &[u8]) -> Resp {
    let content_type = header_value(headers, "content-type").unwrap_or_default();
    let params = parse_params(&content_type, body);
    let redirect_uri = params.get("redirect_uri").cloned().unwrap_or_default();
    let mut target = match validate_redirect_uri(&redirect_uri) {
        Ok(url) => url,
        Err(err) => return json_error(StatusCode::BAD_REQUEST, "invalid_request", &err),
    };
    let state_param = params.get("state").cloned().unwrap_or_default();
    let client_id = params.get("client_id").cloned().unwrap_or_default();

    if params.get("decision").map(String::as_str) != Some("approve") {
        state.push_server_log(format!(
            "OAuth authorization denied for {}",
            if client_id.is_empty() {
                "unknown"
            } else {
                client_id.as_str()
            }
        ));
        {
            let mut pairs = target.query_pairs_mut();
            pairs.append_pair("error", "access_denied");
            if !state_param.is_empty() {
                pairs.append_pair("state", &state_param);
            }
        }
        return redirect_response(target.to_string());
    }

    let code_challenge = params.get("code_challenge").cloned().unwrap_or_default();
    let code_challenge_method = params
        .get("code_challenge_method")
        .cloned()
        .filter(|method| !method.is_empty())
        .unwrap_or_else(|| "S256".to_string());
    let scope = params
        .get("scope")
        .cloned()
        .filter(|scope| !scope.trim().is_empty())
        .unwrap_or_else(|| SCOPE.to_string());

    if !client_id.is_empty() && state.db.get_client(&client_id).ok().flatten().is_none() {
        let client_name = derive_client_name(&client_id);
        let client = ClientRecord {
            client_id: client_id.clone(),
            client_secret: None,
            client_name,
            redirect_uris: vec![redirect_uri.clone()],
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            token_endpoint_auth_method: "none".into(),
            created_at: config::now_ms(),
        };
        if let Err(err) = state.db.save_client(&client) {
            state.push_server_log(format!("Failed to record OAuth client {client_id}: {err}"));
        }
    }

    let code = random_hex(24);
    let record = CodeRecord {
        code: code.clone(),
        client_id: if client_id.is_empty() {
            None
        } else {
            Some(client_id)
        },
        redirect_uri: redirect_uri.clone(),
        code_challenge: if code_challenge.is_empty() {
            None
        } else {
            Some(code_challenge)
        },
        code_challenge_method: Some(code_challenge_method),
        scope,
        expires_at: config::now_ms() + AUTH_CODE_TTL_MS,
    };
    if let Err(err) = state.db.save_code(&record) {
        state.push_server_log(format!("Failed to persist auth code: {err}"));
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Could not persist the authorization code",
        );
    }
    let _ = state.db.purge_expired_codes(config::now_ms());
    state.push_server_log(format!(
        "Issued authorization code for client {}",
        record.client_id.as_deref().unwrap_or("unknown")
    ));

    {
        let mut pairs = target.query_pairs_mut();
        pairs.append_pair("code", &code);
        if !state_param.is_empty() {
            pairs.append_pair("state", &state_param);
        }
    }
    redirect_response(target.to_string())
}

// ---------------------------------------------------------------------------
// OAuth: token endpoint
// ---------------------------------------------------------------------------

fn derive_client_name(client_id: &str) -> String {
    if let Ok(parsed) = url::Url::parse(client_id) {
        if matches!(parsed.scheme(), "http" | "https") {
            if let Some(host) = parsed.host_str() {
                return host.chars().take(80).collect();
            }
        }
    }
    client_id.chars().take(80).collect()
}

fn decode_form_component(raw: &str) -> String {
    let query = format!("v={raw}");
    url::form_urlencoded::parse(query.as_bytes())
        .next()
        .map(|(_, value)| value.into_owned())
        .unwrap_or_else(|| raw.to_string())
}

fn extract_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?.trim();
    if raw.len() < 6 || !raw[..6].eq_ignore_ascii_case("basic ") {
        return None;
    }
    let encoded = raw[6..].trim();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    let decoded = String::from_utf8(bytes).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((decode_form_component(id), decode_form_component(secret)))
}

fn token_error(state: &AppState, status: StatusCode, error: &str, description: &str) -> Resp {
    state.push_server_log(format!("OAuth token error ({error}): {description}"));
    json_error(status, error, description)
}

fn resolve_client_credentials(
    headers: &HeaderMap,
    params: &HashMap<String, String>,
) -> (String, String) {
    let basic = extract_basic_auth(headers);
    let client_id = params
        .get("client_id")
        .cloned()
        .filter(|value| !value.is_empty())
        .or_else(|| basic.as_ref().map(|(id, _)| id.clone()))
        .unwrap_or_default();
    let client_secret = params
        .get("client_secret")
        .cloned()
        .filter(|value| !value.is_empty())
        .or_else(|| basic.map(|(_, secret)| secret))
        .unwrap_or_default();
    (client_id, client_secret)
}

fn authenticate_client(state: &AppState, client_id: &str, client_secret: &str) -> Result<(), Resp> {
    if client_id.is_empty() {
        return Ok(());
    }
    let client = match state.db.get_client(client_id) {
        Ok(Some(client)) => client,
        Ok(None) => return Ok(()),
        Err(err) => {
            state.push_server_log(format!("Failed to read OAuth client: {err}"));
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Database error",
            ));
        }
    };

    if matches!(
        client.token_endpoint_auth_method.as_str(),
        "client_secret_basic" | "client_secret_post"
    ) {
        let valid = !client_secret.is_empty()
            && client.client_secret.as_deref() == Some(client_secret);
        if !valid {
            return Err(token_error(
                state,
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Client authentication failed",
            ));
        }
    }
    Ok(())
}

fn issue_token(state: &AppState, headers: &HeaderMap, body: &[u8]) -> Resp {
    let content_type = header_value(headers, "content-type").unwrap_or_default();
    let params = parse_params(&content_type, body);
    match params.get("grant_type").map(String::as_str) {
        Some("authorization_code") => exchange_code(state, headers, &params),
        Some("refresh_token") => refresh_token(state, headers, &params),
        Some(_) => token_error(
            state,
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "Only authorization_code and refresh_token are supported",
        ),
        None => token_error(
            state,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing grant_type",
        ),
    }
}

fn exchange_code(state: &AppState, headers: &HeaderMap, params: &HashMap<String, String>) -> Resp {
    let now = config::now_ms();
    let code = params.get("code").cloned().unwrap_or_default();
    let code_verifier = params.get("code_verifier").cloned().unwrap_or_default();
    let redirect_uri = params.get("redirect_uri").cloned().unwrap_or_default();
    let (client_id, client_secret) = resolve_client_credentials(headers, params);

    if let Err(resp) = authenticate_client(state, &client_id, &client_secret) {
        return resp;
    }

    let record = match state.db.get_code(&code) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return token_error(
                state,
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Invalid or already used authorization code",
            )
        }
        Err(err) => {
            state.push_server_log(format!("Failed to read auth code: {err}"));
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Database error",
            );
        }
    };

    if record.expires_at <= now {
        let _ = state.db.consume_code(&code);
        return token_error(
            state,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code expired",
        );
    }
    if !client_id.is_empty() && record.client_id.as_deref() != Some(client_id.as_str()) {
        return token_error(
            state,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id does not match the authorization code",
        );
    }
    if !redirect_uri.is_empty() && record.redirect_uri != redirect_uri {
        return token_error(
            state,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri mismatch",
        );
    }
    if !verify_pkce(
        &code_verifier,
        record.code_challenge.as_deref(),
        record.code_challenge_method.as_deref(),
    ) {
        return token_error(
            state,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "PKCE verification failed",
        );
    }
    // Only a fully validated exchange burns the code.
    match state.db.consume_code(&code) {
        Ok(Some(_)) => {}
        _ => {
            return token_error(
                state,
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Invalid or already used authorization code",
            )
        }
    }

    let access_token = random_hex(32);
    let refresh_token = random_hex(32);
    let expires_at = now + ACCESS_TOKEN_TTL_SECS * 1000;
    if let Err(err) = state.db.save_token(&TokenRecord {
        token: access_token.clone(),
        token_type: "access".into(),
        client_id: record.client_id.clone(),
        scope: record.scope.clone(),
        expires_at: Some(expires_at),
        created_at: now,
    }) {
        state.push_server_log(format!("Failed to persist access token: {err}"));
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Database error",
        );
    }
    if let Err(err) = state.db.save_token(&TokenRecord {
        token: refresh_token.clone(),
        token_type: "refresh".into(),
        client_id: record.client_id.clone(),
        scope: record.scope.clone(),
        expires_at: None,
        created_at: now,
    }) {
        state.push_server_log(format!("Failed to persist refresh token: {err}"));
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Database error",
        );
    }

    state.push_server_log(format!(
        "Issued access token for client {}",
        record.client_id.as_deref().unwrap_or("unknown")
    ));

    json_response(
        StatusCode::OK,
        &json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECS,
            "refresh_token": refresh_token,
            "scope": record.scope,
        }),
    )
}

fn refresh_token(state: &AppState, headers: &HeaderMap, params: &HashMap<String, String>) -> Resp {
    let now = config::now_ms();
    let (client_id, client_secret) = resolve_client_credentials(headers, params);
    if let Err(resp) = authenticate_client(state, &client_id, &client_secret) {
        return resp;
    }

    let refresh = params.get("refresh_token").cloned().unwrap_or_default();
    let record = match state.db.find_token(&refresh, "refresh", now) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return token_error(
                state,
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Invalid or revoked refresh token",
            )
        }
        Err(err) => {
            state.push_server_log(format!("Failed to read refresh token: {err}"));
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Database error",
            );
        }
    };

    if !client_id.is_empty()
        && record
            .client_id
            .as_deref()
            .is_some_and(|expected| expected != client_id.as_str())
    {
        return token_error(
            state,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "client_id does not match the refresh token",
        );
    }

    let access_token = random_hex(32);
    if let Err(err) = state.db.save_token(&TokenRecord {
        token: access_token.clone(),
        token_type: "access".into(),
        client_id: record.client_id.clone(),
        scope: record.scope.clone(),
        expires_at: Some(now + ACCESS_TOKEN_TTL_SECS * 1000),
        created_at: now,
    }) {
        state.push_server_log(format!("Failed to persist refreshed token: {err}"));
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Database error",
        );
    }

    json_response(
        StatusCode::OK,
        &json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": ACCESS_TOKEN_TTL_SECS,
            "refresh_token": refresh,
            "scope": record.scope,
        }),
    )
}

fn verify_pkce(verifier: &str, challenge: Option<&str>, method: Option<&str>) -> bool {
    let challenge = match challenge {
        Some(challenge) if !challenge.is_empty() => challenge,
        _ => return true,
    };
    if verifier.is_empty() {
        return false;
    }
    match method
        .unwrap_or("S256")
        .trim()
        .to_ascii_uppercase()
        .as_str()
    {
        "S256" => {
            let digest = Sha256::digest(verifier.as_bytes());
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
            encoded == challenge
        }
        "PLAIN" => verifier == challenge,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// MCP endpoint
// ---------------------------------------------------------------------------

fn mcp_endpoint(
    state: &AppState,
    method: &Method,
    headers: &HeaderMap,
    body: &[u8],
    base_url: &str,
) -> Resp {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let value = value.trim();
            let lower = value.to_ascii_lowercase();
            lower
                .starts_with("bearer ")
                .then(|| value[7..].trim().to_string())
        })
        .unwrap_or_default();

    let authenticated = if token.is_empty() {
        false
    } else {
        state
            .db
            .find_token(&token, "access", config::now_ms())
            .ok()
            .flatten()
            .is_some()
    };

    if !authenticated {
        let metadata = if token.is_empty() {
            state.push_server_log(format!("MCP 401 ({method} /mcp): missing bearer token"));
            format!(
                "Bearer resource_metadata=\"{base_url}/.well-known/oauth-protected-resource\", scope=\"{SCOPE}\""
            )
        } else {
            state.push_server_log(format!(
                "MCP 401 ({method} /mcp): invalid or expired bearer token"
            ));
            format!(
                "Bearer error=\"invalid_token\", error_description=\"A valid OAuth 2.1 bearer token is required\", resource_metadata=\"{base_url}/.well-known/oauth-protected-resource\", scope=\"{SCOPE}\""
            )
        };
        let mut response = json_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "A valid OAuth 2.1 bearer token is required",
        );
        if let Ok(value) = HeaderValue::from_str(&metadata) {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, value);
        }
        return response;
    }

    match *method {
        Method::OPTIONS => empty_response(StatusCode::NO_CONTENT),
        Method::DELETE => json_response(StatusCode::OK, &json!({})),
        Method::GET => {
            let mut response = empty_response(StatusCode::METHOD_NOT_ALLOWED);
            response.headers_mut().insert(
                header::ALLOW,
                HeaderValue::from_static("POST, DELETE, OPTIONS"),
            );
            response
        }
        Method::POST => mcp_post(state, body),
        _ => {
            let mut response = empty_response(StatusCode::METHOD_NOT_ALLOWED);
            response.headers_mut().insert(
                header::ALLOW,
                HeaderValue::from_static("POST, DELETE, OPTIONS"),
            );
            response
        }
    }
}

fn mcp_post(state: &AppState, body: &[u8]) -> Resp {
    if body.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Empty JSON-RPC body",
        );
    }
    let payload: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                &json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": "Parse error" }
                }),
            )
        }
    };

    match payload {
        Value::Array(messages) => {
            let mut responses = Vec::new();
            for message in &messages {
                if let Some(response) = handle_rpc(state, message) {
                    responses.push(response);
                }
            }
            if responses.is_empty() {
                empty_response(StatusCode::ACCEPTED)
            } else {
                json_response(StatusCode::OK, &Value::Array(responses))
            }
        }
        Value::Object(_) => match handle_rpc(state, &payload) {
            Some(response) => json_response(StatusCode::OK, &response),
            None => empty_response(StatusCode::ACCEPTED),
        },
        _ => json_response(
            StatusCode::OK,
            &rpc_error(Value::Null, -32600, "Invalid Request"),
        ),
    }
}

fn handle_rpc(state: &AppState, message: &Value) -> Option<Value> {
    let object = message.as_object()?;
    let method = object.get("method").and_then(Value::as_str).unwrap_or("");
    let id = object.get("id").cloned().filter(|value| !value.is_null());
    let params = object.get("params").cloned().unwrap_or(Value::Null);

    if method.is_empty() {
        return Some(rpc_error(
            id.unwrap_or(Value::Null),
            -32600,
            "Invalid Request",
        ));
    }

    // Any message without an id is a notification: acknowledge with 202 and
    // never write a JSON-RPC response.
    if id.is_none() || method.starts_with("notifications/") {
        return None;
    }
    let id = id.unwrap_or(Value::Null);

    let result = match method {
        "initialize" => {
            state.push_server_log("MCP initialize");
            let requested = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(LATEST_PROTOCOL_VERSION);
            let protocol_version = if MCP_PROTOCOL_VERSIONS.contains(&requested) {
                requested
            } else {
                LATEST_PROTOCOL_VERSION
            };
            Ok(json!({
                "protocolVersion": protocol_version,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": {
                    "name": "DeskPort",
                    "title": "DeskPort",
                    "version": VERSION,
                },
                "instructions": INSTRUCTIONS,
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => {
            state.push_server_log("MCP tools/list");
            Ok(json!({ "tools": tools::schemas() }))
        }
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let arguments = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            if name.is_empty() {
                Err((-32602, "Missing tool name".to_string()))
            } else if !tools::is_known(name) {
                Err((-32602, format!("Unknown tool: {name}")))
            } else {
                state.push_server_log(format!("MCP tools/call {name}"));
                let config: ServerConfig = state.config();
                let result = tools::call(&config, name, &arguments);
                Ok(json!({
                    "content": [{ "type": "text", "text": result.text }],
                    "isError": result.is_error,
                }))
            }
        }
        other => Err((-32601, format!("Method not found: {other}"))),
    };

    match result {
        Ok(result) => Some(json!({ "jsonrpc": "2.0", "id": id, "result": result })),
        Err((code, message)) => Some(rpc_error(id, code, &message)),
    }
}

fn rpc_error(id: Value, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WorkspaceItem;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn state() -> (tempfile::TempDir, Arc<AppState>) {
        let dir = tempfile::tempdir().unwrap();
        let mut state = AppState::open(dir.path()).unwrap();
        let mut config = state.config();
        config.workspaces = vec![WorkspaceItem {
            id: "work".into(),
            name: "Work".into(),
            path: dir.path().to_string_lossy().to_string(),
        }];
        config.default_workspace = "work".into();
        Arc::get_mut(&mut state).unwrap().replace_config(config);
        (dir, state.clone())
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

    async fn json_call(
        state: &Arc<AppState>,
        path: &str,
        body: Value,
        token: Option<&str>,
    ) -> HttpResponse {
        let mut extra: Vec<(&str, &str)> = Vec::new();
        let owned;
        if let Some(token) = token {
            owned = format!("Bearer {token}");
            extra.push((header::AUTHORIZATION.as_str(), owned.as_str()));
        }
        send(
            state,
            "POST",
            path,
            "application/json",
            &body.to_string(),
            &extra,
        )
        .await
    }

    fn seed_token(state: &AppState) -> String {
        let token = "test-access-token".to_string();
        state
            .db
            .save_token(&TokenRecord {
                token: token.clone(),
                token_type: "access".into(),
                client_id: Some("dp_test".into()),
                scope: SCOPE.into(),
                expires_at: Some(config::now_ms() + 60_000),
                created_at: config::now_ms(),
            })
            .unwrap();
        token
    }

    #[tokio::test]
    async fn service_descriptor_and_discovery_documents() {
        let (_dir, state) = state();
        let root = send(&state, "GET", "/", "", "", &[]).await;
        assert_eq!(root.status, StatusCode::OK);
        assert_eq!(root.json()["service"], "DeskPort");
        assert_eq!(root.json()["version"], VERSION);
        assert!(root.json()["mcp_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/mcp"));

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
        assert_eq!(resource.json()["resource_name"], "DeskPort");
        assert_eq!(resource.json()["scopes_supported"][0], "mcp:tools");

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
        assert_eq!(body["code_challenge_methods_supported"][0], "S256");
        assert_eq!(body["grant_types_supported"][1], "refresh_token");
        assert!(body["registration_endpoint"]
            .as_str()
            .unwrap()
            .ends_with("/oauth/register"));
    }

    #[tokio::test]
    async fn dynamic_registration_issues_prefixed_credentials() {
        let (_dir, state) = state();
        let response = json_call(
            &state,
            "/oauth/register",
            json!({"client_name": "Claude", "redirect_uris": ["http://127.0.0.1/cb"]}),
            None,
        )
        .await;
        assert_eq!(response.status, StatusCode::CREATED);
        let body = response.json();
        assert!(body["client_id"].as_str().unwrap().starts_with("dp_"));
        assert_eq!(body["client_id"].as_str().unwrap().len(), 27);
        assert_eq!(body["client_secret"].as_str().unwrap().len(), 48);
        assert_eq!(body["client_name"], "Claude");
        assert_eq!(body["token_endpoint_auth_method"], "none");
    }

    #[tokio::test]
    async fn authorize_page_escapes_untrusted_client_names() {
        let (_dir, state) = state();
        let payload = json!({"client_name": "<script>alert(\"xss\")</script>"});
        let registered = json_call(&state, "/oauth/register", payload, None).await;
        let client_id = registered.json()["client_id"].as_str().unwrap().to_string();
        let path = format!(
            "/oauth/authorize?client_id={client_id}&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb&state=xyz&code_challenge=abc&code_challenge_method=S256"
        );
        let page = send(&state, "GET", &path, "", "", &[]).await;
        assert_eq!(page.status, StatusCode::OK);
        assert!(page
            .body
            .contains("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"));
        assert!(!page.body.contains("<script>alert"));
        assert!(page.body.contains("Work"));
        assert!(page.body.contains("允许连接"));
        assert!(page.headers["content-type"]
            .to_str()
            .unwrap()
            .contains("text/html"));
    }

    #[tokio::test]
    async fn authorize_rejects_dangerous_redirect_schemes() {
        let (_dir, state) = state();
        let get = send(
            &state,
            "GET",
            "/oauth/authorize?redirect_uri=javascript%3Aalert(1)",
            "",
            "",
            &[],
        )
        .await;
        assert_eq!(get.status, StatusCode::BAD_REQUEST);

        let post = send(
            &state,
            "POST",
            "/oauth/authorize",
            "application/x-www-form-urlencoded",
            "decision=approve&redirect_uri=javascript%3Aalert(1)",
            &[],
        )
        .await;
        assert_eq!(post.status, StatusCode::BAD_REQUEST);
        assert!(post.headers.get(header::LOCATION).is_none());
    }

    #[tokio::test]
    async fn full_pkce_authorization_code_flow() {
        let (_dir, state) = state();
        let registered = json_call(
            &state,
            "/oauth/register",
            json!({"client_name": "Cursor"}),
            None,
        )
        .await;
        let client_id = registered.json()["client_id"].as_str().unwrap().to_string();

        let verifier = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let redirect_uri = "http://127.0.0.1:53682/callback";

        let form = format!(
            "decision=approve&client_id={client_id}&redirect_uri={}&state=st-1&code_challenge={challenge}&code_challenge_method=S256&scope=mcp%3Atools",
            url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>()
        );
        let approval = send(
            &state,
            "POST",
            "/oauth/authorize",
            "application/x-www-form-urlencoded",
            &form,
            &[],
        )
        .await;
        assert_eq!(approval.status, StatusCode::FOUND);
        let location = approval.headers[header::LOCATION]
            .to_str()
            .unwrap()
            .to_string();
        assert!(location.starts_with(redirect_uri));
        let parsed = url::Url::parse(&location).unwrap();
        let query: HashMap<String, String> = parsed.query_pairs().into_owned().collect();
        assert_eq!(query.get("state").map(String::as_str), Some("st-1"));
        let code = query.get("code").cloned().unwrap();

        let wrong = format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}&code_verifier=wrong-verifier",
            url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>()
        );
        let rejected = send(
            &state,
            "POST",
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &wrong,
            &[],
        )
        .await;
        assert_eq!(rejected.status, StatusCode::BAD_REQUEST);
        assert_eq!(rejected.json()["error"], "invalid_grant");

        // A failed PKCE check must not burn the code: the correct verifier
        // can still exchange it.
        let good = format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}&code_verifier={verifier}",
            url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>()
        );
        let granted = send(
            &state,
            "POST",
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &good,
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

        // Code replay is rejected.
        let replay = send(
            &state,
            "POST",
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &good,
            &[],
        )
        .await;
        assert_eq!(replay.status, StatusCode::BAD_REQUEST);

        // Refresh grant works and keeps the same refresh token.
        let refreshed = send(
            &state,
            "POST",
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &format!("grant_type=refresh_token&refresh_token={refresh}"),
            &[],
        )
        .await;
        assert_eq!(refreshed.status, StatusCode::OK);
        assert_eq!(refreshed.json()["refresh_token"], refresh);
        assert_ne!(refreshed.json()["access_token"], access);

        // JSON body tokens are supported too.
        let json_token = json_call(
            &state,
            "/oauth/token",
            json!({"grant_type": "refresh_token", "refresh_token": refresh}),
            None,
        )
        .await;
        assert_eq!(json_token.status, StatusCode::OK);

        let clients = state.snapshot().oauth;
        assert_eq!(clients.client_count, 1);
        assert!(clients.active_token_count >= 4);
    }

    #[tokio::test]
    async fn mcp_requires_a_valid_bearer_token() {
        let (_dir, state) = state();
        let missing = json_call(
            &state,
            "/mcp",
            json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
            None,
        )
        .await;
        assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
        assert!(missing.headers[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap()
            .contains("resource_metadata="));

        let bogus = json_call(
            &state,
            "/mcp",
            json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
            Some("not-a-token"),
        )
        .await;
        assert_eq!(bogus.status, StatusCode::UNAUTHORIZED);

        let token = seed_token(&state);
        state.db.revoke_token(&token).unwrap();
        let revoked = json_call(
            &state,
            "/mcp",
            json!({"jsonrpc":"2.0","id":1,"method":"ping"}),
            Some(&token),
        )
        .await;
        assert_eq!(revoked.status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn mcp_initializes_lists_eleven_tools_and_calls_them() {
        let (_dir, state) = state();
        let token = seed_token(&state);

        let init = json_call(
            &state,
            "/mcp",
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}
            }),
            Some(&token),
        )
        .await;
        assert_eq!(init.status, StatusCode::OK);
        assert_eq!(init.json()["result"]["protocolVersion"], "2025-06-18");
        assert!(init.json()["result"]["capabilities"]["tools"].is_object());
        assert_eq!(init.json()["result"]["serverInfo"]["name"], "DeskPort");

        let notified = json_call(
            &state,
            "/mcp",
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            Some(&token),
        )
        .await;
        assert_eq!(notified.status, StatusCode::ACCEPTED);
        assert!(notified.body.is_empty());

        let list = json_call(
            &state,
            "/mcp",
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            Some(&token),
        )
        .await;
        let tools_json = list.json();
        let tools = tools_json["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 11);
        for tool in tools {
            assert!(tool["description"].is_string());
            assert_eq!(tool["inputSchema"]["type"], "object");
            assert!(tool["annotations"].is_object());
        }
        let names: Vec<&str> = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, tools::TOOL_NAMES.to_vec());

        let called = json_call(
            &state,
            "/mcp",
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_workspaces", "arguments": {}}}),
            Some(&token),
        )
        .await;
        let text = called.json()["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(text.contains("defaultWorkspace"));
        assert!(text.contains("Work"));

        let write = json_call(
            &state,
            "/mcp",
            json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "write_files", "arguments": {"files": [{"filePath": "note.txt", "content": "hello mcp"}]}}}),
            Some(&token),
        )
        .await;
        assert_eq!(write.json()["result"]["isError"], false);

        let read = json_call(
            &state,
            "/mcp",
            json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "read_files", "arguments": {"filePaths": ["note.txt"]}}}),
            Some(&token),
        )
        .await;
        let text = read.json()["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_string();
        assert!(text.contains("hello mcp"));

        let denied = json_call(
            &state,
            "/mcp",
            json!({"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "read_file", "arguments": {"filePath": "../../outside.txt"}}}),
            Some(&token),
        )
        .await;
        let result = denied.json();
        assert_eq!(result["result"]["isError"], true);
        assert!(result["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Access denied"));

        let unknown = json_call(
            &state,
            "/mcp",
            json!({"jsonrpc": "2.0", "id": 7, "method": "resources/list"}),
            Some(&token),
        )
        .await;
        assert_eq!(unknown.json()["error"]["code"], -32601);

        let unknown_tool = json_call(
            &state,
            "/mcp",
            json!({"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "nope"}}),
            Some(&token),
        )
        .await;
        assert_eq!(unknown_tool.json()["error"]["code"], -32602);

        let batch = json_call(
            &state,
            "/mcp",
            json!([
                {"jsonrpc": "2.0", "id": 9, "method": "ping"},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 10, "method": "tools/list"}
            ]),
            Some(&token),
        )
        .await;
        assert_eq!(batch.status, StatusCode::OK);
        assert_eq!(batch.json().as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn mcp_methods_and_options_are_handled() {
        let (_dir, state) = state();
        let token = seed_token(&state);

        let options = send(&state, "OPTIONS", "/mcp", "", "", &[]).await;
        assert_eq!(options.status, StatusCode::NO_CONTENT);
        assert_eq!(options.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");

        let get = send(
            &state,
            "GET",
            "/mcp",
            "",
            "",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(get.status, StatusCode::METHOD_NOT_ALLOWED);
        assert!(get.headers[header::ALLOW]
            .to_str()
            .unwrap()
            .contains("POST"));

        let delete = send(
            &state,
            "DELETE",
            "/mcp",
            "",
            "",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(delete.status, StatusCode::OK);

        let missing = send(
            &state,
            "POST",
            "/mcp",
            "application/json",
            "",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(missing.status, StatusCode::BAD_REQUEST);

        let invalid = send(
            &state,
            "POST",
            "/mcp",
            "application/json",
            "{not json",
            &[("Authorization", &format!("Bearer {token}"))],
        )
        .await;
        assert_eq!(invalid.status, StatusCode::BAD_REQUEST);
        assert_eq!(invalid.json()["error"]["code"], -32700);
    }

    #[test]
    fn pkce_verification_handles_all_methods() {
        let verifier = "verifier-1234567890";
        let s256 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        assert!(verify_pkce(verifier, Some(&s256), Some("S256")));
        assert!(!verify_pkce("wrong", Some(&s256), Some("S256")));
        assert!(verify_pkce(
            "plain-value",
            Some("plain-value"),
            Some("plain")
        ));
        assert!(!verify_pkce("plain-value", Some("other"), Some("plain")));
        assert!(verify_pkce("", None, None));
        assert!(!verify_pkce("", Some("challenge"), Some("S256")));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn serve_answers_over_a_real_socket() {
        let (_dir, state) = state();
        let token = seed_token(&state);
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(serve(listener, Arc::clone(&state), shutdown_rx));

        let root_url = format!("http://127.0.0.1:{port}/");
        let root = tokio::task::spawn_blocking(move || {
            ureq::get(&root_url)
                .call()
                .map(|response| response.into_string().unwrap_or_default())
        })
        .await
        .unwrap()
        .expect("root request");
        assert!(root.contains("\"service\":\"DeskPort\""), "{root}");

        let mcp_url = format!("http://127.0.0.1:{port}/mcp");
        let ping = tokio::task::spawn_blocking(move || {
            ureq::post(&mcp_url)
                .set("Authorization", &format!("Bearer {token}"))
                .send_string("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}")
                .map(|response| response.into_string().unwrap_or_default())
        })
        .await
        .unwrap()
        .expect("mcp request");
        assert!(ping.contains("\"result\":{}"), "{ping}");

        let _ = shutdown_tx.send(());
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), task).await;
    }

    #[test]
    fn redirect_validation_blocks_scriptable_schemes() {
        assert!(validate_redirect_uri("http://127.0.0.1:1234/cb").is_ok());
        assert!(validate_redirect_uri("https://example.com/callback").is_ok());
        assert!(validate_redirect_uri("cursor://anysphere.cursor/callback").is_ok());
        assert!(validate_redirect_uri("javascript:alert(1)").is_err());
        assert!(validate_redirect_uri("data:text/html,<script>").is_err());
        assert!(validate_redirect_uri("file:///etc/passwd").is_err());
        assert!(validate_redirect_uri("").is_err());
    }

    #[tokio::test]
    async fn discovery_aliases_and_trailing_slashes_work() {
        let (_dir, state) = state();
        for path in [
            "/.well-known/openid-configuration",
            "/.well-known/openid-configuration/mcp",
            "/.well-known/oauth-authorization-server/mcp",
            "/mcp/.well-known/openid-configuration",
        ] {
            let res = send(&state, "GET", path, "", "", &[]).await;
            assert_eq!(res.status, StatusCode::OK, "path {path}");
            let body = res.json();
            assert_eq!(
                body["authorization_endpoint"],
                "http://127.0.0.1:3334/oauth/authorize"
            );
            assert_eq!(body["client_id_metadata_document_supported"], true);
        }

        let token = seed_token(&state);
        let slash_ping = json_call(
            &state,
            "/mcp/",
            json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
            Some(&token),
        )
        .await;
        assert_eq!(slash_ping.status, StatusCode::OK);
        assert_eq!(slash_ping.json()["result"], json!({}));
    }

    #[tokio::test]
    async fn authorize_page_csp_allows_cross_origin_redirect() {
        let (_dir, state) = state();
        let path = "/oauth/authorize?client_id=https%3A%2F%2Fchatgpt.com%2Fconnector&redirect_uri=https%3A%2F%2Fchatgpt.com%2Fconnector_platform_oauth_redirect&state=s1&code_challenge=abc&code_challenge_method=S256";
        let page = send(&state, "GET", path, "", "", &[]).await;
        assert_eq!(page.status, StatusCode::OK);
        let csp = page.headers["content-security-policy"].to_str().unwrap();
        assert!(!csp.contains("form-action"), "unexpected form-action: {csp}");
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
    }

    #[tokio::test]
    async fn confidential_client_supports_http_basic_auth() {
        let (_dir, state) = state();
        let reg = json_call(
            &state,
            "/oauth/register",
            json!({
                "client_name": "Confidential",
                "redirect_uris": ["https://chatgpt.com/callback"],
                "token_endpoint_auth_method": "client_secret_basic"
            }),
            None,
        )
        .await;
        assert_eq!(reg.status, StatusCode::CREATED);
        let reg_json = reg.json();
        assert_eq!(reg_json["token_endpoint_auth_method"], "client_secret_basic");
        let client_id = reg_json["client_id"].as_str().unwrap().to_string();
        let client_secret = reg_json["client_secret"].as_str().unwrap().to_string();

        let verifier = "basic-auth-verifier-0123456789abcdef";
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let redirect_uri = "https://chatgpt.com/callback";
        let form = format!(
            "decision=approve&client_id={client_id}&redirect_uri={}&state=st&code_challenge={challenge}&code_challenge_method=S256&scope=mcp%3Atools",
            url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>()
        );
        let approval = send(
            &state,
            "POST",
            "/oauth/authorize",
            "application/x-www-form-urlencoded",
            &form,
            &[],
        )
        .await;
        assert_eq!(approval.status, StatusCode::FOUND);
        let location = approval.headers[header::LOCATION].to_str().unwrap();
        let parsed = url::Url::parse(location).unwrap();
        let code = parsed
            .query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned();

        let bad_basic = base64::engine::general_purpose::STANDARD
            .encode(format!("{client_id}:wrong-secret"));
        let token_body = format!(
            "grant_type=authorization_code&code={code}&redirect_uri={}&code_verifier={verifier}",
            url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>()
        );
        let rejected = send(
            &state,
            "POST",
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &token_body,
            &[("Authorization", &format!("Basic {bad_basic}"))],
        )
        .await;
        assert_eq!(rejected.status, StatusCode::UNAUTHORIZED);
        assert_eq!(rejected.json()["error"], "invalid_client");

        let good_basic = base64::engine::general_purpose::STANDARD
            .encode(format!("{client_id}:{client_secret}"));
        let granted = send(
            &state,
            "POST",
            "/oauth/token",
            "application/x-www-form-urlencoded",
            &token_body,
            &[("Authorization", &format!("Basic {good_basic}"))],
        )
        .await;
        assert_eq!(granted.status, StatusCode::OK, "{}", granted.body);
        assert!(granted.json()["access_token"].is_string());
    }

    #[tokio::test]
    async fn cimd_approval_records_client_and_401_logs_reason() {
        let (_dir, state) = state();
        let unauthorized = json_call(
            &state,
            "/mcp",
            json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
            None,
        )
        .await;
        assert_eq!(unauthorized.status, StatusCode::UNAUTHORIZED);
        let www = unauthorized.headers[header::WWW_AUTHENTICATE]
            .to_str()
            .unwrap();
        assert!(www.contains("scope=\"mcp:tools\""), "{www}");
        assert!(state
            .snapshot()
            .server
            .logs
            .iter()
            .any(|line| line.contains("MCP 401")));

        let cimd_id = "https://chatgpt.com/.well-known/oauth-client.json";
        let redirect_uri = "https://chatgpt.com/connector_platform_oauth_redirect";
        let form = format!(
            "decision=approve&client_id={}&redirect_uri={}&scope=mcp%3Atools",
            url::form_urlencoded::byte_serialize(cimd_id.as_bytes()).collect::<String>(),
            url::form_urlencoded::byte_serialize(redirect_uri.as_bytes()).collect::<String>()
        );
        let approval = send(
            &state,
            "POST",
            "/oauth/authorize",
            "application/x-www-form-urlencoded",
            &form,
            &[],
        )
        .await;
        assert_eq!(approval.status, StatusCode::FOUND);
        let saved = state.db.get_client(cimd_id).unwrap().unwrap();
        assert_eq!(saved.client_name, "chatgpt.com");
    }
}
