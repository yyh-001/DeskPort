//! The 11 MCP tools plus the path-allow-list and cross-platform shell layer.
//!
//! Every filesystem entry point funnels through [`resolve_path`], which
//! lexically normalises the path, resolves existing prefixes with
//! `canonicalize` (so symlinks cannot escape) and finally compares the result
//! against the configured workspace roots.

use crate::config::{ServerConfig, ShellKind, WorkspaceItem};
use regex::{Regex, RegexBuilder};
use serde_json::{json, Value};
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const TOOL_NAMES: [&str; 11] = [
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
];

const SKIP_DIRS: [&str; 11] = [
    "node_modules",
    ".git",
    "__pycache__",
    ".next",
    "dist",
    "build",
    ".venv",
    "venv",
    "target",
    ".svn",
    ".idea",
];

const MAX_LIST_ENTRIES: usize = 300;
const MAX_SEARCH_FILES: usize = 2_000;
const MAX_SEARCH_FILE_BYTES: u64 = 512 * 1024;
const MAX_NAME_MATCHES: usize = 30;
const MAX_OUTPUT_CHARS: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    pub text: String,
    pub is_error: bool,
}

impl ToolResult {
    pub fn error(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            is_error: true,
        }
    }
}

type Outcome = Result<(String, bool), String>;

/// Execute one tool. Unknown names and invalid arguments come back as
/// `is_error` results, matching the MCP convention that tool failures are
/// content, not protocol errors.
pub fn call(cfg: &ServerConfig, name: &str, args: &Value) -> ToolResult {
    let null = Value::Null;
    let args = if args.is_null() { &null } else { args };
    let outcome = match name {
        "list_workspaces" => tool_list_workspaces(cfg),
        "list_files" => tool_list_files(cfg, args),
        "search_files" => tool_search_files(cfg, args),
        "read_file" => tool_read_file(cfg, args),
        "read_files" => tool_read_files(cfg, args),
        "write_file" => tool_write_file(cfg, args),
        "write_files" => tool_write_files(cfg, args),
        "edit_file" => tool_edit_file(cfg, args),
        "edit_files" => tool_edit_files(cfg, args),
        "delete_file" => tool_delete_file(cfg, args),
        "bash" => tool_bash(cfg, args),
        other => return ToolResult::error(format!("Unknown tool: {other}")),
    };
    match outcome {
        Ok((text, is_error)) => ToolResult { text, is_error },
        Err(message) => ToolResult::error(message),
    }
}

pub fn is_known(name: &str) -> bool {
    TOOL_NAMES.contains(&name)
}

/// Full `tools/list` payload: JSON schemas plus MCP annotations.
pub fn schemas() -> Vec<Value> {
    let workspace = json!({
        "type": "string",
        "description": "Optional workspace id or name from list_workspaces"
    });
    let file_path = json!({
        "type": "string",
        "description": "File path, relative to the workspace or absolute"
    });

    vec![
        json!({
            "name": "list_workspaces",
            "description": "List every configured local workspace, which one is the default, and whether access is restricted to the allow-list.",
            "inputSchema": {"type": "object", "properties": {}},
            "annotations": annotations(true, false, true, false),
        }),
        json!({
            "name": "list_files",
            "description": "List files and subdirectories of a connected folder. Use depth 2 or 3 for a fast tree view in a single call.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": workspace,
                    "dirPath": {"type": "string", "description": "Directory path relative to the workspace (default '.')"},
                    "depth": {"type": "integer", "minimum": 1, "maximum": 3, "description": "Recursion depth (default 1, max 3)"}
                }
            },
            "annotations": annotations(true, false, true, false),
        }),
        json!({
            "name": "search_files",
            "description": "Fast in-process search for file names and text content across a workspace. Skips node_modules, .git and binary files.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Text or regular expression to search for"},
                    "workspace": workspace,
                    "dirPath": {"type": "string", "description": "Subdirectory to scope the search (default '.')"},
                    "filePattern": {"type": "string", "description": "Optional filename glob such as '*.rs' or '*.md'"},
                    "isRegex": {"type": "boolean", "description": "Treat query as a regular expression (default false)"},
                    "maxResults": {"type": "integer", "minimum": 1, "maximum": 100, "description": "Max content matches (default 50)"}
                },
                "required": ["query"]
            },
            "annotations": annotations(true, false, true, false),
        }),
        json!({
            "name": "read_file",
            "description": "Read a UTF-8 text file, optionally limited to a 1-based line range.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": workspace,
                    "filePath": file_path,
                    "startLine": {"type": "integer", "minimum": 1, "description": "Optional 1-based first line"},
                    "endLine": {"type": "integer", "minimum": 1, "description": "Optional 1-based last line (inclusive)"}
                },
                "required": ["filePath"]
            },
            "annotations": annotations(true, false, true, false),
        }),
        json!({
            "name": "read_files",
            "description": "Read multiple text files in one round-trip (up to 10). Prefer this over repeated read_file calls.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": workspace,
                    "filePaths": {"type": "array", "minItems": 1, "maxItems": 10, "items": {"type": "string"}},
                    "maxCharsPerFile": {"type": "integer", "minimum": 200, "maximum": 20000, "description": "Max characters per file (default 6000)"}
                },
                "required": ["filePaths"]
            },
            "annotations": annotations(true, false, true, false),
        }),
        json!({
            "name": "write_file",
            "description": "Create or overwrite a UTF-8 text file. Parent directories are created automatically.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": workspace,
                    "filePath": file_path,
                    "content": {"type": "string", "description": "Full UTF-8 content to write"}
                },
                "required": ["filePath", "content"]
            },
            "annotations": annotations(false, true, true, false),
        }),
        json!({
            "name": "write_files",
            "description": "Create or overwrite multiple UTF-8 text files in one round-trip (up to 20). Prefer this over repeated write_file calls.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": workspace,
                    "files": {
                        "type": "array", "minItems": 1, "maxItems": 20,
                        "items": {
                            "type": "object",
                            "properties": {
                                "filePath": {"type": "string"},
                                "content": {"type": "string"}
                            },
                            "required": ["filePath", "content"]
                        }
                    }
                },
                "required": ["files"]
            },
            "annotations": annotations(false, true, true, false),
        }),
        json!({
            "name": "edit_file",
            "description": "Replace an exact text block inside a UTF-8 text file.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": workspace,
                    "filePath": file_path,
                    "target": {"type": "string", "description": "Exact text to search for"},
                    "replacement": {"type": "string", "description": "Replacement text"},
                    "replaceAll": {"type": "boolean", "description": "Replace every occurrence (default false)"}
                },
                "required": ["filePath", "target", "replacement"]
            },
            "annotations": annotations(false, true, false, false),
        }),
        json!({
            "name": "edit_files",
            "description": "Apply exact-text replacements to multiple files in one round-trip (up to 20 edits, applied in order). Prefer this over repeated edit_file calls.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": workspace,
                    "edits": {
                        "type": "array", "minItems": 1, "maxItems": 20,
                        "items": {
                            "type": "object",
                            "properties": {
                                "filePath": {"type": "string"},
                                "target": {"type": "string"},
                                "replacement": {"type": "string"},
                                "replaceAll": {"type": "boolean"}
                            },
                            "required": ["filePath", "target", "replacement"]
                        }
                    }
                },
                "required": ["edits"]
            },
            "annotations": annotations(false, true, false, false),
        }),
        json!({
            "name": "delete_file",
            "description": "Delete a single local file. Directories are refused.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workspace": workspace,
                    "filePath": file_path
                },
                "required": ["filePath"]
            },
            "annotations": annotations(false, true, false, false),
        }),
        json!({
            "name": "bash",
            "description": "Execute a shell command locally. Windows auto-detects Git Bash then PowerShell; macOS/Linux use $SHELL. Timeouts kill the whole process tree.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Command string to execute"},
                    "workspace": workspace,
                    "cwd": {"type": "string", "description": "Working directory, relative to the workspace or absolute (default '.')"},
                    "shell": {
                        "type": "string",
                        "enum": ["auto", "bash", "powershell", "cmd", "zsh", "sh"],
                        "description": "Shell override (default: the configured default shell)"
                    },
                    "timeoutSec": {"type": "integer", "minimum": 5, "maximum": 300, "description": "Timeout in seconds (default 60)"},
                    "gui": {"type": "boolean", "description": "Keep windows visible on Windows when launching GUI apps (default false)"}
                },
                "required": ["command"]
            },
            "annotations": annotations(false, true, false, true),
        }),
    ]
}

fn annotations(read_only: bool, destructive: bool, idempotent: bool, open_world: bool) -> Value {
    json!({
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        "openWorldHint": open_world,
    })
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

fn opt_string(args: &Value, key: &str) -> Result<Option<String>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("Invalid parameter `{key}`: expected a string")),
    }
}

fn required_string(args: &Value, key: &str) -> Result<String, String> {
    match opt_string(args, key)? {
        Some(value) if !value.trim().is_empty() => Ok(value),
        Some(_) => Err(format!("Parameter `{key}` must not be empty")),
        None => Err(format!("Missing required parameter `{key}`")),
    }
}

fn opt_bool(args: &Value, key: &str) -> Result<bool, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(format!("Invalid parameter `{key}`: expected a boolean")),
    }
}

fn opt_u64(args: &Value, key: &str) -> Result<Option<u64>, String> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(number)) => number
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("Invalid parameter `{key}`: expected a positive integer")),
        Some(_) => Err(format!(
            "Invalid parameter `{key}`: expected a positive integer"
        )),
    }
}

fn required_string_array(args: &Value, key: &str) -> Result<Vec<String>, String> {
    let array = args
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("Missing required parameter `{key}`"))?;
    array
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or_else(|| format!("Each entry of `{key}` must be a string"))
        })
        .collect()
}

fn required_object_array<'a>(args: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    args.get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("Missing required parameter `{key}`"))
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

// ---------------------------------------------------------------------------
// Path resolution & allow-list
// ---------------------------------------------------------------------------

pub fn find_workspace<'a>(
    cfg: &'a ServerConfig,
    reference: Option<&str>,
) -> Result<&'a WorkspaceItem, String> {
    match reference.map(str::trim).filter(|value| !value.is_empty()) {
        Some(reference) => {
            let wanted = reference.to_lowercase();
            cfg.workspaces
                .iter()
                .find(|w| w.id.to_lowercase() == wanted || w.name.to_lowercase() == wanted)
                .ok_or_else(|| {
                    let available = cfg
                        .workspaces
                        .iter()
                        .map(|w| format!("{} ({})", w.id, w.path))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("Unknown workspace \"{reference}\". Available workspaces: {available}")
                })
        }
        None => cfg
            .default_workspace()
            .ok_or_else(|| "No workspace configured".to_string()),
    }
}

/// Resolve a user supplied path against a workspace and enforce the allow-list.
pub fn resolve_path(
    cfg: &ServerConfig,
    workspace: Option<&str>,
    input: &str,
) -> Result<PathBuf, String> {
    let workspace = find_workspace(cfg, workspace)?;
    let raw = input.trim();
    let raw = if raw.is_empty() { "." } else { raw };
    let raw_path = Path::new(raw);

    let joined = if raw_path.is_absolute() || raw_path.has_root() {
        raw_path.to_path_buf()
    } else {
        Path::new(&workspace.path).join(raw_path)
    };

    let target = canonicalize_best(&joined);

    if cfg.restrict_to_workspaces {
        let allowed = cfg
            .workspaces
            .iter()
            .any(|w| is_within(&canonicalize_best(Path::new(&w.path)), &target));
        if !allowed {
            let roots = cfg
                .workspaces
                .iter()
                .map(|w| format!("{}: {}", w.id, w.path))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(format!(
                "Access denied: path \"{}\" is outside whitelisted workspaces ({roots})",
                target.display()
            ));
        }
    }

    Ok(target)
}

/// Resolve every existing ancestor with `canonicalize`, then append the
/// remaining (not yet created) components.
pub fn canonicalize_best(path: &Path) -> PathBuf {
    let mut current = path.to_path_buf();
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(canonical) = current.canonicalize() {
            let mut resolved = canonical;
            for part in suffix.iter().rev() {
                resolved.push(part);
            }
            return resolved;
        }
        match current.file_name() {
            Some(name) => {
                suffix.push(name.to_os_string());
                if !current.pop() {
                    break;
                }
            }
            None => break,
        }
    }
    normalize_lexically(path)
}

fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn norm_string(path: &Path) -> String {
    let raw = path.to_string_lossy();
    #[cfg(windows)]
    {
        let mut value = raw.replace('/', "\\");
        while value.len() > 3 && value.ends_with('\\') {
            value.pop();
        }
        value.to_lowercase()
    }
    #[cfg(not(windows))]
    {
        let mut value = raw.to_string();
        while value.len() > 1 && value.ends_with('/') {
            value.pop();
        }
        value
    }
}

pub fn is_within(root: &Path, target: &Path) -> bool {
    let root = norm_string(root);
    let target = norm_string(target);
    if root == target {
        return true;
    }
    if root == "/" {
        return target.starts_with('/');
    }
    #[cfg(windows)]
    {
        target.starts_with(&format!("{root}\\"))
    }
    #[cfg(not(windows))]
    {
        target.starts_with(&format!("{root}/"))
    }
}

// ---------------------------------------------------------------------------
// list_workspaces
// ---------------------------------------------------------------------------

fn tool_list_workspaces(cfg: &ServerConfig) -> Outcome {
    let workspaces: Vec<Value> = cfg
        .workspaces
        .iter()
        .map(|w| {
            json!({
                "id": w.id,
                "name": w.name,
                "path": w.path,
                "isDefault": w.id == cfg.default_workspace,
            })
        })
        .collect();
    let value = json!({
        "defaultWorkspace": cfg.default_workspace,
        "restrictToWorkspaces": cfg.restrict_to_workspaces,
        "workspaces": workspaces,
    });
    Ok((pretty(&value), false))
}

// ---------------------------------------------------------------------------
// list_files
// ---------------------------------------------------------------------------

fn tool_list_files(cfg: &ServerConfig, args: &Value) -> Outcome {
    let workspace = opt_string(args, "workspace")?;
    let dir_path = opt_string(args, "dirPath")?.unwrap_or_else(|| ".".to_string());
    let depth = opt_u64(args, "depth")?.unwrap_or(1).clamp(1, 3);
    let target = resolve_path(cfg, workspace.as_deref(), &dir_path)?;
    if !target.is_dir() {
        return Err(format!("Not a directory: {}", target.display()));
    }

    let mut lines = Vec::new();
    let mut count = 0usize;
    collect_tree(&target, depth as u32, "", &mut lines, &mut count)?;
    let body = if lines.is_empty() {
        "(empty)".to_string()
    } else {
        lines.join("\n")
    };
    Ok((format!("Directory: {}\n\n{body}", target.display()), false))
}

fn collect_tree(
    dir: &Path,
    depth: u32,
    prefix: &str,
    lines: &mut Vec<String>,
    count: &mut usize,
) -> Result<(), String> {
    if *count >= MAX_LIST_ENTRIES {
        lines.push(format!(
            "{prefix}... (truncated at {MAX_LIST_ENTRIES} entries)"
        ));
        return Ok(());
    }
    let read_dir =
        fs::read_dir(dir).map_err(|err| format!("Cannot list {}: {err}", dir.display()))?;
    let mut entries: Vec<fs::DirEntry> = read_dir.filter_map(|entry| entry.ok()).collect();
    entries.sort_by(|a, b| {
        let a_dir = a.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let b_dir = b.file_type().map(|t| t.is_dir()).unwrap_or(false);
        b_dir.cmp(&a_dir).then_with(|| {
            a.file_name()
                .to_string_lossy()
                .to_lowercase()
                .cmp(&b.file_name().to_string_lossy().to_lowercase())
        })
    });

    for entry in entries {
        if *count >= MAX_LIST_ENTRIES {
            lines.push(format!(
                "{prefix}... (truncated at {MAX_LIST_ENTRIES} entries)"
            ));
            break;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir && depth > 1 && SKIP_DIRS.contains(&name.as_str()) {
            lines.push(format!("{prefix}[DIR]  {name}/ (skipped)"));
            *count += 1;
            continue;
        }
        lines.push(format!(
            "{prefix}{} {name}",
            if is_dir { "[DIR] " } else { "[FILE]" }
        ));
        *count += 1;
        if is_dir && depth > 1 {
            let _ = collect_tree(
                &entry.path(),
                depth - 1,
                &format!("{prefix}  "),
                lines,
                count,
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// search_files
// ---------------------------------------------------------------------------

enum Matcher {
    Text(String),
    Regex(Regex),
}

impl Matcher {
    fn matches(&self, value: &str) -> bool {
        match self {
            Matcher::Text(needle) => value.to_lowercase().contains(needle.as_str()),
            Matcher::Regex(regex) => regex.is_match(value),
        }
    }
}

#[derive(Default)]
struct SearchState {
    scanned: usize,
    names: Vec<String>,
    content: Vec<String>,
}

fn tool_search_files(cfg: &ServerConfig, args: &Value) -> Outcome {
    let query = required_string(args, "query")?;
    let workspace = opt_string(args, "workspace")?;
    let dir_path = opt_string(args, "dirPath")?.unwrap_or_else(|| ".".to_string());
    let file_pattern = opt_string(args, "filePattern")?;
    let is_regex = opt_bool(args, "isRegex")?;
    let max_results = opt_u64(args, "maxResults")?.unwrap_or(50).clamp(1, 100) as usize;

    let root = resolve_path(cfg, workspace.as_deref(), &dir_path)?;
    if !root.is_dir() {
        return Err(format!("Not a directory: {}", root.display()));
    }

    let matcher = if is_regex {
        Matcher::Regex(
            RegexBuilder::new(&query)
                .case_insensitive(true)
                .build()
                .map_err(|err| format!("Invalid regex: {err}"))?,
        )
    } else {
        Matcher::Text(query.to_lowercase())
    };

    let pattern = match file_pattern.as_deref().map(str::trim) {
        Some(pattern) if !pattern.is_empty() => Some(
            RegexBuilder::new(&glob_to_regex(pattern))
                .case_insensitive(true)
                .build()
                .map_err(|err| format!("Invalid filePattern: {err}"))?,
        ),
        _ => None,
    };

    let mut state = SearchState::default();
    walk_search(
        &root,
        &root,
        pattern.as_ref(),
        &matcher,
        max_results,
        &mut state,
    );

    let mut parts = vec![format!(
        "Search \"{query}\" in {} (scanned {} files)",
        root.display(),
        state.scanned
    )];
    if state.names.is_empty() {
        parts.push("\nFilename matches: none".to_string());
    } else {
        parts.push(format!(
            "\nFilename matches ({}):\n{}",
            state.names.len(),
            state.names.join("\n")
        ));
    }
    if state.content.is_empty() {
        parts.push("\nNo content matches.".to_string());
    } else {
        parts.push(format!(
            "\nContent matches ({}):\n{}",
            state.content.len(),
            state.content.join("\n")
        ));
    }
    Ok((parts.join("\n"), false))
}

fn walk_search(
    root: &Path,
    dir: &Path,
    pattern: Option<&Regex>,
    matcher: &Matcher,
    max_results: usize,
    state: &mut SearchState,
) {
    if state.content.len() >= max_results || state.scanned >= MAX_SEARCH_FILES {
        return;
    }
    let read_dir = match fs::read_dir(dir) {
        Ok(read_dir) => read_dir,
        Err(_) => return,
    };
    let mut entries: Vec<fs::DirEntry> = read_dir.filter_map(|entry| entry.ok()).collect();
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        if state.content.len() >= max_results || state.scanned >= MAX_SEARCH_FILES {
            return;
        }
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };
        if file_type.is_dir() {
            if SKIP_DIRS.contains(&entry.file_name().to_string_lossy().as_ref()) {
                continue;
            }
            walk_search(root, &path, pattern, matcher, max_results, state);
            continue;
        }
        if !file_type.is_file() {
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .unwrap_or(path.as_path())
            .to_string_lossy()
            .replace('\\', "/");

        if let Some(pattern) = pattern {
            let name = entry.file_name().to_string_lossy().to_string();
            if !pattern.is_match(&name) && !pattern.is_match(&relative) {
                continue;
            }
        }

        if state.names.len() < MAX_NAME_MATCHES && matcher.matches(&relative) {
            state.names.push(relative.clone());
        }

        state.scanned += 1;

        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.len() > MAX_SEARCH_FILE_BYTES {
            continue;
        }
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        if bytes.contains(&0) {
            continue;
        }
        let text = String::from_utf8_lossy(&bytes);
        for (index, line) in text.lines().enumerate() {
            if state.content.len() >= max_results {
                break;
            }
            if matcher.matches(line) {
                let trimmed = line.trim();
                let snippet: String = if trimmed.chars().count() > 180 {
                    format!("{}…", trimmed.chars().take(180).collect::<String>())
                } else {
                    trimmed.to_string()
                };
                state
                    .content
                    .push(format!("{relative}:{}: {snippet}", index + 1));
            }
        }
    }
}

fn glob_to_regex(pattern: &str) -> String {
    let mut out = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            other => out.push_str(&regex::escape(&other.to_string())),
        }
    }
    out.push('$');
    out
}

// ---------------------------------------------------------------------------
// read_file / read_files
// ---------------------------------------------------------------------------

fn read_text(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|err| format!("Cannot read {}: {err}", path.display()))?;
    Ok(String::from_utf8_lossy(&bytes).to_string())
}

fn tool_read_file(cfg: &ServerConfig, args: &Value) -> Outcome {
    let workspace = opt_string(args, "workspace")?;
    let file_path = required_string(args, "filePath")?;
    let start_line = opt_u64(args, "startLine")?;
    let end_line = opt_u64(args, "endLine")?;

    let target = resolve_path(cfg, workspace.as_deref(), &file_path)?;
    let raw = read_text(&target)?;
    let lines: Vec<&str> = raw.lines().collect();
    let total = lines.len();

    let start = start_line.unwrap_or(1).max(1) as usize;
    let start = if total == 0 { 1 } else { start.min(total) };
    let end = end_line.unwrap_or(total as u64).max(start as u64) as usize;
    let end = end.min(total);

    let body = if total == 0 {
        String::new()
    } else {
        lines[start - 1..end]
            .iter()
            .enumerate()
            .map(|(offset, line)| format!("{}: {line}", start + offset))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let body = truncate_chars(&body, cfg.max_output_chars);
    let shown_end = if total == 0 { 0 } else { end };
    Ok((
        format!(
            "File: {} (lines {start}-{shown_end} of {total})\n\n{body}",
            target.display()
        ),
        false,
    ))
}

fn tool_read_files(cfg: &ServerConfig, args: &Value) -> Outcome {
    let workspace = opt_string(args, "workspace")?;
    let file_paths = required_string_array(args, "filePaths")?;
    if file_paths.is_empty() || file_paths.len() > 10 {
        return Err("`filePaths` must contain between 1 and 10 entries".to_string());
    }
    let max_chars = opt_u64(args, "maxCharsPerFile")?
        .unwrap_or(6000)
        .clamp(200, 20_000) as usize;

    let mut blocks = Vec::new();
    for file_path in &file_paths {
        match resolve_path(cfg, workspace.as_deref(), file_path)
            .and_then(|target| read_text(&target).map(|raw| (target, raw)))
        {
            Ok((target, raw)) => {
                let body = if raw.chars().count() > max_chars {
                    format!("{}\n...[truncated]", truncate_chars(&raw, max_chars))
                } else {
                    raw
                };
                blocks.push(format!(
                    "=== {} ({}) ===\n{body}",
                    file_path,
                    target.display()
                ));
            }
            Err(err) => blocks.push(format!("=== {file_path} (ERROR) ===\n{err}")),
        }
    }
    Ok((blocks.join("\n\n"), false))
}

// ---------------------------------------------------------------------------
// write_file / write_files
// ---------------------------------------------------------------------------

fn write_text(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("Cannot create {}: {err}", parent.display()))?;
    }
    fs::write(path, content.as_bytes())
        .map_err(|err| format!("Cannot write {}: {err}", path.display()))
}

fn tool_write_file(cfg: &ServerConfig, args: &Value) -> Outcome {
    let workspace = opt_string(args, "workspace")?;
    let file_path = required_string(args, "filePath")?;
    let content = opt_string(args, "content")?
        .ok_or_else(|| "Missing required parameter `content`".to_string())?;

    let target = resolve_path(cfg, workspace.as_deref(), &file_path)?;
    write_text(&target, &content)?;
    Ok((
        format!(
            "Wrote {} chars to {}",
            content.chars().count(),
            target.display()
        ),
        false,
    ))
}

fn parse_file_entries(
    args: &Value,
    key: &str,
    max: usize,
) -> Result<Vec<(String, String)>, String> {
    let entries = required_object_array(args, key)?;
    if entries.is_empty() || entries.len() > max {
        return Err(format!("`{key}` must contain between 1 and {max} entries"));
    }
    entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let file_path = entry
                .get("filePath")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{key}[{index}].filePath must be a string"))?;
            let content = entry
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{key}[{index}].content must be a string"))?;
            Ok((file_path.to_string(), content.to_string()))
        })
        .collect()
}

fn tool_write_files(cfg: &ServerConfig, args: &Value) -> Outcome {
    let workspace = opt_string(args, "workspace")?;
    let files = parse_file_entries(args, "files", 20)?;

    let mut lines = Vec::new();
    let mut failed = 0usize;
    for (file_path, content) in &files {
        match resolve_path(cfg, workspace.as_deref(), file_path)
            .and_then(|target| write_text(&target, content).map(|()| target))
        {
            Ok(target) => lines.push(format!(
                "OK   {} ({} chars)",
                target.display(),
                content.chars().count()
            )),
            Err(err) => {
                failed += 1;
                lines.push(format!("FAIL {file_path}: {err}"));
            }
        }
    }
    Ok((
        format!(
            "Wrote {}/{} files\n{}",
            files.len() - failed,
            files.len(),
            lines.join("\n")
        ),
        failed == files.len(),
    ))
}

// ---------------------------------------------------------------------------
// edit_file / edit_files
// ---------------------------------------------------------------------------

fn apply_edit(
    cfg: &ServerConfig,
    workspace: Option<&str>,
    file_path: &str,
    target_text: &str,
    replacement: &str,
    replace_all: bool,
) -> Result<PathBuf, String> {
    if target_text.is_empty() {
        return Err("Target text must not be empty".to_string());
    }
    let target = resolve_path(cfg, workspace, file_path)?;
    let bytes =
        fs::read(&target).map_err(|err| format!("Cannot read {}: {err}", target.display()))?;
    let content = String::from_utf8(bytes)
        .map_err(|_| format!("File is not valid UTF-8: {}", target.display()))?;
    if !content.contains(target_text) {
        return Err(format!("Target text not found in {}", target.display()));
    }
    let updated = if replace_all {
        content.replace(target_text, replacement)
    } else {
        content.replacen(target_text, replacement, 1)
    };
    fs::write(&target, updated.as_bytes())
        .map_err(|err| format!("Cannot write {}: {err}", target.display()))?;
    Ok(target)
}

fn tool_edit_file(cfg: &ServerConfig, args: &Value) -> Outcome {
    let workspace = opt_string(args, "workspace")?;
    let file_path = required_string(args, "filePath")?;
    let target_text = required_string(args, "target")?;
    let replacement = opt_string(args, "replacement")?.unwrap_or_default();
    let replace_all = opt_bool(args, "replaceAll")?;

    let target = apply_edit(
        cfg,
        workspace.as_deref(),
        &file_path,
        &target_text,
        &replacement,
        replace_all,
    )?;
    Ok((format!("Updated {}", target.display()), false))
}

fn tool_edit_files(cfg: &ServerConfig, args: &Value) -> Outcome {
    let workspace = opt_string(args, "workspace")?;
    let edits = required_object_array(args, "edits")?;
    if edits.is_empty() || edits.len() > 20 {
        return Err("`edits` must contain between 1 and 20 entries".to_string());
    }

    let mut lines = Vec::new();
    let mut failed = 0usize;
    for (index, entry) in edits.iter().enumerate() {
        let file_path = entry
            .get("filePath")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("edits[{index}].filePath must be a string"))?;
        let target_text = entry
            .get("target")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("edits[{index}].target must be a string"))?;
        let replacement = entry
            .get("replacement")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let replace_all = entry
            .get("replaceAll")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        match apply_edit(
            cfg,
            workspace.as_deref(),
            file_path,
            target_text,
            replacement,
            replace_all,
        ) {
            Ok(target) => lines.push(format!("OK   {}", target.display())),
            Err(err) => {
                failed += 1;
                lines.push(format!("FAIL {file_path}: {err}"));
            }
        }
    }
    Ok((
        format!(
            "Applied {}/{} edits\n{}",
            edits.len() - failed,
            edits.len(),
            lines.join("\n")
        ),
        failed == edits.len(),
    ))
}

// ---------------------------------------------------------------------------
// delete_file
// ---------------------------------------------------------------------------

fn tool_delete_file(cfg: &ServerConfig, args: &Value) -> Outcome {
    let workspace = opt_string(args, "workspace")?;
    let file_path = required_string(args, "filePath")?;
    let target = resolve_path(cfg, workspace.as_deref(), &file_path)?;
    let metadata =
        fs::metadata(&target).map_err(|err| format!("Cannot stat {}: {err}", target.display()))?;
    if metadata.is_dir() {
        return Err(format!(
            "Refusing to delete a directory: {}",
            target.display()
        ));
    }
    fs::remove_file(&target).map_err(|err| format!("Cannot delete {}: {err}", target.display()))?;
    Ok((format!("Deleted {}", target.display()), false))
}

// ---------------------------------------------------------------------------
// bash
// ---------------------------------------------------------------------------

struct ShellSpec {
    exe: PathBuf,
    args: Vec<String>,
    name: String,
}

fn script_spec(exe: PathBuf, command: &str) -> ShellSpec {
    let name = exe
        .file_stem()
        .map(|stem| stem.to_string_lossy().to_string())
        .unwrap_or_else(|| "sh".to_string());
    ShellSpec {
        exe,
        args: vec!["-c".to_string(), command.to_string()],
        name,
    }
}

fn powershell_spec(command: &str) -> ShellSpec {
    let prefix = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; $OutputEncoding=[System.Text.Encoding]::UTF8; ";
    ShellSpec {
        exe: PathBuf::from("powershell.exe"),
        args: vec![
            "-NoProfile".to_string(),
            "-ExecutionPolicy".to_string(),
            "Bypass".to_string(),
            "-Command".to_string(),
            format!("{prefix}{command}"),
        ],
        name: "powershell".to_string(),
    }
}

fn find_git_bash() -> Option<PathBuf> {
    let candidates = [
        "C:\\Program Files\\Git\\bin\\bash.exe",
        "C:\\Program Files\\Git\\usr\\bin\\bash.exe",
        "C:\\Program Files (x86)\\Git\\bin\\bash.exe",
        "C:\\Program Files (x86)\\Git\\usr\\bin\\bash.exe",
    ];
    for candidate in candidates {
        let path = PathBuf::from(candidate);
        if path.is_file() {
            return Some(path);
        }
    }
    which("bash")
}

fn resolve_shell(
    cfg: &ServerConfig,
    requested: Option<ShellKind>,
    command: &str,
) -> Result<ShellSpec, String> {
    let requested = requested.unwrap_or(cfg.default_shell);
    match requested {
        ShellKind::Auto => {
            if cfg!(windows) {
                if let Some(bash) = find_git_bash() {
                    return Ok(script_spec(bash, command));
                }
                Ok(powershell_spec(command))
            } else {
                let mut candidates: Vec<PathBuf> = Vec::new();
                if let Some(shell) = std::env::var_os("SHELL") {
                    candidates.push(PathBuf::from(shell));
                }
                candidates.push(PathBuf::from("/bin/bash"));
                candidates.push(PathBuf::from("/bin/sh"));
                match candidates.into_iter().find(|path| path.is_file()) {
                    Some(shell) => Ok(script_spec(shell, command)),
                    None => Err("No usable shell found ($SHELL, /bin/bash, /bin/sh)".to_string()),
                }
            }
        }
        ShellKind::Bash => {
            let exe = if cfg!(windows) {
                find_git_bash().ok_or_else(|| {
                    "Git Bash was not found. Install Git for Windows or pick another shell."
                        .to_string()
                })?
            } else {
                which("bash").ok_or_else(|| "bash was not found in PATH".to_string())?
            };
            Ok(script_spec(exe, command))
        }
        ShellKind::Zsh => {
            let exe = which("zsh").ok_or_else(|| "zsh was not found in PATH".to_string())?;
            Ok(script_spec(exe, command))
        }
        ShellKind::Sh => {
            let exe = which("sh").ok_or_else(|| "sh was not found in PATH".to_string())?;
            Ok(script_spec(exe, command))
        }
        ShellKind::Powershell => {
            #[cfg(windows)]
            {
                Ok(powershell_spec(command))
            }
            #[cfg(not(windows))]
            {
                Err("powershell is only available on Windows".to_string())
            }
        }
        ShellKind::Cmd => {
            #[cfg(windows)]
            {
                Ok(ShellSpec {
                    exe: PathBuf::from("cmd.exe"),
                    args: vec![
                        "/d".to_string(),
                        "/s".to_string(),
                        "/c".to_string(),
                        format!("chcp 65001>nul & {command}"),
                    ],
                    name: "cmd".to_string(),
                })
            }
            #[cfg(not(windows))]
            {
                Err("cmd is only available on Windows".to_string())
            }
        }
    }
}

pub fn which(name: &str) -> Option<PathBuf> {
    let candidate = if cfg!(windows) && !name.to_ascii_lowercase().ends_with(".exe") {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(&candidate))
        .find(|path| path.is_file())
}

fn tool_bash(cfg: &ServerConfig, args: &Value) -> Outcome {
    let command = required_string(args, "command")?;
    let workspace = opt_string(args, "workspace")?;
    let cwd = opt_string(args, "cwd")?.unwrap_or_else(|| ".".to_string());
    let shell = match opt_string(args, "shell")? {
        Some(raw) => Some(ShellKind::parse(&raw).ok_or_else(|| {
            format!("Unknown shell \"{raw}\"; expected auto|bash|powershell|cmd|zsh|sh")
        })?),
        None => None,
    };
    let timeout_sec = opt_u64(args, "timeoutSec")?
        .unwrap_or(cfg.default_timeout_sec)
        .clamp(5, 300);
    let gui = opt_bool(args, "gui")?;

    let work_dir = resolve_path(cfg, workspace.as_deref(), &cwd)?;
    if !work_dir.is_dir() {
        return Err(format!(
            "Working directory does not exist: {}",
            work_dir.display()
        ));
    }
    let spec = resolve_shell(cfg, shell, &command)?;
    Ok(run_shell(cfg, spec, work_dir, timeout_sec, gui))
}

fn run_shell(
    cfg: &ServerConfig,
    spec: ShellSpec,
    work_dir: PathBuf,
    timeout_sec: u64,
    gui: bool,
) -> (String, bool) {
    let started = Instant::now();
    let mut command = Command::new(&spec.exe);
    command
        .args(&spec.args)
        .current_dir(&work_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        if !gui {
            command.creation_flags(CREATE_NO_WINDOW);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let _ = gui;
    let _ = cfg!(windows);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            let result = json!({
                "exitCode": -1,
                "timedOut": false,
                "shell": spec.name,
                "cwd": work_dir.to_string_lossy(),
                "durationMs": started.elapsed().as_millis() as u64,
                "stdout": "",
                "stderr": format!("Failed to spawn {}: {err}", spec.exe.display()),
            });
            return (pretty(&result), true);
        }
    };

    let pid = child.id();
    let cap = cfg.max_output_chars.saturating_mul(4).max(4_096);
    let stdout_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let stderr_buf = Arc::new(Mutex::new(Vec::<u8>::new()));
    let (done_tx, done_rx) = mpsc::channel::<()>();

    if let Some(stdout) = child.stdout.take() {
        spawn_reader(stdout, Arc::clone(&stdout_buf), done_tx.clone(), cap);
    }
    if let Some(stderr) = child.stderr.take() {
        spawn_reader(stderr, Arc::clone(&stderr_buf), done_tx, cap);
    }

    let mut timed_out = false;
    let mut exit_code: Option<i32> = None;
    let deadline = Duration::from_secs(timeout_sec);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                exit_code = status.code();
                break;
            }
            Ok(None) => {
                if started.elapsed() >= deadline {
                    timed_out = true;
                    kill_tree(pid);
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                exit_code = None;
                let result = json!({
                    "exitCode": exit_code,
                    "timedOut": timed_out,
                    "shell": spec.name,
                    "cwd": work_dir.to_string_lossy(),
                    "durationMs": started.elapsed().as_millis() as u64,
                    "stdout": "",
                    "stderr": format!("Failed to wait for process: {err}"),
                });
                return (pretty(&result), true);
            }
        }
    }

    let _ = done_rx.recv_timeout(Duration::from_secs(3));
    let _ = done_rx.recv_timeout(Duration::from_secs(3));

    let stdout = read_buffer(&stdout_buf);
    let stderr = read_buffer(&stderr_buf);
    let stdout = truncate_chars(&stdout, cfg.max_output_chars);
    let stderr = truncate_chars(&stderr, cfg.max_output_chars);

    let result = json!({
        "exitCode": exit_code,
        "timedOut": timed_out,
        "shell": spec.name,
        "cwd": work_dir.to_string_lossy(),
        "durationMs": started.elapsed().as_millis() as u64,
        "stdout": stdout,
        "stderr": stderr,
    });
    let is_error = timed_out || exit_code.map(|code| code != 0).unwrap_or(true);
    (pretty(&result), is_error)
}

fn spawn_reader<R: Read + Send + 'static>(
    mut reader: R,
    buffer: Arc<Mutex<Vec<u8>>>,
    done: mpsc::Sender<()>,
    cap: usize,
) {
    std::thread::spawn(move || {
        let mut chunk = [0u8; 8192];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    let mut buffer = buffer.lock().unwrap_or_else(|err| err.into_inner());
                    if buffer.len() < cap {
                        let take = (cap - buffer.len()).min(read);
                        buffer.extend_from_slice(&chunk[..take]);
                    }
                }
                Err(_) => break,
            }
        }
        let _ = done.send(());
    });
}

fn read_buffer(buffer: &Arc<Mutex<Vec<u8>>>) -> String {
    let buffer = buffer.lock().unwrap_or_else(|err| err.into_inner());
    String::from_utf8_lossy(&buffer).to_string()
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
    // Negative pid targets the whole process group created with
    // `process_group(0)`, so background children die with their shell.
    unsafe {
        libc::kill(-(pid as i32), libc::SIGKILL);
    }
}

fn truncate_chars(value: &str, max: usize) -> String {
    let max = max.min(MAX_OUTPUT_CHARS);
    let total = value.chars().count();
    if total <= max {
        return value.to_string();
    }
    let mut out: String = value.chars().take(max).collect();
    out.push_str(&format!("\n...[truncated {} chars]", total - max));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WorkspaceItem;

    fn fixture() -> (tempfile::TempDir, tempfile::TempDir, ServerConfig) {
        let workspace = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let cfg = ServerConfig {
            workspaces: vec![WorkspaceItem {
                id: "work".into(),
                name: "Work".into(),
                path: workspace.path().to_string_lossy().to_string(),
            }],
            default_workspace: "work".into(),
            ..Default::default()
        };
        (workspace, outside, cfg)
    }

    fn call_json(cfg: &ServerConfig, tool: &str, args: Value) -> ToolResult {
        call(cfg, tool, &args)
    }

    #[test]
    fn tool_list_has_eleven_names() {
        assert_eq!(TOOL_NAMES.len(), 11);
        assert!(is_known("bash"));
        assert!(!is_known("pair_request"));
    }

    #[test]
    fn rejects_relative_escape() {
        let (_ws, _outside, cfg) = fixture();
        let err = resolve_path(&cfg, None, "../outside.txt").unwrap_err();
        assert!(err.contains("Access denied"), "{err}");
    }

    #[test]
    fn rejects_absolute_outside_path() {
        let (_ws, outside, cfg) = fixture();
        let escaped = outside.path().join("secret.txt");
        let err = resolve_path(&cfg, None, &escaped.to_string_lossy()).unwrap_err();
        assert!(err.contains("Access denied"), "{err}");
    }

    #[test]
    fn accepts_valid_sub_path() {
        let (ws, _outside, cfg) = fixture();
        let resolved = resolve_path(&cfg, Some("work"), "nested/file.txt").unwrap();
        assert!(resolved.starts_with(ws.path().canonicalize().unwrap()));
    }

    #[test]
    fn restrict_off_allows_outside_paths() {
        let (_ws, outside, mut cfg) = fixture();
        cfg.restrict_to_workspaces = false;
        let target = outside.path().join("free.txt");
        let resolved = resolve_path(&cfg, None, &target.to_string_lossy()).unwrap();
        assert!(resolved.ends_with("free.txt"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_allow_list_ignores_case() {
        let (ws, _outside, cfg) = fixture();
        let upper = ws.path().to_string_lossy().to_uppercase();
        let probe = Path::new(&upper).join("Case.txt");
        assert!(resolve_path(&cfg, None, &probe.to_string_lossy()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_denied() {
        use std::os::unix::fs::symlink;
        let (ws, outside, cfg) = fixture();
        let secret = outside.path().join("secret.txt");
        fs::write(&secret, "top secret").unwrap();
        let link = ws.path().join("link");
        symlink(outside.path(), &link).unwrap();
        let err = resolve_path(&cfg, None, "link/secret.txt").unwrap_err();
        assert!(err.contains("Access denied"), "{err}");
    }

    #[test]
    fn write_read_edit_delete_round_trip() {
        let (_ws, _outside, cfg) = fixture();

        let written = call_json(
            &cfg,
            "write_file",
            json!({"filePath": "docs/a.txt", "content": "hello deskport"}),
        );
        assert!(!written.is_error, "{}", written.text);

        let read = call_json(&cfg, "read_file", json!({"filePath": "docs/a.txt"}));
        assert!(!read.is_error);
        assert!(read.text.contains("1: hello deskport"));

        let edited = call_json(
            &cfg,
            "edit_file",
            json!({"filePath": "docs/a.txt", "target": "deskport", "replacement": "world"}),
        );
        assert!(!edited.is_error, "{}", edited.text);

        let read = call_json(&cfg, "read_file", json!({"filePath": "docs/a.txt"}));
        assert!(read.text.contains("hello world"));

        let listed = call_json(&cfg, "list_files", json!({"dirPath": "docs"}));
        assert!(!listed.is_error);
        assert!(listed.text.contains("[FILE] a.txt"));

        let deleted = call_json(&cfg, "delete_file", json!({"filePath": "docs/a.txt"}));
        assert!(!deleted.is_error, "{}", deleted.text);
        assert!(resolve_path(&cfg, None, "docs/a.txt").is_ok());
        assert!(!Path::new(&cfg.workspaces[0].path)
            .join("docs/a.txt")
            .exists());
    }

    #[test]
    fn batch_write_read_and_edit() {
        let (_ws, _outside, cfg) = fixture();
        let written = call_json(
            &cfg,
            "write_files",
            json!({"files": [
                {"filePath": "a.txt", "content": "one"},
                {"filePath": "b.txt", "content": "two"}
            ]}),
        );
        assert!(!written.is_error);
        assert!(written.text.contains("Wrote 2/2 files"));

        let read = call_json(&cfg, "read_files", json!({"filePaths": ["a.txt", "b.txt"]}));
        assert!(!read.is_error);
        assert!(read.text.contains("=== a.txt"));
        assert!(read.text.contains("two"));

        let edited = call_json(
            &cfg,
            "edit_files",
            json!({"edits": [
                {"filePath": "a.txt", "target": "one", "replacement": "ONE"},
                {"filePath": "b.txt", "target": "two", "replacement": "TWO"}
            ]}),
        );
        assert!(!edited.is_error);
        assert!(edited.text.contains("Applied 2/2 edits"));

        let mismatch = call_json(
            &cfg,
            "edit_files",
            json!({"edits": [{"filePath": "a.txt", "target": "nope", "replacement": "x"}]}),
        );
        assert!(mismatch.is_error);
        assert!(
            mismatch.text.contains("target text not found")
                || mismatch.text.contains("Target text not found")
        );
    }

    #[test]
    fn search_finds_names_and_content() {
        let (_ws, _outside, cfg) = fixture();
        call_json(
            &cfg,
            "write_files",
            json!({"files": [
                {"filePath": "src/main.rs", "content": "fn main() { println!(\"DeskPort\"); }"},
                {"filePath": "node_modules/skip.js", "content": "DeskPort"}
            ]}),
        );
        let result = call_json(&cfg, "search_files", json!({"query": "deskport"}));
        assert!(!result.is_error, "{}", result.text);
        assert!(result.text.contains("src/main.rs"));
        assert!(!result.text.contains("node_modules"));

        let globbed = call_json(
            &cfg,
            "search_files",
            json!({"query": "deskport", "filePattern": "*.rs"}),
        );
        assert!(!globbed.is_error);
        assert!(globbed.text.contains("Content matches"));
    }

    #[test]
    fn list_files_skips_heavy_directories() {
        let (_ws, _outside, cfg) = fixture();
        call_json(
            &cfg,
            "write_files",
            json!({"files": [
                {"filePath": "keep/a.txt", "content": "a"},
                {"filePath": "node_modules/pkg/index.js", "content": "x"}
            ]}),
        );
        let listed = call_json(&cfg, "list_files", json!({"depth": 3}));
        assert!(!listed.is_error);
        assert!(listed.text.contains("keep"));
        assert!(listed.text.contains("(skipped)"));
    }

    #[test]
    fn read_file_supports_line_ranges() {
        let (_ws, _outside, cfg) = fixture();
        call_json(
            &cfg,
            "write_file",
            json!({"filePath": "lines.txt", "content": "a\nb\nc\nd"}),
        );
        let sliced = call_json(
            &cfg,
            "read_file",
            json!({"filePath": "lines.txt", "startLine": 2, "endLine": 3}),
        );
        assert!(!sliced.is_error);
        assert!(sliced.text.contains("2: b"));
        assert!(sliced.text.contains("3: c"));
        assert!(!sliced.text.contains("4: d"));
    }

    #[test]
    fn unknown_tool_and_workspace_report_errors() {
        let (_ws, _outside, cfg) = fixture();
        let unknown = call_json(&cfg, "rm_rf", json!({}));
        assert!(unknown.is_error);
        assert!(unknown.text.contains("Unknown tool"));

        let bad_ws = call_json(&cfg, "list_files", json!({"workspace": "nope"}));
        assert!(bad_ws.is_error);
        assert!(bad_ws.text.contains("Unknown workspace"));
    }

    #[test]
    fn bash_runs_in_workspace() {
        let (_ws, _outside, cfg) = fixture();
        let result = call_json(&cfg, "bash", json!({"command": "echo deskport-bash-ok"}));
        assert!(!result.is_error, "{}", result.text);
        assert!(result.text.contains("deskport-bash-ok"), "{}", result.text);
        assert!(result.text.contains("\"exitCode\": 0"), "{}", result.text);
    }

    #[test]
    fn bash_timeout_kills_process() {
        let (_ws, _outside, cfg) = fixture();
        // `sleep` is a Start-Sleep alias in PowerShell and a builtin in Git Bash.
        let command = "sleep 30";
        let started = Instant::now();
        let result = call_json(&cfg, "bash", json!({"command": command, "timeoutSec": 5}));
        assert!(started.elapsed() < Duration::from_secs(25));
        assert!(result.is_error, "{}", result.text);
        assert!(
            result.text.contains("\"timedOut\": true"),
            "{}",
            result.text
        );
    }

    #[test]
    fn truncate_keeps_utf8_boundaries() {
        let text = "桌面端口DeskPort";
        let truncated = truncate_chars(text, 4);
        assert!(truncated.starts_with("桌面端口"));
        assert!(truncated.contains("[truncated"));
    }
}
