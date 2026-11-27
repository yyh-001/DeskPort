# DeskPort — local MCP bridge for your machine

> 把本机变成一个安全、可授权的 MCP 服务：内置 Streamable HTTP + OAuth 2.1/PKCE，
> 一个 Rust 单二进制，无 Node.js 运行时。

[![Release](https://img.shields.io/github/v/release/yyh001/deskport?display_name=tag)](https://github.com/yyh001/deskport/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## 简介 · What is DeskPort

**DeskPort** 是一个极简的跨平台桌面应用（Tauri v2 + Rust）。它在 `127.0.0.1` 上启动内置的
MCP Streamable HTTP 服务，把选定的本机工作区（文件夹）以 **11 个文件 / Shell 工具**的形式
暴露给你信任的 AI 客户端 —— Claude、ChatGPT、Cursor 等。

- **零运行时依赖**：没有 Node.js，没有后台守护进程，只有一个二进制。
- **默认安全**：首次启动即开启工作区白名单，路径穿越与符号链接逃逸一律拒绝。
- **OAuth 2.1 + PKCE**：每个客户端都要在浏览器里看到原生风格的授权页，逐次批准。
- **一键公网接入**：内置 Cloudflare Quick / Named Tunnel 与 ngrok 隧道管理，含 cloudflared 一键下载安装。
- **系统托盘常驻**：关闭窗口只是隐藏，服务与隧道继续后台运行。

**DeskPort** is a minimal cross-platform desktop app (Tauri v2 + Rust) that runs a built-in
MCP Streamable HTTP server on `127.0.0.1`. It exposes the workspaces (folders) you choose
through **11 file & shell tools** to the AI clients you trust — no Node.js runtime, one binary.

---

## 特性 · Features

| | |
| :--- | :--- |
| 🧩 **11 个跨平台 MCP 工具** | `list_workspaces` `list_files` `search_files` `read_file` `read_files` `write_file` `write_files` `edit_file` `edit_files` `delete_file` `bash` |
| 🔐 **OAuth 2.1 + PKCE** | 动态客户端注册（RFC 7591）、RFC 8414 / RFC 9728 自动发现、`S256` 与 `plain`、refresh token、单条或全部吊销 |
| 🛡 **路径白名单** | 词法规范化 + `canonicalize` 消解符号链接后再比对，Windows 忽略大小写；`../` 与越界绝对路径直接 `Access denied` |
| 🐚 **跨平台 Shell** | Windows 自动探测 Git Bash → PowerShell，`CREATE_NO_WINDOW` + 进程树超时清理；macOS/Linux 使用 `$SHELL` 与独立进程组 |
| 🌐 **隧道** | Cloudflare Quick（零配置）/ Named（Token + 固定域名）/ ngrok；日志自动把 Token 脱敏为 `***` |
| 🖥 **系统托盘** | 显示窗口、复制 MCP URL、启动/停止全部、退出；关闭窗口仅隐藏 |
| 🎨 **原生授权页** | 与主程序一致的 Linear 风格深浅自适应授权界面，所有动态内容 HTML 转义 |

---

## 下载 · Download

从 [Releases](https://github.com/yyh001/deskport/releases) 下载对应安装包：

| 平台 | 文件 |
| :--- | :--- |
| **Windows 10/11 (x64)** | `.msi`（WiX）或 `.exe`（NSIS） |
| **macOS 11+** | `.dmg`（Apple Silicon `aarch64` / Intel `x64`） |
| **Linux (x64)** | `.AppImage` 或 `.deb` |

> 首次打开 macOS 若提示未签名，可在「系统设置 → 隐私与安全性」中选择「仍要打开」。

---

## 30 秒接入 · Connect in 30 seconds

1. 打开 DeskPort，在 **工作区** 中添加要开放的文件夹，保持「仅限白名单目录访问」开启。
2. 点击 **一键启动**，复制顶部的 MCP 地址：
   - 仅本地：`http://127.0.0.1:3334/mcp`
   - 公网隧道：`https://<your-tunnel-domain>/mcp`
3. 把地址填进你的 AI 客户端：

**Claude / Claude Code**

```bash
# Claude Code（CLI）
claude mcp add --transport http deskport http://127.0.0.1:3334/mcp
```

Claude Desktop / claude.ai 的自定义连接器（Connectors）中粘贴远端 `https://.../mcp` 地址即可，
客户端会自动完成 OAuth 2.1 发现与授权。

**ChatGPT（Developer mode / Connectors）**

在 Connectors 中添加自定义 MCP 服务器，填写 `https://.../mcp`，按提示在 DeskPort 授权页点击
「允许连接」。

**Cursor**

```json
// ~/.cursor/mcp.json  （Windows: %USERPROFILE%\.cursor\mcp.json）
{
  "mcpServers": {
    "deskport": {
      "url": "http://127.0.0.1:3334/mcp"
    }
  }
}
```

客户端会打开系统浏览器进入 DeskPort 授权页；确认应用名与开放工作区后批准即可。
已授权的客户端可在 **日志与授权** 页随时吊销。

---

## 开发与构建 · Development

前置：Rust（stable，≥ 1.77）、Node.js 20+（仅用于 Tauri CLI）、各平台 Tauri v2 系统依赖
（Linux：`libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev`）。

```bash
npm install          # 安装 @tauri-apps/cli
npm run dev          # 开发模式（tauri dev）
npm run build        # 生成安装包（tauri build）

# 仅后端校验
cd src-tauri
cargo test
cargo clippy --all-targets
```

前端静态文件位于 `ui/`（无打包步骤，`frontendDist` 直接指向该目录）。

数据目录（可用环境变量 `DESKPORT_DATA_DIR` 覆盖）：

- Windows：`%APPDATA%\io.github.yyh001.deskport`
- macOS：`~/Library/Application Support/io.github.yyh001.deskport`
- Linux：`~/.local/share/io.github.yyh001.deskport`

其中包含 `config.json`（工作区与运行参数）、`tunnel.json`（隧道 Token，Unix 权限 `0600`）、
`oauth.db`（SQLite，WAL）与 `bin/`（一键下载的 `cloudflared`）。

---

## 安全说明 · Security

- 服务默认只监听 `127.0.0.1`，公网访问必须由你主动开启隧道。
- 默认强制工作区白名单；请只添加确实需要开放的目录。
- `bash` 工具可以执行任意本机命令 —— **只授权给你完全信任的客户端**。
- 仓库与二进制中不包含任何预置 OAuth 客户端、密钥或个人信息。
- 隧道日志中的 Token 会被替换为 `***`，`tunnel.json` 在 Unix 上以 `0600` 落盘。

发现安全问题请通过 GitHub Security Advisories 私下报告。

---

## License

[MIT](LICENSE) © 2026 DeskPort Contributors
