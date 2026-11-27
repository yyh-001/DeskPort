# DeskPort — 本机 MCP 桥

> 把本机变成一个安全、可授权的 MCP 服务：内置 Streamable HTTP + OAuth 2.1/PKCE，
> 一个 Rust 单二进制，不需要 Node.js 运行时。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/yyh-001/DeskPort?display_name=tag&include_prereleases)](https://github.com/yyh-001/DeskPort/releases)

---

## 简介 · What is DeskPort

**DeskPort** 是一个极简的跨平台桌面应用（Tauri v2 + Rust）。它在 `127.0.0.1:3334` 上启动内置的
MCP Streamable HTTP 服务，把选定的本机工作区（文件夹）以 **11 个文件 / Shell 工具**的形式
暴露给你信任的 AI 客户端 —— Claude、ChatGPT、Cursor 等。

- **零运行时依赖**：没有 Node.js，没有后台守护进程，只有一个二进制
- **默认安全**：首次启动即开启工作区白名单，路径穿越与符号链接逃逸一律拒绝
- **OAuth 2.1 + PKCE**：每个客户端都要在浏览器里看到原生风格的授权页，逐次批准
- **一键公网接入**：内置 Cloudflare Quick / Named Tunnel 与 ngrok 隧道管理，含 cloudflared 一键下载安装
- **系统托盘常驻**：关闭窗口只是隐藏，服务与隧道继续后台运行

**DeskPort** is a minimal cross-platform desktop app (Tauri v2 + Rust) that runs a built-in
MCP Streamable HTTP server on `127.0.0.1:3334`. It exposes the workspaces (folders) you choose
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

## 安装 · Install

### 从 Release 安装

> 最新版本 **v0.1.0 已发布**：Windows / macOS（Apple Silicon 与 Intel）/ Linux，共 9 个安装包。
> 也可以直接用下面的源码构建。

发版后从 [Releases](https://github.com/yyh-001/DeskPort/releases) 下载。两种形态都提供：

**免安装版 · Portable**（推荐，解压即用，不写注册表、不建快捷方式）

| 平台 | 文件 | 用法 |
| :--- | :--- | :--- |
| **Windows 10/11 (x64)** | `deskport_windows_x64.exe` | 双击直接运行（依赖系统自带 WebView2，Win10/11 一般已预装） |
| **macOS** | `deskport_darwin_aarch64` / `deskport_darwin_x64` | `chmod +x` 后运行；首次打开需右键「打开」绕过 Gatekeeper |
| **Linux (x64)** | `deskport_linux_x64` | `chmod +x` 后运行，需要系统已装 `webkit2gtk-4.1` 等运行库 |

**安装包 · Installer**

| 平台 | 产物 |
| :--- | :--- |
| **Windows 10/11 (x64)** | `.msi`（WiX）或 `.exe`（NSIS） |
| **macOS 11+** | `.dmg`（Apple Silicon `aarch64` / Intel `x64`） |
| **Linux (x64)** | `.AppImage` / `.deb` / `.rpm` |

> 两者共用同一份数据目录，换成免安装版不会丢配置。macOS 若提示未签名，可在「系统设置 → 隐私与安全性」中选择「仍要打开」。

### 从源码构建

前置：Rust（stable，≥ 1.77.2）、Node.js 20+（仅用于 Tauri CLI），以及各平台的 Tauri v2 系统依赖
（Linux：`libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev`）。

```bash
git clone https://github.com/yyh-001/DeskPort.git
cd DeskPort
npm install          # 只装 @tauri-apps/cli
npm run dev          # 开发模式（tauri dev）
npm run build        # 产出安装包（tauri build）
```

前端是 `ui/` 下的静态页面，**没有打包步骤**（`frontendDist` 直接指向该目录）。

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

## 项目结构 · Layout

```
DeskPort/
├─ src-tauri/                  Rust 内核（Tauri v2）
│  ├─ src/
│  │  ├─ lib.rs                命令注册、托盘、启动流程
│  │  ├─ main.rs               入口
│  │  ├─ config.rs             配置、工作区白名单、路径规范化
│  │  ├─ db.rs                 SQLite（OAuth 客户端 / 授权码 / 令牌）
│  │  ├─ state.rs              运行状态、快照（IPC 契约）
│  │  ├─ tools.rs              11 个文件 / Shell 工具
│  │  ├─ mcp_server.rs         MCP Streamable HTTP + OAuth 2.1 端点
│  │  └─ tunnel.rs             Cloudflare / ngrok 隧道与日志脱敏
│  ├─ tests/qa_boundary.rs     71 项边界验收（复刻生产模块，不动业务代码）
│  ├─ icons/                   图标（ico / icns / png）
│  └─ tauri.conf.json          窗口、打包与标识符
├─ ui/                         前端静态页（index.html / app.js / styles.css）
├─ .github/workflows/release.yml   三端构建矩阵
└─ package.json                只含 @tauri-apps/cli
```

---

## 测试 · Tests

```bash
cd src-tauri
cargo test                 # 122 项：51 项 lib 单元测试 + 71 项边界验收
cargo clippy --all-targets
cargo fmt --check
```

边界验收覆盖：工作区白名单的 `../` 穿越、前缀伪造、Windows 大小写与分隔符变体；OAuth 2.1
完整流程（发现、注册、授权页 XSS 转义、`javascript:` 拦截、PKCE 失败、授权码重放、refresh、吊销）；
MCP 协议与 11 个工具、批量请求、未知方法错误码；隧道日志不泄露明文密钥；配置损坏时的安全回退。

---

## 发布 · 三端打包

`release.yml` 在**推送 `v*` 标签**或**手动 `workflow_dispatch`** 时触发，四个构建任务：

| Job | Runner | 目标 |
| :--- | :--- | :--- |
| Windows x64 | `windows-latest` | `.msi` + `.exe`（NSIS） |
| macOS Apple Silicon | `macos-latest` | `aarch64-apple-darwin` |
| macOS Intel | `macos-latest` | `x86_64-apple-darwin` |
| Linux x64 | `ubuntu-22.04` | `.AppImage` + `.deb` |

> **状态**：v0.1.0 已通过 `workflow_dispatch` 完整构建并发布（四个 job 全绿）。
> 之后推 `v*` 标签即可自动发布新版本。

发版流程：

```bash
git tag v0.1.0
git push origin v0.1.0
```

---

## 数据目录 · Data

可用环境变量 `DESKPORT_DATA_DIR` 覆盖：

- Windows：`%APPDATA%\io.github.yyh001.deskport`
- macOS：`~/Library/Application Support/io.github.yyh001.deskport`
- Linux：`~/.local/share/io.github.yyh001.deskport`

其中包含 `config.json`（工作区与运行参数）、`tunnel.json`（隧道 Token，Unix 权限 `0600`）、
`oauth.db`（SQLite，WAL）与 `bin/`（一键下载的 `cloudflared`）。

---

## 安全说明 · Security

- 服务默认只监听 `127.0.0.1`，公网访问必须由你主动开启隧道
- 默认强制工作区白名单；请只添加确实需要开放的目录
- `bash` 工具可以执行任意本机命令 —— **只授权给你完全信任的客户端**
- 仓库与二进制中不包含任何预置 OAuth 客户端、密钥或个人信息
- 隧道日志中的 Token 会被替换为 `***`，`tunnel.json` 在 Unix 上以 `0600` 落盘

发现安全问题请通过 GitHub Security Advisories 私下报告。

---

## License

[MIT](LICENSE) © 2026 DeskPort Contributors
