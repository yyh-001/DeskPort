/* DeskPort UI — Tauri v2 frontend (vanilla JS, no build step, no dependencies). */
(function () {
  "use strict";

  /* ---------------------------------------------------------------- runtime */
  var TAURI_CORE = window.__TAURI__ && window.__TAURI__.core;
  var invokeRaw =
    TAURI_CORE && typeof TAURI_CORE.invoke === "function" ? TAURI_CORE.invoke.bind(TAURI_CORE) : null;
  var IS_TAURI = Boolean(invokeRaw);
  var CAN_LISTEN_EVENTS = Boolean(
    window.__TAURI__ && window.__TAURI__.event && typeof window.__TAURI__.event.listen === "function"
  );

  var THEME_KEY = "deskport.theme";

  // Mirror the inline <head> boot script: keeps a saved theme even if a strict
  // CSP ever blocks inline scripts.
  try {
    var storedTheme = localStorage.getItem(THEME_KEY);
    if (storedTheme === "light" || storedTheme === "dark") {
      document.documentElement.setAttribute("data-theme", storedTheme);
    } else if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
      document.documentElement.setAttribute("data-theme", "light");
    }
  } catch (themeError) {
    /* keep the markup default */
  }

  /* Every IPC command allowed by the shared contract. The guard below makes a
     typo fail loudly instead of silently doing nothing. */
  var IPC_COMMANDS = [
    "get_state",
    "start_all",
    "stop_all",
    "start_server",
    "stop_server",
    "restart_server",
    "start_tunnel",
    "stop_tunnel",
    "clear_logs",
    "save_config",
    "save_tunnel_config",
    "revoke_token",
    "pick_folder",
    "install_cloudflared",
    "open_data_dir",
    "check_update",
    "install_update",
    "open_release_page"
  ];
  var IPC_ALLOWED = new Set(IPC_COMMANDS);

  var TOOL_NAMES = [
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
    "bash"
  ];

  var SHELLS = ["auto", "bash", "powershell", "cmd", "zsh", "sh"];

  var ESC_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

  function esc(value) {
    return String(value === null || value === undefined ? "" : value).replace(
      /[&<>"']/g,
      function (ch) {
        return ESC_MAP[ch];
      }
    );
  }

  function icon(name, extraClass) {
    return (
      '<svg class="icon' +
      (extraClass ? " " + extraClass : "") +
      '" aria-hidden="true"><use href="#i-' +
      name +
      '"></use></svg>'
    );
  }

  function ipc(command, args) {
    if (!IPC_ALLOWED.has(command)) {
      return Promise.reject(new Error("未知 IPC 命令: " + command));
    }
    if (!invokeRaw) {
      return Promise.reject(new Error("Tauri IPC 不可用"));
    }
    return invokeRaw(command, args || {});
  }

  function errorMessage(err) {
    if (!err) return "未知错误";
    if (typeof err === "string") return err;
    if (typeof err.message === "string" && err.message) return err.message.replace(/^Error:\s*/, "");
    try {
      return JSON.stringify(err);
    } catch (e) {
      return String(err);
    }
  }

  /* ---------------------------------------------------------------- mock */
  function createMockState() {
    var now = Date.now();
    return {
      version: "0.2.0",
      platform: "windows",
      dataDir: "C:\\Users\\you\\AppData\\Roaming\\io.github.yyh001.deskport",
      tools: TOOL_NAMES.slice(),
      config: {
        port: 3334,
        defaultWorkspace: "desktop",
        restrictToWorkspaces: true,
        workspaces: [
          { id: "desktop", name: "Desktop", path: "C:\\Users\\you\\Desktop" },
          { id: "projects", name: "Projects", path: "C:\\Users\\you\\Desktop\\projects" },
          { id: "notes", name: "Notes", path: "C:\\Users\\you\\Documents\\notes" }
        ],
        defaultShell: "auto",
        defaultTimeoutSec: 60,
        maxOutputChars: 20000
      },
      tunnelConfig: {
        mode: "quick",
        hasCloudflareToken: false,
        cloudflareTokenPreview: "",
        fixedUrl: "",
        hasNgrokAuthToken: false,
        ngrokAuthTokenPreview: "",
        ngrokDomain: ""
      },
      binaries: {
        cloudflaredInstalled: false,
        cloudflaredPath: null,
        ngrokInstalled: false,
        ngrokPath: null,
        installingCloudflared: false
      },
      server: {
        status: "running",
        startedAt: now - 7 * 60 * 1000,
        localUrl: "http://127.0.0.1:3334/mcp",
        logs: [
          "[09:41:02] DeskPort 0.2.0 启动",
          "[09:41:02] data dir: C:\\Users\\you\\AppData\\Roaming\\io.github.yyh001.deskport",
          "[09:41:03] listening on http://127.0.0.1:3334",
          "[09:41:03] MCP endpoint ready: /mcp",
          "[09:42:19] oauth: client registered (Claude Desktop)",
          "[09:43:07] tools/list → 11 tools",
          "[09:44:52] bash: git status --short"
        ]
      },
      tunnel: {
        mode: "quick",
        status: "stopped",
        pid: null,
        publicUrl: null,
        mcpUrl: null,
        error: null,
        logs: []
      },
      oauth: {
        clientCount: 2,
        activeTokenCount: 2,
        clients: [
          {
            clientId: "dp_7c41a9e28b3f5d60e1a4c8",
            clientName: "Claude Desktop",
            createdAt: now - 2 * 24 * 60 * 60 * 1000
          },
          {
            clientId: "dp_1f09b6d4c7e28a53f0b1d6",
            clientName: "Cursor",
            createdAt: now - 5 * 60 * 60 * 1000
          }
        ],
        tokens: [
          {
            tokenId: "mock-access-token-01",
            tokenPrefix: "a1b2c3d4...9f0e",
            tokenType: "access",
            clientId: "dp_7c41a9e28b3f5d60e1a4c8",
            scope: "mcp:tools",
            expiresAt: now + 5 * 24 * 60 * 60 * 1000,
            createdAt: now - 2 * 24 * 60 * 60 * 1000,
            expired: false
          },
          {
            tokenId: "mock-refresh-token-02",
            tokenPrefix: "5e6f7a8b...1c2d",
            tokenType: "refresh",
            clientId: "dp_1f09b6d4c7e28a53f0b1d6",
            scope: "mcp:tools",
            expiresAt: null,
            createdAt: now - 5 * 60 * 60 * 1000,
            expired: false
          },
          {
            tokenId: "mock-access-token-03",
            tokenPrefix: "9081a2b3...7e6f",
            tokenType: "access",
            clientId: "dp_1f09b6d4c7e28a53f0b1d6",
            scope: "mcp:tools",
            expiresAt: now - 60 * 60 * 1000,
            createdAt: now - 3 * 24 * 60 * 60 * 1000,
            expired: true
          }
        ]
      },
      now: now
    };
  }

  /* ---------------------------------------------------------------- state */
  var ui = {
    snapshot: null,
    loading: true,
    loadError: null,
    tab: "workspaces",
    logSource: "server",
    toolsOpen: false,
    runtimeOpen: false,
    busy: null,
    picking: false,
    installing: false,
    installError: "",
    update: {
      checking: false,
      installing: false,
      info: null,
      progress: null,
      error: "",
      dismissed: false
    },
    preview: false,
    draft: {
      mode: "quick",
      tunnel: { cfToken: "", cfUrl: "", ngrokToken: "", ngrokDomain: "" },
      runtime: { port: "3334", shell: "auto", timeout: "60", maxOut: "20000" }
    },
    logSig: "",
    logAutoScroll: true,
    toastTimer: null,
    confirm: null,
    modalReturnFocus: null,
    heroSig: "",
    bodySig: "",
    actionsHtml: "",
    headerSig: ""
  };

  var loadSeq = 0;

  var els = {
    hero: document.getElementById("hero"),
    panelActions: document.getElementById("panelActions"),
    panelBody: document.getElementById("panelBody"),
    versionBadge: document.getElementById("versionBadge"),
    updatePill: document.getElementById("updatePill"),
    checkUpdateBtn: document.getElementById("checkUpdateBtn"),
    platformTag: document.getElementById("platformTag"),
    dataDirBtn: document.getElementById("dataDirBtn"),
    themeBtn: document.getElementById("themeBtn"),
    previewFlag: document.getElementById("previewFlag"),
    tabs: Array.prototype.slice.call(document.querySelectorAll(".seg[data-tab]")),
    toast: document.getElementById("toast"),
    modal: document.getElementById("modal"),
    modalTitle: document.getElementById("modalTitle"),
    modalBody: document.getElementById("modalBody"),
    modalConfirm: document.getElementById("modalConfirm")
  };

  /* ---------------------------------------------------------------- theme */
  function currentTheme() {
    return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
  }

  function renderThemeButton() {
    var dark = currentTheme() === "dark";
    els.themeBtn.innerHTML = icon(dark ? "sun" : "moon");
    els.themeBtn.title = dark ? "切换到浅色主题" : "切换到深色主题";
    els.themeBtn.setAttribute("aria-label", els.themeBtn.title);
  }

  function toggleTheme() {
    var next = currentTheme() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    try {
      localStorage.setItem(THEME_KEY, next);
    } catch (e) {
      /* ignore */
    }
    renderThemeButton();
  }

  function watchSystemTheme() {
    if (!window.matchMedia) return;
    var query = window.matchMedia("(prefers-color-scheme: light)");
    var onChange = function (event) {
      var stored = null;
      try {
        stored = localStorage.getItem(THEME_KEY);
      } catch (e) {
        /* ignore */
      }
      if (stored === "light" || stored === "dark") return;
      document.documentElement.setAttribute("data-theme", event.matches ? "light" : "dark");
      renderThemeButton();
    };
    if (typeof query.addEventListener === "function") {
      query.addEventListener("change", onChange);
    } else if (typeof query.addListener === "function") {
      query.addListener(onChange);
    }
  }

  /* ---------------------------------------------------------------- toast / modal / clipboard */
  function showToast(message, kind) {
    var tone = kind === "error" ? " error" : kind === "success" ? " success" : "";
    els.toast.className = "toast" + tone;
    els.toast.innerHTML =
      (kind === "success" ? icon("check") : kind === "error" ? icon("alert") : "") +
      "<span>" +
      esc(message) +
      "</span>";
    els.toast.classList.add("show");
    clearTimeout(ui.toastTimer);
    ui.toastTimer = setTimeout(function () {
      els.toast.classList.remove("show");
    }, 2400);
  }

  function previewOnly() {
    showToast("浏览器预览模式 · 请在 DeskPort 桌面端操作");
    return false;
  }

  function ensureInteractive() {
    if (!IS_TAURI) return previewOnly();
    return true;
  }

  function openConfirm(options) {
    ui.modalReturnFocus = document.activeElement;
    ui.confirm = options || {};
    els.modalTitle.textContent = (options && options.title) || "确认操作";
    els.modalBody.textContent = (options && options.message) || "";
    els.modalConfirm.textContent = (options && options.confirmLabel) || "确认";
    els.modalConfirm.className = "btn btn-sm " + (options && options.danger === false ? "btn-primary" : "btn-danger");
    els.modal.classList.add("open");
    els.modal.setAttribute("aria-hidden", "false");
    setTimeout(function () {
      els.modalConfirm.focus();
    }, 30);
  }

  function closeConfirm() {
    els.modal.classList.remove("open");
    els.modal.setAttribute("aria-hidden", "true");
    ui.confirm = null;
    if (ui.modalReturnFocus && ui.modalReturnFocus.isConnected) {
      ui.modalReturnFocus.focus();
    }
    ui.modalReturnFocus = null;
  }

  function acceptConfirm() {
    var callback = ui.confirm && ui.confirm.onConfirm;
    closeConfirm();
    if (typeof callback === "function") {
      Promise.resolve()
        .then(callback)
        .catch(function (err) {
          showToast("操作失败：" + errorMessage(err), "error");
        });
    }
  }

  function legacyCopy(text) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.top = "-1000px";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (e) {
      ok = false;
    }
    area.remove();
    return ok;
  }

  async function writeClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch (e) {
        /* fall through */
      }
    }
    try {
      return legacyCopy(text);
    } catch (e) {
      return false;
    }
  }

  async function copyToClipboard(text, button) {
    if (!text) return;
    var ok = await writeClipboard(text);
    if (!ok) {
      showToast("复制失败，请手动选择文本", "error");
      return;
    }
    if (button) {
      if (!button.dataset.original) button.dataset.original = button.innerHTML;
      button.classList.add("is-copied");
      button.innerHTML = icon("check") + "<span>已复制</span>";
      clearTimeout(button._copyTimer);
      button._copyTimer = setTimeout(function () {
        if (!button.isConnected) return;
        button.classList.remove("is-copied");
        button.innerHTML = button.dataset.original;
      }, 1500);
    }
    showToast("MCP 地址已复制", "success");
  }

  /* ---------------------------------------------------------------- formatting */
  function fmtDate(ts) {
    if (!ts) return "—";
    try {
      return new Date(ts).toLocaleString("zh-CN", {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false
      });
    } catch (e) {
      return "—";
    }
  }

  function fmtUptime(startedAt) {
    if (!startedAt) return "";
    var seconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    if (seconds < 60) return "刚刚启动";
    var minutes = Math.floor(seconds / 60);
    if (minutes < 60) return "已运行 " + minutes + " 分钟";
    var hours = Math.floor(minutes / 60);
    return "已运行 " + hours + " 小时 " + (minutes % 60) + " 分";
  }

  function modeLabel(mode) {
    if (mode === "named") return "Cloudflare Fixed";
    if (mode === "ngrok") return "ngrok";
    return "Cloudflare Quick";
  }

  function platformLabel(platform) {
    if (platform === "windows") return "Windows";
    if (platform === "macos") return "macOS";
    if (platform === "linux") return "Linux";
    return platform ? String(platform) : "";
  }

  function baseName(path) {
    var cleaned = String(path || "").replace(/[\\/]+$/, "");
    var parts = cleaned.split(/[\\/]/);
    return parts[parts.length - 1] || "workspace";
  }

  function slugify(name) {
    return String(name || "")
      .toLowerCase()
      .normalize("NFKD")
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 40);
  }

  function uniqueWorkspaceId(name, list) {
    var base = slugify(name);
    if (!base) base = "ws-" + Math.random().toString(36).slice(2, 6);
    var used = new Set(
      list.map(function (item) {
        return String(item.id || "").toLowerCase();
      })
    );
    var candidate = base;
    var index = 2;
    while (used.has(candidate.toLowerCase())) {
      candidate = base + "-" + index;
      index += 1;
    }
    return candidate;
  }

  function samePath(a, b) {
    var normalize = function (value) {
      return String(value || "")
        .replace(/[\\/]+/g, "/")
        .replace(/\/+$/, "");
    };
    var x = normalize(a);
    var y = normalize(b);
    var platform = ui.snapshot && ui.snapshot.platform;
    return platform === "windows" ? x.toLowerCase() === y.toLowerCase() : x === y;
  }

  function shortId(value) {
    var str = String(value || "");
    return str.length > 16 ? str.slice(0, 10) + "…" + str.slice(-4) : str;
  }

  function tokenExpiry(token) {
    if (!token.expiresAt) return "长期有效";
    return token.expired ? fmtDate(token.expiresAt) + " 过期" : fmtDate(token.expiresAt) + " 到期";
  }

  function mcpUrl(snapshot) {
    if (!snapshot) return "";
    if (snapshot.tunnel && snapshot.tunnel.status === "running" && snapshot.tunnel.mcpUrl) {
      return snapshot.tunnel.mcpUrl;
    }
    if (snapshot.server && snapshot.server.localUrl) return snapshot.server.localUrl;
    return "http://127.0.0.1:" + snapshot.config.port + "/mcp";
  }

  function isSnapshot(value) {
    return Boolean(
      value &&
        typeof value === "object" &&
        value.config &&
        value.tunnelConfig &&
        value.server &&
        value.tunnel
    );
  }

  /* ---------------------------------------------------------------- drafts */
  function tunnelDraftDirty() {
    if (!ui.snapshot) return false;
    var tc = ui.snapshot.tunnelConfig || {};
    var draft = ui.draft;
    if (draft.mode !== (tc.mode || "quick")) return true;
    if (String(draft.tunnel.cfToken || "").trim() !== "") return true;
    if (String(draft.tunnel.ngrokToken || "").trim() !== "") return true;
    if (String(draft.tunnel.cfUrl || "") !== String(tc.fixedUrl || "")) return true;
    if (String(draft.tunnel.ngrokDomain || "") !== String(tc.ngrokDomain || "")) return true;
    return false;
  }

  function runtimeDraftDirty() {
    if (!ui.snapshot) return false;
    var config = ui.snapshot.config;
    var runtime = ui.draft.runtime;
    return (
      String(runtime.port) !== String(config.port) ||
      String(runtime.shell) !== String(config.defaultShell) ||
      String(runtime.timeout) !== String(config.defaultTimeoutSec) ||
      String(runtime.maxOut) !== String(config.maxOutputChars)
    );
  }

  function anyDraftDirty() {
    return tunnelDraftDirty() || runtimeDraftDirty();
  }

  function syncTunnelDraft(force) {
    if (!ui.snapshot) return;
    if (!force && tunnelDraftDirty()) return;
    var tc = ui.snapshot.tunnelConfig || {};
    ui.draft.mode = tc.mode || "quick";
    ui.draft.tunnel = {
      cfToken: "",
      cfUrl: tc.fixedUrl || "",
      ngrokToken: "",
      ngrokDomain: tc.ngrokDomain || ""
    };
  }

  function syncRuntimeDraft(force) {
    if (!ui.snapshot) return;
    if (!force && runtimeDraftDirty()) return;
    var config = ui.snapshot.config;
    ui.draft.runtime = {
      port: String(config.port),
      shell: String(config.defaultShell || "auto"),
      timeout: String(config.defaultTimeoutSec),
      maxOut: String(config.maxOutputChars)
    };
  }

  function applySnapshot(snapshot) {
    if (!isSnapshot(snapshot)) return false;
    var firstSnapshot = !ui.snapshot;
    ui.snapshot = snapshot;
    ui.loading = false;
    ui.loadError = null;
    // The very first snapshot must win over the placeholder draft, otherwise a
    // saved non-default mode (for example Fixed) would look like an edit.
    syncTunnelDraft(firstSnapshot);
    syncRuntimeDraft(firstSnapshot);
    return true;
  }

  function configFromSnapshot(overrides) {
    var config = ui.snapshot.config;
    var base = {
      port: Number(config.port),
      defaultWorkspace: config.defaultWorkspace,
      restrictToWorkspaces: Boolean(config.restrictToWorkspaces),
      workspaces: (config.workspaces || []).map(function (item) {
        return { id: String(item.id), name: String(item.name), path: String(item.path) };
      }),
      defaultShell: config.defaultShell,
      defaultTimeoutSec: Number(config.defaultTimeoutSec),
      maxOutputChars: Number(config.maxOutputChars)
    };
    if (overrides) {
      Object.keys(overrides).forEach(function (key) {
        base[key] = overrides[key];
      });
    }
    return base;
  }

  function syncDirtyUI() {
    var tunnelDirty = tunnelDraftDirty();
    var runtimeDirty = runtimeDraftDirty();
    var tunnelNote = document.getElementById("tunnelDirtyNote");
    if (tunnelNote) tunnelNote.hidden = !tunnelDirty;
    var tunnelDiscard = document.getElementById("tunnelDiscard");
    if (tunnelDiscard) tunnelDiscard.hidden = !tunnelDirty;
    var runtimeNote = document.getElementById("runtimeDirtyNote");
    if (runtimeNote) runtimeNote.hidden = !runtimeDirty;
    var runtimeDiscard = document.getElementById("runtimeDiscard");
    if (runtimeDiscard) runtimeDiscard.hidden = !runtimeDirty;
    var tab = document.getElementById("tab-tunnel");
    if (tab) tab.classList.toggle("has-dirty", tunnelDirty || runtimeDirty);
  }

  /* ---------------------------------------------------------------- status helpers */
  function deriveStatus(snapshot) {
    var serverOn = snapshot.server.status === "running";
    var tunnelStatus = snapshot.tunnel.status;
    if (tunnelStatus === "starting") {
      return { tone: "starting", label: "正在连接隧道", dot: "starting" };
    }
    if (tunnelStatus === "running") {
      return { tone: "online", label: "公网在线", dot: "online" };
    }
    if (tunnelStatus === "error") {
      return { tone: "error", label: serverOn ? "仅本地运行" : "已停止", dot: "error" };
    }
    if (serverOn) {
      return { tone: "local", label: "仅本地运行", dot: "online" };
    }
    return { tone: "idle", label: "已停止", dot: "" };
  }

  function heroSubtitle(snapshot, status) {
    var address = "127.0.0.1:" + snapshot.config.port;
    if (status.tone === "online") {
      return [modeLabel(snapshot.tunnelConfig.mode), fmtUptime(snapshot.server.startedAt)]
        .filter(Boolean)
        .join(" · ");
    }
    if (status.tone === "starting") return "正在建立加密隧道，请稍候…";
    if (status.tone === "error") {
      return snapshot.server.status === "running"
        ? "公网隧道异常，本地服务仍可用"
        : "服务与隧道均已停止";
    }
    if (status.tone === "local") {
      return [address, fmtUptime(snapshot.server.startedAt)].filter(Boolean).join(" · ");
    }
    return address + " · 等待启动";
  }

  function tunnelRuntimeNote(snapshot) {
    var status = snapshot.tunnel.status;
    if (status === "running") return "运行中";
    if (status === "starting") return "连接中…";
    if (status === "error") return "连接失败";
    return "未连接";
  }

  /* ---------------------------------------------------------------- render: header */
  function renderHeader() {
    var snapshot = ui.snapshot;
    var updateInfo = ui.update.info;
    var hasUpdate = Boolean(updateInfo && updateInfo.hasUpdate);
    var latestVersion = updateInfo ? updateInfo.latestVersion : "";
    var sig = JSON.stringify([
      snapshot && snapshot.version,
      snapshot && snapshot.platform,
      snapshot && snapshot.dataDir,
      ui.preview,
      ui.update.checking,
      ui.update.installing,
      hasUpdate,
      latestVersion
    ]);
    if (sig === ui.headerSig) return;
    ui.headerSig = sig;
    if (snapshot) {
      els.versionBadge.textContent = "v" + (snapshot.version || "0.2.0");
      var platform = platformLabel(snapshot.platform);
      els.platformTag.textContent = platform;
      els.platformTag.hidden = !platform;
      els.dataDirBtn.title = snapshot.dataDir ? "打开数据目录\n" + snapshot.dataDir : "打开数据目录";
    }
    els.previewFlag.hidden = !ui.preview;
    if (els.checkUpdateBtn) {
      els.checkUpdateBtn.disabled = ui.update.checking || ui.update.installing;
      els.checkUpdateBtn.classList.toggle("spinning", ui.update.checking);
      els.checkUpdateBtn.title = ui.update.checking ? "正在检查更新…" : "检查更新";
    }
    if (els.updatePill) {
      els.updatePill.hidden = !hasUpdate;
      if (hasUpdate) {
        els.updatePill.innerHTML = icon("arrow-up") + "<span>v" + esc(latestVersion) + "</span>";
        els.updatePill.title = "发现新版本 v" + latestVersion + "，点击查看";
      }
    }
  }

  /* ---------------------------------------------------------------- render: hero */
  function actionButton(action, label, options) {
    var opts = options || {};
    var busy = ui.busy === action;
    var disabled = Boolean(opts.disabled) || Boolean(ui.busy);
    var text = busy && opts.busyLabel ? opts.busyLabel : label;
    var inner = busy
      ? '<span class="spinner"></span>'
      : opts.icon
        ? icon(opts.icon)
        : "";
    inner += "<span>" + esc(text) + "</span>";
    return (
      '<button class="btn ' +
      (opts.className || "") +
      '" data-action="' +
      action +
      '"' +
      (disabled ? " disabled" : "") +
      ">" +
      inner +
      "</button>"
    );
  }

  function heroActions(snapshot) {
    var serverOn = snapshot.server.status === "running";
    var tunnelOn = snapshot.tunnel.status === "running";
    var tunnelStarting = snapshot.tunnel.status === "starting";
    var anyOn = serverOn || tunnelOn || tunnelStarting;
    var html = "";
    if (!anyOn) {
      return actionButton("start_all", "一键启动", {
        className: "btn-primary",
        icon: "play",
        busyLabel: "启动中…"
      });
    }
    var stopAction = tunnelOn || tunnelStarting ? "stop_all" : "stop_server";
    html += actionButton(stopAction, "停止", {
      className: "btn-danger",
      icon: "stop",
      busyLabel: "停止中…"
    });
    if (serverOn && !tunnelStarting) {
      html += actionButton("restart_server", "重启", {
        className: "btn-ghost",
        icon: "restart",
        busyLabel: "重启中…"
      });
    }
    if (tunnelOn || tunnelStarting) {
      html += actionButton("stop_tunnel", "断开隧道", {
        className: "btn-ghost",
        icon: "x",
        busyLabel: "断开中…"
      });
    } else if (serverOn) {
      html += actionButton("start_tunnel", "连接隧道", {
        className: "btn-ghost",
        icon: "link",
        busyLabel: "连接中…"
      });
    }
    if (!serverOn) {
      html += actionButton("start_server", "仅启服务", {
        className: "btn-ghost",
        icon: "play",
        busyLabel: "启动中…"
      });
    }
    return html;
  }

  function cloudflaredNotice(snapshot) {
    var mode = snapshot.tunnelConfig.mode;
    var binaries = snapshot.binaries || {};
    var installing = ui.installing || Boolean(binaries.installingCloudflared);
    if ((mode === "quick" || mode === "named") && binaries.cloudflaredInstalled === false) {
      var button = installing
        ? '<button class="btn btn-sm btn-secondary" disabled><span class="spinner"></span><span>正在下载…</span></button>'
        : '<button class="btn btn-sm btn-secondary" data-action="install-cloudflared"' +
          (ui.busy ? " disabled" : "") +
          '>' +
          icon("download") +
          "<span>一键安装</span></button>";
      return (
        '<div class="notice">' +
        '<span class="notice-icon">' +
        icon("download") +
        "</span>" +
        '<div class="notice-body">' +
        '<p class="notice-title">未检测到 cloudflared</p>' +
        '<p class="' +
        (ui.installError ? "notice-desc error" : "notice-desc") +
        '">' +
        (ui.installError
          ? esc(ui.installError)
          : "Quick / Fixed 隧道需要它，可从 Cloudflare 官方 Release 自动下载到数据目录。") +
        "</p>" +
        "</div>" +
        button +
        "</div>"
      );
    }
    if (mode === "ngrok" && binaries.ngrokInstalled === false) {
      return (
        '<div class="notice">' +
        '<span class="notice-icon">' +
        icon("alert") +
        "</span>" +
        '<div class="notice-body">' +
        '<p class="notice-title">未检测到 ngrok</p>' +
        '<p class="notice-desc">请先安装 ngrok 并加入 PATH，DeskPort 会调用本机二进制。</p>' +
        "</div>" +
        "</div>"
      );
    }
    return "";
  }

  function tunnelErrorNotice(snapshot) {
    if (!snapshot.tunnel.error) return "";
    var retry =
      snapshot.tunnel.status === "error"
        ? actionButton("start_tunnel", "重试", {
            className: "btn-sm btn-secondary",
            icon: "restart",
            busyLabel: "连接中…"
          })
        : "";
    return (
      '<div class="notice danger">' +
      '<span class="notice-icon">' +
      icon("alert") +
      "</span>" +
      '<div class="notice-body">' +
      '<p class="notice-title">隧道错误</p>' +
      '<p class="notice-desc error">' +
      esc(snapshot.tunnel.error) +
      "</p>" +
      "</div>" +
      retry +
      "</div>"
    );
  }

  function formatBytes(bytes) {
    if (!bytes || bytes <= 0) return "";
    if (bytes < 1024 * 1024) return Math.round(bytes / 1024) + " KB";
    return (bytes / (1024 * 1024)).toFixed(1) + " MB";
  }

  function summarizeReleaseNotes(notes) {
    var lines = String(notes || "")
      .split(/\r?\n/)
      .map(function (line) {
        return line.replace(/^#+\s*/, "").replace(/^[-*]\s*/, "").trim();
      })
      .filter(Boolean);
    if (!lines.length) return "有新版本可用，建议更新以获取最新修复与功能。";
    var first = lines[0];
    return first.length > 90 ? first.slice(0, 89) + "…" : first;
  }

  function updateNotice() {
    var info = ui.update.info;
    if (!info || !info.hasUpdate || ui.update.dismissed) return "";
    var installing = ui.update.installing;
    var progress = ui.update.progress;
    var canDirectInstall = Boolean(info.downloadUrl && info.assetName && info.installMode !== "manual");
    var sizeText = info.assetSize ? " · " + formatBytes(info.assetSize) : "";
    var descHtml = "";
    if (installing && progress) {
      var pct = typeof progress.percent === "number" ? progress.percent : null;
      var downloadedText = progress.downloaded ? formatBytes(progress.downloaded) : "";
      var totalText = progress.total ? formatBytes(progress.total) : "";
      var detail =
        (progress.message || "正在更新…") +
        (pct !== null ? " " + pct + "%" : "") +
        (downloadedText && totalText ? " (" + downloadedText + " / " + totalText + ")" : "");
      descHtml =
        '<p class="notice-desc">' +
        esc(detail) +
        "</p>" +
        '<div class="update-progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="' +
        (pct !== null ? pct : 0) +
        '"><div class="update-progress-fill" style="width:' +
        (pct !== null ? pct : 35) +
        '%"></div></div>';
    } else if (ui.update.error) {
      descHtml = '<p class="notice-desc error">' + esc(ui.update.error) + "</p>";
    } else {
      descHtml =
        '<p class="notice-desc">' +
        esc(summarizeReleaseNotes(info.releaseNotes) + sizeText) +
        "</p>";
    }

    var primaryBtn = "";
    if (canDirectInstall) {
      primaryBtn = installing
        ? '<button class="btn btn-sm btn-primary" disabled><span class="spinner"></span><span>更新中…</span></button>'
        : '<button class="btn btn-sm btn-primary" data-action="install-update"' +
          (ui.busy ? " disabled" : "") +
          ">" +
          icon("download") +
          "<span>立即更新</span></button>";
    } else {
      primaryBtn =
        '<button class="btn btn-sm btn-primary" data-action="open-release-page">' +
        icon("arrow-right") +
        "<span>前往下载</span></button>";
    }

    var detailsBtn = installing
      ? ""
      : '<button class="btn btn-sm btn-ghost" data-action="open-release-page">查看详情</button>';
    var dismissBtn = installing
      ? ""
      : '<button class="icon-btn" data-action="dismiss-update" title="暂时忽略" aria-label="暂时忽略">' +
        icon("x") +
        "</button>";

    return (
      '<div class="notice update">' +
      '<span class="notice-icon">' +
      icon("arrow-up") +
      "</span>" +
      '<div class="notice-body">' +
      '<p class="notice-title">发现新版本 v' +
      esc(info.latestVersion) +
      "</p>" +
      descHtml +
      "</div>" +
      '<div class="notice-actions">' +
      primaryBtn +
      detailsBtn +
      dismissBtn +
      "</div>" +
      "</div>"
    );
  }

  function heroSignature(snapshot) {
    if (!snapshot) {
      return "empty|" + String(ui.loading) + "|" + String(ui.loadError || "");
    }
    return JSON.stringify({
      version: snapshot.version,
      platform: snapshot.platform,
      serverStatus: snapshot.server.status,
      startedAt: snapshot.server.startedAt,
      uptimeBucket: snapshot.server.startedAt
        ? Math.floor((Date.now() - snapshot.server.startedAt) / 60000)
        : 0,
      tunnelStatus: snapshot.tunnel.status,
      tunnelError: snapshot.tunnel.error,
      publicUrl: snapshot.tunnel.publicUrl,
      mcpUrl: snapshot.tunnel.mcpUrl,
      port: snapshot.config.port,
      mode: snapshot.tunnelConfig.mode,
      defaultWorkspace: snapshot.config.defaultWorkspace,
      workspaces: (snapshot.config.workspaces || []).map(function (item) {
        return [item.id, item.name];
      }),
      cloudflaredInstalled: (snapshot.binaries || {}).cloudflaredInstalled,
      ngrokInstalled: (snapshot.binaries || {}).ngrokInstalled,
      installing: Boolean((snapshot.binaries || {}).installingCloudflared) || ui.installing,
      installError: ui.installError,
      updateChecking: ui.update.checking,
      updateInstalling: ui.update.installing,
      updateDismissed: ui.update.dismissed,
      updateError: ui.update.error,
      updateVersion: ui.update.info && ui.update.info.hasUpdate ? ui.update.info.latestVersion : "",
      updatePercent: ui.update.progress ? ui.update.progress.percent : null,
      updateDownloaded: ui.update.progress ? ui.update.progress.downloaded : 0,
      updateStage: ui.update.progress ? ui.update.progress.stage : "",
      toolsCount: (snapshot.tools || []).length,
      toolsOpen: ui.toolsOpen,
      busy: ui.busy
    });
  }

  function renderHero(force) {
    var snapshot = ui.snapshot;
    var sig = heroSignature(snapshot);
    if (!force && sig === ui.heroSig) return;
    ui.heroSig = sig;

    if (!snapshot) {
      if (ui.loadError) {
        els.hero.innerHTML =
          '<div class="hero-top">' +
          '<div class="status-block">' +
          '<span class="status-dot error" aria-hidden="true"></span>' +
          '<div class="status-text">' +
          '<div class="hero-title">无法读取本地状态</div>' +
          '<div class="hero-sub">' +
          esc(ui.loadError) +
          "</div>" +
          "</div>" +
          "</div>" +
          '<div class="hero-actions">' +
          actionButton("retry-load", "重试", { className: "btn-secondary", icon: "restart" }) +
          "</div>" +
          "</div>";
      } else {
        els.hero.innerHTML =
          '<div class="hero-loading"><span class="status-dot starting"></span><span>正在连接 DeskPort 核心…</span></div>';
      }
      return;
    }

    var status = deriveStatus(snapshot);
    var publicOn = snapshot.tunnel.status === "running" && Boolean(snapshot.tunnel.mcpUrl);
    var url = mcpUrl(snapshot);
    var dim = snapshot.server.status !== "running" && !publicOn;
    var tools = snapshot.tools || [];
    var workspaces = snapshot.config.workspaces || [];
    var defaultWorkspace = snapshot.config.defaultWorkspace;
    var workspaceSelect = "";

    if (workspaces.length > 0) {
      var options = workspaces
        .map(function (item) {
          return (
            '<option value="' +
            esc(item.id) +
            '"' +
            (item.id === defaultWorkspace ? " selected" : "") +
            ">" +
            esc(item.name || item.id) +
            "</option>"
          );
        })
        .join("");
      workspaceSelect =
        '<span class="meta-item ws-switch" title="快速切换 MCP 默认工作区"><span>默认工作区</span>' +
        '<span class="select-wrap"><select class="mini-select" data-change="default-workspace" aria-label="默认工作区" ' +
        (ui.busy ? "disabled" : "") +
        ">" +
        options +
        "</select>" +
        icon("chevron", "chev") +
        "</span></span>";
    }

    els.hero.innerHTML =
      '<div class="hero-top">' +
      '<div class="status-block">' +
      '<span class="status-dot ' +
      status.dot +
      '" aria-hidden="true"></span>' +
      '<div class="status-text">' +
      '<div class="hero-title">' +
      esc(status.label) +
      "</div>" +
      '<div class="hero-sub">' +
      esc(heroSubtitle(snapshot, status)) +
      "</div>" +
      "</div>" +
      "</div>" +
      '<div class="hero-actions">' +
      heroActions(snapshot) +
      "</div>" +
      "</div>" +
      '<div class="urlbar' +
      (dim ? " dim" : "") +
      '">' +
      '<span class="url-kicker">MCP</span>' +
      '<code class="url-text" title="' +
      esc(url) +
      '">' +
      esc(url) +
      "</code>" +
      '<span class="url-tag ' +
      (publicOn ? "public" : "") +
      '">' +
      icon(publicOn ? "globe" : "monitor") +
      (publicOn ? "公网" : "本地") +
      "</span>" +
      '<button class="btn btn-copy" data-copy="' +
      esc(url) +
      '" title="复制 MCP 地址"' +
      (url ? "" : " disabled") +
      ">" +
      icon("copy") +
      "<span>复制</span></button>" +
      "</div>" +
      updateNotice() +
      cloudflaredNotice(snapshot) +
      tunnelErrorNotice(snapshot) +
      '<div class="meta">' +
      '<span class="meta-item"><span>端口</span><span class="meta-val">' +
      esc(snapshot.config.port) +
      "</span></span>" +
      '<span class="meta-item"><span>模式</span><span class="meta-val">' +
      esc(modeLabel(snapshot.tunnelConfig.mode)) +
      "</span></span>" +
      workspaceSelect +
      '<button class="tools-toggle" data-action="toggle-tools" aria-expanded="' +
      String(ui.toolsOpen) +
      '" aria-controls="toolsDrawer">' +
      esc(String(tools.length)) +
      " 个工具 " +
      icon("chevron") +
      "</button>" +
      "</div>" +
      '<div class="tools-drawer' +
      (ui.toolsOpen ? " open" : "") +
      '" id="toolsDrawer"><div class="tools-inner"><div class="tools-chips">' +
      tools
        .map(function (tool) {
          return '<span class="chip">' + esc(tool) + "</span>";
        })
        .join("") +
      "</div></div></div>";
  }

  /* ---------------------------------------------------------------- render: tabs + actions */
  function syncTabs() {
    var dirty = anyDraftDirty();
    els.tabs.forEach(function (tab) {
      var active = tab.getAttribute("data-tab") === ui.tab;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
      tab.tabIndex = active ? 0 : -1;
    });
    var tunnelTab = document.getElementById("tab-tunnel");
    if (tunnelTab) tunnelTab.classList.toggle("has-dirty", dirty);
    els.panelBody.setAttribute("aria-labelledby", "tab-" + ui.tab);
  }

  function renderPanelActions() {
    var snapshot = ui.snapshot;
    var html = "";
    if (ui.tab === "workspaces") {
      if (ui.picking) {
        html =
          '<button class="btn btn-sm btn-secondary" disabled><span class="spinner"></span><span>选择中…</span></button>';
      } else {
        html =
          '<button class="btn btn-sm btn-secondary" data-action="add-workspace"' +
          (!snapshot || ui.busy ? " disabled" : "") +
          ">" +
          icon("folder-plus") +
          "<span>添加文件夹</span></button>";
      }
    } else if (ui.tab === "tunnel") {
      if (snapshot && (snapshot.tunnel.status === "running" || snapshot.tunnel.status === "starting")) {
        html = actionButton("restart-tunnel", "重启隧道", {
          className: "btn-sm btn-ghost",
          icon: "restart",
          busyLabel: "重启中…"
        });
      }
    } else {
      var logCount = snapshot
        ? (snapshot.server.logs || []).length + (snapshot.tunnel.logs || []).length
        : 0;
      var busy = ui.busy === "clear_logs";
      html =
        '<button class="btn btn-sm btn-ghost" data-action="clear-logs"' +
        (!logCount || ui.busy ? " disabled" : "") +
        ">" +
        (busy ? '<span class="spinner"></span>' : icon("trash")) +
        "<span>清空日志</span></button>";
    }
    if (html === ui.actionsHtml) return;
    ui.actionsHtml = html;
    els.panelActions.innerHTML = html;
  }

  /* ---------------------------------------------------------------- render: workspaces */
  function renderWorkspaces(snapshot) {
    var list = Array.isArray(snapshot.config.workspaces) ? snapshot.config.workspaces : [];
    var defaultId = snapshot.config.defaultWorkspace;
    var restrict = Boolean(snapshot.config.restrictToWorkspaces);

    var rows = list
      .map(function (item) {
        var isDefault = item.id === defaultId;
        return (
          '<div class="ws-row">' +
          '<span class="ws-icon">' +
          icon("folder") +
          "</span>" +
          '<div class="ws-main">' +
          '<div class="ws-line">' +
          '<span class="ws-name" title="' +
          esc(item.name || item.id) +
          '">' +
          esc(item.name || item.id) +
          "</span>" +
          (isDefault ? '<span class="badge badge-green">默认</span>' : "") +
          '<span class="ws-id" title="工作区 ID">' +
          esc(item.id) +
          "</span>" +
          "</div>" +
          '<div class="ws-path" title="' +
          esc(item.path) +
          '">' +
          esc(item.path) +
          "</div>" +
          "</div>" +
          '<div class="ws-actions">' +
          (!isDefault
            ? '<button class="btn btn-ghost" data-action="set-default-workspace" data-ws-id="' +
              esc(item.id) +
              '" title="设为 MCP 默认工作区">设为默认</button>'
            : "") +
          (list.length > 1
            ? '<button class="icon-btn danger" data-action="delete-workspace" data-ws-id="' +
              esc(item.id) +
              '" title="移除工作区" aria-label="移除 ' +
              esc(item.name || item.id) +
              '">' +
              icon("trash") +
              "</button>"
            : "") +
          "</div>" +
          "</div>"
        );
      })
      .join("");

    return (
      '<div class="section-head">' +
      '<span class="section-title">已授权目录 · ' +
      list.length +
      "</span>" +
      '<span class="section-note">' +
      (restrict ? "白名单已开启" : "白名单已关闭") +
      "</span>" +
      "</div>" +
      '<div class="ws-list">' +
      (rows ||
        '<div class="list-empty">还没有工作区<br><span>点击右上角「添加文件夹」，用系统选择器添加</span></div>') +
      "</div>" +
      '<div class="safety ' +
      (restrict ? "" : "warn") +
      '">' +
      '<span class="safety-icon">' +
      icon(restrict ? "shield" : "alert") +
      "</span>" +
      '<div class="safety-body">' +
      '<div class="safety-title">仅限白名单目录访问 <span class="badge ' +
      (restrict ? "badge-green" : "badge-red") +
      '">' +
      (restrict ? "已开启" : "已关闭") +
      "</span></div>" +
      '<p class="safety-desc">' +
      (restrict
        ? "路径穿越与符号链接逃逸都会被拒绝，AI 只能触碰上面的目录。"
        : "风险：MCP 客户端可读写这台电脑上的任意文件。建议保持开启。") +
      "</p>" +
      "</div>" +
      '<label class="switch" title="' +
      (restrict ? "关闭白名单保护" : "开启白名单保护") +
      '">' +
      '<input type="checkbox" data-change="restrict" aria-label="仅限白名单目录访问" ' +
      (restrict ? "checked " : "") +
      (ui.busy ? "disabled " : "") +
      "/>" +
      '<span class="track"></span>' +
      "</label>" +
      "</div>"
    );
  }

  /* ---------------------------------------------------------------- render: tunnel */
  function renderTunnel(snapshot) {
    var mode = ui.draft.mode;
    var draft = ui.draft;
    var tunnelConfig = snapshot.tunnelConfig;
    var busyAttr = ui.busy ? " disabled" : "";

    var tiles = [
      ["quick", "Quick", "零配置临时域名"],
      ["named", "Fixed", "固定域名隧道"],
      ["ngrok", "ngrok", "自有固定域名"]
    ]
      .map(function (entry) {
        var active = mode === entry[0];
        return (
          '<button type="button" class="mode-tile' +
          (active ? " active" : "") +
          '" data-action="set-tunnel-mode" data-mode="' +
          entry[0] +
          '" aria-pressed="' +
          String(active) +
          '">' +
          '<span class="mode-top"><span class="mode-name">' +
          entry[1] +
          '</span><span class="mode-check">' +
          icon("check") +
          "</span></span>" +
          '<span class="mode-desc">' +
          entry[2] +
          "</span>" +
          "</button>"
        );
      })
      .join("");

    var fields = "";
    if (mode === "quick") {
      fields =
        '<div class="callout">' +
        icon("globe") +
        "<div><strong>零配置，开箱即用。</strong> 自动生成 <span class=\"mono\">*.trycloudflare.com</span> " +
        "公网地址，无需域名或 Cloudflare 账号；每次重启地址会变化。</div></div>";
    } else if (mode === "named") {
      fields =
        '<div class="form-grid">' +
        '<label class="field">' +
        '<span class="field-label"><span>Cloudflare Tunnel Token</span>' +
        (tunnelConfig.hasCloudflareToken ? '<span class="saved-tag">已保存</span>' : "") +
        "</span>" +
        '<input class="input" type="password" data-draft="tunnel.cfToken" autocomplete="off" spellcheck="false" value="' +
        esc(draft.tunnel.cfToken) +
        '" placeholder="' +
        (tunnelConfig.hasCloudflareToken
          ? "留空保持不变（" + esc(tunnelConfig.cloudflareTokenPreview || "已配置") + "）"
          : "粘贴 Tunnel Token") +
        '"' +
        busyAttr +
        " />" +
        '<span class="field-hint">' +
        (tunnelConfig.hasCloudflareToken
          ? "本机已保存 Token，留空不会被覆盖。"
          : "Token 只保存在本机 tunnel.json。") +
        "</span>" +
        "</label>" +
        '<label class="field">' +
        '<span class="field-label"><span>固定域名 URL</span><span class="opt">可选</span></span>' +
        '<input class="input" type="text" data-draft="tunnel.cfUrl" autocomplete="off" spellcheck="false" value="' +
        esc(draft.tunnel.cfUrl) +
        '" placeholder="https://mcp.example.com"' +
        busyAttr +
        " />" +
        '<span class="field-hint">留空时自动识别 Cloudflare 路由。</span>' +
        "</label>" +
        "</div>" +
        '<div class="callout">' +
        icon("key") +
        "<div>在 Cloudflare Zero Trust → Networks → Tunnels 创建隧道并复制 Token，再为它绑定一个 Public Hostname。</div></div>";
    } else {
      fields =
        '<div class="form-grid">' +
        '<label class="field">' +
        '<span class="field-label"><span>ngrok Authtoken</span>' +
        (tunnelConfig.hasNgrokAuthToken ? '<span class="saved-tag">已保存</span>' : "") +
        "</span>" +
        '<input class="input" type="password" data-draft="tunnel.ngrokToken" autocomplete="off" spellcheck="false" value="' +
        esc(draft.tunnel.ngrokToken) +
        '" placeholder="' +
        (tunnelConfig.hasNgrokAuthToken
          ? "留空保持不变（" + esc(tunnelConfig.ngrokAuthTokenPreview || "已配置") + "）"
          : "粘贴 ngrok Authtoken") +
        '"' +
        busyAttr +
        " />" +
        '<span class="field-hint">' +
        (tunnelConfig.hasNgrokAuthToken
          ? "留空保持已保存的 Token。"
          : "Token 只保存在本机 tunnel.json。") +
        "</span>" +
        "</label>" +
        '<label class="field">' +
        '<span class="field-label"><span>固定域名</span><span class="opt">可选</span></span>' +
        '<input class="input" type="text" data-draft="tunnel.ngrokDomain" autocomplete="off" spellcheck="false" value="' +
        esc(draft.tunnel.ngrokDomain) +
        '" placeholder="your-name.ngrok-free.app"' +
        busyAttr +
        " />" +
        '<span class="field-hint">填写 dev domain，不含 https://。</span>' +
        "</label>" +
        "</div>" +
        (snapshot.binaries.ngrokInstalled === false
          ? '<div class="callout amber">' +
            icon("alert") +
            "<div><strong>未检测到 ngrok。</strong> 请先安装 ngrok 并加入 PATH，DeskPort 会在启动隧道时调用本机二进制。</div></div>"
          : "");
    }

    var tunnelDirty = tunnelDraftDirty();
    var runtimeDirty = runtimeDraftDirty();

    return (
      '<div class="section-head">' +
      '<span class="section-title">公网隧道</span>' +
      '<span class="section-note">' +
      "当前 " +
      esc(modeLabel(tunnelConfig.mode)) +
      " · " +
      esc(tunnelRuntimeNote(snapshot)) +
      "</span>" +
      "</div>" +
      '<div class="mode-grid">' +
      tiles +
      "</div>" +
      fields +
      '<div class="form-foot">' +
      '<span class="dirty-note" id="tunnelDirtyNote"' +
      (tunnelDirty ? "" : " hidden") +
      ">未保存的更改</span>" +
      '<div class="form-actions">' +
      '<button class="btn btn-sm btn-ghost" data-action="discard-tunnel" id="tunnelDiscard"' +
      (tunnelDirty ? "" : " hidden") +
      ">放弃</button>" +
      '<button class="btn btn-sm btn-primary" data-action="save-tunnel">保存设置</button>' +
      "</div>" +
      "</div>" +
      renderRuntime(snapshot, runtimeDirty) +
      '<div class="section">' +
      '<div class="section-head">' +
      '<span class="section-title">30 秒接入</span>' +
      '<span class="section-note">OAuth 2.1 自动发现</span>' +
      "</div>" +
      renderSetup(snapshot) +
      "</div>"
    );
  }

  function renderRuntime(snapshot, runtimeDirty) {
    var runtime = ui.draft.runtime;
    var shellOptions = SHELLS.map(function (shell) {
      var labels = {
        auto: "自动检测",
        bash: "Bash",
        powershell: "PowerShell",
        cmd: "CMD",
        zsh: "Zsh",
        sh: "sh"
      };
      return (
        '<option value="' +
        shell +
        '"' +
        (shell === runtime.shell ? " selected" : "") +
        ">" +
        labels[shell] +
        "</option>"
      );
    }).join("");

    return (
      '<details class="runtime" id="runtimeDetails"' +
      (ui.runtimeOpen ? " open" : "") +
      ">" +
      "<summary>" +
      icon("terminal") +
      "<span>运行参数</span>" +
      '<span class="summary-values">:' +
      esc(snapshot.config.port) +
      " · " +
      esc(snapshot.config.defaultShell) +
      " · " +
      esc(snapshot.config.defaultTimeoutSec) +
      "s</span>" +
      icon("chevron", "chev") +
      "</summary>" +
      '<div class="runtime-body">' +
      '<div class="form-grid">' +
      '<label class="field">' +
      '<span class="field-label"><span>本地端口</span></span>' +
      '<input class="input" type="number" min="1" max="65535" data-draft="runtime.port" value="' +
      esc(runtime.port) +
      '"' +
      (ui.busy ? " disabled" : "") +
      " />" +
      '<span class="field-hint">修改后需重启 MCP 服务。</span>' +
      "</label>" +
      '<label class="field">' +
      '<span class="field-label"><span>默认 Shell</span></span>' +
      '<select class="select" data-draft="runtime.shell"' +
      (ui.busy ? " disabled" : "") +
      ">" +
      shellOptions +
      "</select>" +
      '<span class="field-hint">bash 工具未指定 shell 时使用。</span>' +
      "</label>" +
      '<label class="field">' +
      '<span class="field-label"><span>命令超时（秒）</span></span>' +
      '<input class="input" type="number" min="5" max="300" data-draft="runtime.timeout" value="' +
      esc(runtime.timeout) +
      '"' +
      (ui.busy ? " disabled" : "") +
      " />" +
      '<span class="field-hint">范围 5 – 300 秒。</span>' +
      "</label>" +
      '<label class="field">' +
      '<span class="field-label"><span>最大输出字符</span></span>' +
      '<input class="input" type="number" min="2000" max="100000" data-draft="runtime.maxOut" value="' +
      esc(runtime.maxOut) +
      '"' +
      (ui.busy ? " disabled" : "") +
      " />" +
      '<span class="field-hint">范围 2,000 – 100,000。</span>' +
      "</label>" +
      "</div>" +
      '<div class="form-foot">' +
      '<span class="dirty-note" id="runtimeDirtyNote"' +
      (runtimeDirty ? "" : " hidden") +
      ">未保存的更改</span>" +
      '<div class="form-actions">' +
      '<button class="btn btn-sm btn-ghost" data-action="discard-runtime" id="runtimeDiscard"' +
      (runtimeDirty ? "" : " hidden") +
      ">放弃</button>" +
      '<button class="btn btn-sm btn-secondary" data-action="save-runtime">保存参数</button>' +
      "</div>" +
      "</div>" +
      "</div>" +
      "</details>"
    );
  }

  function renderSetup(snapshot) {
    var url = mcpUrl(snapshot);
    var copyAttr = esc(url);
    var cards = [
      {
        name: "Claude",
        kind: "Desktop / Code",
        text: "设置 → Connectors → 添加自定义连接器，粘贴 MCP 地址并在浏览器完成授权。"
      },
      {
        name: "ChatGPT",
        kind: "Connectors",
        text: "设置 → Connectors（开发者模式）→ 新建 MCP 连接，粘贴 MCP 地址。"
      },
      {
        name: "Cursor",
        kind: "Settings → MCP",
        text: "Settings → MCP → Add new MCP server，类型选 http，粘贴 MCP 地址。"
      }
    ]
      .map(function (card) {
        return (
          '<div class="setup-card">' +
          '<div class="setup-head"><span class="setup-name">' +
          card.name +
          '</span><span class="setup-kind">' +
          card.kind +
          "</span></div>" +
          "<p>" +
          card.text +
          "</p>" +
          '<button class="btn btn-sm btn-ghost" data-copy="' +
          copyAttr +
          '">' +
          icon("copy") +
          "<span>复制 MCP 地址</span></button>" +
          "</div>"
        );
      })
      .join("");

    return (
      '<div class="setup-grid">' +
      cards +
      "</div>" +
      '<div class="callout">' +
      icon("shield") +
      "<div><strong>OAuth 2.1 自动发现：</strong> 客户端会读取 " +
      '<span class="mono">/.well-known/oauth-protected-resource</span>，弹出授权页即可，无需手动填 Token。</div></div>'
    );
  }

  /* ---------------------------------------------------------------- render: logs + oauth */
  function renderOAuth(snapshot) {
    var oauth = snapshot.oauth || {};
    var clients = Array.isArray(oauth.clients) ? oauth.clients : [];
    var tokens = Array.isArray(oauth.tokens) ? oauth.tokens : [];
    var activeCount = typeof oauth.activeTokenCount === "number" ? oauth.activeTokenCount : tokens.length;

    var clientRows = clients
      .map(function (client) {
        return (
          '<div class="client-row">' +
          '<span class="client-avatar">' +
          icon("key") +
          "</span>" +
          '<div class="client-main">' +
          '<div class="client-name">' +
          esc(client.clientName || "未命名客户端") +
          "</div>" +
          '<div class="client-id" title="' +
          esc(client.clientId) +
          '">' +
          esc(client.clientId) +
          "</div>" +
          "</div>" +
          '<span class="client-time" title="' +
          esc(fmtDate(client.createdAt)) +
          '">' +
          esc(fmtDate(client.createdAt)) +
          "</span>" +
          "</div>"
        );
      })
      .join("");

    var tokenRows = tokens
      .map(function (token) {
        var expired = Boolean(token.expired);
        return (
          '<div class="token-row' +
          (expired ? " expired" : "") +
          '">' +
          '<div class="token-main">' +
          '<div class="token-line">' +
          '<span class="token-prefix" title="' +
          esc(token.tokenId) +
          '">' +
          esc(token.tokenPrefix || "—") +
          "</span>" +
          '<span class="type-badge">' +
          esc(token.tokenType || "access") +
          "</span>" +
          (expired ? '<span class="badge badge-red">已过期</span>' : "") +
          "</div>" +
          '<div class="token-meta">' +
          "<span>" +
          esc(shortId(token.clientId) || "未知客户端") +
          "</span>" +
          '<span class="sep"></span>' +
          "<span>" +
          esc(token.scope || "mcp:tools") +
          "</span>" +
          '<span class="sep"></span>' +
          "<span>" +
          esc(tokenExpiry(token)) +
          "</span>" +
          "</div>" +
          "</div>" +
          '<button class="btn btn-danger-ghost token-revoke" data-action="revoke-token" data-token-id="' +
          esc(token.tokenId) +
          '" title="吊销此 Token">吊销</button>' +
          "</div>"
        );
      })
      .join("");

    return (
      '<div class="oauth">' +
      '<div class="section-head">' +
      '<span class="section-title">OAuth 授权</span>' +
      '<span class="section-note">' +
      clients.length +
      " 个客户端 · " +
      esc(activeCount) +
      " 个活跃 Token</span>" +
      "</div>" +
      '<div class="oauth-grid">' +
      '<div class="oauth-card">' +
      '<div class="oauth-card-head"><span>已授权客户端</span><span class="count">' +
      clients.length +
      "</span></div>" +
      '<div class="oauth-list">' +
      (clientRows ||
        '<div class="list-empty">暂无已授权客户端<br><span>应用发起 OAuth 连接后出现在这里</span></div>') +
      "</div>" +
      "</div>" +
      '<div class="oauth-card">' +
      '<div class="oauth-card-head"><span>Token</span>' +
      '<button class="btn btn-danger-ghost" data-action="revoke-all"' +
      (tokens.length ? "" : " disabled") +
      ">吊销全部</button></div>" +
      '<div class="oauth-list">' +
      (tokenRows ||
        '<div class="list-empty">暂无 Token<br><span>完成一次授权后即可看到签发记录</span></div>') +
      "</div>" +
      "</div>" +
      "</div>" +
      "</div>"
    );
  }

  function renderLogs(snapshot) {
    var tunnel = ui.logSource === "tunnel";
    var statusText = "";
    var statusClass = "";
    if (tunnel) {
      if (snapshot.tunnel.status === "running") {
        statusText = "运行中 · PID " + (snapshot.tunnel.pid || "—");
        statusClass = "live";
      } else if (snapshot.tunnel.status === "starting") {
        statusText = "正在连接…";
      } else if (snapshot.tunnel.status === "error") {
        statusText = "连接失败";
        statusClass = "err";
      } else {
        statusText = "未连接";
      }
    } else {
      statusText =
        snapshot.server.status === "running"
          ? "运行中 · 127.0.0.1:" + snapshot.config.port
          : "已停止";
      statusClass = snapshot.server.status === "running" ? "live" : "";
    }

    return (
      '<div class="logbar">' +
      '<div class="segmented" role="group" aria-label="日志来源">' +
      '<button class="seg' +
      (tunnel ? "" : " active") +
      '" data-action="set-log-source" data-source="server" aria-pressed="' +
      String(!tunnel) +
      '">MCP 服务</button>' +
      '<button class="seg' +
      (tunnel ? " active" : "") +
      '" data-action="set-log-source" data-source="tunnel" aria-pressed="' +
      String(tunnel) +
      '">隧道</button>' +
      "</div>" +
      '<span class="log-status ' +
      statusClass +
      '">' +
      esc(statusText) +
      "</span>" +
      "</div>" +
      '<div class="console" id="logConsole" role="log" tabindex="0" aria-label="' +
      (tunnel ? "隧道" : "MCP 服务") +
      '日志"></div>' +
      renderOAuth(snapshot)
    );
  }

  function logLineHtml(line) {
    var text = String(line === null || line === undefined ? "" : line);
    var match = /^(\[[^\]]+\]|\d{2}:\d{2}:\d{2})\s*([\s\S]*)$/.exec(text);
    var stamp = match ? match[1].replace(/^\[|\]$/g, "") : "";
    var message = match ? match[2] : text;
    var cls = "";
    if (/(error|failed|failure|exception|denied|panic|timed out|exited with code [1-9])/i.test(message)) {
      cls = "err";
    } else if (
      /(listening|ready|started|connected|registered|issued|success|saved|installed)/i.test(message)
    ) {
      cls = "ok";
    }
    return (
      '<div class="log-line ' +
      cls +
      '">' +
      (stamp ? '<span class="log-time">' + esc(stamp) + "</span>" : "") +
      '<span class="log-msg">' +
      esc(message) +
      "</span></div>"
    );
  }

  function renderLogConsole(force) {
    var consoleEl = document.getElementById("logConsole");
    if (!consoleEl || !ui.snapshot) return;
    var lines =
      ui.logSource === "tunnel"
        ? ui.snapshot.tunnel.logs || []
        : ui.snapshot.server.logs || [];
    if (!Array.isArray(lines)) lines = [];
    var sig = lines.length + "|" + (lines[0] || "") + "|" + (lines[lines.length - 1] || "");
    if (!force && sig === ui.logSig && consoleEl.dataset.sig === sig) return;
    ui.logSig = sig;
    consoleEl.dataset.sig = sig;
    if (!lines.length) {
      var emptyTitle = ui.logSource === "tunnel" ? "暂无隧道日志" : "暂无服务日志";
      var emptyHint =
        ui.logSource === "tunnel"
          ? "启动隧道后日志会实时出现在这里"
          : "启动 MCP 服务后日志会实时出现在这里";
      consoleEl.innerHTML =
        '<div class="console-empty">' +
        esc(emptyTitle) +
        "<span>" +
        esc(emptyHint) +
        "</span></div>";
      return;
    }
    consoleEl.innerHTML = lines.map(logLineHtml).join("");
    if (ui.logAutoScroll) consoleEl.scrollTop = consoleEl.scrollHeight;
  }

  /* ---------------------------------------------------------------- render: panel */
  function panelSignature() {
    if (!ui.snapshot) return "empty|" + ui.tab;
    return JSON.stringify({
      tab: ui.tab,
      mode: ui.draft.mode,
      logSource: ui.logSource,
      config: ui.snapshot.config,
      tunnelConfig: ui.snapshot.tunnelConfig,
      binaries: ui.snapshot.binaries,
      oauth: ui.snapshot.oauth
    });
  }

  function renderPanelBody(force) {
    var sig = panelSignature();
    if (!force && sig === ui.bodySig) return;
    ui.bodySig = sig;
    var snapshot = ui.snapshot;
    if (!snapshot) {
      els.panelBody.innerHTML =
        '<div class="list-empty">' +
        (ui.loadError ? "状态不可用" : "正在读取本地状态…") +
        "<br><span>" +
        esc(ui.loadError || "DeskPort 核心启动后会自动载入") +
        "</span></div>";
      return;
    }
    if (ui.tab === "workspaces") {
      els.panelBody.innerHTML = renderWorkspaces(snapshot);
    } else if (ui.tab === "tunnel") {
      els.panelBody.innerHTML = renderTunnel(snapshot);
      attachRuntimeDetails();
    } else {
      els.panelBody.innerHTML = renderLogs(snapshot);
      renderLogConsole(true);
    }
    syncDirtyUI();
  }

  function attachRuntimeDetails() {
    var details = document.getElementById("runtimeDetails");
    if (!details) return;
    details.addEventListener("toggle", function () {
      ui.runtimeOpen = details.open;
    });
  }

  function renderAll(options) {
    var opts = options || {};
    var force = Boolean(opts.force);
    renderHeader();
    syncTabs();
    renderHero(force);
    renderPanelActions();
    var editing = ui.tab === "tunnel" && anyDraftDirty();
    if (!editing || force) {
      renderPanelBody(force);
    }
    syncDirtyUI();
    renderLogConsole(force);
  }

  /* ---------------------------------------------------------------- data operations */
  async function fetchState() {
    var snapshot = await ipc("get_state", {});
    if (!isSnapshot(snapshot)) throw new Error("状态数据格式异常");
    return snapshot;
  }

  async function pullState(force) {
    if (!IS_TAURI) return;
    var seq = ++loadSeq;
    try {
      var snapshot = await ipc("get_state", {});
      if (seq !== loadSeq) return;
      if (!isSnapshot(snapshot)) throw new Error("状态数据格式异常");
      applySnapshot(snapshot);
      renderAll({ force: Boolean(force) });
    } catch (err) {
      if (seq !== loadSeq) return;
      if (!ui.snapshot) {
        ui.loading = false;
        ui.loadError = errorMessage(err);
        renderAll({ force: true });
      }
    }
  }

  var SNAPSHOT_MESSAGES = {
    start_all: "服务与隧道已启动",
    stop_all: "服务与隧道已停止",
    start_server: "MCP 服务已启动",
    stop_server: "MCP 服务已停止",
    restart_server: "MCP 服务已重启",
    start_tunnel: "隧道已连接",
    stop_tunnel: "隧道已断开",
    clear_logs: "日志已清空"
  };

  async function runSnapshotCommand(command, successText) {
    if (!ensureInteractive()) return;
    if (ui.busy) return;
    ui.busy = command;
    loadSeq += 1;
    renderAll({ soft: true });
    try {
      var snapshot = await ipc(command, {});
      if (isSnapshot(snapshot)) {
        applySnapshot(snapshot);
      } else {
        await fetchState().then(applySnapshot);
      }
      showToast(successText, "success");
    } catch (err) {
      showToast("操作失败：" + errorMessage(err), "error");
    } finally {
      ui.busy = null;
      renderAll();
    }
  }

  async function persistConfig(config, successText, afterSnapshot) {
    if (ui.busy) return false;
    ui.busy = "save_config";
    loadSeq += 1;
    try {
      var snapshot = await ipc("save_config", { config: config });
      if (!isSnapshot(snapshot)) snapshot = await fetchState();
      applySnapshot(snapshot);
      if (typeof afterSnapshot === "function") afterSnapshot();
      showToast(successText, "success");
      return true;
    } catch (err) {
      showToast("保存失败：" + errorMessage(err), "error");
      return false;
    } finally {
      ui.busy = null;
      renderAll();
    }
  }

  async function openDataDir() {
    if (!ensureInteractive()) return;
    try {
      await ipc("open_data_dir", {});
      showToast("已在文件管理器中打开数据目录", "success");
    } catch (err) {
      showToast("无法打开数据目录：" + errorMessage(err), "error");
    }
  }

  async function addWorkspace() {
    if (!ensureInteractive()) return;
    if (ui.picking || ui.busy) return;
    ui.picking = true;
    renderPanelActions();
    try {
      var picked = await ipc("pick_folder", {});
      if (!picked || typeof picked !== "string") return;
      var snapshot = ui.snapshot;
      if (!snapshot) return;
      var list = Array.isArray(snapshot.config.workspaces) ? snapshot.config.workspaces : [];
      var exists = list.some(function (item) {
        return samePath(item.path, picked);
      });
      if (exists) {
        showToast("这个文件夹已在工作区列表中");
        return;
      }
      var name = baseName(picked);
      var id = uniqueWorkspaceId(name, list);
      var next = list.concat([{ id: id, name: name, path: picked }]);
      var defaultWorkspace = list.some(function (item) {
        return item.id === snapshot.config.defaultWorkspace;
      })
        ? snapshot.config.defaultWorkspace
        : id;
      var config = configFromSnapshot({ workspaces: next, defaultWorkspace: defaultWorkspace });
      await persistConfig(config, "已添加工作区「" + name + "」");
    } catch (err) {
      showToast("选择文件夹失败：" + errorMessage(err), "error");
    } finally {
      ui.picking = false;
      renderPanelActions();
    }
  }

  async function setDefaultWorkspace(id) {
    if (!ensureInteractive()) {
      renderAll({ force: true });
      return;
    }
    if (!id || ui.busy) return;
    var snapshot = ui.snapshot;
    if (!snapshot) return;
    var list = snapshot.config.workspaces || [];
    var target = list.filter(function (item) {
      return item.id === id;
    })[0];
    if (!target) return;
    await persistConfig(
      configFromSnapshot({ defaultWorkspace: id }),
      "默认工作区已切换到「" + (target.name || target.id) + "」"
    );
  }

  function confirmDeleteWorkspace(id) {
    var snapshot = ui.snapshot;
    if (!snapshot) return;
    var list = snapshot.config.workspaces || [];
    if (list.length <= 1) return;
    var target = list.filter(function (item) {
      return item.id === id;
    })[0];
    if (!target) return;
    openConfirm({
      title: "移除工作区？",
      message: "「" + (target.name || target.id) + "」将从 MCP 白名单中移除，磁盘上的文件不会被删除。",
      confirmLabel: "移除",
      danger: true,
      onConfirm: async function () {
        if (!ensureInteractive()) return;
        var current = ui.snapshot;
        if (!current) return;
        var remaining = (current.config.workspaces || []).filter(function (item) {
          return item.id !== id;
        });
        if (!remaining.length) return;
        var stillDefault = remaining.some(function (item) {
          return item.id === current.config.defaultWorkspace;
        });
        await persistConfig(
          configFromSnapshot({
            workspaces: remaining,
            defaultWorkspace: stillDefault ? current.config.defaultWorkspace : remaining[0].id
          }),
          "工作区已移除"
        );
      }
    });
  }

  async function toggleRestrict(checked) {
    if (!ensureInteractive()) {
      renderAll({ force: true });
      return;
    }
    if (ui.busy) return;
    await persistConfig(
      configFromSnapshot({ restrictToWorkspaces: Boolean(checked) }),
      checked ? "白名单保护已开启" : "白名单保护已关闭"
    );
  }

  function setTunnelMode(mode) {
    if (mode !== "quick" && mode !== "named" && mode !== "ngrok") return;
    if (ui.draft.mode === mode) return;
    ui.draft.mode = mode;
    renderPanelBody(true);
    syncDirtyUI();
  }

  function buildTunnelPatch() {
    var mode = ui.draft.mode;
    var tunnelConfig = ui.snapshot.tunnelConfig;
    var patch = { mode: mode };
    if (mode === "named") {
      var cloudflareToken = String(ui.draft.tunnel.cfToken || "").trim();
      if (!cloudflareToken && !tunnelConfig.hasCloudflareToken) {
        showToast("请填写 Cloudflare Tunnel Token", "error");
        focusDraft("tunnel.cfToken");
        return null;
      }
      if (cloudflareToken) patch.cloudflareToken = cloudflareToken;
      patch.fixedUrl = String(ui.draft.tunnel.cfUrl || "").trim();
    } else if (mode === "ngrok") {
      var ngrokToken = String(ui.draft.tunnel.ngrokToken || "").trim();
      if (!ngrokToken && !tunnelConfig.hasNgrokAuthToken) {
        showToast("请填写 ngrok Authtoken", "error");
        focusDraft("tunnel.ngrokToken");
        return null;
      }
      if (ngrokToken) patch.ngrokAuthToken = ngrokToken;
      patch.ngrokDomain = String(ui.draft.tunnel.ngrokDomain || "").trim();
    }
    return patch;
  }

  function focusDraft(path) {
    var input = document.querySelector('[data-draft="' + path + '"]');
    if (input) input.focus();
  }

  async function saveTunnel() {
    if (!ensureInteractive()) return;
    if (ui.busy || !ui.snapshot) return;
    var patch = buildTunnelPatch();
    if (!patch) return;
    ui.busy = "save_tunnel_config";
    loadSeq += 1;
    try {
      var snapshot = await ipc("save_tunnel_config", { patch: patch });
      if (!isSnapshot(snapshot)) snapshot = await fetchState();
      applySnapshot(snapshot);
      syncTunnelDraft(true);
      var running =
        ui.snapshot.tunnel.status === "running" || ui.snapshot.tunnel.status === "starting";
      showToast(running ? "隧道设置已保存，重启隧道后生效" : "隧道设置已保存", "success");
    } catch (err) {
      showToast("保存失败：" + errorMessage(err), "error");
    } finally {
      ui.busy = null;
      renderAll({ force: true });
    }
  }

  function discardTunnel() {
    syncTunnelDraft(true);
    renderPanelBody(true);
    syncDirtyUI();
    showToast("已放弃隧道设置更改");
  }

  async function saveRuntime() {
    if (!ensureInteractive()) return;
    if (ui.busy || !ui.snapshot) return;

    var port = Number(ui.draft.runtime.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      showToast("端口需为 1 – 65535 的整数", "error");
      focusDraft("runtime.port");
      return;
    }
    var timeout = Number(ui.draft.runtime.timeout);
    if (!Number.isInteger(timeout) || timeout < 5 || timeout > 300) {
      showToast("命令超时需为 5 – 300 秒", "error");
      focusDraft("runtime.timeout");
      return;
    }
    var maxOut = Number(ui.draft.runtime.maxOut);
    if (!Number.isInteger(maxOut) || maxOut < 2000 || maxOut > 100000) {
      showToast("最大输出字符需为 2,000 – 100,000", "error");
      focusDraft("runtime.maxOut");
      return;
    }
    var shell = ui.draft.runtime.shell;
    if (SHELLS.indexOf(shell) === -1) {
      showToast("不支持该 Shell", "error");
      return;
    }

    var previousPort = ui.snapshot.config.port;
    var config = configFromSnapshot({
      port: port,
      defaultShell: shell,
      defaultTimeoutSec: timeout,
      maxOutputChars: maxOut
    });
    var message =
      previousPort !== port ? "运行参数已保存，重启服务后端口生效" : "运行参数已保存";
    await persistConfig(config, message, function () {
      syncRuntimeDraft(true);
    });
  }

  function discardRuntime() {
    syncRuntimeDraft(true);
    renderPanelBody(true);
    syncDirtyUI();
    showToast("已放弃运行参数更改");
  }

  async function checkForUpdates(silent) {
    if (!IS_TAURI) {
      if (!silent) showToast("浏览器预览模式 · 请在 DeskPort 桌面端检查更新");
      return;
    }
    if (ui.update.checking || ui.update.installing) return;
    ui.update.checking = true;
    renderHeader();
    try {
      var info = await ipc("check_update", {});
      ui.update.info = info;
      ui.update.error = "";
      if (info && info.hasUpdate) {
        ui.update.dismissed = false;
        if (!silent) showToast("发现新版本 v" + info.latestVersion, "success");
      } else if (!silent) {
        showToast("当前已是最新版本 v" + ((info && info.currentVersion) || "0.2.0"), "success");
      }
    } catch (err) {
      var msg = errorMessage(err);
      ui.update.error = msg;
      if (!silent) showToast("检查更新失败：" + msg, "error");
    } finally {
      ui.update.checking = false;
      renderHeader();
      renderHero(true);
    }
  }

  async function installUpdate() {
    if (!ensureInteractive()) return;
    var info = ui.update.info;
    if (ui.update.installing || !info || !info.downloadUrl || !info.assetName) return;
    ui.update.installing = true;
    ui.update.error = "";
    ui.update.progress = {
      stage: "downloading",
      downloaded: 0,
      total: info.assetSize || null,
      percent: 0,
      message: "正在准备下载…"
    };
    renderHeader();
    renderHero(true);
    try {
      await ipc("install_update", {
        downloadUrl: info.downloadUrl,
        assetName: info.assetName,
        installMode: info.installMode || "manual"
      });
    } catch (err) {
      ui.update.error = errorMessage(err);
      showToast("更新失败：" + ui.update.error, "error");
    } finally {
      ui.update.installing = false;
      renderHeader();
      renderHero(true);
    }
  }

  async function openReleasePage() {
    if (!ensureInteractive()) return;
    try {
      var url = ui.update.info && ui.update.info.releaseUrl ? ui.update.info.releaseUrl : null;
      await ipc("open_release_page", { url: url });
    } catch (err) {
      showToast("无法打开发布页：" + errorMessage(err), "error");
    }
  }

  function showUpdateBanner() {
    ui.update.dismissed = false;
    renderHero(true);
    var mainEl = document.getElementById("main");
    if (mainEl && typeof mainEl.scrollTo === "function") {
      mainEl.scrollTo({ top: 0, behavior: "smooth" });
    }
  }

  function dismissUpdateBanner() {
    ui.update.dismissed = true;
    renderHero(true);
  }

  async function installCloudflared() {
    if (!ensureInteractive()) return;
    if (ui.installing || ui.busy) return;
    ui.installing = true;
    ui.installError = "";
    renderHero(true);
    try {
      await ipc("install_cloudflared", {});
      showToast("cloudflared 安装完成", "success");
      await pullState(true);
    } catch (err) {
      ui.installError = errorMessage(err);
      showToast("安装失败：" + ui.installError, "error");
    } finally {
      ui.installing = false;
      renderHero(true);
    }
  }

  async function restartTunnel() {
    if (!ensureInteractive()) return;
    if (ui.busy) return;
    ui.busy = "restart-tunnel";
    loadSeq += 1;
    renderAll({ soft: true });
    try {
      await ipc("stop_tunnel", {});
      var snapshot = await ipc("start_tunnel", {});
      if (!isSnapshot(snapshot)) snapshot = await fetchState();
      applySnapshot(snapshot);
      showToast("隧道已按新设置重启", "success");
    } catch (err) {
      showToast("隧道重启失败：" + errorMessage(err), "error");
      await pullState(true);
    } finally {
      ui.busy = null;
      renderAll({ force: true });
    }
  }

  async function revokeTokens(tokenId) {
    if (!ensureInteractive()) return;
    if (ui.busy) return;
    ui.busy = "revoke_token";
    loadSeq += 1;
    try {
      var result = await ipc("revoke_token", { tokenId: tokenId === null ? null : tokenId });
      var deleted = result && typeof result.deleted === "number" ? result.deleted : 0;
      showToast(deleted ? "已吊销 " + deleted + " 个 Token" : "没有需要吊销的 Token", "success");
      await pullState(true);
    } catch (err) {
      showToast("吊销失败：" + errorMessage(err), "error");
    } finally {
      ui.busy = null;
      renderAll();
    }
  }

  function confirmRevokeAll() {
    if (!ui.snapshot) return;
    var tokens = ui.snapshot.oauth.tokens || [];
    if (!tokens.length) return;
    openConfirm({
      title: "吊销全部 Token？",
      message: "所有已连接的 MCP 客户端会立即断开，下次使用时需要重新发起 OAuth 授权。",
      confirmLabel: "全部吊销",
      danger: true,
      onConfirm: function () {
        return revokeTokens(null);
      }
    });
  }

  /* ---------------------------------------------------------------- ui actions */
  function setTab(tab) {
    if (tab !== "workspaces" && tab !== "tunnel" && tab !== "logs") return;
    if (ui.tab === tab) return;
    ui.tab = tab;
    renderAll({ force: true });
  }

  function setLogSource(source) {
    if (source !== "server" && source !== "tunnel") return;
    if (ui.logSource === source) return;
    ui.logSource = source;
    ui.logAutoScroll = true;
    renderPanelBody(true);
    syncTabs();
    renderLogConsole(true);
  }

  function toggleTools() {
    ui.toolsOpen = !ui.toolsOpen;
    var drawer = document.getElementById("toolsDrawer");
    var button = document.querySelector(".tools-toggle");
    if (drawer) drawer.classList.toggle("open", ui.toolsOpen);
    if (button) button.setAttribute("aria-expanded", String(ui.toolsOpen));
  }

  function retryLoad() {
    ui.loading = true;
    ui.loadError = null;
    renderAll({ force: true });
    pullState(true);
  }

  /* ---------------------------------------------------------------- events */
  function handleAction(action, element) {
    switch (action) {
      case "switch-tab":
        setTab(element.getAttribute("data-tab"));
        break;
      case "toggle-tools":
        toggleTools();
        break;
      case "toggle-theme":
        toggleTheme();
        break;
      case "open-data-dir":
        openDataDir();
        break;
      case "check-update":
        checkForUpdates(false);
        break;
      case "show-update":
        showUpdateBanner();
        break;
      case "install-update":
        installUpdate();
        break;
      case "open-release-page":
        openReleasePage();
        break;
      case "dismiss-update":
        dismissUpdateBanner();
        break;
      case "retry-load":
        retryLoad();
        break;
      case "start_all":
        runSnapshotCommand("start_all", SNAPSHOT_MESSAGES.start_all);
        break;
      case "stop_all":
        runSnapshotCommand("stop_all", SNAPSHOT_MESSAGES.stop_all);
        break;
      case "start_server":
        runSnapshotCommand("start_server", SNAPSHOT_MESSAGES.start_server);
        break;
      case "stop_server":
        runSnapshotCommand("stop_server", SNAPSHOT_MESSAGES.stop_server);
        break;
      case "restart_server":
        runSnapshotCommand("restart_server", SNAPSHOT_MESSAGES.restart_server);
        break;
      case "start_tunnel":
        runSnapshotCommand("start_tunnel", SNAPSHOT_MESSAGES.start_tunnel);
        break;
      case "stop_tunnel":
        runSnapshotCommand("stop_tunnel", SNAPSHOT_MESSAGES.stop_tunnel);
        break;
      case "clear-logs":
        runSnapshotCommand("clear_logs", SNAPSHOT_MESSAGES.clear_logs);
        break;
      case "install-cloudflared":
        installCloudflared();
        break;
      case "restart-tunnel":
        restartTunnel();
        break;
      case "add-workspace":
        addWorkspace();
        break;
      case "set-default-workspace":
        setDefaultWorkspace(element.getAttribute("data-ws-id"));
        break;
      case "delete-workspace":
        confirmDeleteWorkspace(element.getAttribute("data-ws-id"));
        break;
      case "set-tunnel-mode":
        setTunnelMode(element.getAttribute("data-mode"));
        break;
      case "save-tunnel":
        saveTunnel();
        break;
      case "discard-tunnel":
        discardTunnel();
        break;
      case "save-runtime":
        saveRuntime();
        break;
      case "discard-runtime":
        discardRuntime();
        break;
      case "set-log-source":
        setLogSource(element.getAttribute("data-source"));
        break;
      case "revoke-all":
        confirmRevokeAll();
        break;
      case "revoke-token":
        revokeTokens(element.getAttribute("data-token-id"));
        break;
      case "modal-cancel":
        closeConfirm();
        break;
      case "modal-confirm":
        acceptConfirm();
        break;
      default:
        break;
    }
  }

  function bindEvents() {
    document.addEventListener("click", function (event) {
      var target = event.target instanceof Element ? event.target : null;
      if (!target) return;
      var copyButton = target.closest("[data-copy]");
      if (copyButton) {
        event.preventDefault();
        copyToClipboard(copyButton.getAttribute("data-copy"), copyButton);
        return;
      }
      var actionElement = target.closest("[data-action]");
      if (!actionElement) return;
      handleAction(actionElement.getAttribute("data-action"), actionElement);
    });

    var onDraftEdit = function (event) {
      var target = event.target;
      if (!(target instanceof Element)) return;
      var field = target.closest("[data-draft]");
      if (!field) return;
      var path = field.getAttribute("data-draft").split(".");
      if (path.length !== 2 || !ui.draft[path[0]]) return;
      ui.draft[path[0]][path[1]] = field.value;
      syncDirtyUI();
    };

    document.addEventListener("input", onDraftEdit);
    document.addEventListener("change", onDraftEdit);

    document.addEventListener("change", function (event) {
      var target = event.target;
      if (!(target instanceof Element)) return;
      if (target.matches('[data-change="default-workspace"]')) {
        setDefaultWorkspace(target.value);
        return;
      }
      if (target.matches('[data-change="restrict"]')) {
        toggleRestrict(target.checked);
      }
    });

    document.addEventListener(
      "scroll",
      function (event) {
        var target = event.target;
        if (!(target instanceof Element) || target.id !== "logConsole") return;
        ui.logAutoScroll = target.scrollHeight - target.scrollTop - target.clientHeight < 12;
      },
      true
    );

    document.addEventListener("keydown", function (event) {
      var target = event.target instanceof Element ? event.target : null;
      if (!target) return;
      var tabButton = target.closest('.seg[data-tab]');
      if (!tabButton) return;
      var index = els.tabs.indexOf(tabButton);
      if (index === -1) return;
      var next = null;
      if (event.key === "ArrowRight") next = els.tabs[(index + 1) % els.tabs.length];
      else if (event.key === "ArrowLeft") next = els.tabs[(index - 1 + els.tabs.length) % els.tabs.length];
      else if (event.key === "Home") next = els.tabs[0];
      else if (event.key === "End") next = els.tabs[els.tabs.length - 1];
      if (!next) return;
      event.preventDefault();
      next.focus();
      setTab(next.getAttribute("data-tab"));
    });

    document.addEventListener("keydown", function (event) {
      if (!ui.confirm) return;
      if (event.key === "Escape") {
        event.preventDefault();
        closeConfirm();
        return;
      }
      if (event.key !== "Tab") return;
      var focusable = els.modal.querySelectorAll("button:not(:disabled)");
      if (!focusable.length) return;
      var first = focusable[0];
      var last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });

    document.addEventListener("visibilitychange", function () {
      if (document.visibilityState !== "visible") return;
      if (ui.busy || ui.picking || ui.installing) return;
      pullState(false);
    });

    els.modal.addEventListener("click", function (event) {
      if (event.target === els.modal) closeConfirm();
    });

    window.addEventListener("online", function () {
      if (ui.busy || ui.picking || ui.installing) return;
      pullState(false);
    });
  }

  async function subscribeStateEvents() {
    if (!IS_TAURI || !CAN_LISTEN_EVENTS) return;
    try {
      await window.__TAURI__.event.listen("state-changed", function () {
        if (ui.busy || ui.picking || ui.installing) return;
        pullState(false);
      });
      await window.__TAURI__.event.listen("update-progress", function (event) {
        if (event && event.payload) {
          ui.update.progress = event.payload;
          renderHero();
        }
      });
      await window.__TAURI__.event.listen("trigger-check-update", function () {
        checkForUpdates(false);
      });
    } catch (err) {
      /* The 2.5s fallback poll still keeps the UI fresh. */
    }
  }

  /* ---------------------------------------------------------------- boot */
  function boot() {
    renderThemeButton();
    watchSystemTheme();
    bindEvents();
    renderAll({ force: true });

    if (!IS_TAURI) {
      ui.preview = true;
      els.previewFlag.hidden = false;
      ui.snapshot = createMockState();
      ui.loading = false;
      syncTunnelDraft(true);
      syncRuntimeDraft(true);
      renderAll({ force: true });
      return;
    }

    subscribeStateEvents();
    pullState(true);
    setTimeout(function () {
      checkForUpdates(true);
    }, 3000);
    setInterval(function () {
      if (document.visibilityState !== "visible") return;
      if (ui.busy || ui.picking || ui.installing) return;
      pullState(false);
    }, 2500);
  }

  boot();
})();
