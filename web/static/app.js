// capgo dashboard 共享 JS（原生 ES 模块，无框架）
// 约定：所有写操作自动带 X-CSRF-Token（登录时下发，存 sessionStorage）。

let csrfToken = sessionStorage.getItem("capgo.csrf") || "";

/** 页面启动时尝试恢复 CSRF（新标签页 sessionStorage 为空）。 */
export async function ensureCSRF() {
  if (csrfToken) return csrfToken;
  await refreshCSRF();
  return csrfToken;
}

export function setCSRF(token) {
  csrfToken = token || "";
  if (token) sessionStorage.setItem("capgo.csrf", token);
  else sessionStorage.removeItem("capgo.csrf");
}

export function getCSRF() {
  return csrfToken;
}

export class ApiError extends Error {
  constructor(status, body) {
    super((body && (body.error || body.message)) || `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

/** api 执行 JSON 请求；401 自动跳登录页。 */
export async function api(method, path, body) {
  const init = { method, headers: {}, credentials: "same-origin" };
  if (body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  if (method !== "GET" && method !== "HEAD") {
    if (!csrfToken) {
      // 页面刷新后 sessionStorage 仍在；若丢失则先取一次
      await refreshCSRF();
    }
    if (csrfToken) init.headers["X-CSRF-Token"] = csrfToken;
  }
  const resp = await fetch(path, init);
  let data = null;
  const text = await resp.text();
  if (text) {
    try { data = JSON.parse(text); } catch { data = { error: text.slice(0, 200) }; }
  }
  if (resp.status === 401) {
    setCSRF("");
    if (!location.pathname.endsWith("/login") && !location.pathname.endsWith("/login.html")) {
      location.href = "/admin/login";
    }
    throw new ApiError(resp.status, data);
  }
  if (!resp.ok) throw new ApiError(resp.status, data);
  return data;
}

async function refreshCSRF() {
  try {
    const resp = await fetch("/admin/api/session", { credentials: "same-origin" });
    if (!resp.ok) return;
    const data = await resp.json().catch(() => ({}));
    if (data.csrf) setCSRF(data.csrf);
  } catch { /* 网络异常：保持无 token，写操作会得到 403 */ }
}

/** 带二次认证（再输入 admin key）的高危操作。 */
export async function apiReauth(method, path, key) {
  return api(method, path, { key });
}

export function el(sel) { return document.querySelector(sel); }

export function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

export function fmtTime(ms) {
  if (!ms) return "—";
  const d = new Date(ms);
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export function fmtDuration(ms) {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

export function showAlert(node, msg, kind = "err") {
  if (!node) return;
  node.textContent = msg;
  node.className = `alert show ${kind}`;
  if (kind === "ok") setTimeout(() => { node.className = "alert"; }, 4000);
}

export function clearAlert(node) { if (node) node.className = "alert"; }

export function badge(text, cls) {
  return h("span", { class: `badge ${cls || ""}`.trim(), text });
}

export function outcomeBadge(outcome) {
  const map = { pass: "pass", fail: "fail", blocked: "fail", limit: "limit" };
  return badge(outcome || "—", map[outcome] || "");
}

export function protocolBadge(p) {
  if (p === "format2") return badge("format-2", "fmt2");
  if (p === "format1") return badge("format-1", "fmt1");
  return badge("—");
}

/** 渲染面包屑式标题栏（nav 高亮由各页脚本设置 data-nav） */
export function mountNav(active) {
  document.querySelectorAll("header.topbar nav a").forEach((a) => {
    if (a.dataset.nav === active) a.classList.add("active");
  });
}

/** 简易确认对话框（原生 confirm 便于无障碍/无额外依赖） */
export function confirmAction(msg) { return window.confirm(msg); }
