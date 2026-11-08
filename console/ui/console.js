"use strict";

const STATUS_EVERY_MS = 5000;
const DETAILS_EVERY_MS = 30000;
const AFTER_EVENT_MS = 1500;
const FEED_CAP = 500;
const THEME_KEY = "lepic-console-theme";

const $ = (id) => document.getElementById(id);

// The API reference, once its tab has been opened.
let reference = null;
let referenceLoading = false;

// Small DOM builder: el("td", { class: "num" }, "12") or el("dl", null, [a, b]).
function el(tag, attrs, children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (name === "text") node.textContent = value;
    else if (name.startsWith("on")) node.addEventListener(name.slice(2), value);
    else node.setAttribute(name, value === true ? "" : value);
  }
  for (const child of [].concat(children || [])) {
    if (child === null || child === undefined) continue;
    node.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return node;
}

function replace(node, children) {
  node.replaceChildren(...[].concat(children || []).filter((c) => c !== null && c !== undefined));
}

// Formatting

const integerFormat = new Intl.NumberFormat(undefined, { useGrouping: true });
const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" });
const timeFormat = new Intl.DateTimeFormat(undefined, { timeStyle: "medium" });

function amount(text) {
  if (text === null || text === undefined || text === "") return "–";
  const [whole, fraction] = String(text).split(".");
  const sign = whole.startsWith("-") ? "-" : "";
  const digits = whole.replace("-", "");
  const grouped = /^\d+$/.test(digits) ? integerFormat.format(BigInt(digits)) : digits;
  return fraction === undefined ? sign + grouped : `${sign}${grouped}.${fraction}`;
}

function count(value) {
  return typeof value === "number" ? integerFormat.format(value) : "–";
}

function when(text) {
  if (!text) return "–";
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? String(text) : dateFormat.format(date);
}

function duration(seconds) {
  if (typeof seconds !== "number") return "–";
  const parts = [];
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) parts.push(`${days}d`);
  if (days || hours) parts.push(`${hours}h`);
  parts.push(`${minutes}m`);
  if (!days && !hours) parts.push(`${seconds % 60}s`);
  return parts.join(" ");
}

function plural(n, word) {
  return `${integerFormat.format(n)} ${word}${n === 1 ? "" : "s"}`;
}

function words(key) {
  return String(key).replace(/_/g, " ");
}

// Theme

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const light = theme === "light";
  $("theme").textContent = light ? "Use dark theme" : "Use light theme";
  $("theme").setAttribute("aria-pressed", String(light));
  document.querySelector('meta[name="theme-color"]').content = getComputedStyle(document.documentElement).getPropertyValue("--bg").trim();
  if (reference) reference.updateConfiguration(referenceOptions());
}

$("theme").addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  try { localStorage.setItem(THEME_KEY, next); } catch { /* storage may be off */ }
  applyTheme(next);
});

(function initTheme() {
  let saved = null;
  try { saved = localStorage.getItem(THEME_KEY); } catch { /* storage may be off */ }
  if (saved === "light" || saved === "dark") applyTheme(saved);
})();

// Tabs with hash routing

const tabs = [...document.querySelectorAll('[role="tab"]')];

function showTab(id, focus) {
  let found = false;
  for (const tab of tabs) {
    const on = tab.id === `tab-${id}`;
    found = found || on;
    tab.setAttribute("aria-selected", String(on));
    tab.tabIndex = on ? 0 : -1;
    $(tab.getAttribute("aria-controls")).hidden = !on;
    if (on && focus) tab.focus();
  }
  if (!found) return showTab("overview", focus);
  if (location.hash !== `#${id}`) history.replaceState(null, "", `#${id}`);
  if (id === "api") loadReference();
}

for (const tab of tabs) {
  tab.addEventListener("click", () => showTab(tab.id.slice(4), false));
  tab.addEventListener("keydown", (event) => {
    const keys = { ArrowDown: 1, ArrowRight: 1, ArrowUp: -1, ArrowLeft: -1, Home: -Infinity, End: Infinity };
    if (!(event.key in keys)) return;
    event.preventDefault();
    const index = tabs.indexOf(tab);
    const step = keys[event.key];
    const next = Number.isFinite(step)
      ? (index + step + tabs.length) % tabs.length
      : step < 0 ? 0 : tabs.length - 1;
    showTab(tabs[next].id.slice(4), true);
  });
}

window.addEventListener("hashchange", () => showTab(location.hash.slice(1) || "overview", false));
showTab(location.hash.slice(1) || "overview", false);

// The API, through the console's own proxy

class Problem extends Error {
  constructor(body, status) {
    super(body.detail || body.title || `HTTP ${status}`);
    this.code = body.code || null;
    this.status = status;
  }
}

async function api(path, init) {
  let response;
  try {
    response = await fetch(`/api${path}`, { cache: "no-store", ...init });
  } catch (error) {
    throw new Problem({ detail: `the console itself is not answering: ${error.message}`, code: "console" }, 0);
  }
  const type = response.headers.get("content-type") || "";
  const body = type.includes("json") ? await response.json().catch(() => ({})) : {};
  if (!response.ok) throw new Problem(body, response.status);
  return body;
}

// Reachability banner and connection line

let unreachable = false;

function setLink(state, text) {
  const link = $("link");
  link.dataset.state = state;
  link.textContent = text;
}

function markUnreachable(problem) {
  unreachable = true;
  $("unreachable").hidden = false;
  $("unreachable-detail").textContent = problem.message;
  setLink("bad", "lepic serve is not answering");
}

function markReachable(socket) {
  if (unreachable) {
    unreachable = false;
    $("unreachable").hidden = true;
  }
  setLink("ok", socket ? `Connected to serve at ${socket}` : "Connected to serve");
}

function isUnreachable(error) {
  return error instanceof Problem && (error.code === "unreachable" || error.code === "console");
}

$("retry").addEventListener("click", () => refreshAll());

// Facts rendering

function kv(pairs) {
  const nodes = [];
  for (const [label, value, tone] of pairs) {
    const long = typeof value === "string" && value.length > 48;
    nodes.push(el("dt", { text: label }));
    nodes.push(el("dd", { class: [tone ? `tone-${tone}` : "", long ? "long" : ""].join(" ").trim() || null }, value));
  }
  return nodes;
}

function renderStatus(status) {
  const wallet = status.height;
  const node = status.node_tip;
  const sync = $("sync");
  let word;
  let tone;
  if (typeof node !== "number" && typeof wallet !== "number") {
    word = "serve has not confirmed a node tip yet";
    tone = "unknown";
  } else if (typeof wallet !== "number") {
    word = `No refresh has applied yet. The node tip is ${count(node)}.`;
    tone = "unknown";
  } else if (typeof node !== "number") {
    word = `Wallet at height ${count(wallet)}, node tip not confirmed yet`;
    tone = "unknown";
  } else if (node === wallet) {
    word = `In step with the node at height ${count(node)}`;
    tone = "ok";
  } else if (node > wallet) {
    word = `${plural(node - wallet, "block")} behind the node`;
    tone = "behind";
  } else {
    word = `${plural(wallet - node, "block")} above the last confirmed tip`;
    tone = "ok";
  }
  sync.dataset.tone = tone;
  $("sync-word").textContent = word;
  $("sync-wallet").textContent = count(wallet);
  $("sync-node").textContent = count(node);
  const top = Math.max(node || 0, wallet || 0);
  const at = (h) => (top > 0 && typeof h === "number" ? `${Math.min(100, (h / top) * 100)}%` : null);
  $("sync-fill").style.width = at(wallet) || "0%";
  $("sync-wallet-pin").style.left = at(wallet) || "0%";
  $("sync-node-pin").style.left = at(node) || "100%";

  const epicbox = status.epicbox || "no report yet";
  const epicboxTone = { connected: "ok", connecting: "warn", disconnected: "bad", stopped: "muted" }[status.epicbox] || "muted";
  replace($("serve-facts"), kv([
    ["Socket", el("code", { text: status.socket || "–" })],
    ["Uptime", duration(status.uptime_s)],
    ["Epicbox", epicbox, epicboxTone],
  ]));

  const requests = status.requests || {};
  replace($("request-facts"), kv([
    ["Served", count(requests.served)],
    ["In flight", count(requests.in_flight)],
    ["Refused", count(requests.refused), requests.refused ? "warn" : null],
  ]));

  const listeners = [["Owner API", "Unix socket"], ["Epicbox", epicbox, epicboxTone]];
  const http = status.http;
  if (http) {
    listeners.push(["HTTP", `port ${http.port}, ${http.exposure}`]);
    listeners.push(["HTTP payments", `${count(http.received)} received, ${count(http.repeated)} repeated, ${count(http.refused)} refused`]);
    listeners.push(["Coinbase", http.coinbase]);
  } else {
    listeners.push(["HTTP", "not running", "muted"]);
  }
  replace($("listener-facts"), kv(listeners));

  const maintenance = [];
  for (const [label, report] of [["Refresh", status.refresh], ["Collect", status.collect]]) {
    const r = report || {};
    maintenance.push([`Last ${label.toLowerCase()}`, r.last_success ? when(r.last_success) : "none yet", r.last_success ? null : "muted"]);
    maintenance.push([`${label} failures in a row`, count(r.consecutive_failures), r.consecutive_failures ? "warn" : null]);
    if (r.last_error) maintenance.push([`${label} last error`, r.last_error, r.consecutive_failures ? "bad" : "muted"]);
  }
  replace($("maintenance-facts"), kv(maintenance));
}

function renderWallet(info) {
  const tag = $("network");
  tag.textContent = info.network || "";
  tag.hidden = !info.network;

  const columns = ["total", "spendable", "awaiting_confirmation", "awaiting_finalization", "immature", "locked"];
  const head = el("tr", null, [el("th", { text: "Account" }), ...columns.map((c) => el("th", { class: "num", text: words(c) }))]);
  const rows = (info.accounts || []).map((a) =>
    el("tr", null, [
      el("td", null, [el("b", { text: a.label }), " ", el("span", { class: "muted small", text: `#${a.index}` })]),
      ...columns.map((c) => el("td", { class: "num", text: amount(a[c]) })),
    ]));
  const notes = [];
  notes.push(`Balances at height ${count(info.height)}.`);
  if (info.catching_up) notes.push(`The node is at ${count(info.node_height)} and the wallet is catching up.`);
  if (info.node_behind) notes.push("The node is behind the last refresh, so the balances were not updated.");
  replace($("balances"), [
    rows.length
      ? el("table", null, [el("thead", null, head), el("tbody", null, rows)])
      : el("p", { class: "empty", text: "This wallet has no accounts." }),
    el("p", { class: "muted small", style: "margin-top:10px", text: notes.join(" ") }),
  ]);
}

function renderAddress(report) {
  $("address").textContent = report.address || "–";
  $("copy-address").hidden = !report.address;
}

$("copy-address").addEventListener("click", async () => {
  const note = $("copy-note");
  try {
    await navigator.clipboard.writeText($("address").textContent);
    note.textContent = "Copied.";
  } catch {
    note.textContent = "Copy is not available here. Select the address to copy it.";
  }
  setTimeout(() => { note.textContent = ""; }, 4000);
});

function renderNode(node) {
  replace($("node-facts"), kv([
    ["Node", el("code", { text: node.node || "–" })],
    ["Version", node.node_version || "–"],
    ["Header version", count(node.block_header_version)],
    ["Height", count(node.height)],
    ["Last block", el("code", { text: node.last_block || "–" })],
  ]));
}

function renderProblemInto(container, what, error) {
  replace(container, el("p", { class: "empty", text: `Could not load ${what}: ${error.message}` }));
}

// Transactions and outputs

let canCancel = false;

function stateChip(text) {
  return el("span", { class: "state", text: text || "–" });
}

function renderTransactions(report) {
  const list = report.transactions || [];
  $("tx-summary").textContent = list.length
    ? `${plural(list.length, "transaction")} in account ${report.account ?? 0}, newest first.`
    : "";
  if (!list.length) {
    replace($("transactions"), el("p", { class: "empty", text: "No transactions in this wallet yet." }));
    return;
  }
  const sorted = [...list].sort((a, b) => String(b.updated_at).localeCompare(String(a.updated_at)));
  const head = el("tr", null, [
    el("th", { text: "Id" }), el("th", { text: "Direction" }), el("th", { text: "State" }),
    el("th", { class: "num", text: "Credited" }), el("th", { class: "num", text: "Debited" }),
    el("th", { class: "num", text: "Fee" }), el("th", { text: "Created" }), el("th", { text: "Updated" }),
  ]);
  const rows = sorted.map((tx) => {
    const open = () => openTransaction(tx.tx_id);
    const row = el("tr", { "data-tx": tx.tx_id, onclick: open }, [
      el("td", null, el("button", { type: "button", text: String(tx.tx_id), "aria-label": `Open transaction ${tx.tx_id}`, onclick: (e) => { e.stopPropagation(); open(); } })),
      el("td", { text: tx.direction || "–" }),
      el("td", null, stateChip(tx.state)),
      el("td", { class: "num", text: amount(tx.amount_credited) }),
      el("td", { class: "num", text: amount(tx.amount_debited) }),
      el("td", { class: "num", text: amount(tx.fee) }),
      el("td", { text: when(tx.created_at) }),
      el("td", { text: when(tx.updated_at) }),
    ]);
    return row;
  });
  replace($("transactions"), el("div", { class: "table-card" }, el("table", null, [el("thead", null, head), el("tbody", null, rows)])));
}

function renderOutputs(report) {
  const list = report.outputs || [];
  $("outputs-summary").textContent = list.length ? `${plural(list.length, "output")} in account ${report.account ?? 0}.` : "";
  if (!list.length) {
    replace($("outputs"), el("p", { class: "empty", text: "No outputs in this wallet yet." }));
    return;
  }
  const head = el("tr", null, [
    el("th", { text: "Commitment" }), el("th", { class: "num", text: "Value" }), el("th", { text: "Status" }),
    el("th", { text: "Category" }), el("th", { class: "num", text: "Height" }), el("th", { class: "num", text: "Confirmations" }),
    el("th", { class: "num", text: "Lock height" }), el("th", { text: "Coinbase" }), el("th", { class: "num", text: "Tx" }),
  ]);
  const rows = list.map((o) => el("tr", null, [
    el("td", null, el("code", { text: `${o.commitment.slice(0, 12)}…${o.commitment.slice(-6)}`, title: o.commitment })),
    el("td", { class: "num", text: amount(o.value) }),
    el("td", null, stateChip(o.status)),
    el("td", { text: o.category ? words(o.category) : "–" }),
    el("td", { class: "num", text: count(o.height) }),
    el("td", { class: "num", text: count(o.confirmations) }),
    el("td", { class: "num", text: typeof o.lock_height === "number" ? count(o.lock_height) : "–" }),
    el("td", { text: o.is_coinbase ? "yes" : "no" }),
    el("td", { class: "num", text: typeof o.tx_id === "number" ? String(o.tx_id) : "–" }),
  ]));
  replace($("outputs"), el("div", { class: "table-card" }, el("table", null, [el("thead", null, head), el("tbody", null, rows)])));
}

// Transaction detail

const dialog = $("tx-dialog");
let openTxId = null;

function detailValue(key, value) {
  if (value === null || value === undefined) return el("span", { class: "muted", text: "–" });
  if (/^amount|fee$/.test(key) || key === "amount") return amount(value);
  if (/_at$/.test(key)) return when(value);
  if (key === "state") return stateChip(value);
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value === "number") return count(value);
  if (Array.isArray(value)) {
    if (!value.length) return el("span", { class: "muted", text: "none" });
    return el("ul", { style: "margin:0;padding-left:18px" }, value.map((item) =>
      el("li", null, typeof item === "object" ? el("code", { text: JSON.stringify(item) }) : String(item))));
  }
  if (typeof value === "object") {
    return el("dl", { class: "kv" }, kv(Object.entries(value).map(([k, v]) => [words(k), detailValue(k, v)])));
  }
  if (/^[0-9a-f]{16,}$/i.test(String(value)) || key === "slate_id") return el("code", { text: String(value) });
  return String(value);
}

async function openTransaction(id) {
  openTxId = id;
  dialog.dataset.returnTo = String(id);
  $("tx-dialog-title").textContent = `Transaction ${id}`;
  replace($("tx-dialog-body"), el("p", { class: "muted", text: "Loading…" }));
  $("tx-dialog-actions").hidden = true;
  resetCancel();
  if (!dialog.open) dialog.showModal();
  try {
    const tx = await api(`/v1/transactions/${id}`);
    if (openTxId !== id) return;
    const pairs = Object.entries(tx).map(([k, v]) => [words(k), detailValue(k, v)]);
    replace($("tx-dialog-body"), el("dl", { class: "kv" }, kv(pairs)));
    $("tx-dialog-actions").hidden = !canCancel;
  } catch (error) {
    if (openTxId !== id) return;
    replace($("tx-dialog-body"), el("p", { class: "empty", text: `Could not load the transaction: ${error.message}` }));
  }
}

function resetCancel() {
  $("tx-cancel").hidden = false;
  $("tx-cancel").disabled = false;
  $("tx-cancel-confirm").hidden = true;
  $("tx-cancel-note").textContent = "";
}

$("tx-cancel").addEventListener("click", () => {
  $("tx-cancel").hidden = true;
  $("tx-cancel-confirm").hidden = false;
  $("tx-cancel-note").textContent = "serve will refuse a cancel the transaction's state does not allow.";
  $("tx-cancel-confirm").focus();
});

$("tx-cancel-confirm").addEventListener("click", async () => {
  const id = openTxId;
  $("tx-cancel-confirm").disabled = true;
  $("tx-cancel-note").textContent = "Cancelling…";
  try {
    const result = await api(`/v1/transactions/${id}/cancel`, { method: "POST" });
    $("tx-cancel-note").textContent = `Transaction ${result.tx_id ?? id} is now ${result.state || "cancelled"}.`;
    $("tx-cancel-confirm").hidden = true;
    scheduleDetails();
  } catch (error) {
    $("tx-cancel-note").textContent = `Not cancelled: ${error.message}`;
    $("tx-cancel-confirm").disabled = false;
  }
});

dialog.addEventListener("close", () => {
  openTxId = null;
  const row = document.querySelector(`tr[data-tx="${CSS.escape(String(dialog.dataset.returnTo || ""))}"] button`);
  if (row) row.focus();
});
dialog.addEventListener("click", (event) => {
  if (event.target === dialog) dialog.close();
});

// Event feed, read from serve's stream through the proxy

const feed = $("events");

function addEvent(kind, data) {
  const fields = Object.entries(data || {}).filter(([k, v]) => k !== "kind" && v !== null && v !== undefined);
  const item = el("li", { class: kind === "lagged" ? "lagged" : null }, [
    el("time", { datetime: new Date().toISOString(), text: timeFormat.format(new Date()) }),
    el("span", { class: "kind", text: words(kind) }),
    el("span", { class: "fields" }, fields.flatMap(([k, v], i) => [
      i ? ", " : null,
      `${words(k)} `,
      el("b", { text: k === "amount" ? amount(v) : String(v) }),
    ])),
  ]);
  feed.prepend(item);
  while (feed.children.length > FEED_CAP) feed.lastElementChild.remove();
  $("events-empty").hidden = true;
}

$("events-clear").addEventListener("click", () => {
  feed.replaceChildren();
  $("events-empty").hidden = false;
});

function setEventsState(text) {
  $("events-state").textContent = text;
}

async function readEvents() {
  let delay = 1000;
  for (;;) {
    setEventsState("Opening the event stream…");
    try {
      const response = await fetch("/api/v1/events", { cache: "no-store" });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Problem(body, response.status);
      }
      setEventsState("Live");
      delay = 1000;
      await consume(response.body);
      setEventsState("The stream ended. Reconnecting");
    } catch (error) {
      if (isUnreachable(error)) markUnreachable(error);
      setEventsState(`Stream not open (${error.message}). Reconnecting`);
    }
    await new Promise((resolve) => setTimeout(resolve, delay));
    delay = Math.min(delay * 2, 30000);
  }
}

async function consume(body) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let event = { kind: "message", data: [] };
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buffer += decoder.decode(value, { stream: true });
    let end;
    while ((end = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, end).replace(/\r$/, "");
      buffer = buffer.slice(end + 1);
      if (line === "") {
        if (event.data.length) dispatch(event.kind, event.data.join("\n"));
        event = { kind: "message", data: [] };
      } else if (line.startsWith("event:")) {
        event.kind = line.slice(6).trim();
      } else if (line.startsWith("data:")) {
        event.data.push(line.slice(5).replace(/^ /, ""));
      }
    }
  }
}

function dispatch(kind, text) {
  let data = {};
  try { data = JSON.parse(text); } catch { data = { data: text }; }
  addEvent(data.kind || kind, data);
  scheduleDetails();
}

// Refresh cycle

let detailsTimer = null;

async function refreshStatus() {
  try {
    const status = await api("/v1/status");
    markReachable(status.socket);
    renderStatus(status);
  } catch (error) {
    if (isUnreachable(error)) markUnreachable(error);
    else setLink("busy", `Status not available: ${error.message}`);
  }
}

async function refreshDetails() {
  const jobs = [
    ["/v1/wallet", renderWallet, $("balances"), "the balances"],
    ["/v1/wallet/address", renderAddress, null, "the address"],
    ["/v1/node", renderNode, $("node-facts"), "the node status"],
    ["/v1/transactions", renderTransactions, $("transactions"), "the transactions"],
    ["/v1/outputs", renderOutputs, $("outputs"), "the outputs"],
  ];
  await Promise.all(jobs.map(async ([path, render, container, what]) => {
    try {
      render(await api(path));
    } catch (error) {
      if (isUnreachable(error)) markUnreachable(error);
      if (container) renderProblemInto(container, what, error);
      else if (path.endsWith("/address")) $("address").textContent = `Not available: ${error.message}`;
    }
  }));
}

async function refreshDocument() {
  try {
    const document_ = await api("/v1/openapi.json");
    const paths = document_.paths || {};
    canCancel = Object.entries(paths).some(([path, item]) =>
      /^\/v1\/transactions\/\{[^}]+\}\/cancel$/.test(path) && item && item.post);
  } catch {
    canCancel = false;
  }
}

function scheduleDetails() {
  clearTimeout(detailsTimer);
  detailsTimer = setTimeout(refreshDetails, AFTER_EVENT_MS);
}

async function refreshAll() {
  await Promise.all([refreshStatus(), refreshDetails(), refreshDocument()]);
}

setInterval(refreshStatus, STATUS_EVERY_MS);
setInterval(refreshDetails, DETAILS_EVERY_MS);
refreshAll();
readEvents();

// API reference, loaded only when its tab is opened

// The whole configuration every time: Scalar replaces, rather than merges, what it is given.
function referenceOptions() {
  return {
    url: "/api/v1/openapi.json",
    withDefaultFonts: false,
    telemetry: false,
    hideClientButton: true,
    hideTestRequestButton: true,
    hideDarkModeToggle: true,
    hiddenClients: true,
    showDeveloperTools: "never",
    agent: { disabled: true },
    forceDarkModeState: document.documentElement.dataset.theme === "light" ? "light" : "dark",
    proxyUrl: "",
    servers: [{ url: `${location.origin}/api`, description: "This console's proxy, read routes only" }],
  };
}

function loadReference() {
  if (reference || referenceLoading) return;
  referenceLoading = true;
  const script = el("script", { src: "/vendor/scalar.js" });
  script.addEventListener("load", () => {
    if (!window.Scalar) {
      $("api-note").textContent = "The API reference did not load.";
      return;
    }
    reference = window.Scalar.createApiReference("#api-doc", referenceOptions());
  });
  script.addEventListener("error", () => {
    referenceLoading = false;
    $("api-note").textContent = "The API reference script did not load.";
  });
  document.body.append(script);
}
