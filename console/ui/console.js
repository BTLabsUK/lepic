"use strict";

const STATUS_EVERY_MS = 5000;
const DETAILS_EVERY_MS = 30000;
const AFTER_EVENT_MS = 1500;
const AGO_EVERY_MS = 5000;
const FEED_CAP = 500;
const RECENT = 5;
const THEME_KEY = "lepic-console-theme";
const SESSION_KEY = "lepic-console-session";
const NO_SESSION = "Open the console with the link lepic-console printed in its terminal. A new link is printed each time one is used.";
const V1 = "/api/v1";
const PAGE = 50;
const PAGE_MAX = 500;
const VIEWS = { overview: "Overview", transactions: "Payments", outputs: "Outputs", events: "Events", api: "API" };
const SVG_NS = "http://www.w3.org/2000/svg";

const $ = (id) => document.getElementById(id);

// The API reference, once its view has been opened.
let reference = null;
let referenceLoading = false;
let referenceDocument = null;

// Small DOM builder: el("p", { class: "lc-note", text: "Copied." }) or el("dl", null, [a, b]).
function el(tag, attrs, children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (name === "text") node.textContent = value;
    else if (name.startsWith("on")) node.addEventListener(name.slice(2), value);
    else node.setAttribute(name, value === true ? "" : value);
  }
  for (const child of [].concat(children || [])) {
    if (child === null || child === undefined || child === "") continue;
    node.append(child.nodeType ? child : document.createTextNode(String(child)));
  }
  return node;
}

function icon(name, extra) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", extra ? `lc-icon ${extra}` : "lc-icon");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const use = document.createElementNS(SVG_NS, "use");
  use.setAttribute("href", `#i-${name}`);
  svg.append(use);
  return svg;
}

// Writes only a text that differs, so a live region is not announced again for nothing.
function setText(node, text) {
  if (node.textContent !== text) node.textContent = text;
}

// Replaces a list's rows and keeps the keyboard focus on the row that had it.
function swap(list, items) {
  const active = document.activeElement;
  const key = active && list.contains(active) ? active.dataset.key : null;
  list.replaceChildren(...items);
  if (!key) return;
  const again = list.querySelector(`[data-key="${CSS.escape(key)}"]`);
  if (again) again.focus({ preventScroll: true });
}

// What each part of the page last showed, so an unchanged answer redraws nothing.
const shown = {};

function changed(key, value) {
  const text = JSON.stringify(value);
  if (shown[key] === text) return false;
  shown[key] = text;
  return true;
}

// Formatting

const ATOMS = 100000000n;
const integerFormat = new Intl.NumberFormat(undefined, { useGrouping: true });
const decimalMark = (new Intl.NumberFormat().formatToParts(1.5).find((part) => part.type === "decimal") || { value: "." }).value;
const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" });
const dayFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

// "5.00000000" to the count of its smallest units. Null for anything that is not an amount.
function atoms(text) {
  if (text === null || text === undefined) return null;
  const match = /^(-?)(\d+)(?:\.(\d{1,8}))?$/.exec(String(text).trim());
  if (!match) return null;
  const value = BigInt(match[2]) * ATOMS + BigInt((match[3] || "").padEnd(8, "0"));
  return match[1] ? -value : value;
}

// Smallest units as a plain number: 500000000 is "5", 123450000000 is "1,234.5".
function plain(value) {
  if (value === null) return "–";
  const negative = value < 0n;
  const size = negative ? -value : value;
  const fraction = (size % ATOMS).toString().padStart(8, "0").replace(/0+$/, "");
  return (negative ? "−" : "") + integerFormat.format(size / ATOMS) + (fraction ? decimalMark + fraction : "");
}

function signed(value) {
  if (value === null) return "–";
  return value > 0n ? `+${plain(value)}` : plain(value);
}

function epic(text) {
  const value = atoms(text);
  return value === null ? "" : `${plain(value)} EPIC`;
}

function count(value) {
  return typeof value === "number" ? integerFormat.format(value) : "–";
}

function plural(n, word) {
  return `${integerFormat.format(n)} ${word}${n === 1 ? "" : "s"}`;
}

function times(n) {
  if (n === 1) return "once";
  if (n === 2) return "twice";
  return `${integerFormat.format(n)} times`;
}

function words(key) {
  return String(key).replace(/_/g, " ");
}

function capital(text) {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function when(text) {
  if (!text) return "–";
  const date = new Date(text);
  return Number.isNaN(date.getTime()) ? String(text) : dateFormat.format(date);
}

function ago(date) {
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${plural(Math.floor(seconds / 60), "minute")} ago`;
  if (seconds < 86400) return `${plural(Math.floor(seconds / 3600), "hour")} ago`;
  if (seconds < 7 * 86400) return `${plural(Math.floor(seconds / 86400), "day")} ago`;
  return dayFormat.format(date);
}

// A time as "3 minutes ago", with the full date in its title. Kept current by the ticker below.
function timeNode(value, extra) {
  const date = value instanceof Date ? value : new Date(value);
  if (!value || Number.isNaN(date.getTime())) return el("span", { class: extra || null, text: value ? String(value) : "–" });
  return el("time", {
    class: extra ? `lc-ago ${extra}` : "lc-ago",
    datetime: date.toISOString(),
    title: dateFormat.format(date),
    text: ago(date),
  });
}

setInterval(() => {
  for (const node of document.querySelectorAll(".lc-ago")) setText(node, ago(new Date(node.dateTime)));
}, AGO_EVERY_MS);

function lasting(seconds) {
  if (typeof seconds !== "number") return "";
  if (seconds < 60) return "less than a minute";
  if (seconds < 3600) return plural(Math.floor(seconds / 60), "minute");
  if (seconds < 2 * 86400) return plural(Math.floor(seconds / 3600), "hour");
  return plural(Math.floor(seconds / 86400), "day");
}

function hostOf(text) {
  try { return new URL(text).host || String(text); } catch { return String(text); }
}

function facts(pairs) {
  const nodes = [];
  for (const [label, value, mono] of pairs) {
    if (value === null || value === undefined || value === "") continue;
    nodes.push(el("dt", { text: label }));
    nodes.push(el("dd", { class: mono ? "lc-mono" : null, translate: mono ? "no" : null }, value));
  }
  return nodes;
}

// Theme

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const light = theme === "light";
  $("theme-icon").setAttribute("href", light ? "#i-moon" : "#i-sun");
  $("theme-label").textContent = light ? "Dark" : "Light";
  $("theme").setAttribute("aria-label", light ? "Switch to the dark theme" : "Switch to the light theme");
  document.querySelector('meta[name="theme-color"]').content = getComputedStyle(document.documentElement).getPropertyValue("--bg").trim();
  if (reference) reference.updateConfiguration(referenceOptions());
  syncReferenceTheme();
}

// The reference colours itself from `dark-mode` or `light-mode` on <body>, which it sets once and
// does not change when its configuration does. The console keeps the class in step with its theme.
function syncReferenceTheme() {
  if (!reference) return;
  const light = document.documentElement.dataset.theme === "light";
  const body = document.body.classList;
  if (body.contains("light-mode") !== light) body.toggle("light-mode", light);
  if (body.contains("dark-mode") === light) body.toggle("dark-mode", !light);
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

// Session: the link token in the address is traded for a session, which every request carries

class Problem extends Error {
  constructor(body, status) {
    super(body.detail || body.title || `HTTP ${status}`);
    this.code = body.code || null;
    this.status = status;
  }
}

let session = null;
let signedOut = false;

function storedSession() {
  try { return sessionStorage.getItem(SESSION_KEY); } catch { return null; }
}

function keepSession(value) {
  try {
    if (value) sessionStorage.setItem(SESSION_KEY, value);
    else sessionStorage.removeItem(SESSION_KEY);
  } catch { /* storage may be off; the session then lasts until a reload */ }
}

// The link token leaves the address bar before anything else runs, so it is never in the
// history or in a later request. Null when the address holds no link.
function takeLink() {
  const prefix = "#token=";
  if (!location.hash.startsWith(prefix)) return null;
  const value = location.hash.slice(prefix.length);
  history.replaceState(null, "", location.pathname + location.search);
  return value;
}

async function exchangeLink(link) {
  const response = await fetch("/session", {
    method: "POST",
    cache: "no-store",
    headers: { "X-Lepic-Console-Link": link },
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const body = await response.json();
  if (typeof body.session !== "string" || body.session === "") throw new Error("no session in the answer");
  return body.session;
}

// Trades a link for a session. An old link leaves the session this tab already holds, if any.
async function openLink(link) {
  try {
    session = await exchangeLink(link);
    keepSession(session);
  } catch { /* a used or wrong link */ }
}

// Settles once the link in the address has been traded, or there was none to trade.
let sessionReady = (async () => {
  session = storedSession();
  const link = takeLink();
  if (link !== null) await openLink(link);
})();

// A link pasted into a tab that already shows the console changes the fragment only.
window.addEventListener("hashchange", () => {
  const link = takeLink();
  if (link === null) return;
  sessionReady = openLink(link).then(() => {
    if (!session) return;
    signedOut = false;
    $("no-session").hidden = true;
    refreshAll();
    readEvents();
  });
});

function noSession() {
  session = null;
  signedOut = true;
  keepSession(null);
  $("no-session").hidden = false;
  setLink("bad", "Not signed in");
  setEventsState("bad", "Not signed in.");
  renderHealth();
  return new Problem({ detail: NO_SESSION, code: "no_session" }, 401);
}

async function authorization() {
  await sessionReady;
  if (!session) throw noSession();
  return { Authorization: `Bearer ${session}` };
}

// The API, through the console's own proxy

async function api(path, init) {
  const auth = await authorization();
  let response;
  try {
    response = await fetch(path, {
      cache: "no-store",
      ...init,
      headers: { ...((init && init.headers) || {}), ...auth },
    });
  } catch (error) {
    throw new Problem({ detail: `the console itself is not answering: ${error.message}`, code: "console" }, 0);
  }
  if (response.status === 401) throw noSession();
  const type = response.headers.get("content-type") || "";
  const body = type.includes("json") ? await response.json().catch(() => ({})) : {};
  if (!response.ok) throw new Problem(body, response.status);
  return body;
}

// Views, by the first part of the address fragment
//
// The API reference writes its own fragments while it is read ("#api/tag/…"). They belong to
// the API view and are left as they are, so a reload or Back returns to the same place.

const navItems = [...document.querySelectorAll(".lc-nav-item")];
let currentView = null;

function viewOf(hash) {
  const text = hash.replace(/^#/, "");
  if (text === "") return "overview";
  if (text.startsWith("token=")) return currentView || "overview";
  const first = text.split(/[/?]/)[0];
  if (first in VIEWS) return first;
  return currentView === "api" || text.includes("/") ? "api" : "overview";
}

function showView(id, keepScroll) {
  const moved = id !== currentView;
  currentView = id;
  for (const item of navItems) {
    if (item.dataset.view === id) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  }
  for (const name of Object.keys(VIEWS)) $(`view-${name}`).hidden = name !== id;
  document.title = id === "overview" ? "LEPIC console" : `${VIEWS[id]} – LEPIC console`;
  if (moved && !keepScroll) window.scrollTo(0, 0);
  if (id === "api") loadReference();
}

function route() {
  const id = viewOf(location.hash);
  showView(id, id === "api" && location.hash !== "#api");
}

window.addEventListener("hashchange", route);
route();

document.querySelector(".lc-skip").addEventListener("click", (event) => {
  event.preventDefault();
  $("main").focus();
});

// Reachability notice and the connection line in the rail

let unreachable = false;

function setLink(state, text) {
  $("link").dataset.state = state;
  setText($("link-text"), text);
}

function markUnreachable(problem) {
  unreachable = true;
  $("unreachable").hidden = false;
  setText($("unreachable-detail"), `${capital(problem.message)}. This page keeps trying.`);
  setLink("bad", "Not answering");
  renderHealth();
  renderServices();
}

function markReachable() {
  if (unreachable) {
    unreachable = false;
    $("unreachable").hidden = true;
  }
  setLink("ok", "Connected");
}

function isUnreachable(error) {
  return error instanceof Problem && (error.code === "unreachable" || error.code === "console");
}

$("retry").addEventListener("click", () => refreshAll());

// Overview

// The last answer of each read, and the error of a read that failed.
const seen = { status: null, wallet: null, accounts: null, node: null, address: null, walletError: null, nodeError: null };

function health() {
  if (signedOut) {
    return { tone: "unknown", icon: "lock", line: "This page is not signed in.", sub: ["Open it with the link lepic-console printed in its terminal."] };
  }
  if (unreachable) {
    return { tone: "risk", icon: "stop", line: "The wallet service is not answering.", sub: ["This page keeps trying and updates when it answers."] };
  }
  const status = seen.status;
  if (!status) return { tone: "unknown", icon: "wait", line: "Checking the wallet…", sub: [] };

  const refresh = status.refresh || {};
  const refreshed = refresh.last_success_at ? ["Last refreshed from the node ", timeNode(refresh.last_success_at), "."] : [];
  if (refresh.failures > 0) {
    return {
      tone: "warn",
      icon: "warn",
      line: "The wallet cannot refresh from its node.",
      sub: [`It failed ${times(refresh.failures)} in a row. `, refresh.last_error ? `The last error: ${refresh.last_error}. ` : "", ...refreshed],
    };
  }
  const wallet = seen.wallet;
  if (!wallet) {
    if (seen.walletError) return { tone: "warn", icon: "warn", line: "The wallet cannot be read.", sub: [`${capital(seen.walletError.message)}.`] };
    return { tone: "unknown", icon: "wait", line: "Checking the wallet…", sub: [] };
  }
  const scan = wallet.scan;
  if (scan && scan.state === "running") {
    return {
      tone: "info",
      icon: "wait",
      line: typeof scan.target_height === "number" && scan.target_height > scan.height
        ? `Reading the chain, block ${count(scan.height)} of ${count(scan.target_height)}.`
        : "Reading the chain.",
      sub: refreshed,
    };
  }
  if (!(wallet.height > 0)) {
    return { tone: "info", icon: "wait", line: "Waiting for the first sync.", sub: ["The wallet has not read the chain yet."] };
  }
  const tip = seen.node && seen.node.tip_height;
  if (typeof tip === "number" && tip > wallet.height) {
    return {
      tone: "info",
      icon: "wait",
      line: `Catching up with the network, ${plural(tip - wallet.height, "block")} to go.`,
      sub: refreshed,
    };
  }
  if (epicboxState(status) === "disconnected") {
    return {
      tone: "warn",
      icon: "warn",
      line: "Up to date, but disconnected from Epicbox.",
      sub: ["Payments sent to the address below do not arrive until it reconnects."],
    };
  }
  if (wallet.node_behind) {
    return { tone: "warn", icon: "warn", line: "The node is behind the wallet.", sub: ["The balance was not updated at the last refresh."] };
  }
  return { tone: "ok", icon: "check", line: "Your wallet is up to date.", sub: refreshed };
}

function epicboxState(status) {
  const listener = status && status.listeners && status.listeners.epicbox;
  return listener ? listener.state : undefined;
}

function renderHealth() {
  const now = health();
  $("health").dataset.tone = now.tone;
  $("health-icon").setAttribute("href", `#i-${now.icon}`);
  setText($("health-line"), now.line);
  const key = now.sub.map((part) => (part.nodeType ? part.dateTime : part));
  if (changed("health-sub", key)) $("health-sub").replaceChildren(...now.sub.filter((part) => part !== ""));
}

function services() {
  const status = seen.status;
  const rows = [];
  if (unreachable || !status) {
    rows.push(unreachable
      ? { tone: "risk", icon: "stop", name: "Wallet service", state: "Not answering", hint: "lepic serve may have stopped, or its socket moved." }
      : { tone: "unknown", icon: "wait", name: "Wallet service", state: "Checking", hint: "" });
    return rows;
  }
  rows.push({ tone: "ok", icon: "check", name: "Wallet service", state: "Running", hint: lasting(status.uptime_s) ? `Up for ${lasting(status.uptime_s)}` : "" });

  const node = seen.node;
  const nodeHint = node ? `Version ${node.version}, block ${count(node.tip_height)}` : "";
  if (seen.nodeError) {
    rows.push({ tone: "warn", icon: "warn", name: "Node", state: "Not answering", hint: capital(seen.nodeError.message) });
  } else if (seen.wallet && seen.wallet.node_behind) {
    rows.push({ tone: "warn", icon: "warn", name: "Node", state: "Behind the wallet", hint: nodeHint });
  } else if (node && node.syncing) {
    rows.push({ tone: "info", icon: "wait", name: "Node", state: "Syncing", hint: nodeHint });
  } else if (node) {
    rows.push({ tone: "ok", icon: "check", name: "Node", state: "Connected", hint: nodeHint });
  } else {
    rows.push({ tone: "unknown", icon: "wait", name: "Node", state: "Checking", hint: "" });
  }

  const relay = seen.address && seen.address.text ? String(seen.address.text).split("@")[1] || "" : "";
  const epicbox = {
    connected: { tone: "ok", icon: "check", state: "Connected", hint: relay ? `Through ${relay}` : "" },
    connecting: { tone: "info", icon: "wait", state: "Connecting", hint: relay ? `To ${relay}` : "" },
    disconnected: { tone: "risk", icon: "stop", state: "Disconnected", hint: "Payments to the address wait until it reconnects." },
    stopped: { tone: "unknown", icon: "off", state: "Off", hint: "This wallet does not listen on Epicbox." },
  }[epicboxState(status)] || { tone: "unknown", icon: "wait", state: "No report yet", hint: "" };
  rows.push({ name: "Epicbox", ...epicbox });

  const http = status.listeners && status.listeners.http;
  if (http) {
    const reach = { local: "Listening on this computer only", internet: "Open to the internet" }[http.exposure] || capital(words(http.exposure || "listening"));
    rows.push({ tone: "ok", icon: "check", name: "Payments over HTTP", state: "On", hint: reach });
  } else {
    rows.push({ tone: "unknown", icon: "off", name: "Payments over HTTP", state: "Off", hint: "" });
  }

  const refresh = status.refresh || {};
  if (refresh.failures > 0) {
    rows.push({ tone: "warn", icon: "warn", name: "Keeping in sync", state: "Failing", hint: `Failed ${times(refresh.failures)} in a row.${refresh.last_error ? ` ${capital(refresh.last_error)}` : ""}` });
  } else if (refresh.last_success_at) {
    rows.push({ tone: "ok", icon: "check", name: "Keeping in sync", state: "Working", hint: "Last refreshed ", since: refresh.last_success_at });
  } else {
    rows.push({ tone: "info", icon: "wait", name: "Keeping in sync", state: "Not yet", hint: "No refresh has finished yet." });
  }

  const collect = status.collect || {};
  if (collect.failures > 0) {
    rows.push({ tone: "warn", icon: "warn", name: "Collecting payments", state: "Failing", hint: `Failed ${times(collect.failures)} in a row.${collect.last_error ? ` ${capital(collect.last_error)}` : ""}` });
  }
  return rows;
}

function renderServices() {
  const rows = services();
  if (!changed("services", rows)) return;
  $("services").replaceChildren(...rows.map((row) =>
    el("li", { class: "lc-check-row", "data-tone": row.tone }, [
      icon(row.icon),
      el("div", null, [
        el("div", { class: "lc-check-head" }, [
          el("span", { class: "lc-check-name", text: row.name }),
          el("span", { class: "lc-check-state", text: row.state }),
        ]),
        row.hint || row.since ? el("p", { class: "lc-check-hint" }, [row.hint, row.since ? timeNode(row.since) : null]) : null,
      ]),
    ])));
}

// The raw values an engineer asks for, out of the way until they are opened.
function renderTech() {
  const list = $("tech-facts");
  const selection = window.getSelection();
  if (selection && !selection.isCollapsed && list.contains(selection.anchorNode)) return;

  const status = seen.status || {};
  const node = seen.node || {};
  const wallet = seen.wallet || {};
  const requests = status.requests || {};
  const http = status.listeners && status.listeners.http;
  const refresh = status.refresh || {};
  const collect = status.collect || {};
  const scan = wallet.scan;
  const pairs = [
    ["Version", status.version],
    ["Running for", lasting(status.uptime_s)],
    ["Requests served", typeof requests.served === "number" ? count(requests.served) : null],
    ["Requests in progress", typeof requests.in_flight === "number" ? count(requests.in_flight) : null],
    ["Requests refused", typeof requests.refused === "number" ? count(requests.refused) : null],
    ["Wallet height", typeof wallet.height === "number" ? count(wallet.height) : null],
    ["Node height", typeof node.tip_height === "number" ? count(node.tip_height) : null],
    ["Network", wallet.network],
    ["Node version", node.version],
    ["Node syncing", typeof node.syncing === "boolean" ? (node.syncing ? "yes" : "no") : null],
    ["Chain scan", scan ? `${scan.state}, block ${count(scan.height)}${typeof scan.target_height === "number" ? ` of ${count(scan.target_height)}` : ""}` : null],
    ["Epicbox", epicboxState(status)],
  ];
  if (http) {
    pairs.push(["HTTP port", String(http.port)]);
    pairs.push(["HTTP exposure", http.exposure]);
    pairs.push(["HTTP payments", `${count(http.received)} received, ${count(http.repeated)} repeated, ${count(http.refused)} refused`]);
    pairs.push(["Coinbase over HTTP", http.coinbase]);
  }
  for (const [label, report] of [["refresh", refresh], ["collect", collect]]) {
    pairs.push([`Last ${label}`, report.last_success_at ? when(report.last_success_at) : "none yet"]);
    pairs.push([`${capital(label)} failures in a row`, typeof report.failures === "number" ? count(report.failures) : null]);
    pairs.push([`Last ${label} error`, report.last_error]);
  }
  list.replaceChildren(...facts(pairs));
}

const BALANCE_PARTS = [
  ["spendable", "Ready to spend"],
  ["confirming", "Waiting for confirmations"],
  ["pending", "Waiting for a payment to finish"],
  ["maturing", "Maturing"],
  ["locked", "Reserved for payments in progress"],
];

function renderNetwork() {
  const info = seen.wallet;
  if (!info) return;
  const tag = $("network");
  tag.textContent = info.network ? capital(String(info.network)) : "";
  tag.hidden = !info.network;
}

// The balance of each account and their total, from the accounts list.
function renderBalances() {
  const accounts = seen.accounts;
  if (!accounts) return;
  if (!changed("accounts", accounts)) return;

  const sum = (key) => accounts.reduce((total, account) => total + (atoms(account.balance && account.balance[key]) || 0n), 0n);
  const total = sum("total");
  $("balance-total").textContent = accounts.length ? plain(total) : "–";

  const parts = BALANCE_PARTS.map(([key, label]) => [label, sum(key)]).filter(([, value]) => value !== 0n);
  let note = "";
  if (!accounts.length) note = "This wallet has no accounts.";
  else if (total === 0n) note = "Nothing here yet. A payment to the address below shows up here.";
  else if (sum("spendable") === total) note = "All of it is ready to spend.";
  $("balance-note").textContent = note;
  $("balance-note").hidden = note === "";
  const list = $("balance-parts");
  list.hidden = note !== "" || !parts.length;
  list.replaceChildren(...parts.flatMap(([label, value]) => [el("dt", { text: label }), el("dd", { text: `${plain(value)} EPIC` })]));

  const perAccount = $("balance-accounts");
  perAccount.hidden = accounts.length < 2;
  perAccount.replaceChildren(el("dl", { class: "lc-parts" }, accounts.flatMap((account) => [
    el("dt", { text: account.label || `Account ${account.index}` }),
    el("dd", { text: `${plain(atoms(account.balance && account.balance.total))} EPIC` }),
  ])));
}

function renderAddress() {
  const report = seen.address || {};
  setText($("address"), report.text || "–");
  $("copy-address").hidden = !report.text;
}

let copyTimer = null;

$("copy-address").addEventListener("click", async () => {
  const note = $("copy-note");
  try {
    await navigator.clipboard.writeText($("address").textContent);
    note.textContent = "Copied.";
  } catch {
    note.textContent = "Copying is not available here. Select the address to copy it.";
  }
  clearTimeout(copyTimer);
  copyTimer = setTimeout(() => { note.textContent = ""; }, 4000);
});

// Lists with a "more" link: the first page, and the pages after it that were asked for

const lists = {
  payments: { path: `${V1}/payments`, items: [], cursor: null, loaded: false, busy: false, version: 0, more: "transactions-more", what: "payments", key: (item) => item.id },
  outputs: { path: `${V1}/outputs`, items: [], cursor: null, loaded: false, busy: false, version: 0, more: "outputs-more", what: "outputs", key: (item) => item.commitment },
};

// Reads the pages again from the start, as many items as are shown, so a refresh keeps them.
async function refreshList(name) {
  const list = lists[name];
  const version = ++list.version;
  const limit = Math.min(PAGE_MAX, Math.max(PAGE, list.items.length));
  const report = await api(`${list.path}?limit=${limit}`);
  if (version !== list.version) return list;
  list.items = report.items || [];
  list.cursor = report.next_cursor || null;
  list.loaded = true;
  return list;
}

async function loadMore(name) {
  const list = lists[name];
  if (!list.cursor || list.busy) return;
  const button = $(list.more);
  const version = list.version;
  list.busy = true;
  button.disabled = true;
  setText(button, "Loading…");
  try {
    const report = await api(`${list.path}?limit=${PAGE}&cursor=${encodeURIComponent(list.cursor)}`);
    if (version === list.version) {
      const have = new Set(list.items.map(list.key));
      list.items = list.items.concat((report.items || []).filter((item) => !have.has(list.key(item))));
      list.cursor = report.next_cursor || null;
    }
    drawList(name);
  } catch (error) {
    if (error.code === "no_session") return;
    setText(button, `Could not load more: ${error.message}. Try again.`);
  } finally {
    list.busy = false;
    button.disabled = false;
  }
}

function updateMore(name) {
  const list = lists[name];
  const button = $(list.more);
  button.parentElement.hidden = !list.cursor;
  setText(button, `Show more ${list.what}`);
}

function drawList(name) {
  if (name === "payments") drawPayments();
  else drawOutputs();
  updateMore(name);
}

for (const name of Object.keys(lists)) $(lists[name].more).addEventListener("click", () => loadMore(name));

// Payments

const PAYMENT_STATE = {
  needs_approval: "Waiting for your approval",
  awaiting_answer: "Waiting for the other side",
  awaiting_post: "Waiting for the sender",
  finalized: "Signed, not yet on the network",
  posted: "Published, waiting for the first confirmation",
  confirmed: "Confirmed",
  cancelled: "Cancelled",
  declined: "Declined",
  expired: "Expired",
};
const PAYMENT_LEAD = {
  needs_approval: "A payment was asked of this wallet. Nothing was paid, and it waits for an approval.",
  awaiting_answer: "The payment was created and handed over. It goes on when the other side answers.",
  awaiting_post: "This wallet answered. The sender has to finish the payment and publish it.",
  finalized: "Both sides signed. The node has not taken the payment yet.",
  posted: "The network has the payment. It counts once a block includes it.",
};
const PAYMENT_TONE = { confirmed: ["ok", "check"], cancelled: ["unknown", "stop"], declined: ["unknown", "stop"], expired: ["unknown", "stop"] };
const ENDED = new Set(["confirmed", "cancelled", "declined", "expired"]);
const VIA = {
  epicbox: "over Epicbox",
  http: "over HTTP",
  tor: "over Tor",
  file: "by file",
  contact: "through a contact",
  link: "through a link",
  in_person: "in person",
  peer: "straight to the other wallet",
  chain: "found on the chain",
};

function over(via) {
  if (!via) return "";
  return VIA[via] || `over ${words(via)}`;
}

function relayName(transport) {
  return { epicbox: "Epicbox", http: "HTTP", tor: "Tor" }[transport] || capital(words(transport || "the transport"));
}

// The first group of the payment's id, enough to tell payments apart on a row.
function shortId(id) {
  return String(id).split("-")[0];
}

function paymentTitle(payment) {
  const direction = payment.direction;
  if (payment.state === "confirmed") return direction === "in" ? "Received" : direction === "out" ? "Sent" : "Moved within this wallet";
  if (ENDED.has(payment.state)) return direction === "in" ? "Incoming payment" : direction === "out" ? "Outgoing payment" : "Payment within this wallet";
  return direction === "in" ? "Receiving" : direction === "out" ? "Sending" : "Moving within this wallet";
}

function paymentState(payment) {
  if (payment.state === "awaiting_answer") {
    if (payment.direction === "out") return "Waiting for the recipient";
    if (payment.direction === "in") return "Waiting for the payer";
  }
  return PAYMENT_STATE[payment.state] || capital(words(payment.state || "unknown"));
}

// What the payment adds to or takes from the wallet, the fee apart. Null when it cannot be told.
function paymentAmount(payment) {
  const value = atoms(payment.amount);
  if (value === null) return null;
  if (payment.direction === "out") return -value;
  return value;
}

function offers(payment, action) {
  return Array.isArray(payment.actions) && payment.actions.includes(action);
}

function paymentRow(payment) {
  const incoming = payment.direction === "in";
  const ended = payment.state !== "confirmed" && ENDED.has(payment.state);
  const value = paymentAmount(payment);
  const meta = [`Payment ${shortId(payment.id)}`, over(payment.via)].filter(Boolean).join(", ");
  return el("li", null, el("button", {
    type: "button",
    class: "lc-row-btn",
    "data-key": `pay-${payment.id}`,
    "data-tx": payment.id,
    title: payment.id,
    onclick: () => openPayment(payment.id),
  }, [
    el("span", { class: "lc-row-icon", "data-tone": ended ? null : incoming ? "in" : "out" }, icon(incoming ? "in" : "out")),
    el("span", { class: "lc-row-main" }, [
      el("span", { class: "lc-row-title", text: paymentTitle(payment) }),
      el("span", { class: "lc-row-sub", text: paymentState(payment) }),
    ]),
    el("span", { class: "lc-row-meta", text: meta }),
    el("span", { class: "lc-row-end" }, [
      el("span", { class: "lc-row-amount", "data-tone": ended ? "void" : value !== null && value > 0n ? "in" : null, text: `${signed(value)} EPIC` }),
      timeNode(payment.updated_at || payment.created_at, "lc-row-time"),
    ]),
  ]));
}

function placeholder(text) {
  return el("li", { class: "lc-placeholder", text });
}

function renderPayments() {
  const list = lists.payments;
  if (!changed("payments", [list.items, list.cursor])) return;
  drawList("payments");
}

function drawPayments() {
  const { items, cursor } = lists.payments;
  const waiting = items.filter((payment) => !ENDED.has(payment.state)).length;
  $("tx-summary").textContent = items.length
    ? `${cursor ? `The newest ${plural(items.length, "payment")}` : capital(plural(items.length, "payment"))}, newest first${waiting ? `. ${capital(plural(waiting, "payment"))} still in progress.` : "."}`
    : "Every payment this wallet sends or receives is listed here.";
  if (!items.length) {
    const none = "No payments yet. Give someone this wallet's address to receive the first one.";
    swap($("transactions"), [placeholder(none)]);
    swap($("recent"), [placeholder(none)]);
    return;
  }
  swap($("transactions"), items.map(paymentRow));
  swap($("recent"), items.slice(0, RECENT).map(paymentRow));
}

// Outputs

const OUTPUT_STATE = {
  unspent: ["Ready to spend", "ok", "check"],
  unconfirmed: ["Waiting for confirmations", "info", "wait"],
  locked: ["Reserved for a payment in progress", "unknown", "lock"],
  spent: ["Spent", "unknown", "off"],
};

function outputRow(output) {
  const spent = output.state === "spent";
  const [label, tone, mark] = OUTPUT_STATE[output.state] || [capital(words(output.state || "unknown")), "unknown", "info"];
  const height = seen.wallet && seen.wallet.height;
  const maturing = !spent && typeof output.lock_height === "number" && typeof height === "number" && output.lock_height > height;
  const state = maturing ? `Maturing, ready at block ${count(output.lock_height)}` : label;
  const commitment = String(output.commitment || "");
  const source = output.payment_id
    ? el("button", {
      type: "button",
      class: "lc-inline-btn lc-link",
      "data-key": `out-${commitment}`,
      "data-tx": output.payment_id,
      text: `From payment ${shortId(output.payment_id)}`,
      onclick: () => openPayment(output.payment_id),
    })
    : null;
  return el("li", null, el("div", { class: spent ? "lc-row lc-is-spent" : "lc-row" }, [
    el("span", { class: "lc-row-icon", "data-tone": maturing ? "info" : tone }, icon(maturing ? "wait" : mark)),
    el("span", { class: "lc-row-main" }, [
      el("span", { class: "lc-row-title", text: `${plain(atoms(output.amount))} EPIC` }),
      el("span", { class: "lc-row-sub", text: output.coinbase ? `${state}. Mining reward.` : state }),
    ]),
    el("span", { class: "lc-row-meta" }, source),
    el("span", { class: "lc-row-end" }, [
      el("span", { class: "lc-mono", translate: "no", title: commitment, text: commitment.length > 20 ? `${commitment.slice(0, 10)}…${commitment.slice(-6)}` : commitment }),
      typeof output.height === "number" && output.height > 0 ? el("span", { class: "lc-row-time", text: `Block ${count(output.height)}` }) : null,
    ]),
  ]));
}

function renderOutputs() {
  const list = lists.outputs;
  if (!changed("outputs", [list.items, list.cursor, seen.wallet && seen.wallet.height])) return;
  drawList("outputs");
}

function drawOutputs() {
  const { items, cursor } = lists.outputs;
  const ready = items.filter((output) => output.state === "unspent").length;
  $("outputs-summary").textContent = items.length
    ? `${cursor ? `The first ${plural(items.length, "output")}` : capital(plural(items.length, "output"))}, ${ready} ready to spend.`
    : "";
  swap($("outputs"), items.length ? items.map(outputRow) : [placeholder("No outputs yet. The first payment this wallet receives adds one.")]);
}

function renderProblemInto(list, what, error) {
  swap(list, [placeholder(`Could not load ${what}: ${error.message}`)]);
}

// One payment, in a dialog

const dialog = $("tx-dialog");
let openPaymentId = null;
let opener = null;

function techValue(key, value) {
  if (typeof value === "boolean") return [value ? "yes" : "no", false];
  if (typeof value === "number") return [count(value), false];
  if (Array.isArray(value) && value.every((item) => typeof item !== "object")) return [value.join(", ") || "none", false];
  if (typeof value === "object") return [JSON.stringify(value), true];
  if (/_at$/.test(key)) return [when(value), false];
  if (/^[0-9a-f-]{16,}$/i.test(String(value))) return [String(value), true];
  return [String(value), false];
}

function renderPayment(payment) {
  const incoming = payment.direction === "in";
  const value = paymentAmount(payment);
  const fee = atoms(payment.fee);
  const [tone, mark] = PAYMENT_TONE[payment.state] || ["info", "wait"];
  const plainKeys = new Set(["id", "direction", "state", "via", "created_at", "updated_at", "actions", "amount", "fee"]);
  const rest = Object.entries(payment)
    .filter(([key, v]) => !plainKeys.has(key) && v !== null && v !== undefined && v !== "" && !(Array.isArray(v) && !v.length))
    .map(([key, v]) => [capital(words(key)), ...techValue(key, v)]);
  const wasOpen = Boolean(dialog.querySelector(".lc-tech[open]"));

  $("tx-dialog-title").textContent = `${paymentTitle(payment)}, payment ${shortId(payment.id)}`;
  $("tx-dialog-body").replaceChildren(
    el("p", { class: "lc-state", "data-tone": tone }, [icon(mark), `${paymentState(payment)}.`]),
    el("p", { class: "lc-state-lead", text: PAYMENT_LEAD[payment.state] || "" }),
    el("dl", { class: "lc-facts" }, facts([
      ["Amount", `${signed(value)} EPIC`],
      ["Network fee", payment.direction !== "in" && fee !== null && fee > 0n ? `${plain(fee)} EPIC` : null],
      ["Direction", incoming ? "Into this wallet" : payment.direction === "out" ? "Out of this wallet" : "Between this wallet's own coins"],
      ["Delivery", payment.via ? capital(over(payment.via)) : null],
      ["Payment id", payment.id, true],
      ["Started", payment.created_at ? when(payment.created_at) : null],
      ["Last change", payment.updated_at ? timeNode(payment.updated_at) : null],
    ])),
    rest.length
      ? el("details", { class: "lc-tech", open: wasOpen }, [
        el("summary", { class: "lc-tech-summary", text: "Technical details" }),
        el("dl", { class: "lc-facts" }, facts(rest)),
      ])
      : "",
  );
  // Cancel is offered when the payment's own list of actions has it.
  $("tx-dialog-actions").hidden = !offers(payment, "cancel");
}

async function loadPayment(id) {
  try {
    const payment = await api(`${V1}/payments/${id}`);
    if (openPaymentId !== id) return false;
    renderPayment(payment);
    return true;
  } catch (error) {
    if (openPaymentId !== id) return false;
    $("tx-dialog-body").replaceChildren(el("p", { class: "lc-state-lead", text: `Could not load this payment: ${error.message}` }));
    return false;
  }
}

async function openPayment(id) {
  if (!dialog.open) opener = document.activeElement;
  openPaymentId = id;
  $("tx-dialog-title").textContent = `Payment ${shortId(id)}`;
  $("tx-dialog-body").replaceChildren(el("p", { class: "lc-state-lead", text: "Loading…" }));
  $("tx-dialog-actions").hidden = true;
  resetCancel();
  if (!dialog.open) dialog.showModal();
  await loadPayment(id);
}

function resetCancel() {
  $("tx-cancel").hidden = false;
  $("tx-cancel-keep").hidden = true;
  $("tx-cancel-confirm").hidden = true;
  $("tx-cancel-confirm").disabled = false;
  $("tx-cancel-keep").disabled = false;
  $("tx-cancel-note").textContent = "";
}

$("tx-cancel").addEventListener("click", () => {
  $("tx-cancel").hidden = true;
  $("tx-cancel-keep").hidden = false;
  $("tx-cancel-confirm").hidden = false;
  $("tx-cancel-note").textContent = "Cancelling ends this payment in this wallet and cannot be undone.";
  $("tx-cancel-keep").focus();
});

$("tx-cancel-keep").addEventListener("click", () => {
  resetCancel();
  $("tx-cancel").focus();
});

$("tx-cancel-confirm").addEventListener("click", async () => {
  const id = openPaymentId;
  $("tx-cancel-confirm").disabled = true;
  $("tx-cancel-keep").disabled = true;
  $("tx-cancel-note").textContent = "Cancelling…";
  try {
    const result = await api(`${V1}/payments/${id}/cancel`, { method: "POST" });
    scheduleDetails();
    if (openPaymentId !== id) return;
    await loadPayment(id);
    if (openPaymentId !== id) return;
    $("tx-dialog-actions").hidden = false;
    $("tx-cancel").hidden = true;
    $("tx-cancel-keep").hidden = true;
    $("tx-cancel-confirm").hidden = true;
    $("tx-cancel-note").textContent = `Payment ${shortId(result.id || id)} is ${paymentState({ state: result.state || "cancelled" }).toLowerCase()}.`;
  } catch (error) {
    if (openPaymentId !== id) return;
    $("tx-cancel-note").textContent = `Not cancelled: ${error.message}`;
    $("tx-cancel-confirm").disabled = false;
    $("tx-cancel-keep").disabled = false;
  }
});

dialog.addEventListener("close", () => {
  const id = openPaymentId;
  openPaymentId = null;
  const back = opener && opener.isConnected
    ? opener
    : document.querySelector(`.lc-view:not([hidden]) [data-tx="${CSS.escape(String(id))}"]`);
  opener = null;
  if (back) back.focus();
});
dialog.addEventListener("click", (event) => {
  if (event.target === dialog) dialog.close();
});

// Events, read from serve's stream through the proxy and put into words

const feed = $("events");

// The id of the payment an event is about, if it is about one.
function paymentOf(event) {
  const data = event.data || {};
  const object = data.object || {};
  if (event.type.startsWith("payment.")) return object.id || data.payment_id || null;
  return null;
}

function paymentName(event) {
  const id = paymentOf(event);
  return id ? `Payment ${shortId(id)}` : "A payment";
}

function reason(data, lead) {
  const text = data.reason ? `${capital(words(String(data.reason)))}.` : "";
  return [lead, text].filter(Boolean).join(" ");
}

function stateWords(state) {
  return (PAYMENT_STATE[state] || words(state || "changed")).toLowerCase();
}

const PAYMENT_ENDED_MARK = { confirmed: ["check", "ok"], cancelled: ["stop", "unknown"], declined: ["stop", "unknown"], expired: ["stop", "unknown"] };

// type: (event) => [icon, tone, title, detail]. `GROUPED` joins repeats that differ in detail only.
const EVENTS = {
  "payment.created": (e) => {
    const object = e.data.object || {};
    const amount = epic(object.amount);
    if (object.state === "needs_approval") return ["wait", "info", "A payment waits for an approval", [amount, over(object.via)].filter(Boolean).join(", ")];
    const title = object.direction === "in" ? "A payment to this wallet started" : object.direction === "out" ? "A payment from this wallet started" : "A payment within this wallet started";
    return [object.direction === "in" ? "in" : "out", "info", title, [amount, over(object.via)].filter(Boolean).join(", ")];
  },
  "payment.state_changed": (e) => {
    const to = e.data.to_state;
    const [mark, tone] = PAYMENT_ENDED_MARK[to] || ["wait", "info"];
    return [mark, tone, `${paymentName(e)}: ${stateWords(to)}`, e.data.from_state ? reason(e.data, `Before: ${stateWords(e.data.from_state)}.`) : reason(e.data, "")];
  },
  "payment.updated": (e) => ["info", "unknown", `${paymentName(e)} changed`, changedFields(e.data)],
  "contact.created": () => ["people", "info", "A contact was added", ""],
  "contact.state_changed": (e) => ["people", "info", "A contact's pairing changed", e.data.to_state ? `Now: ${words(e.data.to_state)}.` : ""],
  "contact.updated": (e) => ["people", "unknown", "A contact changed", changedFields(e.data)],
  "contact.removed": () => ["people", "unknown", "A contact was removed", ""],
  "pair_request.received": () => ["people", "info", "Another wallet asked to pair", "The request waits for an answer."],
  "payload.received": () => ["people", "unknown", "A contact sent data", ""],
  "quarantine.added": () => ["warn", "warn", "Messages from a contact could not be opened", "They may be written for another install of this wallet."],
  "account.balance_changed": (e) => {
    const object = e.data.object || {};
    const total = object.balance ? epic(object.balance.total) : "";
    return ["check", "unknown", "Balance changed", [object.label ? `Account ${object.label}` : "", total ? `${total} in total` : ""].filter(Boolean).join(": ")];
  },
  "wallet.progress": (e) => typeof e.data.target_height === "number" && typeof e.data.height === "number" && e.data.target_height > e.data.height
    ? ["wait", "info", `Catching up: block ${count(e.data.height)} of ${count(e.data.target_height)}`, ""]
    : ["check", "unknown", typeof e.data.height === "number" ? `Read the chain up to block ${count(e.data.height)}` : "Read the chain", ""],
  "relay.updated": (e) => e.data.reason === "home_unreachable"
    ? ["warn", "warn", "A contact relay is not answering", e.data.host ? `${e.data.host}. Collecting from it is slowed down.` : "Collecting from it is slowed down."]
    : ["link", "unknown", "A relay changed", reason(e.data, "")],
  "slate.unmatched": (e) => e.data.reason === "notice"
    ? ["info", "unknown", "A notice arrived for a payment this wallet does not hold", "Nothing changed."]
    : ["warn", "warn", "An answer arrived for a payment this wallet does not know", "Another install of this wallet may have started it. Open that one to finish the payment."],
  "events.skipped": (e) => ["warn", "warn",
    `This page missed ${typeof e.data.count === "number" ? plural(e.data.count, "event") : "some events"}.`,
    "The lists above were refreshed."],
};
const ROUTINE = new Set(["wallet.progress"]);
const GROUPED = new Set(["wallet.progress"]);

function changedFields(data) {
  return Array.isArray(data.changed) && data.changed.length ? `Changed: ${data.changed.map(words).join(", ")}.` : "";
}

function describeEvent(event) {
  const make = EVENTS[event.type];
  if (make) {
    const [mark, tone, title, detail] = make(event);
    return { mark, tone, title, detail };
  }
  return { mark: "info", tone: "unknown", title: capital(String(event.type).replace(/[._]/g, " ")), detail: "" };
}

function drawEvent(item, event, text, repeats) {
  const id = paymentOf(event);
  const payment = id
    ? el("button", {
      type: "button",
      class: "lc-inline-btn lc-link",
      "data-tx": id,
      text: `Open payment ${shortId(id)}`,
      onclick: () => openPayment(id),
    })
    : null;
  item.replaceChildren(el("div", { class: "lc-row" }, [
    el("span", { class: "lc-row-icon", "data-tone": text.tone }, icon(text.mark)),
    el("span", { class: "lc-row-main" }, [
      el("span", { class: "lc-row-title" }, [text.title, repeats > 1 ? " " : null, repeats > 1 ? el("span", { class: "lc-row-count", text: times(repeats) }) : null]),
      text.detail ? el("span", { class: "lc-row-sub", text: text.detail }) : null,
    ]),
    el("span", { class: "lc-row-meta" }, payment),
    el("span", { class: "lc-row-end" }, timeNode(event.created_at || new Date(), "lc-row-time")),
  ]));
}

function showFeedState() {
  $("events-empty").hidden = Boolean(feed.querySelector("li:not([hidden])"));
}

function addEvent(event) {
  const text = describeEvent(event);
  const routine = ROUTINE.has(event.type);
  const key = GROUPED.has(event.type) ? event.type : `${event.type}|${text.title}|${text.detail}`;
  // A repeat joins the newest row of its sort, across the routine rows hidden in between.
  const newest = feed.querySelector(routine ? "li[data-routine]" : "li:not([data-routine])");
  if (newest && newest.dataset.key === key) {
    const repeats = Number(newest.dataset.repeats || "1") + 1;
    newest.dataset.repeats = String(repeats);
    drawEvent(newest, event, text, repeats);
    if (newest !== feed.firstElementChild) feed.prepend(newest);
  } else {
    const item = el("li", { "data-key": key, "data-routine": routine });
    item.hidden = routine && !$("events-routine").checked;
    drawEvent(item, event, text, 1);
    feed.prepend(item);
    while (feed.children.length > FEED_CAP) feed.lastElementChild.remove();
  }
  showFeedState();
}

$("events-routine").addEventListener("change", (event) => {
  for (const item of feed.querySelectorAll("li[data-routine]")) item.hidden = !event.target.checked;
  showFeedState();
});

$("events-clear").addEventListener("click", () => {
  feed.replaceChildren();
  showFeedState();
});

function setEventsState(state, text) {
  $("events-state").dataset.state = state;
  setText($("events-state-text"), text);
}

let eventsOpen = false;
// The id of the last event seen, sent on a reconnect so the stream goes on after it.
let lastEventId = null;

async function readEvents() {
  if (eventsOpen) return;
  eventsOpen = true;
  try {
    await keepReadingEvents();
  } finally {
    eventsOpen = false;
  }
}

async function keepReadingEvents() {
  let delay = 1000;
  for (;;) {
    try {
      const headers = { ...(await authorization()), Accept: "text/event-stream" };
      if (lastEventId !== null) headers["Last-Event-ID"] = String(lastEventId);
      const response = await fetch(`${V1}/events`, { cache: "no-store", headers });
      if (response.status === 401) throw noSession();
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Problem(body, response.status);
      }
      setEventsState("ok", "Live. New events appear as they happen.");
      delay = 1000;
      await consume(response.body);
      setEventsState("busy", "The connection ended. Connecting again…");
    } catch (error) {
      if (error.code === "no_session") return;
      if (isUnreachable(error)) markUnreachable(error);
      setEventsState("bad", `Not connected: ${error.message}. Trying again.`);
    }
    await new Promise((resolve) => setTimeout(resolve, delay));
    delay = Math.min(delay * 2, 30000);
  }
}

// Reads the frames of the stream: `id:`, `event:` and `data:` lines, a blank line after each.
async function consume(body) {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let frame = { type: "message", id: null, data: [] };
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buffer += decoder.decode(value, { stream: true });
    let end;
    while ((end = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, end).replace(/\r$/, "");
      buffer = buffer.slice(end + 1);
      if (line === "") {
        if (frame.data.length) dispatch(frame);
        frame = { type: "message", id: null, data: [] };
      } else if (line.startsWith("id:")) {
        frame.id = line.slice(3).trim();
      } else if (line.startsWith("event:")) {
        frame.type = line.slice(6).trim();
      } else if (line.startsWith("data:")) {
        frame.data.push(line.slice(5).replace(/^ /, ""));
      }
      // A line that starts with ":" is a comment, the keepalive.
    }
  }
}

function dispatch(frame) {
  let event;
  try { event = JSON.parse(frame.data.join("\n")); } catch { event = null; }
  if (event === null || typeof event !== "object" || Array.isArray(event)) event = {};
  event.type = typeof event.type === "string" && event.type ? event.type : frame.type;
  event.data = event.data && typeof event.data === "object" ? event.data : {};
  const id = /^\d+$/.test(String(frame.id)) ? frame.id : typeof event.id === "number" ? String(event.id) : null;
  if (id !== null) lastEventId = id;
  addEvent(event);
  touch(event.type);
}

// What each kind of event changes on the page. Types this page does not know change nothing.
function touch(type) {
  if (type === "events.skipped") {
    refreshAll();
  } else if (type === "wallet.progress" || type === "relay.updated") {
    scheduleStatus();
  } else if (type.startsWith("payment.") || type === "account.balance_changed") {
    scheduleDetails();
  }
}

// Refresh cycle

let detailsTimer = null;
let statusTimer = null;

async function refreshStatus() {
  const [status, wallet, node] = await Promise.allSettled([api(`${V1}/status`), api(`${V1}/wallet`), api(`${V1}/node`)]);
  if (status.status === "rejected") {
    const error = status.reason;
    if (isUnreachable(error)) markUnreachable(error);
    else if (error.code !== "no_session") setLink("busy", "Status not available");
    return;
  }
  if ([wallet, node].some((read) => read.status === "rejected" && read.reason.code === "no_session")) return;
  seen.status = status.value;
  markReachable();
  if (wallet.status === "fulfilled") {
    seen.wallet = wallet.value;
    seen.walletError = null;
  } else {
    seen.wallet = null;
    seen.walletError = wallet.reason;
  }
  if (node.status === "fulfilled") {
    seen.node = node.value;
    seen.nodeError = null;
  } else {
    seen.node = null;
    seen.nodeError = node.reason;
  }
  renderNetwork();
  renderHealth();
  renderServices();
  renderTech();
  if (lists.outputs.loaded) renderOutputs();
}

async function refreshDetails() {
  const jobs = [
    [async () => { seen.accounts = (await api(`${V1}/accounts?limit=${PAGE_MAX}`)).items || []; renderBalances(); },
      () => { shown.accounts = null; $("balance-total").textContent = "–"; }, "the balance"],
    [async () => { seen.address = ((await api(`${V1}/addresses?type=epicbox&limit=1`)).items || [])[0] || null; renderAddress(); },
      null, "the address"],
    [async () => { await refreshList("payments"); renderPayments(); },
      (error) => { shown.payments = null; renderProblemInto($("transactions"), "the payments", error); renderProblemInto($("recent"), "the payments", error); $(lists.payments.more).parentElement.hidden = true; }, "the payments"],
    [async () => { await refreshList("outputs"); renderOutputs(); },
      (error) => { shown.outputs = null; renderProblemInto($("outputs"), "the outputs", error); $(lists.outputs.more).parentElement.hidden = true; }, "the outputs"],
  ];
  await Promise.all(jobs.map(async ([run, failed, what]) => {
    try {
      await run();
    } catch (error) {
      if (error.code === "no_session") return;
      if (isUnreachable(error)) markUnreachable(error);
      if (failed) failed(error);
      if (what === "the balance") {
        $("balance-note").hidden = false;
        $("balance-note").textContent = `Could not load ${what}: ${error.message}`;
        $("balance-parts").hidden = true;
      } else if (what === "the address") {
        setText($("address"), `Not available: ${error.message}`);
        $("copy-address").hidden = true;
      }
    }
  }));
  renderHealth();
  renderServices();
  renderTech();
}

function scheduleDetails() {
  clearTimeout(detailsTimer);
  detailsTimer = setTimeout(refreshDetails, AFTER_EVENT_MS);
}

function scheduleStatus() {
  if (statusTimer !== null) return;
  statusTimer = setTimeout(() => { statusTimer = null; refreshStatus(); }, AFTER_EVENT_MS);
}

async function refreshAll() {
  await Promise.all([refreshStatus(), refreshDetails()]);
}

setInterval(refreshStatus, STATUS_EVERY_MS);
setInterval(refreshDetails, DETAILS_EVERY_MS);
refreshAll();
readEvents();

// API reference, loaded only when its view is opened

const REFERENCE_FONT = 'ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif';
const REFERENCE_MONO = 'ui-monospace, "JetBrains Mono", "SF Mono", "Cascadia Mono", Menlo, Consolas, monospace';

// The reference takes the console's colours. It sets `dark-mode` or `light-mode` on <body>.
const REFERENCE_CSS = `
.light-mode, .dark-mode {
  --scalar-font: ${REFERENCE_FONT};
  --scalar-font-code: ${REFERENCE_MONO};
  --scalar-custom-header-height: 0px;
}
.dark-mode {
  --scalar-background-1: #08080a;
  --scalar-background-2: #0d0d10;
  --scalar-background-3: #1a1a21;
  --scalar-background-accent: rgb(246 212 113 / 0.12);
  --scalar-color-1: #fff9f9;
  --scalar-color-2: #a4a4ad;
  --scalar-color-3: #8a8a94;
  --scalar-color-accent: #f6d471;
  --scalar-border-color: #24242a;
  --scalar-color-green: #8ad98a;
  --scalar-color-red: #f08a8a;
  --scalar-color-yellow: #f5a54a;
  --scalar-color-orange: #f5a54a;
  --scalar-color-blue: #8fb8e8;
}
.light-mode {
  --scalar-background-1: #f5efe4;
  --scalar-background-2: #ffffff;
  --scalar-background-3: #f1ede6;
  --scalar-background-accent: rgb(143 94 31 / 0.1);
  --scalar-color-1: #211a11;
  --scalar-color-2: #574d40;
  --scalar-color-3: #645d56;
  --scalar-color-accent: #815525;
  --scalar-border-color: #eae0ce;
  --scalar-color-green: #1f7a3a;
  --scalar-color-red: #b3261e;
  --scalar-color-yellow: #b54708;
  --scalar-color-orange: #b54708;
  --scalar-color-blue: #2f5f9e;
}
.light-mode .t-doc__sidebar, .dark-mode .t-doc__sidebar {
  --scalar-sidebar-background-1: var(--scalar-background-2);
  --scalar-sidebar-border-color: var(--scalar-border-color);
  --scalar-sidebar-color-1: var(--scalar-color-1);
  --scalar-sidebar-color-2: var(--scalar-color-2);
  --scalar-sidebar-color-active: var(--scalar-color-1);
  --scalar-sidebar-item-hover-background: var(--scalar-background-3);
  --scalar-sidebar-item-active-background: var(--scalar-background-3);
  --scalar-sidebar-search-background: var(--scalar-background-1);
  --scalar-sidebar-search-border-color: var(--scalar-border-color);
  --scalar-sidebar-search-color: var(--scalar-color-2);
}
`;

// The whole configuration every time: Scalar replaces, rather than merges, what it is given.
function referenceOptions() {
  return {
    content: referenceDocument,
    slug: "api",
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
    customCss: REFERENCE_CSS,
    // Where the API is really served. The console's own proxy passes read routes only, so it is
    // not offered as a server here.
    servers: [{ url: "http://lepic/api/v1", description: "lepic serve's Unix socket, for example with curl --unix-socket" }],
  };
}

function referenceState(text) {
  $("api-doc").replaceChildren(el("p", { class: "lc-api-state", role: "status", text }));
}

// The document is fetched with the session and handed to the reference, which cannot send the
// header itself.
async function loadReference() {
  if (reference || referenceLoading) return;
  referenceLoading = true;
  referenceState("Loading the reference…");
  try {
    referenceDocument = await api(`${V1}/openapi.json`);
  } catch (error) {
    referenceLoading = false;
    referenceState(error.code === "no_session"
      ? "Sign in to read the reference."
      : `The API document is not available: ${error.message}. Open this view again to retry.`);
    return;
  }
  if (window.Scalar) {
    mountReference();
    return;
  }
  const script = el("script", { src: "/vendor/scalar.js" });
  script.addEventListener("load", () => {
    if (!window.Scalar) {
      referenceLoading = false;
      referenceState("The API reference did not start.");
      return;
    }
    mountReference();
  });
  script.addEventListener("error", () => {
    referenceLoading = false;
    script.remove();
    referenceState("The API reference did not load. Open this view again to retry.");
  });
  document.body.append(script);
}

function mountReference() {
  $("api-doc").replaceChildren();
  reference = window.Scalar.createApiReference("#api-doc", referenceOptions());
  syncReferenceTheme();
  // The reference writes its own class as it starts; this holds the console's choice.
  new MutationObserver(syncReferenceTheme).observe(document.body, { attributes: true, attributeFilter: ["class"] });
}
