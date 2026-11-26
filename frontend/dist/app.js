// HashHarvest window logic. All work happens in Go (app.go); this file only
// renders state and forwards user actions. Bindings come from Wails:
// window.go.main.App.* (bound methods) and window.runtime.* (events, clipboard).
"use strict";

const App = window.go.main.App;
const rt = window.runtime;
const $ = (id) => document.getElementById(id);

const COLS = ["path", "fileType", "hashType", "hashValue", "line", "context"];
let rows = [];          // {path, fileType, hashType, hashValue, line, context, hit, tr}
let skipped = [];       // {path, reason} of the current live scan
let sortable = false;   // header sorting is enabled once a result set is complete
let sort = { col: null, asc: true };
let menuRow = null;

const tbody = $("results").tBodies[0];

function setStatus(text) { $("status").textContent = text; }

function cellText(row, col) {
  if (col === "line") return row.line ? String(row.line) : "";
  return row[col] || "";
}

function matchesFilter(row) {
  const needle = $("filter").value.toLowerCase();
  return !needle || COLS.some((c) => cellText(row, c).toLowerCase().includes(needle));
}

function makeTr(row) {
  const tr = document.createElement("tr");
  for (const col of COLS) {
    const td = document.createElement("td");
    td.className = "c-" + col + (col === "line" ? " num" : "");
    td.textContent = cellText(row, col);
    if (col === "path" || col === "context" || col === "hashValue") td.title = cellText(row, col);
    tr.appendChild(td);
  }
  if (row.hit) tr.classList.add("hit");
  tr.hidden = !matchesFilter(row);
  tr._row = row;
  row.tr = tr;
  return tr;
}

function addRows(batch) {
  const frag = document.createDocumentFragment();
  for (const r of batch) {
    rows.push(r);
    frag.appendChild(makeTr(r));
  }
  tbody.appendChild(frag);
  $("hashes-found").textContent = String(rows.length);
}

function renderAll() {
  tbody.replaceChildren();
  const frag = document.createDocumentFragment();
  for (const r of rows) frag.appendChild(makeTr(r));
  tbody.appendChild(frag);
}

function setSortable(on) {
  sortable = on;
  $("results").classList.toggle("sortable", on);
}

function resetOutput() {
  setSortable(false);
  sort = { col: null, asc: true };
  for (const th of $("results").tHead.rows[0].cells) th.classList.remove("asc", "desc");
  rows = [];
  tbody.replaceChildren();
  $("filter").value = "";
  setProgress($("progress"), $("progress-text"), 0);
  $("files-scanned").textContent = "0";
  $("hashes-found").textContent = "0";
  $("skipped-files").textContent = "0";
  setSkipped([]);
  $("export-csv").disabled = true;
  $("export-json").disabled = true;
}

function setProgress(bar, label, value) {
  bar.value = value;
  label.textContent = value + "%";
}

function setControlsEnabled(enabled) {
  for (const id of ["start", "clear", "browse", "dir"]) $(id).disabled = !enabled;
  $("cancel").hidden = enabled;
  $("cancel").disabled = false;
  for (const el of document.querySelectorAll("input[name=mode], input.hash-type")) el.disabled = !enabled;
}

function highlight(matches) {
  const set = new Set(matches || []);
  for (const r of rows) {
    r.hit = set.has(r.hashValue);
    r.tr.classList.toggle("hit", r.hit);
  }
}

function showSummary(summary) {
  $("files-scanned").textContent = String(summary.filesScanned);
  $("hashes-found").textContent = String(summary.hashesFound);
  $("skipped-files").textContent = String(summary.skippedFiles);
  setSkipped(summary.skipped);
  setStatus(summary.status);
  highlight(summary.matches);
  setSortable(true);
  $("export-csv").disabled = false;
  $("export-json").disabled = false;
}

function report(error) { setStatus("Error: " + error); }

function setSkipped(list) {
  skipped = list || [];
  $("show-skipped").hidden = skipped.length === 0;
}

// ---- main window ---------------------------------------------------------

$("browse").addEventListener("click", async () => {
  const dir = await App.BrowseDirectory();
  if (dir) $("dir").value = dir;
});

$("start").addEventListener("click", async () => {
  resetOutput();
  const mode = document.querySelector("input[name=mode]:checked").value;
  const types = [...document.querySelectorAll("input.hash-type:checked")].map((c) => c.value);
  const start = await App.StartScan($("dir").value, mode, types);
  if (start.status) setStatus(start.status);
  if (start.ok) setControlsEnabled(false);
});

$("clear").addEventListener("click", () => {
  $("dir").value = "";
  document.querySelector("input[name=mode][value=text]").checked = true;
  for (const c of document.querySelectorAll("input.hash-type")) c.checked = true;
  resetOutput();
  App.ResetResults();
  setStatus("Ready");
});

rt.EventsOn("scan:progress", (p) => setProgress($("progress"), $("progress-text"), p));
rt.EventsOn("scan:status", (message) => setStatus(message));
rt.EventsOn("scan:findings", (batch) => addRows(batch));
rt.EventsOn("scan:finished", (summary) => {
  showSummary(summary);
  setControlsEnabled(true);
});
$("cancel").addEventListener("click", () => {
  $("cancel").disabled = true; // until the scan reports that it stopped
  setStatus("Cancelling…");
  App.CancelScan();
});

rt.EventsOn("scan:cancelled", (status) => {
  resetOutput(); // the partial rows were not saved and cannot be exported
  setStatus(status);
  setControlsEnabled(true);
});

rt.EventsOn("scan:failed", (status) => {
  setStatus(status);
  setSortable(true);
  setControlsEnabled(true);
});

$("filter").addEventListener("input", () => {
  for (const r of rows) r.tr.hidden = !matchesFilter(r);
});

$("show-context").addEventListener("change", (e) => {
  $("results").classList.toggle("hide-context", !e.target.checked);
});

$("results").tHead.addEventListener("click", (e) => {
  const th = e.target.closest("th");
  if (!th || !sortable) return;
  const col = th.dataset.col;
  sort = { col, asc: sort.col === col ? !sort.asc : true };
  for (const h of th.parentElement.cells) h.classList.remove("asc", "desc");
  th.classList.add(sort.asc ? "asc" : "desc");
  const dir = sort.asc ? 1 : -1;
  rows.sort((a, b) => {
    if (col === "line") return dir * ((a.line || 0) - (b.line || 0));
    const x = cellText(a, col), y = cellText(b, col);
    return x < y ? -dir : x > y ? dir : 0;
  });
  renderAll();
});

tbody.addEventListener("click", (e) => {
  const tr = e.target.closest("tr");
  for (const s of tbody.querySelectorAll("tr.selected")) s.classList.remove("selected");
  if (tr) tr.classList.add("selected");
});

// Right-click: copy the hash value or the whole row (tab-separated).
tbody.addEventListener("contextmenu", (e) => {
  const tr = e.target.closest("tr");
  if (!tr) return;
  e.preventDefault();
  menuRow = tr._row;
  const menu = $("menu");
  menu.hidden = false;
  menu.style.left = Math.min(e.clientX, innerWidth - menu.offsetWidth - 4) + "px";
  menu.style.top = Math.min(e.clientY, innerHeight - menu.offsetHeight - 4) + "px";
  menu.querySelector("button").focus();
});
$("menu").addEventListener("click", (e) => {
  const action = e.target.dataset.action;
  if (menuRow && action === "hash") rt.ClipboardSetText(menuRow.hashValue);
  if (menuRow && action === "row") rt.ClipboardSetText(COLS.map((c) => cellText(menuRow, c)).join("\t"));
  hideMenu();
});
function hideMenu() { $("menu").hidden = true; menuRow = null; }
document.addEventListener("click", (e) => { if (!$("menu").contains(e.target)) hideMenu(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") hideMenu(); });

$("export-csv").addEventListener("click", async () => {
  const status = await App.ExportCSV();
  if (status) setStatus(status);
});
$("export-json").addEventListener("click", async () => {
  const status = await App.ExportJSON();
  if (status) setStatus(status);
});

$("show-skipped").addEventListener("click", () => {
  const body = $("skipped").tBodies[0];
  body.replaceChildren();
  for (const file of skipped) {
    const tr = body.insertRow();
    for (const text of [file.path, file.reason]) {
      const td = tr.insertCell();
      td.textContent = text;
      td.title = text;
    }
  }
  $("skipped-dialog").showModal();
});

for (const button of document.querySelectorAll("dialog [data-close]")) {
  button.addEventListener("click", () => button.closest("dialog").close());
}

// ---- Scan History --------------------------------------------------------

let historyRows = [];
let historySelected = -1;

$("history").addEventListener("click", async () => {
  const select = $("time-range");
  if (!select.options.length) {
    for (const label of await App.TimeRanges()) select.add(new Option(label));
  }
  select.selectedIndex = 2; // Last 30 days
  await refreshHistory();
  $("history-dialog").showModal();
});

$("time-range").addEventListener("change", refreshHistory);

async function refreshHistory() {
  const body = $("scans").tBodies[0];
  body.replaceChildren();
  historySelected = -1;
  try {
    historyRows = await App.GetScans($("time-range").selectedIndex);
  } catch (error) {
    historyRows = [];
    report(error);
  }
  historyRows.forEach((scan, i) => {
    const tr = body.insertRow();
    for (const text of [scan.when, scan.directory, scan.files, scan.hashes]) {
      const td = tr.insertCell();
      td.textContent = String(text);
      td.title = String(text);
    }
    tr.addEventListener("click", () => {
      for (const s of body.querySelectorAll("tr.selected")) s.classList.remove("selected");
      tr.classList.add("selected");
      historySelected = i;
    });
    tr.addEventListener("dblclick", loadSelectedScan);
  });
}

async function loadSelectedScan() {
  if (historySelected < 0) return;
  try {
    const summary = await App.LoadScan(historyRows[historySelected].id);
    resetOutput();
    addRows(summary.rows || []);
    showSummary(summary);
    $("history-dialog").close();
  } catch (error) {
    report(error);
  }
}
$("load-scan").addEventListener("click", loadSelectedScan);

$("view-log").addEventListener("click", async () => {
  if (historySelected < 0) return;
  let text;
  try {
    text = await App.GetScanLog(historyRows[historySelected].id);
  } catch (error) {
    text = String(error);
  }
  $("log-text").textContent = text;
  $("log-dialog").showModal();
});

// ---- Watchlist Manager ---------------------------------------------------

$("watchlist").addEventListener("click", async () => {
  $("import-status").textContent = "";
  await refreshWatchlists();
  $("watchlist-dialog").showModal();
});

function selectedWatchlist() {
  const value = $("watchlists").value;
  return value ? Number(value) : 0;
}

async function refreshWatchlists() {
  const select = $("watchlists");
  const keep = select.value;
  select.replaceChildren();
  try {
    for (const w of await App.GetWatchlists()) select.add(new Option(w.label, String(w.id)));
  } catch (error) {
    $("import-status").textContent = String(error);
  }
  select.value = keep;
}

$("new-watchlist").addEventListener("click", async () => {
  try {
    await App.CreateWatchlist($("new-name").value);
    $("new-name").value = "";
  } catch (error) {
    $("import-status").textContent = String(error);
  }
  await refreshWatchlists();
});
$("new-name").addEventListener("keydown", (e) => { if (e.key === "Enter") $("new-watchlist").click(); });

$("delete-watchlist").addEventListener("click", async () => {
  const id = selectedWatchlist();
  if (!id) return;
  try {
    await App.DeleteWatchlist(id);
  } catch (error) {
    $("import-status").textContent = String(error);
  }
  await refreshWatchlists();
});

$("import-text").addEventListener("click", async () => {
  const result = await App.ImportText(selectedWatchlist(), $("paste").value);
  $("import-status").textContent = result.status;
  if (result.clear) $("paste").value = "";
  await refreshWatchlists();
});

$("import-file").addEventListener("click", async () => {
  const status = await App.ImportFile(selectedWatchlist());
  if (status) $("import-status").textContent = status;
  await refreshWatchlists();
});

// ---- VirusTotal ----------------------------------------------------------

let vt = null; // dialog state from App.OpenVirusTotal
const vtRows = new Map();

$("virustotal").addEventListener("click", async () => {
  vt = await App.OpenVirusTotal();
  if (!vt.ok) return;
  const key = $("api-key"), secure = $("secure");
  key.value = vt.apiKey;
  key.disabled = vt.fromEnv;
  $("env-note").hidden = !vt.fromEnv;
  secure.checked = false;
  secure.disabled = true;
  secure.parentElement.title = "";
  if (vt.fromEnv) {
    secure.parentElement.title = "The key comes from VT_API_KEY; nothing is saved.";
  } else if (vt.keychainAvailable) {
    secure.disabled = false;
    secure.checked = vt.keyInKeychain;
  } else {
    secure.parentElement.title = "Encrypted storage needs the Windows Credential Manager, which is not available on this platform.";
  }
  const n = vt.hashes.length;
  $("lookup").textContent = "Look Up " + n + " Hash" + (n !== 1 ? "es" : "");
  $("lookup").disabled = false;
  setProgress($("vt-progress"), $("vt-progress-text"), 0);
  const body = $("vt-table").tBodies[0];
  body.replaceChildren();
  vtRows.clear();
  for (const hash of vt.hashes) {
    const tr = body.insertRow();
    for (const text of [hash, "—", ""]) tr.insertCell().textContent = text;
    vtRows.set(hash, tr);
  }
  $("vt-dialog").showModal();
});

$("key-link").addEventListener("click", (e) => {
  e.preventDefault();
  App.OpenKeyPage();
});

$("lookup").addEventListener("click", async () => {
  const started = await App.StartLookup($("api-key").value, $("secure").checked, vt.hashes);
  if (!started) return;
  $("lookup").disabled = true;
  $("api-key").disabled = true;
  setProgress($("vt-progress"), $("vt-progress-text"), 0);
});

rt.EventsOn("vt:progress", (p) => setProgress($("vt-progress"), $("vt-progress-text"), p));
rt.EventsOn("vt:result", (r) => {
  const tr = vtRows.get(r.hash);
  if (!tr) return;
  tr.cells[1].textContent = r.verdict;
  tr.cells[2].textContent = r.detail;
  tr.className = ["malicious", "suspicious", "clean"].includes(r.verdict) ? r.verdict : "";
});
rt.EventsOn("vt:done", () => {
  $("lookup").disabled = false;
  if (vt && !vt.fromEnv) $("api-key").disabled = false;
});

// Closing the dialog (button or Escape) stops a lookup in progress.
$("vt-dialog").addEventListener("close", () => {
  App.CancelLookup();
});

// ---- start-up ------------------------------------------------------------

App.Info().then((info) => {
  document.title = info.title;
  $("version").textContent = info.version;
  $("build-date").textContent = info.buildDate;
});
