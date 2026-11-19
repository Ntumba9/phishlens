/* PhishLens workbench UI. All message-derived content is inserted via
 * textContent, never innerHTML, so email content stays inert. */
"use strict";

const $ = (id) => document.getElementById(id);

const state = {
  cases: [],
  current: null, // full case object from GET /api/cases/{id}
  files: [], // files chosen for the next analysis
};

/* ---------- helpers ---------- */

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function defang(value) {
  return String(value)
    .replace(/https:\/\//g, "hxxps://")
    .replace(/http:\/\//g, "hxxp://")
    .replace(/\./g, "[.]")
    .replace(/@/g, "[at]");
}

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed: ${res.status}`);
  }
  return res.json();
}

let toastTimer = null;
function toast(message) {
  const node = $("toast");
  node.textContent = message;
  node.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.add("hidden"), 2600);
}

function showError(message) {
  const box = $("error");
  box.textContent = message;
  box.classList.remove("hidden");
}

function relativeTime(iso) {
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return iso;
  const seconds = Math.max(0, (Date.now() - then.getTime()) / 1000);
  const steps = [
    [60, "just now"],
    [3600, (s) => `${Math.floor(s / 60)} min ago`],
    [86400, (s) => `${Math.floor(s / 3600)} hr ago`],
    [86400 * 30, (s) => `${Math.floor(s / 86400)} days ago`],
  ];
  for (const [limit, fmt] of steps) {
    if (seconds < limit) return typeof fmt === "string" ? fmt : fmt(seconds);
  }
  return then.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}

/* ---------- sheet (new analysis) ---------- */

function openSheet() {
  $("error").classList.add("hidden");
  $("sheet-overlay").classList.remove("hidden");
  $("raw").focus();
}

function closeSheet() {
  $("sheet-overlay").classList.add("hidden");
  $("new-analysis-btn").focus();
}

function setChosenFiles(fileList) {
  state.files = Array.from(fileList).slice(0, 20);
  const label = $("chosen-files");
  label.textContent = state.files.length
    ? state.files.map((f) => f.name).join(", ")
    : "";
}

/* ---------- queue ---------- */

async function refreshQueue(selectId) {
  const search = encodeURIComponent($("queue-search").value.trim());
  const verdict = encodeURIComponent($("queue-filter").value);
  const status = encodeURIComponent($("queue-status-filter").value);
  const data = await api(`/api/cases?search=${search}&verdict=${verdict}&status=${status}`);
  state.cases = data.cases;
  renderQueue();
  if (selectId) await openCase(selectId);
}

function renderQueue() {
  const list = $("queue-list");
  list.textContent = "";
  if (!state.cases.length) {
    list.appendChild(el("p", "queue-empty", "No cases yet. Analyze an email to start one."));
    return;
  }
  for (const c of state.cases) {
    const item = el("button", "queue-item");
    item.setAttribute("role", "listitem");
    if (state.current && state.current.id === c.id) item.classList.add("active");

    const top = el("div", "q-top");
    top.appendChild(el("span", `verdict-dot ${c.verdict}`));
    top.appendChild(el("span", "q-subject", c.subject || "(no subject)"));
    item.appendChild(top);

    const meta = el("div", "q-meta");
    meta.appendChild(el("span", "q-sender", c.sender || "unknown sender"));
    const right = el("span", "q-right");
    right.appendChild(el("span", `status-chip ${c.status || "new"}`, statusLabel(c.status)));
    right.appendChild(
      el("span", "q-age", `${c.score}/100 · ${relativeTime(c.created_at)}`)
    );
    meta.appendChild(right);
    item.appendChild(meta);

    if (c.analyst_verdict) {
      const over = el("div", "q-meta");
      over.appendChild(el("span", "q-override", `Analyst: ${c.analyst_verdict.replace(/_/g, " ")}`));
      item.appendChild(over);
    }

    item.addEventListener("click", () => openCase(c.id).catch((err) => toast(err.message)));
    list.appendChild(item);
  }
}

/* ---------- case detail ---------- */

function showLoading() {
  $("empty-state").classList.add("hidden");
  $("case-view").classList.add("hidden");
  $("loading-state").classList.remove("hidden");
}

async function openCase(caseId) {
  showLoading();
  document.body.classList.add("case-open");
  $("case-nav").classList.remove("hidden");
  const data = await api(`/api/cases/${caseId}`);
  state.current = data;
  renderCase();
  $("loading-state").classList.add("hidden");
  renderQueue();
}

function closeCase() {
  state.current = null;
  document.body.classList.remove("case-open");
  $("case-nav").classList.add("hidden");
  history.replaceState(null, "", location.pathname);
  renderQueue();
  $("new-analysis-btn").focus();
}

const STATUS_LABELS = { new: "New", in_review: "In review", closed: "Closed" };

function statusLabel(status) {
  return STATUS_LABELS[status] || "New";
}

function verdictLabel(verdict) {
  return {
    likely_phish: "Likely phish",
    suspicious: "Suspicious",
    no_strong_signals: "No strong signals",
  }[verdict] || verdict;
}

const SEV_ORDER = ["high", "medium", "low", "info"];

function renderCase() {
  const c = state.current;
  const report = c.report;

  $("case-view").classList.remove("hidden");

  const word = $("verdict-word");
  word.textContent = verdictLabel(report.verdict);
  word.className = `verdict-word ${report.verdict}`;

  $("score-pill").textContent = `Heuristic score ${report.score}/100`;

  const summary = $("signal-summary");
  summary.textContent = "";
  const findings = report.findings || [];
  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  let anyChip = false;
  for (const sev of SEV_ORDER) {
    if (!counts[sev]) continue;
    anyChip = true;
    summary.appendChild(el("span", `sig-chip ${sev}`, `${counts[sev]} ${sev}`));
  }
  if (!anyChip) {
    summary.appendChild(el("span", "sig-none", "No heuristic signals fired on this message."));
  }

  $("case-subject").textContent = report.subject || "(no subject)";
  const analyzed = report.created_at || c.created_at;
  $("case-meta").textContent =
    `From ${report.from || "unknown sender"} · Analyzed ${relativeTime(analyzed)}`;

  const dl = $("case-details-body");
  dl.textContent = "";
  const detailRows = [
    ["Case ID", c.id],
    ["Analyzed (UTC)", analyzed],
    ["From", report.from || "unknown sender"],
    ["Subject", report.subject || "(no subject)"],
  ];
  if (c.analyst_verdict) {
    detailRows.push(["Your verdict", verdictLabel(c.analyst_verdict)]);
  }
  if (c.analyst_reason) {
    detailRows.push(["Your reason", c.analyst_reason]);
  }
  for (const [term, value] of detailRows) {
    dl.appendChild(el("dt", null, term));
    dl.appendChild(el("dd", null, value));
  }

  $("analyst-verdict").value = c.analyst_verdict || "";
  $("analyst-reason").value = c.analyst_reason || "";

  $("export-html").href = `/api/cases/${c.id}/report.html`;
  $("export-json").href = `/api/cases/${c.id}/report.json`;
  $("export-iocs").href = `/api/cases/${c.id}/iocs.txt`;

  renderFindings(findings);
  renderLinks(report.links || []);
  renderAttachments(report.attachments || []);
  renderRoute(report.route || []);
  renderNotes(c.notes || []);
  renderIocs(report.iocs || {});
  $("case-status").value = c.status || "new";
  renderRelated(c.id).catch((err) => toast(err.message));

  $("safety-notes").textContent = (report.notes || []).join(" ");

  // The tab strip is measurable only once the case view is visible.
  requestAnimationFrame(updateTabScrollAffordance);

  // Deep link support: ?case=<id>&tab=links opens a specific evidence view.
  const wantedTab = new URLSearchParams(location.search).get("tab");
  if (wantedTab) {
    const tab = document.querySelector(`.segment[data-tab="${wantedTab}"]`);
    if (tab) tab.click();
  }
}

function renderFindings(findings) {
  const panel = $("tab-findings");
  panel.textContent = "";
  if (!findings.length) {
    panel.appendChild(
      el("p", "hint", "No findings. That describes this message only; it is not proof of safety.")
    );
    return;
  }
  const byCategory = new Map();
  for (const f of findings) {
    const cat = f.category || "other";
    if (!byCategory.has(cat)) byCategory.set(cat, []);
    byCategory.get(cat).push(f);
  }
  for (const [category, items] of byCategory) {
    panel.appendChild(el("div", "category-heading", category));
    if (category === "authentication") {
      panel.appendChild(
        el(
          "p",
          "category-note",
          "Outcomes recorded by the receiving server in this message's own " +
            "headers. Headers inside an uploaded message can be forged by the " +
            "sender: treat them as the receiver's claims, not independently " +
            "verified facts."
        )
      );
    }
    for (const f of items) {
      const row = el("details", "finding");
      if (f.severity === "high") row.open = true;
      const summary = el("summary");
      summary.appendChild(el("span", `sev-badge ${f.severity}`, f.severity));
      summary.appendChild(el("span", "finding-title", f.title));
      row.appendChild(summary);
      const body = el("div", "finding-body");
      body.appendChild(el("div", "finding-detail", f.detail));
      if (f.why) {
        const why = el("div", "finding-why", f.why);
        if (f.reference) {
          why.appendChild(document.createTextNode(" "));
          why.appendChild(el("span", "finding-ref", f.reference));
        }
        body.appendChild(why);
      }
      row.appendChild(body);
      panel.appendChild(row);
    }
  }
}

function emptyRow(cellText, colspan) {
  const row = el("tr");
  const cell = el("td", null, cellText);
  cell.colSpan = colspan;
  row.appendChild(cell);
  return row;
}

function wrapTable(table) {
  const wrap = el("div", "table-wrap");
  wrap.appendChild(table);
  return wrap;
}

function renderLinks(links) {
  const panel = $("tab-links");
  panel.textContent = "";
  panel.appendChild(el("p", "table-hint", "Extracted from the message. Never opened, resolved or fetched."));
  const table = el("table", "data");
  const head = el("thead");
  const headRow = el("tr");
  for (const label of ["URL", "Shown text", "Source"]) headRow.appendChild(el("th", null, label));
  head.appendChild(headRow);
  table.appendChild(head);
  const tbody = el("tbody");
  for (const l of links) {
    const row = el("tr");
    const urlCell = el("td");
    urlCell.appendChild(el("code", null, l.url));
    row.appendChild(urlCell);
    row.appendChild(el("td", null, l.anchor_text || ""));
    row.appendChild(el("td", null, l.source || ""));
    tbody.appendChild(row);
  }
  if (!links.length) tbody.appendChild(emptyRow("No links found.", 3));
  table.appendChild(tbody);
  panel.appendChild(wrapTable(table));
}

function renderAttachments(attachments) {
  const panel = $("tab-attachments");
  panel.textContent = "";
  panel.appendChild(
    el("p", "table-hint", "Metadata, hashes and magic-byte type only. Contents are never executed or opened.")
  );
  const table = el("table", "data");
  const head = el("thead");
  const headRow = el("tr");
  for (const label of ["Name", "Detected type", "Bytes", "SHA-256"]) headRow.appendChild(el("th", null, label));
  head.appendChild(headRow);
  table.appendChild(head);
  const tbody = el("tbody");
  for (const a of attachments) {
    const row = el("tr");
    row.appendChild(el("td", null, a.filename));
    row.appendChild(el("td", null, a.truncated ? `${a.detected_type} (truncated)` : a.detected_type));
    row.appendChild(el("td", null, String(a.size)));
    const hashCell = el("td");
    hashCell.appendChild(el("code", null, a.sha256 || "not hashed (oversized)"));
    row.appendChild(hashCell);
    tbody.appendChild(row);
  }
  if (!attachments.length) tbody.appendChild(emptyRow("No attachments.", 4));
  table.appendChild(tbody);
  panel.appendChild(wrapTable(table));
}

function renderRoute(hops) {
  const panel = $("tab-route");
  panel.textContent = "";
  panel.appendChild(el("p", "table-hint", "The relay path as recorded in Received headers, origin first."));
  const table = el("table", "data");
  const head = el("thead");
  const headRow = el("tr");
  for (const label of ["Hop", "From", "By", "Timestamp"]) headRow.appendChild(el("th", null, label));
  head.appendChild(headRow);
  table.appendChild(head);
  const tbody = el("tbody");
  for (const h of hops) {
    const row = el("tr");
    row.appendChild(el("td", null, String(h.index)));
    const fromCell = el("td"); fromCell.appendChild(el("code", null, h.from_host || "unknown")); row.appendChild(fromCell);
    const byCell = el("td"); byCell.appendChild(el("code", null, h.by_host || "unknown")); row.appendChild(byCell);
    row.appendChild(el("td", null, h.timestamp || "unknown"));
    tbody.appendChild(row);
  }
  if (!hops.length) tbody.appendChild(emptyRow("No Received chain in this message.", 4));
  table.appendChild(tbody);
  panel.appendChild(wrapTable(table));
}

function renderNotes(notes) {
  const list = $("notes-list");
  list.textContent = "";
  if (!notes.length) {
    list.appendChild(el("p", "hint", "No notes yet. Record what you checked and what you decided."));
    return;
  }
  for (const n of notes) {
    const card = el("div", "note");
    card.appendChild(el("div", "note-time", n.created_at));
    card.appendChild(el("div", null, n.body));
    list.appendChild(card);
  }
}

/* ---------- related cases ---------- */

async function renderRelated(caseId) {
  const list = $("related-list");
  list.textContent = "";
  const data = await api(`/api/cases/${caseId}/related`);
  if (!data.related.length) {
    list.appendChild(
      el("p", "hint", "No other cases share indicators with this one.")
    );
    return;
  }
  for (const r of data.related) {
    const item = el("button", "related-item");
    const top = el("div", "q-top");
    top.appendChild(el("span", `verdict-dot ${r.verdict}`));
    top.appendChild(el("span", "q-subject", r.subject || "(no subject)"));
    item.appendChild(top);

    const meta = el("div", "q-meta");
    meta.appendChild(el("span", "q-sender", r.sender || "unknown sender"));
    meta.appendChild(
      el("span", null, `${r.score}/100 · ${relativeTime(r.created_at)}`)
    );
    item.appendChild(meta);

    const shared = el("div", "related-shared");
    for (const s of r.shared) shared.appendChild(el("span", "shared-chip", s));
    item.appendChild(shared);

    item.addEventListener("click", () =>
      openCase(r.id).catch((err) => toast(err.message))
    );
    list.appendChild(item);
  }
}

/* ---------- indicators ---------- */

function renderIocs(iocs) {
  const body = $("ioc-body");
  body.textContent = "";
  const defanged = $("defang-toggle").checked;
  const show = (v) => (defanged ? defang(v) : v);

  const sections = [
    ["Domains", iocs.domains || []],
    ["URLs", iocs.urls || []],
    ["IP addresses", iocs.ips || []],
    ["Email addresses", iocs.addresses || []],
  ];
  let any = false;
  for (const [label, values] of sections) {
    if (!values.length) continue;
    any = true;
    const section = el("div", "ioc-section");
    section.appendChild(el("h4", null, label));
    for (const value of values) {
      section.appendChild(iocItem(show(value), show(value)));
    }
    body.appendChild(section);
  }
  const hashes = iocs.file_hashes || [];
  if (hashes.length) {
    any = true;
    const section = el("div", "ioc-section");
    section.appendChild(el("h4", null, "File hashes (SHA-256)"));
    for (const h of hashes) {
      section.appendChild(iocItem(`${h.sha256}  ${h.filename}`, h.sha256));
    }
    body.appendChild(section);
  }
  if (!any) {
    body.appendChild(el("p", "hint", "No indicators in this message."));
  }
}

function iocItem(display, copyValue) {
  const item = el("div", "ioc-item");
  item.appendChild(el("span", null, display));
  const copy = el("button", "copy-btn", "copy");
  copy.setAttribute("aria-label", "Copy indicator");
  copy.addEventListener("click", async () => {
    try {
      await copyTextToClipboard(copyValue);
      toast("Copied");
    } catch (err) {
      toast("Copy failed");
    }
  });
  item.appendChild(copy);
  return item;
}

/* ---------- tabs ---------- */

function updateTabScrollAffordance() {
  const tabs = $("tabs");
  const wrap = tabs.parentElement;
  const maxScroll = tabs.scrollWidth - tabs.clientWidth;
  wrap.classList.toggle("can-scroll-left", tabs.scrollLeft > 1);
  wrap.classList.toggle("can-scroll-right", tabs.scrollLeft < maxScroll - 1);
}

function activateTab(tab) {
  for (const t of document.querySelectorAll(".segment")) {
    t.classList.remove("active");
    t.setAttribute("aria-selected", "false");
    t.tabIndex = -1;
  }
  for (const p of document.querySelectorAll(".tab-panel")) p.classList.add("hidden");
  tab.classList.add("active");
  tab.setAttribute("aria-selected", "true");
  tab.tabIndex = 0;
  $(`tab-${tab.dataset.tab}`).classList.remove("hidden");
  // Keep the active tab visible inside the horizontally scrollable strip:
  // center it explicitly rather than relying on ancestor scroll behavior.
  const tabs = $("tabs");
  tabs.scrollLeft = Math.max(
    0,
    tab.offsetLeft - (tabs.clientWidth - tab.offsetWidth) / 2
  );
  updateTabScrollAffordance();
}

const tabButtons = Array.from(document.querySelectorAll(".segment"));
for (const tab of tabButtons) {
  tab.addEventListener("click", () => activateTab(tab));
}
$("tabs").addEventListener("scroll", updateTabScrollAffordance);
window.addEventListener("resize", updateTabScrollAffordance);
$("tabs").addEventListener("keydown", (event) => {
  const current = tabButtons.findIndex((t) => t.classList.contains("active"));
  let next = null;
  if (event.key === "ArrowRight") next = (current + 1) % tabButtons.length;
  if (event.key === "ArrowLeft") next = (current - 1 + tabButtons.length) % tabButtons.length;
  if (event.key === "Home") next = 0;
  if (event.key === "End") next = tabButtons.length - 1;
  if (next !== null) {
    event.preventDefault();
    activateTab(tabButtons[next]);
    tabButtons[next].focus();
  }
});

/* ---------- events ---------- */

$("new-analysis-btn").addEventListener("click", openSheet);
$("empty-cta").addEventListener("click", openSheet);
$("back-to-cases").addEventListener("click", closeCase);
$("cancel-sheet").addEventListener("click", closeSheet);
$("sheet-overlay").addEventListener("click", (event) => {
  if (event.target === $("sheet-overlay")) closeSheet();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !$("sheet-overlay").classList.contains("hidden")) closeSheet();
});

$("browse-btn").addEventListener("click", () => $("files").click());
$("drop-zone").addEventListener("click", (event) => {
  if (event.target === $("drop-zone")) $("files").click();
});
$("drop-zone").addEventListener("keydown", (event) => {
  if ((event.key === "Enter" || event.key === " ") && event.target === $("drop-zone")) {
    event.preventDefault();
    $("files").click();
  }
});
$("files").addEventListener("change", () => setChosenFiles($("files").files));
$("drop-zone").addEventListener("dragover", (event) => {
  event.preventDefault();
  $("drop-zone").classList.add("dragging");
});
$("drop-zone").addEventListener("dragleave", () => $("drop-zone").classList.remove("dragging"));
$("drop-zone").addEventListener("drop", (event) => {
  event.preventDefault();
  $("drop-zone").classList.remove("dragging");
  if (event.dataTransfer.files.length) setChosenFiles(event.dataTransfer.files);
});

$("queue-search").addEventListener("input", () => refreshQueue().catch((err) => toast(err.message)));
$("queue-filter").addEventListener("change", () => refreshQueue().catch((err) => toast(err.message)));
$("queue-status-filter").addEventListener("change", () => refreshQueue().catch((err) => toast(err.message)));

$("case-status").addEventListener("change", async () => {
  if (!state.current) return;
  const status = $("case-status").value;
  try {
    await api(`/api/cases/${state.current.id}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    await openCase(state.current.id);
    toast(`Status set to ${statusLabel(status)}`);
  } catch (err) {
    toast(err.message);
  }
});

// Copy that never reports success without the clipboard actually taking the
// text: async Clipboard API where available, execCommand fallback elsewhere,
// and a thrown error (caught by the caller) when neither works.
async function copyTextToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.top = "0";
  ta.style.opacity = "0";
  document.body.appendChild(ta);
  ta.focus();
  ta.select();
  let ok = false;
  try {
    ok = document.execCommand("copy");
  } finally {
    ta.remove();
  }
  if (!ok) throw new Error("This browser blocked clipboard access");
}

$("copy-handoff").addEventListener("click", async () => {
  if (!state.current) return;
  try {
    const resp = await fetch(`/api/cases/${state.current.id}/handoff.txt`);
    if (!resp.ok) throw new Error("Handoff unavailable");
    const text = await resp.text();
    await copyTextToClipboard(text);
    toast("Handoff copied - nothing was sent");
  } catch (err) {
    toast("Copy failed - the Report and Evidence exports still work");
  }
});
$("defang-toggle").addEventListener("change", () => {
  if (state.current) renderIocs(state.current.report.iocs || {});
});

$("go").addEventListener("click", async () => {
  $("error").classList.add("hidden");
  const button = $("go");
  button.disabled = true;
  try {
    const form = new FormData();
    if (state.files.length) {
      for (const file of state.files) form.append("files", file);
    } else if ($("raw").value.trim()) {
      form.append("raw", $("raw").value);
    } else {
      throw new Error("Add at least one .eml file, or paste a message.");
    }
    const data = await api("/api/analyze", { method: "POST", body: form });
    $("raw").value = "";
    $("files").value = "";
    state.files = [];
    $("chosen-files").textContent = "";
    closeSheet();
    const lastId = data.cases[data.cases.length - 1].case_id;
    await refreshQueue(lastId);
    toast(
      data.cases.length === 1
        ? "Case created"
        : `${data.cases.length} cases created`
    );
  } catch (err) {
    showError(err.message);
  } finally {
    button.disabled = false;
  }
});

$("save-verdict").addEventListener("click", async () => {
  if (!state.current) return;
  const verdict = $("analyst-verdict").value;
  if (!verdict) {
    toast("Choose a verdict first");
    return;
  }
  try {
    await api(`/api/cases/${state.current.id}/verdict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ verdict, reason: $("analyst-reason").value.trim() }),
    });
    await openCase(state.current.id);
    await refreshQueue();
    toast("Verdict saved");
  } catch (err) {
    toast(err.message);
  }
});

$("add-note").addEventListener("click", async () => {
  if (!state.current) return;
  const body = $("note-body").value.trim();
  if (!body) return;
  try {
    await api(`/api/cases/${state.current.id}/notes`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ body }),
    });
    $("note-body").value = "";
    await openCase(state.current.id);
    document.querySelector('.segment[data-tab="notes"]').click();
  } catch (err) {
    toast(err.message);
  }
});

/* ---------- boot ---------- */

refreshQueue()
  .then(() => {
    // Deep link: /?case=<id> opens a case directly (shareable within the machine).
    const caseId = new URLSearchParams(location.search).get("case");
    if (caseId) return openCase(caseId).catch(() => {});
    return undefined;
  })
  .catch((err) => toast(err.message));
