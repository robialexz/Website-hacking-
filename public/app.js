const state = { csrf: "", findings: new Map(), publicPages: [], timer: null };
const $ = (selector) => document.querySelector(selector);

async function api(path, options = {}) {
  const headers = { "Accept": "application/json", ...(options.headers || {}) };
  if (options.method && options.method !== "GET") {
    headers["Content-Type"] = "application/json";
    headers["X-CSRF-Token"] = state.csrf;
  }
  const response = await fetch(path, { ...options, headers, cache: "no-store", credentials: "same-origin" });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || "Request failed");
  return body;
}

function node(tag, className, text) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined) item.textContent = text;
  return item;
}

function showToast(message) {
  const toast = $("#toast");
  toast.textContent = message;
  toast.classList.add("visible");
  clearTimeout(showToast.timer);
  showToast.timer = setTimeout(() => toast.classList.remove("visible"), 3200);
}

function severityClass(value) {
  const normalized = String(value || "info").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(normalized) ? normalized : "info";
}

function statusClass(value) {
  if (value === "CONFIRMED") return "confirmed";
  if (value === "SUSPECTED") return "suspected";
  if (value === "FIXED AND RETESTED") return "fixed";
  return "neutral";
}

function renderFindings(items, total = items.length) {
  state.findings = new Map(items.map((item) => [item.id, item]));
  const body = $("#findingsBody");
  body.replaceChildren();
  $("#findingsTotal").textContent = `${total} total`;
  $("#sideFindingCount").textContent = String(total);
  if (!items.length) {
    const row = node("tr");
    const cell = node("td", "empty", "No findings yet. Run a local audit or an approved source or public page review.");
    cell.colSpan = 5;
    row.append(cell);
    body.append(row);
    return;
  }
  for (const item of items.slice(0, 8)) {
    const row = node("tr");
    const name = node("td");
    name.append(node("span", "finding-name", item.title));
    name.append(node("small", "finding-id", item.findingKey));
    const severity = node("td");
    severity.append(node("span", `severity ${severityClass(item.severity)}`, item.severity));
    const status = node("td");
    status.append(node("span", `status-pill ${statusClass(item.status)}`, item.status));
    const confidence = node("td", "confidence", item.confidence || "—");
    const action = node("td");
    const button = node("button", "detail-link", "View evidence →");
    button.type = "button";
    button.addEventListener("click", () => showFinding(item.id));
    action.append(button);
    row.append(name, severity, status, confidence, action);
    body.append(row);
  }
}

function showFinding(id) {
  const item = state.findings.get(id);
  if (!item) return;
  $("#detailTitle").textContent = item.title;
  const content = $("#detailContent");
  content.replaceChildren();
  const sections = [
    ["Classification", `${item.status} · ${item.severity} · ${item.confidence || "confidence not recorded"}`],
    ["Target and component", `${item.target || "Local demo"} · ${item.endpoint || ""}`],
    ["Expected behavior", item.expected || "Not recorded"],
    ["Observed behavior", item.actual || "Not recorded"],
    ["Demonstrated impact", item.impact || "No impact recorded"],
    ["Recommended remediation", item.remediation || "No recommendation recorded"],
    ["Retest status", item.retestStatus || "Not retested"],
    ["Evidence", JSON.stringify(item.evidence || {}, null, 2)]
  ];
  for (const [title, value] of sections) {
    const block = node("section", "detail-block");
    block.append(node("h3", "", title));
    const text = node(title === "Evidence" ? "pre" : "p", "", value);
    block.append(text);
    content.append(block);
  }
  $("#detailDialog").showModal();
}

function renderJobs(items) {
  const list = $("#jobsList");
  list.replaceChildren();
  if (!items.length) {
    list.append(node("div", "empty", "No audit runs yet."));
    return;
  }
  for (const job of items.slice(0, 6)) {
    const row = node("div", "job-row");
    row.append(node("div", "job-icon", job.status === "running" ? "◌" : "✓"));
    const main = node("div", "job-main");
    main.append(node("b", "", job.label || "Local security audit"));
    const profileLabel = job.profile === "approved-source" ? "approved source" : job.profile === "approved-public" ? "approved public pages" : `${job.profile} profile`;
    main.append(node("small", "", `${job.createdAt} · ${profileLabel}`));
    row.append(main);
    const status = node("span", `job-status ${job.status}`, job.status);
    row.append(status);
    if (job.status === "complete") {
      const details = node("button", "detail-link", "Logs");
      details.type = "button";
      details.addEventListener("click", () => showJob(job.id));
      row.append(details);
      const link = node("a", "report-link", "Report");
      link.href = `/reports/${encodeURIComponent(job.id)}/technical`;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      row.append(link);
    }
    list.append(row);
  }
}

async function refresh() {
  try {
    const data = await api("/api/dashboard");
    $("#confirmedCount").textContent = String(data.summary.confirmed);
    $("#suspectedCount").textContent = String(data.summary.suspected);
    $("#jobCount").textContent = String(data.summary.jobs);
    $("#coverageCount").textContent = `${data.summary.checksAttempted}/${data.summary.checksAvailable}`;
    $("#scopeOrigin").textContent = data.scope.origins.join(", ");
    $("#scopePaths").textContent = data.scope.paths.join(", ");
    $("#scopeSources").textContent = data.scope.sourceDirectories.join(", ");
    $("#scopeSourceBudget").textContent = `Read-only; up to ${data.scope.maxSourceFiles} files / ${Math.round(data.scope.maxSourceBytes / 1_000_000)} MB. No code execution or network access.`;
    $("#scopePublicPages").textContent = data.scope.publicPages.join(", ") || "Not configured";
    state.publicPages = data.scope.publicPages;
    $("#scopePublicBudget").textContent = "One unauthenticated GET/page; max " + data.scope.maxPublicPages + " page(s), " + Math.round(data.scope.maxPublicBytesPerPage / 1_000_000) + " MB each. A GET can still trigger site actions; include only pages known safe to request.";
    $("#scopeBudget").textContent = `${data.scope.maxRequests} requests · ${data.scope.timeoutMs} ms timeout`;
    $("#scopeAccounts").textContent = data.scope.testAccounts.map((account) => `${account.name} (${account.role})`).join(", ") || "None configured";
    $("#scopeServices").textContent = data.scope.services.join(", ");
    $("#scopeReset").textContent = data.scope.resetProcedure;
    $("#profileSelect").value = data.profile;
    $("#appVersion").textContent = `v${data.version}`;
    renderFindings(data.findings, data.summary.totalFindings);
    renderJobs(data.jobs);
    const active = data.jobs.some((job) => job.status === "queued" || job.status === "running");
    const activeJob = data.jobs.find((job) => job.status === "queued" || job.status === "running");
    $("#runAuditButton").disabled = active;
    $("#retestButton").disabled = active || data.profile !== "secure" || data.summary.jobs === 0;
    const sourceReviewEnabled = data.scope.services.includes("source-review");
    const publicReviewEnabled = data.scope.services.includes("passive-public-review");
    $("#sourceReviewButton").disabled = active || !sourceReviewEnabled;
    $("#publicReviewButton").disabled = active || !publicReviewEnabled || data.scope.publicPages.length === 0;
    $("#profileSelect").disabled = active;
    const activeLabel = activeJob?.action === "source-review" ? "Source review in progress"
      : activeJob?.action === "public-review" ? "Public review in progress"
      : activeJob?.action === "retest" ? "Retest in progress"
      : "Audit in progress";
    $("#runAuditButton").innerHTML = active ? `<span>◌</span> ${activeLabel}` : "<span>＋</span> Run local audit";
    $("#sourceReviewButton").textContent = active ? activeLabel : sourceReviewEnabled ? "Review approved source" : "Enable source review";
    $("#publicReviewButton").textContent = active ? activeLabel : !publicReviewEnabled ? "Enable public review" : data.scope.publicPages.length ? "Review approved pages" : "Configure approved pages";
    $("#publicReviewDescription").textContent = data.scope.publicPages.length
      ? "Configured page(s): " + data.scope.publicPages.join(", ") + ". One unauthenticated GET per page; no redirects, cookies, assets, or page links are followed. GET can trigger actions on some sites, so each run asks you to confirm these pages are safe to request."
      : "No public pages are configured. Add exact HTTPS page URLs to publicReadOnlyPages in local scope.json and add passive-public-review to approvedServices, then restart the app.";
    if (active && !state.timer) state.timer = setInterval(refresh, 1600);
    if (!active && state.timer) { clearInterval(state.timer); state.timer = null; }
  } catch (error) {
    showToast(error.message || "Could not load the local dashboard");
  }
}

async function showJob(id) {
  try {
    const data = await api(`/api/jobs/${encodeURIComponent(id)}`);
    $("#detailTitle").textContent = data.job.label || "Audit run details";
    const content = $("#detailContent");
    content.replaceChildren();
    const blocks = [
      ["Run", `${data.job.id} · ${data.job.status} · ${data.job.profile} profile`],
      ["Coverage", JSON.stringify(data.job.coverage || [], null, 2)],
      ["Execution log", (data.logs || []).map((entry) => `${entry.created_at} · ${entry.level} · ${entry.message}`).join("\n") || "No execution log entries."],
    ];
    for (const [title, value] of blocks) {
      const block = node("section", "detail-block");
      block.append(node("h3", "", title), node("pre", "", value));
      content.append(block);
    }
    $("#detailDialog").showModal();
  } catch (error) { showToast(error.message || "Could not load the audit log"); }
}

async function createJob(action) {
  try {
    let confirmPublicGet = false;
    if (action === "public-review") {
      const pages = state.publicPages.map((page) => "• " + page).join("\n");
      confirmPublicGet = window.confirm(
        "RevenueGuard will send one unauthenticated GET to each page below:\n\n" + pages +
        "\n\nSome GET URLs can trigger actions on a website. Confirm that you own or have permission to review these exact pages and that each page is safe to request. Continue?"
      );
      if (!confirmPublicGet) return;
    }
    await api("/api/jobs", { method: "POST", body: JSON.stringify({ action, confirmPublicGet }) });
    showToast(action === "retest" ? "Retest queued against the selected secure profile"
      : action === "source-review" ? "Source review queued"
      : action === "public-review" ? "Public page review queued"
      : "Local audit queued");
    await refresh();
  } catch (error) {
    showToast(error.message);
  }
}

$("#runAuditButton").addEventListener("click", () => createJob("audit"));
$("#retestButton").addEventListener("click", () => createJob("retest"));
$("#sourceReviewButton").addEventListener("click", () => createJob("source-review"));
$("#publicReviewButton").addEventListener("click", () => createJob("public-review"));
$("#refreshButton").addEventListener("click", refresh);
$("#closeDialog").addEventListener("click", () => $("#detailDialog").close());
$("#detailDialog").addEventListener("click", (event) => { if (event.target === $("#detailDialog")) $("#detailDialog").close(); });
$("#profileSelect").addEventListener("change", async (event) => {
  try {
    await api("/api/lab/profile", { method: "POST", body: JSON.stringify({ profile: event.target.value }) });
    showToast(`Demo switched to the ${event.target.value} profile. Synthetic state was reset.`);
    await refresh();
  } catch (error) { showToast(error.message); }
});

async function start() {
  try {
    const session = await api("/api/session");
    state.csrf = session.csrfToken;
    await refresh();
  } catch (error) { showToast(error.message || "RevenueGuard Lab is unavailable"); }
}
start();
