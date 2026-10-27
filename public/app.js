const POSTURE_PAGE_CAP = 4;
const state = { csrf: "", findings: new Map(), publicPages: [], publicReviewEnabled: false, webScanEnabled: false, webScanBudgets: { maxPages: 100, maxDepth: 4, maxRequests: 250, maxDurationMs: 180000, maxBytes: 50000000 }, activeWebScanId: null, postureSelectedPages: new Set(), posturePageCap: POSTURE_PAGE_CAP, active: false, timer: null };
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
  const normalized = String(value || "").toUpperCase();
  if (["OBSERVED", "INCONCLUSIVE", "NOT TESTED", "BLOCKED"].includes(normalized)) return "neutral";
  if (value === "CONFIRMED") return "confirmed";
  if (value === "SUSPECTED") return "suspected";
  if (value === "FIXED AND RETESTED") return "fixed";
  return "neutral";
}

function renderFindings(items, total = items.length) {
  state.findings = new Map(items.map((item) => [item.id, item]));
  const body = $("#findingsBody");
  body.replaceChildren();
  const visibleCount = Math.min(items.length, 8);
  $("#findingsTotal").textContent = total > visibleCount
    ? "Showing " + visibleCount + " of " + total + " (dashboard limit: 8)"
    : total + " total";
  $("#sideFindingCount").textContent = String(total);
  if (!items.length) {
    const row = node("tr");
    const cell = node("td", "empty", "No findings recorded. An empty findings list does not establish that a target is secure.");
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
    const jobIcon = { queued: "◷", running: "◌", cancelling: "◌", cancelled: "×", failed: "!", complete: "✓" }[job.status] || "•";
    row.append(node("div", "job-icon " + job.status, jobIcon));
    const main = node("div", "job-main");
    main.append(node("b", "", job.label || "Local security audit"));
    const profileLabel = job.action === "web-scan" ? `web scan · ${job.targetOrigin || "target hidden"}`
      : job.action === "posture-review" ? "HTTPS posture observations"
      : job.profile === "approved-source" ? "approved source"
      : job.profile === "approved-public" ? "approved public pages"
      : `${job.profile} profile`;
    main.append(node("small", "", `${job.createdAt} · ${profileLabel}`));
    row.append(main);
    const statusLabel = job.action === "posture-review" && job.status === "complete" ? "finished" : job.status;
    const status = node("span", `job-status ${job.status}`, statusLabel);
    row.append(status);
    if (job.status === "complete" || job.status === "cancelled" || job.action === "posture-review" || job.action === "web-scan") {
      const details = node("button", "detail-link", job.action === "posture-review" || job.action === "web-scan" ? "Details" : "Logs");
      details.type = "button";
      details.addEventListener("click", () => showJob(job.id));
      row.append(details);
    }
    if (job.action === "web-scan" && ["queued", "running", "cancelling"].includes(job.status)) {
      const cancel = node("button", "detail-link", job.status === "cancelling" ? "Stopping…" : "Stop");
      cancel.type = "button";
      cancel.disabled = job.status === "cancelling";
      cancel.addEventListener("click", () => cancelWebScan(job.id));
      row.append(cancel);
    }
    if (job.status === "complete" || job.status === "cancelled") {
      const link = node("a", "report-link", "Report");
      link.href = `/reports/${encodeURIComponent(job.id)}/technical`;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      row.append(link);
    }
    list.append(row);
  }
}

function updatePostureControls() {
  const authorization = $("#postureAuthorizationAttestation");
  const safeGet = $("#postureSafeGetAttestation");
  const button = $("#postureReviewButton");
  const hint = $("#postureRunHint");
  if (!authorization || !safeGet || !button || !hint) return;

  const hasConfiguredPages = state.publicPages.length > 0;
  const selectedCount = state.postureSelectedPages.size;
  const hasSelectedPages = selectedCount > 0;
  button.disabled = state.active || !state.publicReviewEnabled || !hasConfiguredPages || !hasSelectedPages || selectedCount > state.posturePageCap || !authorization.checked || !safeGet.checked;
  for (const checkbox of $("#posturePageList").querySelectorAll('input[type="checkbox"]')) {
    checkbox.disabled = state.active || (!checkbox.checked && selectedCount >= state.posturePageCap);
  }
  hint.textContent = !state.publicReviewEnabled ? "HTTPS posture observations are disabled. Add passive-public-review to approvedServices in local scope.json and restart the app."
    : state.posturePageCap === 0 ? "The current scope budget allows zero requests. Increase maxPublicPages and/or maxRequests in local scope.json, then restart the app."
    : !hasConfiguredPages ? "No exact HTTPS URLs are configured for posture observations."
    : state.active ? "A run is active. Wait for it to finish before starting another."
    : !hasSelectedPages ? "Select one or more exact URLs to include in this run."
    : !authorization.checked ? "Confirm that you are authorized to request these exact URLs."
    : !safeGet.checked ? "Confirm that one unauthenticated GET per selected route is safe to request."
    : "Ready to queue one unauthenticated GET for each selected URL.";
}

function webScanTargetOrigin(value) {
  try {
    if (value.trim() !== value) return null;
    const url = new URL(value);
    const host = url.hostname.toLowerCase();
    if (url.protocol !== "https:" || url.username || url.password || url.port || url.search || url.hash) return null;
    if (!host.includes(".") || host.endsWith(".") || host.includes(":")) return null;
    if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || /\.(?:localhost|local|internal|test|example|invalid|home\.arpa|lan)$/.test(host)) return null;
    const path = decodeURIComponent(url.pathname);
    if (path.includes("%") || /[\\\u0000-\u001f]/.test(path)) return null;
    const stateful = /(?:^|[-_.])(?:logout|log-out|signout|sign-out|unsubscribe|delete|destroy|remove|deactivate|disable|confirm|confirmation|activate|reset|purchase|checkout|payment|transfer|withdraw|subscribe|verify|callback|accept-invite|revoke|cancel)(?:$|[-_.])/i;
    const sensitive = /^(?:token|key|secret|code|invite|session|auth|reset|verify|confirmation|unsubscribe)$/i;
    if (path.split("/").filter(Boolean).some((segment) => stateful.test(segment) || sensitive.test(segment))) return null;
    return url.origin;
  } catch { return null; }
}

function updateWebScanControls() {
  const target = $("#webScanTarget");
  const pages = $("#webScanMaxPages");
  const depth = $("#webScanMaxDepth");
  const authorized = $("#webScanAuthorized");
  const safeGet = $("#webScanSafeGet");
  const button = $("#webScanButton");
  const cancel = $("#cancelScanButton");
  const hint = $("#webScanRunHint");
  if (!target || !pages || !depth || !authorized || !safeGet || !button || !cancel || !hint) return;
  const origin = webScanTargetOrigin(target.value);
  const pageLimit = Number(pages.value);
  const depthLimit = Number(depth.value);
  const validBudget = Number.isInteger(pageLimit) && pageLimit >= 1 && pageLimit <= state.webScanBudgets.maxPages &&
    Number.isInteger(depthLimit) && depthLimit >= 0 && depthLimit <= state.webScanBudgets.maxDepth;
  const ready = state.webScanEnabled && !state.active && Boolean(origin) && validBudget && authorized.checked && safeGet.checked;
  button.disabled = !ready;
  button.textContent = state.activeWebScanId ? "Web scan in progress" : "Start web scan";
  cancel.hidden = !state.activeWebScanId;
  cancel.disabled = !state.activeWebScanId || state.cancelling;
  pages.max = String(state.webScanBudgets.maxPages);
  depth.max = String(state.webScanBudgets.maxDepth);
  hint.textContent = !state.webScanEnabled ? "Web scanning is not enabled in the current local scope."
    : state.activeWebScanId ? "A same-origin scan is running. You can stop it at any time."
    : state.active ? "Another run is active. Wait for it to finish before starting a web scan."
    : !origin ? "Enter a public HTTPS hostname and safe starting path without credentials, query strings, fragments, or obvious action-like paths."
    : !validBudget ? "Choose page and depth limits within the configured scanner budget."
    : !authorized.checked ? "Confirm that you own this origin or have permission to test it."
    : !safeGet.checked ? "Confirm that bounded unauthenticated GET requests are acceptable for this target."
    : `Ready to scan ${origin} · up to ${pageLimit} pages · depth ${depthLimit}.`;
}

function renderPosturePages(pages) {
  const list = $("#posturePageList");
  const configuredPages = Array.isArray(pages) ? pages : [];
  const allowedPages = new Set(configuredPages);
  const previousSelection = state.postureSelectedPages;
  const nextSelection = new Set([...previousSelection].filter((page) => allowedPages.has(page)));
  const selectionChanged = nextSelection.size !== previousSelection.size;
  state.postureSelectedPages = nextSelection;
  if (selectionChanged) {
    $("#postureAuthorizationAttestation").checked = false;
    $("#postureSafeGetAttestation").checked = false;
  }

  list.replaceChildren();
  if (!configuredPages.length) {
    list.append(node("li", "", "No exact HTTPS URLs are configured in the current scope."));
  } else {
    for (const page of configuredPages) {
      const item = node("li");
      const label = node("label");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.checked = state.postureSelectedPages.has(page);
      checkbox.disabled = state.active;
      checkbox.addEventListener("change", () => {
        if (checkbox.checked) state.postureSelectedPages.add(page);
        else state.postureSelectedPages.delete(page);
        $("#postureAuthorizationAttestation").checked = false;
        $("#postureSafeGetAttestation").checked = false;
        updatePostureControls();
      });
      const exactUrl = node("span", "", page);
      exactUrl.style.overflowWrap = "anywhere";
      label.append(checkbox, " ", exactUrl);
      item.append(label);
      list.append(item);
    }
  }

  const selectionLimit = state.posturePageCap === 0
    ? "Current scope budgets allow zero requests."
    : `Up to ${state.posturePageCap} may be selected per run, limited by the four-page cap and current scope budgets.`;
  $("#posturePageSelectionSummary").textContent = configuredPages.length
    ? `${state.postureSelectedPages.size} of ${configuredPages.length} configured URL(s) selected. ${selectionLimit} Only selected URLs will be requested.`
    : "Select exact URLs from the current public page scope to run posture observations.";
  updatePostureControls();
}

async function refresh() {
  try {
    const data = await api("/api/dashboard");
    $("#confirmedCount").textContent = String(data.summary.confirmed);
    $("#suspectedCount").textContent = String(data.summary.suspected);
    $("#observedCount").textContent = String(data.summary.observed);
    $("#jobCount").textContent = String(data.summary.jobs);
    $("#coverageCount").textContent = `${data.summary.checksAttempted} / ${data.summary.checksAvailable}`;
    $("#scopeOrigin").textContent = data.scope.origins.join(", ");
    $("#scopePaths").textContent = data.scope.paths.join(", ");
    $("#scopeSources").textContent = data.scope.sourceDirectories.join(", ");
    $("#scopeSourceBudget").textContent = `Read-only; up to ${data.scope.maxSourceFiles} files / ${Math.round(data.scope.maxSourceBytes / 1_000_000)} MB. No code execution or network access.`;
    $("#scopePublicPages").textContent = data.scope.publicPages.join(", ") || "Not configured";
    state.publicPages = data.scope.publicPages;
    state.publicReviewEnabled = data.scope.services.includes("passive-public-review");
    const configuredPageCap = Number(data.scope.maxPublicPages);
    const configuredRequestCap = Number(data.scope.maxRequests);
    const hasPageCap = data.scope.maxPublicPages !== null && data.scope.maxPublicPages !== undefined && Number.isFinite(configuredPageCap);
    const hasRequestCap = data.scope.maxRequests !== null && data.scope.maxRequests !== undefined && Number.isFinite(configuredRequestCap);
    state.posturePageCap = Math.min(
      POSTURE_PAGE_CAP,
      hasPageCap ? Math.max(0, configuredPageCap) : POSTURE_PAGE_CAP,
      hasRequestCap ? Math.max(0, configuredRequestCap) : POSTURE_PAGE_CAP
    );
    $("#scopePublicBudget").textContent = "One unauthenticated GET/page; max " + data.scope.maxPublicPages + " page(s), " + Math.round(data.scope.maxPublicBytesPerPage / 1_000_000) + " MB each. A GET can still trigger site actions; include only pages known safe to request.";
    $("#scopeBudget").textContent = `${data.scope.maxRequests} requests · ${data.scope.timeoutMs} ms timeout`;
    $("#scopeAccounts").textContent = data.scope.testAccounts.map((account) => `${account.name} (${account.role})`).join(", ") || "None configured";
    $("#scopeServices").textContent = data.scope.services.join(", ");
    $("#scopeReset").textContent = data.scope.resetProcedure;
    state.webScanEnabled = data.scope.webScanAvailable === true && data.scope.services.includes("web-scan");
    state.webScanBudgets = data.scope.webScanBudgets || state.webScanBudgets;
    $("#webScanBudgetSummary").textContent = state.webScanEnabled
      ? `${state.webScanBudgets.maxPages} pages · ${state.webScanBudgets.maxDepth} depth · ${state.webScanBudgets.maxRequests} requests`
      : "Disabled in local scope";
    $("#webScanBudgetDetails").textContent = state.webScanEnabled
      ? `${Math.round(state.webScanBudgets.maxDurationMs / 1000)} sec total · ${Math.round((data.scope.webScanResponseBytes || 0) / 1_000_000)} MB/page processed in memory · ${Math.round(state.webScanBudgets.maxBytes / 1_000_000)} MB total processed in memory · ${data.scope.webScanTimeoutMs / 1000} sec/request timeout · ${data.scope.webScanDelayMs} ms between pages.`
      : "Enable web-scan in the local scope file and restart the app.";
    $("#profileSelect").value = data.profile;
    $("#appVersion").textContent = `v${data.version}`;
    renderFindings(data.findings, data.summary.totalFindings);
    renderJobs(data.jobs);
    const active = data.jobs.some((job) => ["queued", "running", "cancelling"].includes(job.status));
    const activeJob = data.jobs.find((job) => ["queued", "running", "cancelling"].includes(job.status));
    state.active = active;
    state.activeWebScanId = activeJob?.action === "web-scan" ? activeJob.id : null;
    state.cancelling = activeJob?.status === "cancelling";
    renderPosturePages(state.publicPages);
    $("#runAuditButton").disabled = active;
    $("#retestButton").disabled = active || data.profile !== "secure" || data.summary.jobs === 0;
    const sourceReviewEnabled = data.scope.services.includes("source-review");
    const publicReviewEnabled = data.scope.services.includes("passive-public-review");
    $("#sourceReviewButton").disabled = active || !sourceReviewEnabled;
    $("#publicReviewButton").disabled = active || !publicReviewEnabled || data.scope.publicPages.length === 0;
    $("#profileSelect").disabled = active;
    const activeLabel = activeJob?.action === "web-scan" ? "Web scan in progress"
      : activeJob?.action === "source-review" ? "Source review in progress"
      : activeJob?.action === "public-review" ? "Public review in progress"
      : activeJob?.action === "posture-review" ? "HTTPS posture observations in progress"
      : activeJob?.action === "retest" ? "Retest in progress"
      : "Audit in progress";
    $("#runAuditButton").innerHTML = active ? `<span>◌</span> ${activeLabel}` : "<span>＋</span> Run local fixture checks";
    $("#sourceReviewButton").textContent = active ? activeLabel : sourceReviewEnabled ? "Review approved source" : "Enable source review";
    $("#publicReviewButton").textContent = active ? activeLabel : !publicReviewEnabled ? "Enable public review" : data.scope.publicPages.length ? "Review approved pages" : "Configure approved pages";
    $("#postureReviewButton").textContent = active ? activeLabel
      : !state.publicReviewEnabled ? "Enable posture review in scope.json"
      : state.posturePageCap === 0 ? "Zero request budget"
      : !data.scope.publicPages.length ? "Configure approved pages"
      : "Run HTTPS posture observations";
    $("#publicReviewDescription").textContent = data.scope.publicPages.length
      ? "Configured page(s): " + data.scope.publicPages.join(", ") + ". One unauthenticated GET per page; no redirects, cookies, assets, or page links are followed. GET can trigger actions on some sites, so each run asks you to confirm these pages are safe to request."
      : "No public pages are configured. Add exact HTTPS page URLs to publicReadOnlyPages in local scope.json and add passive-public-review to approvedServices, then restart the app.";
    updateWebScanControls();
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
    const postureBlocks = data.job.action === "posture-review" ? (() => {
      const targetPages = Array.isArray(data.job.targetPages)
        ? data.job.targetPages.filter((page) => typeof page === "string")
        : [];
      const attestation = data.job.authorizationAttestation && typeof data.job.authorizationAttestation === "object" && !Array.isArray(data.job.authorizationAttestation)
        ? data.job.authorizationAttestation
        : {};
      const attestationDetails = [
        `Recorded at: ${attestation.attestedAt || "Not recorded"}`,
        `Authorization attested: ${attestation.authorized === true ? "Yes" : "No"}`,
        `Safe GET attested: ${attestation.safeGet === true ? "Yes" : "No"}`,
        attestation.statement || "No attestation statement was saved.",
      ].join("\n");
      return [
        ["Saved exact target URLs", targetPages.length ? targetPages.join("\n") : "No exact target URLs were saved."],
        ["Recorded operator attestation", attestationDetails],
      ];
    })() : [];
    const webScanBlocks = data.job.action === "web-scan" ? (() => {
      const attestation = data.job.authorizationAttestation && typeof data.job.authorizationAttestation === "object" && !Array.isArray(data.job.authorizationAttestation)
        ? data.job.authorizationAttestation
        : {};
      return [
        ["Target origin", data.job.targetOrigin || "Unavailable"],
        ["Scan budget", `${attestation.maxPages || "?"} pages · depth ${attestation.maxDepth ?? "?"}`],
        ["Per-run authorization", `Recorded at: ${attestation.attestedAt || "Not recorded"}\nAuthorized: ${attestation.authorized === true ? "Yes" : "No"}\nUnauthenticated GETs attested: ${attestation.safeGet === true ? "Yes" : "No"}\n${attestation.statement || "No attestation statement was saved."}`],
      ];
    })() : [];
    const blocks = [
      ["Run", `${data.job.id} · ${data.job.status} · ${data.job.profile} profile`],
      ...postureBlocks,
      ...webScanBlocks,
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
    let requestBody = { action, confirmPublicGet };
    if (action === "web-scan") {
      const target = $("#webScanTarget").value;
      const maxPages = Number($("#webScanMaxPages").value);
      const maxDepth = Number($("#webScanMaxDepth").value);
      const authorized = $("#webScanAuthorized").checked;
      const safeGet = $("#webScanSafeGet").checked;
      const origin = webScanTargetOrigin(target);
      if (!origin) throw new Error("Enter one public HTTPS URL without credentials, a query string, or a fragment.");
      if (!authorized || !safeGet) throw new Error("Confirm both authorization and safe GET statements before starting.");
      if (!Number.isInteger(maxPages) || maxPages < 1 || maxPages > state.webScanBudgets.maxPages ||
          !Number.isInteger(maxDepth) || maxDepth < 0 || maxDepth > state.webScanBudgets.maxDepth) {
        throw new Error("Choose page and depth values within the displayed scanner budget.");
      }
      requestBody = {
        action: "web-scan",
        target,
        maxPages,
        maxDepth,
        authorizationAttestation: {
          authorized: true, safeGet: true, version: 2,
          target: new URL(target).href, origin, maxPages, maxDepth,
        },
      };
    }
    if (action === "posture-review") {
      const pages = [...state.postureSelectedPages];
      const authorized = $("#postureAuthorizationAttestation").checked;
      const safeGet = $("#postureSafeGetAttestation").checked;
      if (!pages.length) throw new Error("Select at least one exact configured URL.");
      if (!authorized || !safeGet) throw new Error("Confirm both required statements before queuing this run.");
      requestBody = {
        action: "posture-review",
        pages,
        authorizationAttestation: { authorized: true, safeGet: true, version: 1 },
      };
    }
    await api("/api/jobs", { method: "POST", body: JSON.stringify(requestBody) });
    if (action === "posture-review") {
      $("#postureAuthorizationAttestation").checked = false;
      $("#postureSafeGetAttestation").checked = false;
      updatePostureControls();
    }
    if (action === "web-scan") {
      $("#webScanAuthorized").checked = false;
      $("#webScanSafeGet").checked = false;
      updateWebScanControls();
    }
    showToast(action === "web-scan" ? "Web security scan queued"
      : action === "retest" ? "Retest queued against the selected secure profile"
      : action === "source-review" ? "Source review queued"
      : action === "public-review" ? "Public page review queued"
      : action === "posture-review" ? "HTTPS posture observations queued"
      : "Local audit queued");
    await refresh();
  } catch (error) {
    showToast(error.message);
  }
}

async function cancelWebScan(jobId = state.activeWebScanId) {
  if (!jobId) return;
  try {
    await api(`/api/jobs/${encodeURIComponent(jobId)}/cancel`, { method: "POST", body: "{}" });
    state.cancelling = true;
    updateWebScanControls();
    showToast("Cancellation requested; the active request is being stopped.");
    await refresh();
  } catch (error) { showToast(error.message || "Could not stop this scan"); }
}

$("#runAuditButton").addEventListener("click", () => createJob("audit"));
$("#retestButton").addEventListener("click", () => createJob("retest"));
$("#sourceReviewButton").addEventListener("click", () => createJob("source-review"));
$("#publicReviewButton").addEventListener("click", () => createJob("public-review"));
$("#postureReviewButton").addEventListener("click", () => createJob("posture-review"));
$("#postureAuthorizationAttestation").addEventListener("change", updatePostureControls);
$("#postureSafeGetAttestation").addEventListener("change", updatePostureControls);
$("#webScanButton").addEventListener("click", () => createJob("web-scan"));
$("#cancelScanButton").addEventListener("click", () => cancelWebScan());
for (const selector of ["#webScanTarget", "#webScanMaxPages", "#webScanMaxDepth"]) {
  $(selector).addEventListener("input", () => {
    $("#webScanAuthorized").checked = false;
    $("#webScanSafeGet").checked = false;
    updateWebScanControls();
  });
  $(selector).addEventListener("change", () => {
    $("#webScanAuthorized").checked = false;
    $("#webScanSafeGet").checked = false;
    updateWebScanControls();
  });
}
for (const selector of ["#webScanAuthorized", "#webScanSafeGet"]) {
  $(selector).addEventListener("input", updateWebScanControls);
  $(selector).addEventListener("change", updateWebScanControls);
}
$("#refreshButton").addEventListener("click", refresh);
$("#closeDialog").addEventListener("click", () => $("#detailDialog").close());
$("#detailDialog").addEventListener("click", (event) => { if (event.target === $("#detailDialog")) $("#detailDialog").close(); });
$("#profileSelect").addEventListener("change", async (event) => {
  try {
    await api("/api/lab/profile", { method: "POST", body: JSON.stringify({ profile: event.target.value }) });
    showToast(`Training fixture switched to the ${event.target.value} profile. Synthetic state was reset.`);
    await refresh();
  } catch (error) { showToast(error.message); }
});

async function start() {
  try {
    const session = await api("/api/session");
    state.csrf = session.csrfToken;
    await refresh();
  } catch (error) { showToast(error.message || "RevenueGuard is unavailable"); }
}
start();
