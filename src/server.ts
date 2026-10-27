import { randomBytes, randomUUID } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { basename, dirname, extname, isAbsolute, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";

import { executeAudit, isCompleteRetest } from "./audit.ts";
import type { AuditFinding, AuditResult, CoverageItem } from "./audit.ts";
import { createLabState, handleLabRequest, resetLabState } from "./lab-target.ts";
import type { LabProfile } from "./lab-target.ts";
import { assertPublicPageInScope, loadScopeConfig } from "./scope.ts";
import type { ScopeConfig } from "./scope.ts";
import { executeSourceReview } from "./source-review.ts";
import { executePublicReview } from "./public-review.ts";
import { executePostureReview, POSTURE_REVIEW_MAX_PAGES } from "./posture-review.ts";

const HOST = "127.0.0.1";
const PORT = 8765;
const ORIGIN = `http://${HOST}:${PORT}`;
const ROOT = process.cwd();
const DATA_DIR = resolve(ROOT, "data");
const SCOPE_PATH = resolve(ROOT, "scope.json");
const SCOPE_EXAMPLE_PATH = resolve(ROOT, "scope.example.json");
const PUBLIC_DIR = resolve(ROOT, "public");
const DB_PATH = resolve(DATA_DIR, "revenueguard.sqlite");
const MAX_BODY_BYTES = 16 * 1024;
const MAX_QUEUED_JOBS = 6;
const CHECK_COUNT = 7;
const POSTURE_ATTESTATION_VERSION = 1;
type ReportRequestStatus = "not-sent" | "unknown" | "response-received";
type ReportCoverageItem = CoverageItem & { requestStatus?: ReportRequestStatus };

mkdirSync(DATA_DIR, { recursive: true });
if (!existsSync(SCOPE_PATH)) copyFileSync(SCOPE_EXAMPLE_PATH, SCOPE_PATH);
const scope: ScopeConfig = loadScopeConfig(SCOPE_PATH);
if (!scope.approvedOrigins.includes(ORIGIN)) {
  throw new Error(`scope.json must include the local app origin ${ORIGIN}`);
}

const db = new DatabaseSync(DB_PATH);
db.exec("PRAGMA foreign_keys = ON;");
db.exec(`
  CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    profile TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    coverage_json TEXT NOT NULL DEFAULT '[]',
    scope_json TEXT NOT NULL DEFAULT '{}',
    target_pages_json TEXT NOT NULL DEFAULT '[]',
    attestation_json TEXT NOT NULL DEFAULT '{}'
  );
  CREATE INDEX IF NOT EXISTS jobs_created_at_idx ON jobs(created_at DESC);
  CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    finding_key TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    confidence TEXT NOT NULL,
    target TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    component TEXT NOT NULL,
    preconditions TEXT NOT NULL,
    expected TEXT NOT NULL,
    actual TEXT NOT NULL,
    reproduction_json TEXT NOT NULL,
    impact TEXT NOT NULL,
    severity_rationale TEXT NOT NULL,
    remediation TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    retest_status TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
  CREATE INDEX IF NOT EXISTS findings_status_idx ON findings(status, created_at DESC);
  CREATE INDEX IF NOT EXISTS findings_job_idx ON findings(job_id);
  CREATE TABLE IF NOT EXISTS execution_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    level TEXT NOT NULL,
    message TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`);
const jobColumns = db.prepare("PRAGMA table_info(jobs)").all() as Array<{ name?: string }>;
if (!jobColumns.some((column) => column.name === "scope_json")) {
  db.exec("ALTER TABLE jobs ADD COLUMN scope_json TEXT NOT NULL DEFAULT '{}'");
}
if (!jobColumns.some((column) => column.name === "target_pages_json")) {
  db.exec("ALTER TABLE jobs ADD COLUMN target_pages_json TEXT NOT NULL DEFAULT '[]'");
}
if (!jobColumns.some((column) => column.name === "attestation_json")) {
  db.exec("ALTER TABLE jobs ADD COLUMN attestation_json TEXT NOT NULL DEFAULT '{}'");
}

const savedProfile = db.prepare("SELECT value FROM settings WHERE key = 'lab_profile'").get() as { value?: string } | undefined;
let currentProfile: LabProfile = savedProfile?.value === "secure" ? "secure" : "vulnerable";
let labState = createLabState();
let csrfToken = randomBytes(24).toString("hex");
let workerRunning = false;

function now(): string {
  return new Date().toISOString();
}

function setSetting(key: string, value: string): void {
  db.prepare("INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value")
    .run(key, value);
}

function addLog(jobId: string, level: string, message: string): void {
  db.prepare("INSERT INTO execution_logs(job_id, created_at, level, message) VALUES(?, ?, ?, ?)")
    .run(jobId, now(), level, message.slice(0, 500));
}

const interruptedJobs = db.prepare("SELECT id FROM jobs WHERE status IN ('queued', 'running')").all() as Array<{ id?: string }>;
if (interruptedJobs.length) {
  const finishedAt = now();
  db.prepare("UPDATE jobs SET status = 'failed', finished_at = ?, error = ? WHERE status IN ('queued', 'running')")
    .run(finishedAt, "Stopped on app restart; start a new run to confirm the current scope.");
  for (const job of interruptedJobs) {
    if (job.id) addLog(job.id, "warning", "This queued or interrupted run was not replayed after restart. Start a new run explicitly.");
  }
}

function json(res: ServerResponse, status: number, value: unknown): void {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(value));
}

function text(res: ServerResponse, status: number, value: string, contentType = "text/plain; charset=utf-8"): void {
  res.statusCode = status;
  res.setHeader("Content-Type", contentType);
  res.end(value);
}

function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function safeJson(value: string, fallback: unknown): unknown {
  try { return JSON.parse(value); } catch { return fallback; }
}

function sourceDirectoryLabel(value: string): string {
  return isAbsolute(value) ? `${basename(dirname(value))}/${basename(value)}` : value;
}

function localSocket(req: IncomingMessage): boolean {
  const address = req.socket.remoteAddress || "";
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
}

function setSecurityHeaders(res: ServerResponse, path: string): void {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Frame-Options", "DENY");
  if (!path.startsWith("/lab/")) {
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'");
  }
}

async function readBody(req: IncomingMessage): Promise<string> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += value.byteLength;
    if (size > MAX_BODY_BYTES) throw new Error("Request body too large");
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const body = await readBody(req);
  if (!body) return {};
  const parsed: unknown = JSON.parse(body);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("JSON body must be an object");
  return parsed as Record<string, unknown>;
}

function validMutation(req: IncomingMessage): boolean {
  const origin = req.headers.origin;
  if (origin && origin !== ORIGIN) return false;
  return req.headers["x-csrf-token"] === csrfToken;
}

function rowToFinding(row: Record<string, unknown>): Record<string, unknown> {
  return {
    id: row.id,
    jobId: row.job_id,
    findingKey: row.finding_key,
    title: row.title,
    category: row.category,
    severity: row.severity,
    status: row.status,
    confidence: row.confidence,
    target: row.target,
    endpoint: row.endpoint,
    component: row.component,
    preconditions: row.preconditions,
    expected: row.expected,
    actual: row.actual,
    reproduction: safeJson(String(row.reproduction_json), []),
    impact: row.impact,
    severityRationale: row.severity_rationale,
    remediation: row.remediation,
    evidence: safeJson(String(row.evidence_json), {}),
    retestStatus: row.retest_status,
    createdAt: row.created_at,
  };
}

function rowToJob(row: Record<string, unknown>): Record<string, unknown> {
  const action = String(row.action);
  return {
    id: row.id,
    action,
    label: action === "retest" ? "Secure-profile retest"
      : action === "source-review" ? "Approved source review"
      : action === "public-review" ? "Passive public page review"
      : action === "posture-review" ? "HTTPS posture observations"
      : "Local security audit",
    profile: row.profile,
    status: row.status,
    createdAt: row.created_at,
    startedAt: row.started_at,
    finishedAt: row.finished_at,
    error: row.error,
    coverage: safeJson(String(row.coverage_json), []),
    targetPages: safeJson(String(row.target_pages_json ?? "[]"), []),
    authorizationAttestation: safeJson(String(row.attestation_json ?? "{}"), {}),
  };
}

function postureTargetsForJob(row: Record<string, unknown>): string[] {
  const rawPages = safeJson(String(row.target_pages_json ?? "[]"), []);
  const rawAttestation = safeJson(String(row.attestation_json ?? "{}"), {});
  const maxPages = Math.min(POSTURE_REVIEW_MAX_PAGES, scope.budgets.maxPublicPages, scope.budgets.maxRequestsPerAudit);
  if (!Array.isArray(rawPages) || maxPages < 1 || rawPages.length === 0 || rawPages.length > maxPages) {
    throw new Error("The saved posture target list is missing or outside the run limit.");
  }
  if (!rawAttestation || typeof rawAttestation !== "object" || Array.isArray(rawAttestation)) {
    throw new Error("The saved authorization attestation is invalid.");
  }
  const attestation = rawAttestation as Record<string, unknown>;
  const pages = rawPages.map((page) => {
    if (typeof page !== "string") throw new Error("The saved posture target list is invalid.");
    return assertPublicPageInScope(page, scope).href;
  });
  if (
    new Set(pages).size !== pages.length ||
    attestation.version !== POSTURE_ATTESTATION_VERSION ||
    attestation.authorized !== true ||
    attestation.safeGet !== true ||
    typeof attestation.attestedAt !== "string" ||
    JSON.stringify(attestation.pages) !== JSON.stringify(pages)
  ) {
    throw new Error("The saved authorization attestation does not match the exact target list.");
  }
  return pages;
}

function storeFinding(jobId: string, finding: AuditFinding): void {
  db.prepare(`INSERT INTO findings(
    id, job_id, finding_key, title, category, severity, status, confidence, target,
    endpoint, component, preconditions, expected, actual, reproduction_json, impact,
    severity_rationale, remediation, evidence_json, retest_status, created_at
  ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(randomUUID(), jobId, finding.key, finding.title, finding.category, finding.severity,
      finding.status, finding.confidence, finding.target, finding.endpoint, finding.component,
      finding.preconditions, finding.expected, finding.actual, JSON.stringify(finding.reproduction),
      finding.impact, finding.severityRationale, finding.remediation,
      JSON.stringify(finding.evidence), finding.retestStatus, now());
}

function storeResult(jobId: string, action: string, profile: LabProfile, result: AuditResult): void {
  const resultKeys = new Set(result.findings.map((finding) => finding.key));
  const verifiedStatuses = new Map<string, "CONFIRMED" | "SUSPECTED">(result.coverage
    .filter((item) => item.controlVerified && (item.status === "CONFIRMED" || item.status === "SUSPECTED"))
    .map((item) => [item.key, item.status] as const));
  const retestFindings = result.findings.map((finding) => {
    if (action !== "retest" || profile !== "secure" || verifiedStatuses.get(finding.key) !== finding.status) return finding;
    const state = finding.status === "CONFIRMED" ? "Still reproduces" : "Still present as suspected";
    return { ...finding, retestStatus: `${state} against secure demo profile in run ${jobId}` };
  });
  db.exec("BEGIN IMMEDIATE;");
  try {
    for (const finding of retestFindings) storeFinding(jobId, finding);

    if (action === "retest" && profile === "secure" && verifiedStatuses.size > 0) {
      for (const [key, status] of verifiedStatuses) {
        const matchingFinding = result.findings.find((finding) => finding.key === key && finding.status === status);
        if (matchingFinding) {
          const state = status === "CONFIRMED" ? "Still reproduces" : "Still present as suspected";
          db.prepare("UPDATE findings SET retest_status = ? WHERE status = ? AND finding_key = ? AND job_id <> ?")
            .run(`${state} against secure demo profile in run ${jobId}`, status, key, jobId);
        }
      }
    }

    if (action === "retest" && profile === "secure" && isCompleteRetest(result)) {
      const previous = db.prepare("SELECT id, finding_key FROM findings WHERE status = 'CONFIRMED'").all() as Array<Record<string, unknown>>;
      for (const row of previous) {
        if (!resultKeys.has(String(row.finding_key))) {
          db.prepare("UPDATE findings SET status = 'FIXED AND RETESTED', retest_status = ? WHERE id = ?")
            .run(`Not reproduced against secure demo profile in run ${jobId}`, row.id);
        }
      }
    }

    db.prepare("UPDATE jobs SET status = 'complete', finished_at = ?, coverage_json = ? WHERE id = ?")
      .run(now(), JSON.stringify(result.coverage), jobId);
    db.exec("COMMIT;");
  } catch (error) {
    db.exec("ROLLBACK;");
    throw error;
  }
}

async function runJob(jobId: string): Promise<void> {
  const row = db.prepare("SELECT * FROM jobs WHERE id = ?").get(jobId) as Record<string, unknown> | undefined;
  if (!row) return;
  const action = String(row.action);
  const profile = row.profile === "secure" ? "secure" : "vulnerable";
  let posturePages: string[] = [];
  if (action === "posture-review") {
    try {
      posturePages = postureTargetsForJob(row);
    } catch (error) {
      db.prepare("UPDATE jobs SET status = 'failed', finished_at = ?, error = ? WHERE id = ?")
        .run(now(), "Saved posture authorization or target scope is invalid; no request was sent.", jobId);
      addLog(jobId, "warning", error instanceof Error ? error.message : "Saved posture target scope is invalid.");
      return;
    }
  }
  const jobScopeSnapshot = action === "posture-review"
    ? { ...scope, publicReadOnlyPages: posturePages }
    : scope;
  if (typeof row.scope_json !== "string" || row.scope_json !== JSON.stringify(jobScopeSnapshot)) {
    db.prepare("UPDATE jobs SET status = 'failed', finished_at = ?, error = ? WHERE id = ?")
      .run(now(), "Approved scope changed; start a new run against the current scope.", jobId);
    addLog(jobId, "warning", "Run stopped because its saved scope does not match the active approved scope.");
    return;
  }
  db.prepare("UPDATE jobs SET status = 'running', started_at = ? WHERE id = ?").run(now(), jobId);
  addLog(jobId, "info", action === "source-review"
    ? `Started a read-only static review of approved source directories: ${scope.sourceDirectories.map(sourceDirectoryLabel).join(", ")}.`
    : action === "public-review"
      ? `Started a passive review of ${scope.publicReadOnlyPages.length} exact HTTPS page(s); one GET per page, no redirects or page assets.`
      : action === "posture-review"
        ? `Started bounded HTTPS posture observations for the exact page snapshot; one unauthenticated GET per page, no redirects or crawling.`
      : `Started ${action} against the local synthetic demo (${profile} profile).`);
  try {
    const jobScope = scope;
    const result = action === "source-review"
      ? await executeSourceReview({ scope: jobScope, projectRoot: ROOT })
      : action === "public-review"
        ? await executePublicReview({ scope: jobScope })
        : action === "posture-review"
          ? await executePostureReview({ scope: jobScope, pages: posturePages })
        : await executeAudit({ scope: jobScope, targetLabel: "RevenueGuard local demo" });
    storeResult(jobId, action, profile, result);
    const confirmed = result.findings.filter((finding) => finding.status === "CONFIRMED").length;
    const suspected = result.findings.filter((finding) => finding.status === "SUSPECTED").length;
    const observed = result.findings.filter((finding) => finding.status === "OBSERVED").length;
    const attempted = result.coverage.filter((item) => item.attempted).length;
    addLog(jobId, "info", `Recorded ${attempted}/${result.coverage.length} attempted checks: ${confirmed} confirmed, ${suspected} suspected, ${observed} informational observation(s). Coverage is not a site-wide security verdict.`);
  } catch (error) {
    db.prepare("UPDATE jobs SET status = 'failed', finished_at = ?, error = ? WHERE id = ?")
      .run(now(), "Audit failed. Review the local execution log.", jobId);
    addLog(jobId, "error", error instanceof Error ? error.message : "Audit failed");
  }
}

async function drainQueue(): Promise<void> {
  if (workerRunning) return;
  workerRunning = true;
  try {
    while (true) {
      const row = db.prepare("SELECT id FROM jobs WHERE status = 'queued' ORDER BY created_at ASC LIMIT 1").get() as { id?: string } | undefined;
      if (!row?.id) break;
      await runJob(row.id);
    }
  } finally {
    workerRunning = false;
  }
}

function enqueueJob(
  action: "audit" | "retest" | "source-review" | "public-review" | "posture-review",
  confirmPublicGet = false,
  postureRequest?: { pages?: unknown; authorizationAttestation?: unknown },
): Record<string, unknown> {
  const active = db.prepare("SELECT COUNT(*) AS count FROM jobs WHERE status IN ('queued', 'running')").get() as { count?: number };
  if (Number(active.count || 0) >= MAX_QUEUED_JOBS) throw new Error("The local queue is full. Wait for a run to finish.");
  if (action === "retest" && currentProfile !== "secure") throw new Error("Switch the demo profile to Secure controls before retesting.");
  if ((action === "audit" || action === "retest") && !scope.approvedServices.includes("revenueguard-demo")) throw new Error("Enable revenueguard-demo in approvedServices before starting a local audit.");
  if (action === "source-review" && !scope.approvedServices.includes("source-review")) throw new Error("Enable source-review in approvedServices before reviewing local source.");
  if (action === "public-review" && !scope.approvedServices.includes("passive-public-review")) throw new Error("Enable passive-public-review in approvedServices before reviewing public pages.");
  if (action === "public-review" && scope.publicReadOnlyPages.length === 0) throw new Error("Add exact HTTPS pages to publicReadOnlyPages in scope.json before starting a public page review.");
  if (action === "public-review" && !confirmPublicGet) throw new Error("Confirm that each listed page is authorized and safe to request with one unauthenticated GET.");
  let targetPages: string[] = [];
  let attestationSnapshot: Record<string, unknown> = {};
  if (action === "posture-review") {
    if (!scope.approvedServices.includes("passive-public-review")) throw new Error("Enable passive-public-review in approvedServices before reviewing public pages.");
    if (!scope.publicReadOnlyPages.length) throw new Error("Add exact HTTPS pages to publicReadOnlyPages in scope.json before starting posture observations.");
    const maxPages = Math.min(POSTURE_REVIEW_MAX_PAGES, scope.budgets.maxPublicPages, scope.budgets.maxRequestsPerAudit);
    if (!Array.isArray(postureRequest?.pages) || maxPages < 1 || postureRequest.pages.length === 0 || postureRequest.pages.length > maxPages) {
      throw new Error(maxPages < 1
        ? "The configured request budget does not allow posture observations."
        : `Choose between 1 and ${maxPages} configured HTTPS page(s).`);
    }
    targetPages = postureRequest.pages.map((page) => {
      if (typeof page !== "string") throw new Error("Each posture target must be an exact HTTPS URL.");
      return assertPublicPageInScope(page, scope).href;
    });
    if (new Set(targetPages).size !== targetPages.length) throw new Error("Posture targets must not contain duplicates.");
    const rawAttestation = postureRequest.authorizationAttestation;
    if (!rawAttestation || typeof rawAttestation !== "object" || Array.isArray(rawAttestation)) {
      throw new Error("Complete both authorization and safe-GET attestations before starting.");
    }
    const attestation = rawAttestation as Record<string, unknown>;
    if (
      attestation.authorized !== true ||
      attestation.safeGet !== true ||
      attestation.version !== POSTURE_ATTESTATION_VERSION
    ) {
      throw new Error("Complete both authorization and safe-GET attestations before starting.");
    }
  }
  const id = randomUUID();
  const createdAt = now();
  if (action === "public-review") {
    attestationSnapshot = {
      version: 1,
      kind: "public-review-confirmation",
      attestedAt: createdAt,
      authorized: true,
      safeGet: true,
      pages: [...scope.publicReadOnlyPages],
      statement: "I confirm that I own or have permission to review these exact pages and that each page is safe to request with one unauthenticated GET.",
    };
  } else if (action === "posture-review") {
    attestationSnapshot = {
      version: POSTURE_ATTESTATION_VERSION,
      attestedAt: createdAt,
      authorized: true,
      safeGet: true,
      pages: [...targetPages],
      statement: "I attest that I am authorized to request these exact URLs for this run. I attest that one unauthenticated GET to each selected route is safe, and understand GET requests may still trigger site actions.",
    };
  }
  const profile = action === "source-review" ? "approved-source"
    : action === "public-review" ? "approved-public"
    : action === "posture-review" ? "approved-posture"
    : currentProfile;
  const scopeSnapshot = action === "posture-review"
    ? { ...scope, publicReadOnlyPages: [...targetPages] }
    : scope;
  db.prepare("INSERT INTO jobs(id, action, profile, status, created_at, coverage_json, scope_json, target_pages_json, attestation_json) VALUES(?, ?, ?, 'queued', ?, '[]', ?, ?, ?)")
    .run(id, action, profile, createdAt, JSON.stringify(scopeSnapshot), JSON.stringify(targetPages), JSON.stringify(attestationSnapshot));
  addLog(id, "info", action === "source-review" ? "Queued static review of approved local source files."
    : action === "public-review" ? `Queued passive GET review of ${scope.publicReadOnlyPages.length} exact HTTPS page(s).`
    : action === "posture-review" ? `Queued posture observations for ${targetPages.length} exact HTTPS page(s) after recording the per-run operator attestation.`
    : `Queued ${action} in ${profile} profile.`);
  setImmediate(() => { void drainQueue(); });
  return { id, action, profile, status: "queued", createdAt };
}

function dashboardData(): Record<string, unknown> {
  const jobs = db.prepare("SELECT * FROM jobs ORDER BY created_at DESC LIMIT 8").all() as Array<Record<string, unknown>>;
  const latest = db.prepare("SELECT id, coverage_json FROM jobs WHERE status = 'complete' ORDER BY created_at DESC LIMIT 1").get() as Record<string, unknown> | undefined;
  const findings = latest
    ? db.prepare("SELECT * FROM findings WHERE job_id = ? ORDER BY created_at DESC LIMIT 24").all(latest.id) as Array<Record<string, unknown>>
    : [];
  const counts = latest
    ? db.prepare(`SELECT
        SUM(CASE WHEN status = 'CONFIRMED' THEN 1 ELSE 0 END) AS confirmed,
        SUM(CASE WHEN status = 'SUSPECTED' THEN 1 ELSE 0 END) AS suspected,
        SUM(CASE WHEN status = 'OBSERVED' THEN 1 ELSE 0 END) AS observed,
        COUNT(*) AS total
        FROM findings WHERE job_id = ?`).get(latest.id) as Record<string, unknown>
    : { confirmed: 0, suspected: 0, observed: 0, total: 0 };
  const jobCount = db.prepare("SELECT COUNT(*) AS count FROM jobs").get() as { count?: number };
  const coverage = latest ? safeJson(String(latest.coverage_json), []) as CoverageItem[] : [];
  const version = JSON.parse(readFileSync(resolve(ROOT, "package.json"), "utf8")).version as string;
  return {
    version,
    profile: currentProfile,
    summary: {
      confirmed: Number(counts.confirmed || 0),
      suspected: Number(counts.suspected || 0),
      observed: Number(counts.observed || 0),
      totalFindings: Number(counts.total || 0),
      jobs: Number(jobCount.count || 0),
      checksAttempted: coverage.filter((item) => item.attempted).length,
      checksAvailable: coverage.length || CHECK_COUNT,
    },
    scope: {
      origins: scope.approvedOrigins,
      paths: scope.approvedPathPrefixes,
      services: scope.approvedServices,
      sourceDirectories: scope.sourceDirectories.map(sourceDirectoryLabel),
      testAccounts: scope.testAccounts,
      callbacks: scope.approvedCallbacks,
      publicPages: scope.publicReadOnlyPages,
      resetProcedure: scope.resetProcedure,
      maxRequests: scope.budgets.maxRequestsPerAudit,
      timeoutMs: scope.budgets.timeoutMs,
      maxSourceFiles: scope.budgets.maxSourceFiles,
      maxSourceBytes: scope.budgets.maxSourceBytes,
      maxPublicPages: scope.budgets.maxPublicPages,
      maxPublicBytesPerPage: scope.budgets.maxPublicBytesPerPage,
    },
    jobs: jobs.map(rowToJob),
    findings: findings.map(rowToFinding),
  };
}

function logsFor(jobId: string): Array<Record<string, unknown>> {
  return db.prepare("SELECT created_at, level, message FROM execution_logs WHERE job_id = ? ORDER BY id ASC")
    .all(jobId) as Array<Record<string, unknown>>;
}

function reportsFor(jobId: string): { job: Record<string, unknown>; findings: Array<Record<string, unknown>>; logs: Array<Record<string, unknown>>; scopeSnapshot: Record<string, unknown> } | undefined {
  const job = db.prepare("SELECT * FROM jobs WHERE id = ?").get(jobId) as Record<string, unknown> | undefined;
  if (!job) return undefined;
  const findings = db.prepare("SELECT * FROM findings WHERE job_id = ? ORDER BY severity, finding_key")
    .all(jobId) as Array<Record<string, unknown>>;
  const savedScope = safeJson(String(job.scope_json || "{}"), {});
  const scopeSnapshot = savedScope !== null && typeof savedScope === "object" && !Array.isArray(savedScope)
    ? savedScope as Record<string, unknown>
    : {};
  if (job.action === "posture-review") {
    const targetPages = safeJson(String(job.target_pages_json ?? "[]"), []);
    if (Array.isArray(targetPages) && targetPages.every((page) => typeof page === "string")) {
      scopeSnapshot.publicReadOnlyPages = targetPages;
    }
  }
  return {
    job: rowToJob(job),
    findings: findings.map(rowToFinding),
    logs: logsFor(jobId),
    scopeSnapshot,
  };
}

function reportHtml(kind: string, data: NonNullable<ReturnType<typeof reportsFor>>): string {
  const { job, findings, logs, scopeSnapshot } = data;
  const sourceReview = job.action === "source-review";
  const publicReview = job.action === "public-review";
  const postureReview = job.action === "posture-review";
  const coverage = Array.isArray(job.coverage) ? job.coverage as ReportCoverageItem[] : [];
  const publicPages = Array.isArray(scopeSnapshot.publicReadOnlyPages)
    ? scopeSnapshot.publicReadOnlyPages.filter((page): page is string => typeof page === "string")
    : [];
  const jobStatus = String(job.status || "unknown").toLowerCase();
  const fetchKeyPrefix = publicReview ? "public.fetch.page-" : postureReview ? "posture.fetch.page-" : undefined;
  const requestStatusForPage = (index: number): ReportRequestStatus => {
    const fetchCoverage = fetchKeyPrefix
      ? coverage.find((item) => item.key === `${fetchKeyPrefix}${index + 1}`)
      : undefined;
    const recordedStatus = fetchCoverage?.requestStatus;
    if (recordedStatus === "not-sent" || recordedStatus === "unknown" || recordedStatus === "response-received") {
      return recordedStatus;
    }
    if (fetchCoverage && /\bHTTP\s+\d{3}\b/i.test(String(fetchCoverage.details || ""))) {
      return "response-received";
    }
    if (fetchCoverage && /\bno request was sent\b/i.test(String(fetchCoverage.error || ""))) {
      return "not-sent";
    }
    if (jobStatus === "queued" || (jobStatus === "failed" && !job.startedAt)) return "not-sent";
    return "unknown";
  };
  const pageRequestStatuses = (publicReview || postureReview)
    ? publicPages.map((_, index) => requestStatusForPage(index))
    : [];
  const requestStatusLabel = (status: ReportRequestStatus): string => status === "response-received"
    ? "HTTP response received"
    : status === "not-sent" ? "Not sent" : "Unknown whether sent";
  const responseReceivedCount = pageRequestStatuses.filter((status) => status === "response-received").length;
  const notSentCount = pageRequestStatuses.filter((status) => status === "not-sent").length;
  const unknownCount = pageRequestStatuses.filter((status) => status === "unknown").length;
  const runStatusNote = jobStatus === "queued"
    ? "This run is queued; no page requests have been sent yet."
    : jobStatus === "running"
      ? "This run is in progress; per-page request delivery is not final."
      : jobStatus === "failed"
        ? "This run failed; review the per-page request statuses and execution log."
        : jobStatus === "complete" ? "This run is complete." : "Run status is unavailable.";
  const requestDeliverySummary = publicPages.length
    ? `${responseReceivedCount} of ${publicPages.length} target page(s) returned an HTTP response; ${notSentCount} were not sent; ${unknownCount} request outcome(s) are unknown.`
    : "No exact HTTPS target pages were saved for this run.";
  const confirmed = findings.filter((finding) => finding.status === "CONFIRMED");
  const suspected = findings.filter((finding) => finding.status === "SUSPECTED");
  const observations = findings.filter((finding) => finding.status === "OBSERVED");
  const title = postureReview
    ? kind === "executive" ? "HTTPS posture observation summary" : kind === "remediation" ? "HTTPS posture review notes" : "HTTPS posture observation evidence"
    : publicReview
    ? kind === "executive" ? "Public page review summary" : kind === "remediation" ? "Page improvement notes" : "Public page review evidence"
    : sourceReview
      ? kind === "executive" ? "Source review summary" : kind === "remediation" ? "Source remediation notes" : "Source review evidence"
      : kind === "executive" ? "Executive summary" : kind === "remediation" ? "Remediation and retest" : "Technical evidence";
  const summary = kind === "executive"
    ? postureReview
      ? `<p>${escapeHtml(runStatusNote)} ${escapeHtml(requestDeliverySummary)} ${jobStatus === "complete" ? "This report records bounded HTTPS response observations for the exact pages in the saved target snapshot." : "Coverage and observations may be incomplete until the run completes."} No crawling, redirects, forms, authentication, or exploit payloads are used. This is not a vulnerability scan or an overall security verdict.</p><p><b>${observations.length}</b> informational observation(s), and <b>${coverage.filter((item) => item.attempted).length}</b> checks attempted.</p>`
      : publicReview
      ? `<p>${escapeHtml(runStatusNote)} ${escapeHtml(requestDeliverySummary)} ${jobStatus === "complete" ? "This report contains passive observations from the exact public HTTPS pages in this run's target snapshot." : "Coverage and observations may be incomplete until the run completes."} It does not contain vulnerability probes or prove a security issue.</p><p><b>${suspected.length}</b> suspected page-level observation(s), and <b>${coverage.filter((item) => item.attempted).length}</b> checks attempted.</p>`
      : sourceReview
      ? `<p>This report contains read-only static pattern matches from approved local source directories. It does not prove runtime reachability or exploitability.</p><p><b>${suspected.length}</b> suspected pattern(s), and <b>${coverage.filter((item) => item.attempted).length}</b> checks attempted.</p>`
      : `<p>This report describes a local synthetic demonstration. It does not establish customer impact or lost revenue in any real business.</p><p><b>${confirmed.length}</b> confirmed lab behavior(s), <b>${suspected.length}</b> suspected marker(s), and <b>${coverage.length}</b> checks attempted.</p>`
    : "";
  const details = findings.map((raw) => {
    const item = raw as Record<string, unknown>;
    const reproduction = Array.isArray(item.reproduction) ? item.reproduction.map((step) => `<li>${escapeHtml(step)}</li>`).join("") : "";
    const evidenceText = escapeHtml(JSON.stringify(item.evidence || {}, null, 2));
    const remediation = kind === "remediation" ? `<h4>Remediation</h4><p>${escapeHtml(item.remediation)}</p><h4>Retest</h4><p>${escapeHtml(item.retestStatus)}</p>` : "";
    return `<article class="finding"><div class="meta"><span>${escapeHtml(item.findingKey)}</span><span>${escapeHtml(item.severity)}</span><span>${escapeHtml(item.status)}</span><span>${escapeHtml(item.confidence)} confidence</span></div><h2>${escapeHtml(item.title)}</h2><p class="category">${escapeHtml(item.category)} · Target: ${escapeHtml(item.target)} · ${escapeHtml(item.endpoint)}</p><h4>Expected</h4><p>${escapeHtml(item.expected)}</p><h4>Observed</h4><p>${escapeHtml(item.actual)}</p><h4>Impact and limits</h4><p>${escapeHtml(item.impact)}</p><h4>Reproduction</h4><ol>${reproduction}</ol>${remediation}<details><summary>Evidence</summary><pre>${evidenceText}</pre></details></article>`;
  }).join("");
  const coverageItems = coverage.map((item) => {
    const pageMatch = /\.page-(\d+)$/.exec(item.key);
    const pageIndex = pageMatch ? Number(pageMatch[1]) - 1 : -1;
    const target = pageIndex >= 0 ? publicPages[pageIndex] : undefined;
    const requestStatus = pageIndex >= 0 ? pageRequestStatuses[pageIndex] : undefined;
    const isFetchCoverage = Boolean(fetchKeyPrefix && item.key === `${fetchKeyPrefix}${pageIndex + 1}`);
    return `<li><b>${escapeHtml(item.label)}</b>: ${escapeHtml(item.status)}${target ? ` · Target: ${escapeHtml(target)}` : ""}${isFetchCoverage && requestStatus ? ` · GET status: ${escapeHtml(requestStatusLabel(requestStatus))}` : ""}${item.details ? ` — ${escapeHtml(item.details)}` : ""}${item.error ? ` — ${escapeHtml(item.error)}` : ""}</li>`;
  }).join("");
  const publicScopeItems = (publicReview || postureReview) && publicPages.length
    ? `<section><h2>Exact pages in this run's target snapshot</h2><ul>${publicPages.map((page, index) => `<li><b>${escapeHtml(page)}</b> · GET status: ${escapeHtml(requestStatusLabel(pageRequestStatuses[index]))}</li>`).join("")}</ul></section>`
    : "";
  const attestation = job.authorizationAttestation && typeof job.authorizationAttestation === "object" && !Array.isArray(job.authorizationAttestation)
    ? job.authorizationAttestation as Record<string, unknown>
    : {};
  const attestationWasRecorded = typeof attestation.attestedAt === "string" && attestation.attestedAt.length > 0;
  const attestationSummary = postureReview || publicReview
    ? `<section><h2>${publicReview ? "Public review confirmation" : "Operator attestation"}</h2><p>Recorded at ${escapeHtml(attestation.attestedAt || "unknown time")}.</p><p>Authorization attested: ${attestation.authorized === true ? "Yes" : "No"}. Safe GET attested: ${attestation.safeGet === true ? "Yes" : "No"}.</p><blockquote>${escapeHtml(attestation.statement || "No confirmation statement was saved.")}</blockquote><p>${attestationWasRecorded ? "Identity, ownership, and permission were not independently verified." : "No per-run confirmation was retained for this run."}</p></section>`
    : "";
  const logItems = logs.map((item) => `<li><time>${escapeHtml(item.created_at)}</time> · ${escapeHtml(item.level)} · ${escapeHtml(item.message)}</li>`).join("");
  const empty = findings.length ? "" : postureReview
    ? "<p class=empty>No posture observations were recorded. Incomplete coverage or no observations does not establish that the site is secure.</p>"
    : publicReview
    ? "<p class=empty>No page-level observations matched the listed checks. This is not a vulnerability scan or an overall security guarantee.</p>"
    : sourceReview
    ? "<p class=empty>No static patterns matched. This heuristic review is limited to the listed checks and is not proof that the source is secure.</p>"
    : "<p class=empty>No findings were stored for this run. Consult coverage to distinguish clean controls from checks that were not reproduced.</p>";
  const scopeLabel = postureReview ? "HTTPS POSTURE OBSERVATIONS" : publicReview ? "PUBLIC PAGE REVIEW" : sourceReview ? "APPROVED LOCAL SOURCE" : "LOCAL SYNTHETIC TARGET";
  const scopeNote = postureReview
    ? `${runStatusNote} ${requestDeliverySummary} An HTTP response received by RevenueGuard confirms a response for that target; no response does not establish whether the GET was sent. GET can still cause side effects. No redirects, crawling, credentials, forms, payloads, or assets are used. The operator attestation is not independent proof of authorization. Results describe selected response facts at the time of this run, not site-wide security. Response bodies, cookie names, and cookie values are not retained.`
    : publicReview
    ? `${runStatusNote} ${requestDeliverySummary} An HTTP response received by RevenueGuard confirms a response for that target; no response does not establish whether the GET was sent. GET requests can still trigger side effects on some sites; only include pages known to be safe to request. No redirects, cookies, forms, assets, or page links are followed. The HTML body is parsed in memory and is not stored.`
    : sourceReview
    ? "This report contains read-only static pattern matches from the explicitly approved local source directories in scope.json. It does not execute source code or prove runtime exploitability."
    : "This report contains evidence from a local demo app with synthetic users, records, and files. It is not proof that another application is vulnerable or secure.";
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)} · RevenueGuard Lab</title><link rel="stylesheet" href="/report.css"><script src="/report.js" defer></script></head><body><main><header><div><p class="eyebrow">REVENUEGUARD LAB · ${scopeLabel}</p><h1>${escapeHtml(title)}</h1><p class="sub">Run ${escapeHtml(job.id)} · ${escapeHtml(job.profile)} · ${escapeHtml(job.status)}</p></div><button id="print">Print / Save as PDF</button></header><section class="notice"><b>Scope note:</b> ${escapeHtml(scopeNote)}</section>${summary}${publicScopeItems}${attestationSummary}<section><h2>Coverage</h2><ul>${coverageItems || "<li>No checks were recorded.</li>"}</ul></section><section><h2>${postureReview ? "Observations" : "Findings"}</h2>${empty}${details}</section><section><h2>Execution log</h2><ul>${logItems || "<li>No log entries.</li>"}</ul></section><footer>Generated locally · ${escapeHtml(now())}</footer></main></body></html>`;
}

async function route(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url || "/", ORIGIN);
  setSecurityHeaders(res, url.pathname);

  if (req.headers.host !== `${HOST}:${PORT}` || !localSocket(req)) {
    text(res, 403, "This application accepts loopback requests only.");
    return;
  }
  const isLabRequest = url.pathname.startsWith("/lab/");
  if (req.method !== "GET" && (isLabRequest ? Boolean(req.headers.origin && req.headers.origin !== ORIGIN) : !validMutation(req))) {
    json(res, 403, { error: "Local origin and CSRF token required" });
    return;
  }

  if (url.pathname === "/" && req.method === "GET") {
    text(res, 200, readFileSync(resolve(PUBLIC_DIR, "index.html"), "utf8"), "text/html; charset=utf-8");
    return;
  }

  if (["/app.js", "/styles.css", "/report.js", "/report.css"].includes(url.pathname) && req.method === "GET") {
    const name = basename(url.pathname);
    const file = resolve(PUBLIC_DIR, name);
    if (!file.startsWith(`${PUBLIC_DIR}/`)) { text(res, 404, "Not found"); return; }
    const mime = extname(file) === ".js" ? "text/javascript; charset=utf-8" : "text/css; charset=utf-8";
    text(res, 200, readFileSync(file, "utf8"), mime);
    return;
  }

  if (url.pathname.startsWith("/lab/")) {
    if (!scope.approvedPathPrefixes.some((prefix) => url.pathname.startsWith(prefix))) {
      json(res, 403, { error: "Path is outside the configured lab scope" });
      return;
    }
    const body = req.method === "POST" ? await readBody(req) : undefined;
    const result = handleLabRequest({
      method: req.method || "GET",
      url: req.url || "/",
      headers: req.headers,
      body,
    }, currentProfile, labState);
    res.statusCode = result.status;
    for (const [key, value] of Object.entries(result.headers)) res.setHeader(key, value);
    res.end(result.body);
    return;
  }

  if (url.pathname === "/api/session" && req.method === "GET") {
    json(res, 200, { csrfToken });
    return;
  }

  if (url.pathname === "/api/health" && req.method === "GET") {
    const publicReviewEnabled = scope.approvedServices.includes("passive-public-review") && scope.publicReadOnlyPages.length > 0;
    json(res, 200, {
      ok: true,
      mode: "laboratory",
      bind: HOST,
      externalNetwork: publicReviewEnabled,
      publicReviewEnabled,
      publicRequests: "one GET per exact approved HTTPS page, only after a local user confirms and starts a review",
      postureReviewAvailable: publicReviewEnabled,
      postureReviewRequests: "one unauthenticated GET per selected exact approved HTTPS page after per-run operator attestations",
      dynamicAuditExternalNetwork: false,
    });
    return;
  }

  if (url.pathname === "/api/dashboard" && req.method === "GET") {
    json(res, 200, dashboardData());
    return;
  }

  if (url.pathname === "/api/jobs" && req.method === "GET") {
    const rows = db.prepare("SELECT * FROM jobs ORDER BY created_at DESC LIMIT 30").all() as Array<Record<string, unknown>>;
    json(res, 200, { jobs: rows.map(rowToJob) });
    return;
  }

  if (url.pathname === "/api/jobs" && req.method === "POST") {
    const body = await readJson(req);
    const action = body.action;
    if (action !== "audit" && action !== "retest" && action !== "source-review" && action !== "public-review" && action !== "posture-review") { json(res, 400, { error: "Action must be audit, retest, source-review, public-review, or posture-review" }); return; }
    try {
      json(res, 202, enqueueJob(action, body.confirmPublicGet === true, {
        pages: body.pages,
        authorizationAttestation: body.authorizationAttestation,
      }));
    }
    catch (error) { json(res, 409, { error: error instanceof Error ? error.message : "Could not queue audit" }); }
    return;
  }

  if (url.pathname === "/api/lab/profile" && req.method === "POST") {
    const active = db.prepare("SELECT COUNT(*) AS count FROM jobs WHERE status IN ('queued', 'running')").get() as { count?: number };
    if (Number(active.count || 0) > 0) { json(res, 409, { error: "Wait for queued audits to finish before changing the demo profile." }); return; }
    const body = await readJson(req);
    if (body.profile !== "vulnerable" && body.profile !== "secure") { json(res, 400, { error: "Profile must be vulnerable or secure" }); return; }
    currentProfile = body.profile;
    resetLabState(labState);
    setSetting("lab_profile", currentProfile);
    json(res, 200, { profile: currentProfile, reset: true, synthetic: true });
    return;
  }

  const jobMatch = /^\/api\/jobs\/([a-f0-9-]+)$/.exec(url.pathname);
  if (jobMatch && req.method === "GET") {
    const job = db.prepare("SELECT * FROM jobs WHERE id = ?").get(jobMatch[1]) as Record<string, unknown> | undefined;
    if (!job) { json(res, 404, { error: "Audit run not found" }); return; }
    const findings = db.prepare("SELECT * FROM findings WHERE job_id = ? ORDER BY created_at DESC").all(jobMatch[1]) as Array<Record<string, unknown>>;
    const logs = logsFor(jobMatch[1]);
    json(res, 200, { job: rowToJob(job), findings: findings.map(rowToFinding), logs });
    return;
  }

  const reportMatch = /^\/reports\/([a-f0-9-]+)\/(technical|executive|remediation)$/.exec(url.pathname);
  if (reportMatch && req.method === "GET") {
    const report = reportsFor(reportMatch[1]);
    if (!report) { text(res, 404, "Audit run not found"); return; }
    text(res, 200, reportHtml(reportMatch[2], report), "text/html; charset=utf-8");
    return;
  }

  text(res, 404, "Not found");
}

const server = createServer((req, res) => {
  void route(req, res).catch((error) => {
    if (res.headersSent) { res.destroy(); return; }
    if (error instanceof SyntaxError || error?.message === "Request body too large") {
      json(res, 400, { error: error.message === "Request body too large" ? error.message : "Invalid JSON" });
      return;
    }
    json(res, 500, { error: "Local application error" });
  });
});

server.listen(PORT, HOST, () => {
  console.log(`RevenueGuard Lab is available at ${ORIGIN}`);
  console.log("Scope: active checks stay loopback-only; optional public review uses only exact HTTPS pages in scope.json; callbacks are disabled.");
  void drainQueue();
});

server.on("close", () => db.close());
process.on("SIGINT", () => server.close());
process.on("SIGTERM", () => server.close());
