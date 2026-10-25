import { scopedFetch } from "./scope.ts";
import type { ScopeConfig, ScopedFetchResponse } from "./scope.ts";

export type FindingStatus = "CONFIRMED" | "SUSPECTED" | "NOT REPRODUCED" | "NOT TESTED";
export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

export interface AuditEvidence {
  request: { method: string; url: string; headers: Record<string, string>; body?: string };
  response?: { status: number; contentType: string; body: string };
  note?: string;
}

export interface AuditFinding {
  key: string;
  title: string;
  category: string;
  severity: Severity;
  status: FindingStatus;
  confidence: "High" | "Medium" | "Low";
  target: string;
  endpoint: string;
  component: string;
  preconditions: string;
  expected: string;
  actual: string;
  reproduction: string[];
  impact: string;
  severityRationale: string;
  remediation: string;
  evidence: AuditEvidence;
  retestStatus: string;
}

export interface CoverageItem {
  key: string;
  label: string;
  attempted: boolean;
  status: "CONFIRMED" | "SUSPECTED" | "NOT REPRODUCED" | "NOT TESTED";
  controlVerified: boolean;
  error?: string;
}

export interface AuditResult {
  findings: AuditFinding[];
  coverage: CoverageItem[];
}

export type AuditTransport = (
  url: string | URL,
  config: ScopeConfig,
  init?: RequestInit,
) => Promise<ScopedFetchResponse>;

interface AuditOptions {
  scope: ScopeConfig;
  transport?: AuditTransport;
  targetLabel?: string;
}

interface CheckOutput {
  finding?: AuditFinding;
  verified: boolean;
  error?: string;
}

const DEMO_ORIGIN = "http://127.0.0.1:8765";
const XSS_CANARY = "LAB_XSS_MARKER";
const DEPENDENCY_KEY = "dependency.synthetic-warning";
const REQUIRED_CHECKS = [
  "authz.idor",
  "authz.admin",
  "input.search-bypass",
  "input.reflected-html",
  "server.path-traversal",
  "logic.coupon-reuse",
  DEPENDENCY_KEY,
] as const;

function parseJson(text: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(text);
    return value && typeof value === "object" && !Array.isArray(value)
      ? value as Record<string, unknown>
      : {};
  } catch {
    return {};
  }
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message.slice(0, 240) : "Request failed";
}

function redactText(value: string): string {
  return value
    .replace(/Bearer\s+[A-Za-z0-9._~+/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/(password|token|secret|api[_-]?key)\s*[:=]\s*[^\s"&,}]*/gi, "$1=[REDACTED]")
    .slice(0, 2000);
}

function evidence(
  method: string,
  url: URL,
  headers: Record<string, string>,
  response?: ScopedFetchResponse,
  body?: string,
  note?: string,
): AuditEvidence {
  const safeHeaders: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    safeHeaders[key] = /authorization|cookie|token|secret|key/i.test(key) ? "[REDACTED]" : value;
  }
  return {
    request: { method, url: redactText(url.href), headers: safeHeaders, ...(body ? { body: redactText(body) } : {}) },
    ...(response ? {
      response: {
        status: response.status,
        contentType: response.headers.get("content-type") || "unknown",
        body: redactText(response.text),
      },
    } : {}),
    ...(note ? { note } : {}),
  };
}

function makeFinding(input: Omit<AuditFinding, "target" | "retestStatus">, target: string): AuditFinding {
  return { ...input, target, retestStatus: "NOT RETESTED" };
}

/**
 * Run the fixed set of non-destructive checks against RevenueGuard's own demo API.
 * The fixed demo origin must be present in scope; check paths and payloads are constants.
 */
export async function executeAudit(options: AuditOptions): Promise<AuditResult> {
  const { scope } = options;
  const transport = options.transport ?? scopedFetch;
  if (!scope.approvedOrigins.includes(DEMO_ORIGIN)) {
    throw new Error(`Scope config must explicitly approve the fixed demo origin ${DEMO_ORIGIN}`);
  }
  const origin = DEMO_ORIGIN;
  const targetLabel = options.targetLabel ?? "RevenueGuard synthetic demo";
  const findings: AuditFinding[] = [];
  const coverage: CoverageItem[] = [];

  async function request(
    path: string,
    method = "GET",
    headers: Record<string, string> = {},
    body?: string,
  ): Promise<{ response: ScopedFetchResponse; url: URL }> {
    const url = new URL(path, origin);
    const response = await transport(url, scope, {
      method,
      headers,
      ...(body ? { body } : {}),
      redirect: "manual",
    });
    if (response.status >= 500) throw new Error(`In-scope demo target returned HTTP ${response.status}`);
    return { response, url };
  }

  async function runCheck(
    key: string,
    label: string,
    check: () => Promise<CheckOutput>,
  ): Promise<void> {
    try {
      const output = await check();
      if (output.finding) findings.push(output.finding);
      coverage.push({
        key,
        label,
        attempted: true,
        status: output.finding?.status === "CONFIRMED"
          ? "CONFIRMED"
          : output.finding?.status === "SUSPECTED" ? "SUSPECTED" : "NOT REPRODUCED",
        controlVerified: output.verified,
        ...(!output.verified ? { error: output.error ?? "Expected demo response or control did not validate." } : {}),
      });
    } catch (error) {
      coverage.push({ key, label, attempted: true, status: "NOT REPRODUCED", controlVerified: false, error: errorText(error) });
    }
  }

  await runCheck("authz.idor", "Horizontal record authorization", async () => {
    const headers = { authorization: "Bearer alice" };
    const { response, url } = await request("/lab/api/records?user_id=2", "GET", headers);
    const record = parseJson(response.text).record as Record<string, unknown> | undefined;
    if (response.status === 403 || response.status === 404) {
      const own = await request("/lab/api/records?user_id=1", "GET", headers);
      const ownRecord = parseJson(own.response.text).record as Record<string, unknown> | undefined;
      return own.response.status === 200 && ownRecord?.ownerUserId === "1"
        ? { verified: true }
        : { verified: false, error: "Cross-user denial was observed, but the valid owner's record could not be read." };
    }
    if (response.status !== 200 || record?.ownerUserId !== "2") {
      return { verified: false, error: `Expected HTTP 200 with Bob's record or a denial; got HTTP ${response.status}.` };
    }
    return { verified: true, finding: makeFinding({
      key: "authz.idor", title: "A synthetic user's record is visible to another user", category: "Authorization",
      severity: "High", status: "CONFIRMED", confidence: "High", endpoint: `${url.pathname}${url.search}`,
      component: "GET /lab/api/records", preconditions: "Authenticated as synthetic Alice (user 1).",
      expected: "Alice requesting Bob's record should receive 403 or 404.",
      actual: `The endpoint returned record ${String(record.recordId)} owned by synthetic user ${String(record.ownerUserId)} with HTTP ${response.status}.`,
      reproduction: ["Authenticate as synthetic Alice.", "Request /lab/api/records?user_id=2.", "Observe Bob's synthetic record in the response."],
      impact: "A user can read another synthetic user's record in the vulnerable fixture.",
      severityRationale: "High in the fixture because object-level authorization is absent; real-world impact depends on the data and tenant boundary.",
      remediation: "Derive the record owner from the authenticated server-side principal and enforce object authorization on every request.",
      evidence: evidence("GET", url, headers, response),
    }, targetLabel) };
  });

  await runCheck("authz.admin", "Administrative function authorization", async () => {
    const { response, url } = await request("/lab/api/admin");
    if (response.status === 401 || response.status === 403) {
      const admin = await request("/lab/api/admin", "GET", { authorization: "Bearer admin" });
      const panel = parseJson(admin.response.text);
      return admin.response.status === 200 && panel.synthetic === true
        ? { verified: true }
        : { verified: false, error: "Anonymous access was denied, but the valid synthetic admin control failed." };
    }
    const panel = parseJson(response.text);
    if (response.status !== 200 || panel.synthetic !== true) {
      return { verified: false, error: `Expected an anonymous denial or the synthetic admin panel; got HTTP ${response.status}.` };
    }
    return { verified: true, finding: makeFinding({
      key: "authz.admin", title: "Administrative endpoint accepts an anonymous request", category: "Authorization",
      severity: "High", status: "CONFIRMED", confidence: "High", endpoint: url.pathname,
      component: "GET /lab/api/admin", preconditions: "No authentication token or role.",
      expected: "The endpoint should require authentication and an administrator role.",
      actual: `The synthetic admin panel returned HTTP ${response.status} without credentials.`,
      reproduction: ["Send GET /lab/api/admin without an Authorization header.", "Observe an HTTP 200 response containing the synthetic admin panel."],
      impact: "An unauthenticated caller reaches the fixture's administrative function.",
      severityRationale: "High in the fixture because the protected function is available anonymously; no real account or data is involved.",
      remediation: "Require authenticated server-side authorization and verify the administrator role at the route handler.",
      evidence: evidence("GET", url, {}, response),
    }, targetLabel) };
  });

  await runCheck("input.search-bypass", "Search filter injection canary", async () => {
    const baseline = await request("/lab/api/search?q=RG_NO_MATCH_2026");
    const probe = await request("/lab/api/search?q=LAB_SEARCH_ALL");
    const baselineData = parseJson(baseline.response.text);
    const probeData = parseJson(probe.response.text);
    if (baseline.response.status !== 200 || probe.response.status !== 200 || !Array.isArray(baselineData.results) || !Array.isArray(probeData.results)) {
      return { verified: false, error: "Search endpoints did not return the expected JSON result lists." };
    }
    const baselineRows = asArray(baselineData.results);
    const probeRows = asArray(probeData.results);
    if (probeRows.length <= baselineRows.length) return { verified: true };
    return { verified: true, finding: makeFinding({
      key: "input.search-bypass", title: "Search canary bypasses the synthetic result filter", category: "Input handling",
      severity: "Medium", status: "CONFIRMED", confidence: "High", endpoint: `${probe.url.pathname}${probe.url.search}`,
      component: "GET /lab/api/search", preconditions: "No authentication required in the synthetic fixture.",
      expected: "An unmatched query should return no items.",
      actual: `The unmatched baseline returned ${baselineRows.length} item(s), while the fixed lab canary returned ${probeRows.length}.`,
      reproduction: ["Request /lab/api/search?q=RG_NO_MATCH_2026.", "Request /lab/api/search?q=LAB_SEARCH_ALL.", "Compare the result counts."],
      impact: "The demo reproduces a search-filter bypass using a fixed synthetic canary. It does not execute a SQL statement and must not be reported as a verified SQL injection in a real application.",
      severityRationale: "Medium for this lab behavior because the fixed canary reveals all synthetic search rows; a real impact assessment needs database-backed validation.",
      remediation: "Use parameterized queries, constrain result visibility server-side, and add regression cases for malformed and special input.",
      evidence: evidence("GET", probe.url, {}, probe.response, undefined,
        `Baseline request: ${baseline.url.href} returned ${baselineRows.length}; the synthetic canary returned ${probeRows.length}.`),
    }, targetLabel) };
  });

  await runCheck("input.reflected-html", "Reflected HTML and browser injection", async () => {
    const path = `/lab/api/comment?q=${encodeURIComponent(XSS_CANARY)}`;
    const { response, url } = await request(path);
    const contentType = response.headers.get("content-type") || "";
    if (response.status !== 200 || !contentType.toLowerCase().includes("text/html")) {
      return { verified: false, error: `Expected an HTML response for the fixed canary; got HTTP ${response.status}.` };
    }
    if (!response.text.includes("onload=\"document.documentElement.dataset.rgLab='xss'\"")) {
      return response.text.includes(XSS_CANARY)
        ? { verified: true }
        : { verified: false, error: "HTML response did not contain the canary or its escaped control text." };
    }
    return { verified: true, finding: makeFinding({
      key: "input.reflected-html", title: "Reflected active markup is returned as HTML", category: "Browser security",
      severity: "Medium", status: "CONFIRMED", confidence: "High", endpoint: `${url.pathname}${url.search}`,
      component: "GET /lab/api/comment", preconditions: "A victim must render the attacker-controlled URL in a browser.",
      expected: "User-controlled text should be HTML-escaped before rendering.",
      actual: "The fixed active SVG event-handler canary is returned unescaped in a text/html response. It only sets a local DOM data attribute; the audit records the response and does not execute it.",
      reproduction: ["Request /lab/api/comment?q=LAB_XSS_MARKER.", "Observe the fixed unescaped SVG marker and text/html content type.", "If rendered, it only sets document.documentElement.dataset.rgLab to xss."],
      impact: "The fixture returns one fixed browser-executable markup canary. Arbitrary query input is escaped; the marker makes no network request, accesses no local data, and runs no command.",
      severityRationale: "Medium in the fixture; browser impact depends on where the response is rendered and its applicable browser policy.",
      remediation: "Render user input as text, apply context-aware HTML escaping, and add a restrictive Content Security Policy as defense in depth.",
      evidence: evidence("GET", url, {}, response, undefined, "The test captures the fixed HTML canary; it does not run JavaScript in a browser."),
    }, targetLabel) };
  });

  await runCheck("server.path-traversal", "Synthetic file access boundary", async () => {
    const path = `/lab/api/file?path=${encodeURIComponent("../private/lab-secret.txt")}`;
    const { response, url } = await request(path);
    if (response.status === 400 || response.status === 403 || response.status === 404) {
      const publicFile = await request("/lab/api/file?path=readme.txt");
      return publicFile.response.status === 200 && publicFile.response.text.includes("Synthetic public lab readme.")
        ? { verified: true }
        : { verified: false, error: "Traversal was denied, but the public synthetic file control failed." };
    }
    if (response.status !== 200 || !response.text.includes("RG_LAB_FILE_MARKER")) {
      return { verified: false, error: `Expected traversal exposure or a denial; got HTTP ${response.status}.` };
    }
    return { verified: true, finding: makeFinding({
      key: "server.path-traversal", title: "Path traversal reaches a synthetic private file", category: "File handling",
      severity: "High", status: "CONFIRMED", confidence: "High", endpoint: `${url.pathname}${url.search}`,
      component: "GET /lab/api/file", preconditions: "No authentication is required by this synthetic fixture.",
      expected: "Path segments must remain inside the public fixture directory.",
      actual: "The traversal path returned a hard-coded in-memory marker for a private synthetic file.",
      reproduction: ["Request /lab/api/file?path=../private/lab-secret.txt.", "Observe RG_LAB_FILE_MARKER in the JSON response."],
      impact: "Only a synthetic in-memory string is exposed. No host file is read.",
      severityRationale: "High for the fixture's path boundary failure; actual file exposure depends on the target's filesystem layout and permissions.",
      remediation: "Resolve requested paths against a fixed base directory, verify the normalized result remains beneath that base, and use an allowlist of served files.",
      evidence: evidence("GET", url, {}, response),
    }, targetLabel) };
  });

  await runCheck("logic.coupon-reuse", "Single-use business action", async () => {
    const headers = { authorization: "Bearer alice", "content-type": "application/json" };
    const body = JSON.stringify({ code: "ONE-USE" });
    const first = await request("/lab/api/discount", "POST", headers, body);
    const second = await request("/lab/api/discount", "POST", headers, body);
    if (first.response.status === 200 && second.response.status === 409) return { verified: true };
    if (first.response.status !== 200 || second.response.status !== 200) {
      return { verified: false, error: `Expected 200/200 or 200/409; got ${first.response.status}/${second.response.status}.` };
    }
    return { verified: true, finding: makeFinding({
      key: "logic.coupon-reuse", title: "A one-use synthetic discount can be redeemed twice", category: "Business logic",
      severity: "Medium", status: "CONFIRMED", confidence: "High", endpoint: second.url.pathname,
      component: "POST /lab/api/discount", preconditions: "Authenticated as synthetic Alice; code ONE-USE is available.",
      expected: "The second redemption should be rejected as already used.",
      actual: "Two sequential redemptions returned HTTP 200 for the same synthetic user.",
      reproduction: ["POST {\"code\":\"ONE-USE\"} as synthetic Alice.", "Repeat the identical request.", "Observe HTTP 200 for both responses."],
      impact: "The fixture allows reuse of a synthetic discount. No payment or real transaction occurs.",
      severityRationale: "Medium in the fixture because a single-use workflow rule is bypassed; real financial impact is not modeled.",
      remediation: "Enforce one-time redemption atomically on the server with a unique transaction constraint or equivalent idempotency guard.",
      evidence: evidence("POST", second.url, headers, second.response, body,
        `First redemption returned HTTP ${first.response.status}; second returned HTTP ${second.response.status}.`),
    }, targetLabel) };
  });

  await runCheck(DEPENDENCY_KEY, "Synthetic dependency advisory marker", async () => {
    const { response, url } = await request("/lab/api/dependencies");
    const payload = parseJson(response.text);
    const dependencies = asArray(payload.dependencies) as Array<Record<string, unknown>>;
    const item = dependencies.find((dependency) => dependency.requiresLiveValidation === true);
    if (response.status !== 200 || payload.synthetic !== true || !item || typeof item.advisory !== "string") {
      return { verified: false, error: "The synthetic dependency inventory marker did not validate." };
    }
    return { verified: true, finding: makeFinding({
      key: DEPENDENCY_KEY, title: "Synthetic dependency marker requires validation", category: "Dependencies",
      severity: "Info", status: "SUSPECTED", confidence: "Low", endpoint: url.pathname,
      component: String(item.name || "synthetic dependency fixture"), preconditions: "The target exposes its local synthetic inventory.",
      expected: "A version match alone is not enough to claim exploitability.",
      actual: `The fixture lists a fictional marker ${String(item.advisory || "RG-DEMO-001")} for ${String(item.name)} ${String(item.version)}; it is not a real advisory.`,
      reproduction: ["GET /lab/api/dependencies.", "Inspect the clearly synthetic RG-DEMO-001 marker."],
      impact: "No vulnerability is confirmed. The marker exists only to demonstrate cautious dependency triage.",
      severityRationale: "Informational: the fixture is fictional and no real dependency or advisory database is queried.",
      remediation: "For a real project, verify the exact package, version, reachability, affected code path, and authoritative advisory before assigning severity.",
      evidence: evidence("GET", url, {}, response),
    }, targetLabel) };
  });

  return { findings, coverage };
}

/** A retest can mark old findings fixed only after every check verified its expected response and safe control. */
export function isCompleteRetest(result: AuditResult): boolean {
  if (result.coverage.length !== REQUIRED_CHECKS.length) return false;
  const observed = new Set(result.coverage.map((item) => item.key));
  if (REQUIRED_CHECKS.some((key) => !observed.has(key))) return false;
  return result.coverage.every((item) => item.attempted && item.controlVerified && !item.error && item.status !== "NOT TESTED");
}
