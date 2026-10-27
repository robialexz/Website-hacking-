import type { AuditEvidence, AuditFinding, AuditResult, CoverageItem, Severity } from "./audit.ts";
import { assertPublicPageInScope } from "./scope.ts";
import type { ScopeConfig } from "./scope.ts";
import { passivePublicGet } from "./public-review.ts";
import type { PublicPageResponse, PublicPageTransport } from "./public-review.ts";

export const POSTURE_REVIEW_MAX_PAGES = 4;

export interface PostureReviewOptions {
  scope: ScopeConfig;
  pages: readonly (string | URL)[];
  transport?: PublicPageTransport;
}

const OBSERVED_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
] as const;

const CSP_DIRECTIVES = new Set([
  "base-uri", "child-src", "connect-src", "default-src", "fenced-frame-src", "font-src",
  "form-action", "frame-ancestors", "frame-src", "img-src", "manifest-src", "media-src",
  "object-src", "prefetch-src", "script-src", "script-src-attr", "script-src-elem",
  "style-src", "style-src-attr", "style-src-elem", "worker-src", "block-all-mixed-content",
  "upgrade-insecure-requests", "sandbox", "report-to", "report-uri", "trusted-types",
  "require-trusted-types-for", "require-sri-for",
]);

const PERMISSIONS_DIRECTIVES = new Set([
  "accelerometer", "ambient-light-sensor", "autoplay", "battery", "camera", "display-capture",
  "document-domain", "encrypted-media", "execution-while-not-rendered", "execution-while-out-of-viewport",
  "fullscreen", "geolocation", "gyroscope", "magnetometer", "microphone", "midi", "payment",
  "picture-in-picture", "publickey-credentials-get", "screen-wake-lock", "sync-xhr", "usb",
  "web-share", "xr-spatial-tracking", "clipboard-read", "clipboard-write", "gamepad",
  "speaker-selection", "window-management", "local-fonts", "identity-credentials-get",
]);

const REFERRER_POLICIES = new Set([
  "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin", "same-origin",
  "strict-origin", "strict-origin-when-cross-origin", "unsafe-url",
]);

function coverage(input: Omit<CoverageItem, "controlVerified">): CoverageItem {
  return { ...input, controlVerified: false };
}

function makeObservation(input: {
  key: string;
  title: string;
  target: string;
  endpoint: string;
  actual: string;
  evidence: AuditEvidence;
}): AuditFinding {
  const severity: Severity = "Info";
  return {
    key: input.key,
    title: input.title,
    category: "HTTPS posture observation",
    severity,
    status: "OBSERVED",
    confidence: "High",
    target: input.target,
    endpoint: input.endpoint,
    component: input.endpoint,
    preconditions: "One unauthenticated GET was made to an exact approved HTTPS page.",
    expected: "Record the observed response without inferring that a control is effective or ineffective.",
    actual: input.actual,
    reproduction: ["Review the recorded one-request observation.", "Validate configuration and behavior in the service owner's environment."],
    impact: "This observation is not a vulnerability finding or an overall security assessment.",
    severityRationale: "The result is a passive observation only; it does not establish exploitability or security.",
    remediation: "Interpret the observed value in the context of the service's intended policy and architecture.",
    evidence: input.evidence,
    retestStatus: "NOT RETESTED",
  };
}

function safeTransportError(): string {
  // Do not persist arbitrary transport error text, which may contain response data.
  return "No response was available; posture observations are inconclusive.";
}

function summarizeHsts(value: string | null): string {
  if (value === null) return "absent";
  const maxAge = /(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i.exec(value)?.[1];
  const parsedMaxAge = maxAge === undefined ? undefined : Number(maxAge);
  const safeMaxAge = parsedMaxAge !== undefined && Number.isSafeInteger(parsedMaxAge) ? parsedMaxAge : "unparsed";
  const directives = new Set(value.split(";").map((part) => part.trim().toLowerCase().split("=", 1)[0]));
  return `present; max-age=${safeMaxAge}; includeSubDomains=${directives.has("includesubdomains")}; preload=${directives.has("preload")}`;
}

function summarizeCsp(value: string | null): string {
  if (value === null) return "absent";
  const directives = new Set<string>();
  let directiveCount = 0;
  let unknownDirectiveCount = 0;
  let hasUnsafeInline = false;
  let hasUnsafeEval = false;
  let hasWildcardSource = false;
  let hasNonceSource = false;
  let hasHashSource = false;
  let hasHttpSource = false;
  let hasDataSource = false;
  let hasSelfSource = false;

  for (const policy of value.split(",")) {
    for (const directive of policy.split(";")) {
      const parts = directive.trim().split(/\s+/).filter(Boolean);
      if (!parts.length) continue;
      directiveCount += 1;
      const name = parts[0].toLowerCase();
      if (CSP_DIRECTIVES.has(name)) directives.add(name);
      else unknownDirectiveCount += 1;
      for (const source of parts.slice(1).map((part) => part.toLowerCase())) {
        if (source === "'unsafe-inline'") hasUnsafeInline = true;
        if (source === "'unsafe-eval'") hasUnsafeEval = true;
        if (source === "*") hasWildcardSource = true;
        if (/^'nonce-[^']+'$/.test(source)) hasNonceSource = true;
        if (/^'sha(?:256|384|512)-[^']+'$/.test(source)) hasHashSource = true;
        if (source === "http:" || source.startsWith("http://")) hasHttpSource = true;
        if (source === "data:" || source.startsWith("data:")) hasDataSource = true;
        if (source === "'self'") hasSelfSource = true;
      }
    }
  }

  return JSON.stringify({
    present: true,
    directiveCount,
    directiveNames: [...directives].sort(),
    unknownDirectiveCount,
    hasUnsafeInline,
    hasUnsafeEval,
    hasWildcardSource,
    hasNonceSource,
    hasHashSource,
    hasHttpSource,
    hasDataSource,
    hasSelfSource,
  });
}

function summarizeXcto(value: string | null): string {
  if (value === null) return "absent";
  return value.trim().toLowerCase() === "nosniff" ? "nosniff" : "other";
}

function summarizeReferrerPolicy(value: string | null): string {
  if (value === null) return "absent";
  const candidates = value.split(",").map((part) => part.trim().toLowerCase()).filter(Boolean);
  const selected = candidates.at(-1);
  return selected && REFERRER_POLICIES.has(selected) ? selected : "other";
}

function summarizePermissionsPolicy(value: string | null): string {
  if (value === null) return "absent";
  const directiveNames = new Set<string>();
  let directiveCount = 0;
  let unknownDirectiveCount = 0;
  for (const directive of value.split(",")) {
    const name = directive.trim().split("=", 1)[0].trim().toLowerCase();
    if (!name) continue;
    directiveCount += 1;
    if (PERMISSIONS_DIRECTIVES.has(name)) directiveNames.add(name);
    else unknownDirectiveCount += 1;
  }
  return JSON.stringify({
    present: true,
    directiveCount,
    directiveNames: [...directiveNames].sort(),
    unknownDirectiveCount,
  });
}

function summarizeHeaderValue(value: string | null, summarize: (value: string | null) => string): string {
  if (value !== null && value.length >= 400) return "present; derived summary unavailable because the transport capped this value";
  return summarize(value);
}

function headerObservations(response: PublicPageResponse): Record<string, string> {
  return {
    "strict-transport-security": summarizeHeaderValue(response.headers.get("strict-transport-security"), summarizeHsts),
    "content-security-policy": summarizeHeaderValue(response.headers.get("content-security-policy"), summarizeCsp),
    "x-content-type-options": summarizeHeaderValue(response.headers.get("x-content-type-options"), summarizeXcto),
    "referrer-policy": summarizeHeaderValue(response.headers.get("referrer-policy"), summarizeReferrerPolicy),
    "permissions-policy": summarizeHeaderValue(response.headers.get("permissions-policy"), summarizePermissionsPolicy),
  };
}

function safeMediaType(value: string | null): string {
  if (value === null) return "unknown";
  const mediaType = value.split(";", 1)[0].trim().toLowerCase();
  return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(mediaType) ? mediaType : "other";
}

function safeCookieFlagCounts(response: PublicPageResponse): NonNullable<PublicPageResponse["cookieFlagCounts"]> | undefined {
  const counts = response.cookieFlagCounts;
  if (!counts) return undefined;
  const values = [counts.setCookieCount, counts.secureCount, counts.httpOnlyCount, counts.sameSiteCount];
  if (values.some((value) => !Number.isSafeInteger(value) || value < 0)) return undefined;
  if (values.slice(1).some((value) => value > counts.setCookieCount)) return undefined;
  return {
    setCookieCount: counts.setCookieCount,
    secureCount: counts.secureCount,
    httpOnlyCount: counts.httpOnlyCount,
    sameSiteCount: counts.sameSiteCount,
  };
}

function pageEvidence(url: URL, response: PublicPageResponse, headers: Record<string, string>): NonNullable<AuditEvidence["page"]> {
  return {
    url: url.href,
    status: response.status,
    contentType: safeMediaType(response.headers.get("content-type")),
    elapsedMs: response.elapsedMs,
    bytes: response.bytes,
    headers,
  };
}

/** Observe headers, TLS completion, and cookie flag counts for exact approved pages only. */
export async function executePostureReview(options: PostureReviewOptions): Promise<AuditResult> {
  const { scope } = options;
  if (scope.mode !== "laboratory" || !scope.approvedServices.includes("passive-public-review")) {
    throw new Error('Scope must approve the "passive-public-review" service in laboratory mode');
  }
  const maxPages = Math.min(POSTURE_REVIEW_MAX_PAGES, scope.budgets.maxPublicPages, scope.budgets.maxRequestsPerAudit);
  if (!Array.isArray(options.pages) || maxPages < 1 || options.pages.length === 0 || options.pages.length > maxPages) {
    throw new Error(maxPages < 1
      ? "The configured request budget does not allow posture observations."
      : `Posture review requires between 1 and ${maxPages} exact approved pages.`);
  }

  const pages = options.pages.map((page) => assertPublicPageInScope(page, scope));
  if (new Set(pages.map((page) => page.href)).size !== pages.length) {
    throw new Error("Posture review pages must not contain duplicates.");
  }

  const transport = options.transport ?? passivePublicGet;
  const findings: AuditFinding[] = [];
  const coverageItems: CoverageItem[] = [];

  for (let index = 0; index < pages.length; index += 1) {
    const url = pages[index];
    const suffix = `page-${index + 1}`;
    let response: PublicPageResponse;
    try {
      response = await transport(url, scope);
    } catch {
      coverageItems.push(coverage({
        key: `posture.fetch.${suffix}`,
        label: `Fetch approved page ${index + 1}`,
        attempted: true,
        requestStatus: "unknown",
        status: "INCONCLUSIVE",
        error: safeTransportError(),
      }));
      for (const [key, label] of [
        ["headers", "Response headers"],
        ["tls", "TLS certificate validation evidence"],
        ["cookies", "Cookie flag counts"],
      ] as const) {
        coverageItems.push(coverage({
          key: `posture.${key}.${suffix}`,
          label: `${label} · page ${index + 1}`,
          attempted: false,
          requestStatus: "unknown",
          status: "INCONCLUSIVE",
          error: safeTransportError(),
        }));
      }
      continue;
    }

    const target = url.origin;
    const endpoint = url.pathname;
    coverageItems.push(coverage({
      key: `posture.fetch.${suffix}`,
      label: `Fetch approved page ${index + 1}`,
      attempted: true,
      requestStatus: "response-received",
      status: "OBSERVED",
      details: `Received HTTP ${response.status}; one GET was sent and no redirect was followed.`,
    }));

    if (response.status < 200 || response.status >= 300) {
      for (const [key, label] of [
        ["headers", "Response header summary"],
        ["tls", "TLS certificate validation evidence"],
        ["cookies", "Cookie flag counts"],
      ] as const) {
        coverageItems.push(coverage({
          key: `posture.${key}.${suffix}`,
          label: `${label} · page ${index + 1}`,
          attempted: false,
          requestStatus: "response-received",
          status: "INCONCLUSIVE",
          error: `HTTP ${response.status}; posture details were not recorded for this response.`,
        }));
      }
      continue;
    }

    const headers = headerObservations(response);
    const page = pageEvidence(url, response, headers);
    const headerDetails = OBSERVED_HEADERS.map((name) => `${name}: ${headers[name]}`).join("; ");
    const headerSummaryIncomplete = Object.values(headers).some((value) => value.includes("summary unavailable"));
    coverageItems.push(coverage({
      key: `posture.headers.${suffix}`,
      label: `Response headers · page ${index + 1}`,
      attempted: true,
      requestStatus: "response-received",
      status: headerSummaryIncomplete ? "INCONCLUSIVE" : "OBSERVED",
      details: headerDetails,
      ...(headerSummaryIncomplete ? { error: "One or more header values exceeded the transport's summary window." } : {}),
    }));
    if (!headerSummaryIncomplete) {
      findings.push(makeObservation({
        key: "posture.response-headers",
        title: "Observed normalized HTTPS response header summary",
        target,
        endpoint,
        actual: `Observed normalized response header summaries: ${headerDetails}. This is not a security judgment.`,
        evidence: { page, note: "Normalized response header summaries are observations only; raw policy values were not retained." },
      }));
    }

    if (response.tlsCertificateValidation === "validated") {
      coverageItems.push(coverage({
        key: `posture.tls.${suffix}`,
        label: `TLS certificate validation evidence · page ${index + 1}`,
        attempted: true,
        requestStatus: "response-received",
        status: "OBSERVED",
        details: "The HTTPS request received a response after certificate and hostname validation.",
      }));
      findings.push(makeObservation({
        key: "posture.tls-connection-evidence",
        title: "Observed TLS certificate validation evidence",
        target,
        endpoint,
        actual: "The HTTPS request received a response after certificate and hostname validation. This is connection evidence only.",
        evidence: { page, note: "TLS certificate and hostname validation evidence: validated for this connection." },
      }));
    } else {
      coverageItems.push(coverage({
        key: `posture.tls.${suffix}`,
        label: `TLS certificate validation evidence · page ${index + 1}`,
        attempted: false,
        requestStatus: "response-received",
        status: "NOT TESTED",
        error: "The supplied transport did not provide TLS validation evidence.",
      }));
    }

    const cookieFlags = safeCookieFlagCounts(response);
    if (cookieFlags) {
      const cookieDetails = `Set-Cookie headers: ${cookieFlags.setCookieCount}; Secure: ${cookieFlags.secureCount}; HttpOnly: ${cookieFlags.httpOnlyCount}; SameSite: ${cookieFlags.sameSiteCount}.`;
      coverageItems.push(coverage({
        key: `posture.cookies.${suffix}`,
        label: `Cookie flag counts · page ${index + 1}`,
        attempted: true,
        requestStatus: "response-received",
        status: "OBSERVED",
        details: cookieDetails,
      }));
      findings.push(makeObservation({
        key: "posture.cookie-flag-counts",
        title: "Observed cookie flag counts",
        target,
        endpoint,
        actual: `${cookieDetails} Cookie names and values were not retained. Counts alone do not establish cookie safety.`,
        evidence: { page, note: `Derived cookie flag counts only: ${cookieDetails} Names and values were not retained.` },
      }));
    } else {
      coverageItems.push(coverage({
        key: `posture.cookies.${suffix}`,
        label: `Cookie flag counts · page ${index + 1}`,
        attempted: false,
        requestStatus: "response-received",
        status: "NOT TESTED",
        error: "The supplied transport did not provide derived cookie flag counts.",
      }));
    }
  }

  return { findings, coverage: coverageItems };
}
