import { isIP } from "node:net";
import { performance } from "node:perf_hooks";

import type { AuditEvidence, AuditFinding, AuditResult, CoverageItem, Severity } from "./audit.ts";
import { tokenizeHtml } from "./html-tokenizer.ts";
import { passivePublicGet } from "./public-review.ts";
import type { PublicPageResponse, PublicPageTransport } from "./public-review.ts";
import type { ScopeConfig } from "./scope.ts";

export interface WebScanOptions {
  readonly target: string | URL;
  readonly scope: ScopeConfig;
  readonly maxPages?: number;
  readonly maxDepth?: number;
  readonly signal?: AbortSignal;
  readonly transport?: PublicPageTransport;
}

interface QueuedPage { readonly url: URL; readonly depth: number; }
interface ScanContext { readonly target: URL; readonly findings: Map<string, AggregatedObservation>; readonly coverage: CoverageItem[]; }
interface CrawlStats { offOrigin: number; query: number; action: number; static: number; frontier: number; }
interface AggregatedObservation {
  readonly key: string; readonly title: string; readonly category: string; readonly severity: Severity;
  readonly status: "SUSPECTED" | "OBSERVED"; readonly confidence: "High" | "Medium" | "Low"; readonly expected: string; readonly impact: string;
  readonly remediation: string; count: number; readonly samples: string[]; readonly facts: Record<string, unknown>;
}

const PRIVATE_HOST_SUFFIXES = [".localhost", ".local", ".internal", ".test", ".example", ".invalid", ".home.arpa", ".lan"];
const MAX_LINKS_PER_PAGE = 1000;
const MAX_FRONTIER = 5000;
const MAX_FINDINGS = 1000;
const MAX_COVERAGE = 10000;
const REPORTABLE_MEDIA_TYPES = new Set([
  "text/html", "application/xhtml+xml", "text/plain", "application/json", "application/xml", "application/octet-stream",
]);
const STATEFUL_PATH_SEGMENT = /(?:^|[-_.])(?:logout|log-out|signout|sign-out|unsubscribe|delete|destroy|remove|deactivate|disable|confirm|confirmation|activate|activation|reset|password-reset|reset-password|forgot-password|purchase|checkout|payment|transfer|withdraw|subscribe|verify|verification|verify-email|email-verification|callback|accept|accept-invite|redeem|consume|claim|login|magic-link|invitation|revoke|cancel)(?:$|[-_.])/i;
const SENSITIVE_PATH_SEGMENT = /^(?:token|key|secret|code|invite|session|auth|reset|verify|confirmation|unsubscribe)$/i;
const TOKEN_LIKE_PATH_SEGMENT = /^(?:\d{6,}|[a-f\d]{16,}|(?=.*[a-z])(?=.*\d)[a-z\d_-]{4,}|[a-z\d_-]{32,}|[a-z]{16,31})$/i;
const STATIC_FILE = /\.(?:avif|bmp|css|csv|eot|gif|ico|jpe?g|js|json|map|mp[34]|pdf|png|svg|ttf|txt|wav|webm|webp|woff2?|xml|zip)$/i;
const VALID_REFERRER_POLICIES = new Set([
  "no-referrer", "no-referrer-when-downgrade", "origin", "origin-when-cross-origin",
  "same-origin", "strict-origin", "strict-origin-when-cross-origin", "unsafe-url",
]);

export function parseWebScanTarget(value: string | URL): URL {
  const raw = value instanceof URL ? value.href : value;
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 2048 || raw.trim() !== raw) {
    throw new Error("Enter one absolute HTTPS URL without surrounding whitespace.");
  }
  let url: URL;
  try { url = new URL(raw); } catch { throw new Error("Enter one valid absolute HTTPS URL."); }
  const hostname = url.hostname.toLowerCase();
  const bareHostname = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  const rawPath = raw.match(/^https:\/\/[^/?#]+([^?#]*)/i)?.[1] || "/";
  if (
    url.protocol !== "https:" || url.username !== "" || url.password !== "" || url.port !== "" ||
    url.search !== "" || url.hash !== "" || isIP(bareHostname) !== 0 || !hostname.includes(".") ||
    hostname.endsWith(".") || PRIVATE_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix)) ||
    /[\\\u0000-\u001f]/.test(rawPath) || /%(?:2f|5c|2e)/i.test(rawPath)
  ) {
    throw new Error("The target must be a public DNS hostname on HTTPS port 443, without credentials, query strings, fragments, or encoded path separators.");
  }
  if (stateChangingPath(url)) throw new Error("The starting path looks like a state-changing action and is excluded from scanning.");
  url.hash = "";
  url.search = "";
  return url;
}

function redactPath(pathname: string): string {
  return pathname === "/" ? "/" : "/[PATH OMITTED]";
}
function safeUrl(url: URL): string { return url.origin + redactPath(url.pathname); }
function decodedPolicyPath(url: URL): string | undefined {
  try {
    const decoded = decodeURIComponent(url.pathname);
    if (decoded.includes("%") || /[\\\u0000-\u001f]/.test(decoded)) return undefined;
    return decoded;
  } catch { return undefined; }
}
function stateChangingPath(url: URL): boolean {
  const path = decodedPolicyPath(url);
  if (path === undefined) return true;
  if (path.includes(";")) return true;
  return path.split("/").filter(Boolean).some((segment) =>
    STATEFUL_PATH_SEGMENT.test(segment) || SENSITIVE_PATH_SEGMENT.test(segment) || TOKEN_LIKE_PATH_SEGMENT.test(segment),
  );
}
function isStaticPath(url: URL): boolean {
  const path = decodedPolicyPath(url);
  return path === undefined || STATIC_FILE.test(path);
}

function safeHtmlPageUrl(value: string, base: URL, origin: string): URL | undefined {
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 2048 || trimmed.startsWith("#")) return undefined;
  if (/^(?:mailto:|tel:|javascript:|data:|blob:)/i.test(trimmed)) return undefined;
  let url: URL;
  try { url = new URL(trimmed, base); } catch { return undefined; }
  if (url.protocol !== "https:" || url.origin !== origin || url.username !== "" || url.password !== "" || url.port !== "") return undefined;
  url.search = "";
  url.hash = "";
  if (/%(?:2f|5c)/i.test(url.pathname)) return undefined;
  return url;
}

function normalizedMediaType(response: PublicPageResponse): string {
  const value = response.headers.get("content-type");
  if (value === null) return "unknown";
  const media = value.split(";", 1)[0].trim().toLowerCase();
  return /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(media) ? media : "other";
}

function reportMediaType(response: PublicPageResponse): string {
  const media = normalizedMediaType(response);
  return media === "unknown" || REPORTABLE_MEDIA_TYPES.has(media) ? media : "other";
}

function isHtml(response: PublicPageResponse): boolean {
  const media = normalizedMediaType(response);
  return media === "text/html" || media === "application/xhtml+xml";
}

function addObservation(
  context: ScanContext,
  input: Omit<AggregatedObservation, "count" | "samples" | "facts" | "status"> & { page: URL; status?: "SUSPECTED" | "OBSERVED"; facts?: Record<string, unknown> },
): void {
  let observation = context.findings.get(input.key);
  if (!observation) {
    if (context.findings.size >= MAX_FINDINGS) return;
    observation = {
      key: input.key, title: input.title, category: input.category, severity: input.severity,
      status: input.status || "SUSPECTED", confidence: input.confidence, expected: input.expected, impact: input.impact,
      remediation: input.remediation, count: 0, samples: [], facts: input.facts || {},
    };
    context.findings.set(input.key, observation);
  }
  observation.count += 1;
  const sample = safeUrl(input.page);
  if (!observation.samples.includes(sample) && observation.samples.length < 5) observation.samples.push(sample);
}

function makeFinding(context: ScanContext, item: AggregatedObservation): AuditFinding {
  const endpoints = item.samples.length ? item.samples.join(", ") : "/";
  const evidence: AuditEvidence = {
    webScan: { pageCount: item.count, samplePaths: [...item.samples], checks: item.facts },
    note: item.count + " page(s) matched this observation. Sample paths are omitted. Request bodies, cookies, and response bodies are not retained.",
  };
  return {
    key: item.key, title: item.title, category: item.category, severity: item.severity,
    status: item.status, confidence: item.confidence, target: context.target.origin,
    endpoint: endpoints, component: "HTTP response or rendered HTML",
    preconditions: "The affected route was fetched once using an unauthenticated same-origin HTTPS GET. No form was submitted and no exploit payload was sent.",
    expected: item.expected, actual: "Observed on " + item.count + " page(s). Sample paths: " + endpoints + ".",
    reproduction: [
      "Review the aggregate observation in the technical report; route paths are omitted.",
      "Validate the behavior in the application's own test environment before changing policy.",
    ],
    impact: item.impact,
    severityRationale: "A response configuration or markup observation is not proof of exploitability. Severity is a triage estimate and may depend on application context.",
    remediation: item.remediation, evidence, retestStatus: "NOT RETESTED",
  };
}

function addCoverage(context: ScanContext, item: Omit<CoverageItem, "controlVerified">): void {
  if (context.coverage.length < MAX_COVERAGE) context.coverage.push({ ...item, controlVerified: false });
}
function responseHeader(response: PublicPageResponse, name: string): string | null {
  const value = response.headers.get(name);
  return value === null ? null : value.trim().slice(0, 400);
}

function securityHeaderChecks(context: ScanContext, page: URL, response: PublicPageResponse): void {
  if (response.status < 200 || response.status >= 300) {
    addCoverage(context, { key: "web.headers", label: "Browser security headers", attempted: false, requestStatus: "response-received", status: "NOT TESTED", error: "A successful 2xx response is required to interpret page headers." });
    return;
  }
  const hsts = responseHeader(response, "strict-transport-security");
  const maxAgeRaw = hsts === null ? undefined : /(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i.exec(hsts)?.[1];
  const maxAge = maxAgeRaw === undefined ? NaN : Number(maxAgeRaw);
  const csp = responseHeader(response, "content-security-policy");
  const cspDirectives = csp?.split(";").map((part) => part.trim().split(/\s+/, 1)[0].toLowerCase()).filter(Boolean) || [];
  const hasDefaultSource = cspDirectives.includes("default-src");
  const cspMissing = [
    !(hasDefaultSource || cspDirectives.includes("script-src")) && "script-src/default-src",
    !(hasDefaultSource || cspDirectives.includes("object-src")) && "object-src/default-src",
    !cspDirectives.includes("base-uri") && "base-uri",
    !cspDirectives.includes("frame-ancestors") && "frame-ancestors",
  ].filter((value): value is string => typeof value === "string");
  const cspUsesUnsafeSource = Boolean(csp && /(?:'unsafe-inline'|'unsafe-eval'|\*)/i.test(csp));
  const cspWeak = csp !== null && (!csp.trim() || !cspDirectives.length || cspMissing.length > 0 || cspUsesUnsafeSource);
  const xcto = responseHeader(response, "x-content-type-options");
  const referrer = responseHeader(response, "referrer-policy");
  const referrerValue = referrer?.split(",").map((part) => part.trim().toLowerCase()).filter(Boolean).at(-1);
  const xfo = responseHeader(response, "x-frame-options");
  const frameAncestors = Boolean(csp && /(?:^|;)\s*frame-ancestors\s+[^;]+/i.test(csp));
  const permissions = responseHeader(response, "permissions-policy");
  const checks = [
    {
      key: "web.headers.hsts", title: "HSTS missing or ineffective", present: hsts !== null,
      weak: hsts !== null && (!Number.isSafeInteger(maxAge) || maxAge <= 0),
      severity: "Low" as Severity, expected: "A valid Strict-Transport-Security header with a positive max-age is returned over HTTPS.",
      impact: "Browsers may not remember to require HTTPS for future visits to this host.",
      remediation: "After confirming all subdomains support HTTPS, configure a suitable positive max-age and consider includeSubDomains.",
      facts: { hstsPresent: hsts !== null, hstsMaxAge: Number.isSafeInteger(maxAge) ? maxAge : "invalid-or-missing" },
    },
    {
      key: "web.headers.csp", title: "Content Security Policy missing or weak", present: csp !== null,
      weak: cspWeak, severity: "Medium" as Severity, expected: "A non-empty CSP limits script, object, base, and framing sources to the application's needs.",
      impact: "A weak or absent policy removes a browser layer that can reduce the impact of some injection flaws.",
      remediation: "Deploy a tested CSP with explicit script-src, object-src, base-uri, and frame-ancestors directives; avoid unsafe-inline and unsafe-eval where feasible.",
      facts: { cspPresent: csp !== null, directiveCount: cspDirectives.length, missingDefensiveDirectives: cspMissing, usesUnsafeSource: cspUsesUnsafeSource },
    },
    {
      key: "web.headers.xcto", title: "X-Content-Type-Options is missing or invalid", present: xcto !== null,
      weak: xcto !== null && xcto.toLowerCase() !== "nosniff", severity: "Low" as Severity,
      expected: "X-Content-Type-Options is set to nosniff.",
      impact: "Some browsers may interpret content using a type different from the server's declared media type.",
      remediation: "Return X-Content-Type-Options: nosniff for web responses.",
      facts: { xContentTypeOptions: xcto === null ? "absent" : xcto.toLowerCase() },
    },
    {
      key: "web.headers.referrer", title: "Referrer-Policy is missing or unsafe", present: referrer !== null,
      weak: referrer !== null && (!referrerValue || !VALID_REFERRER_POLICIES.has(referrerValue) || referrerValue === "unsafe-url"),
      severity: "Low" as Severity, expected: "A valid Referrer-Policy limits URL information sent to other origins.",
      impact: "Full source URLs may be disclosed as referrer data when users follow links.",
      remediation: "Choose a policy such as strict-origin-when-cross-origin or no-referrer based on product needs.",
      facts: { referrerPolicy: referrer === null ? "absent" : referrer.toLowerCase() },
    },
    {
      key: "web.headers.framing", title: "Clickjacking protection is missing", present: xfo !== null || frameAncestors,
      weak: xfo !== null && !/^(?:deny|sameorigin)$/i.test(xfo) && !frameAncestors,
      severity: "Low" as Severity, expected: "Framing is restricted with a valid X-Frame-Options value or CSP frame-ancestors.",
      impact: "The page may be embeddable by another site; exploitability depends on page actions and content.",
      remediation: "Set CSP frame-ancestors to the intended allowlist; use X-Frame-Options as a compatibility fallback.",
      facts: { xFrameOptions: xfo === null ? "absent" : xfo.toLowerCase(), cspFrameAncestors: frameAncestors },
    },
    {
      key: "web.headers.permissions", title: "Permissions-Policy is missing", present: permissions !== null,
      weak: permissions !== null && permissions.length === 0, severity: "Info" as Severity,
      expected: "Permissions-Policy scopes browser features to the application's needs.",
      impact: "Browser capabilities may remain available to embedded contexts.",
      remediation: "Define a Permissions-Policy matching the product's use of browser features.",
      facts: { permissionsPolicyPresent: permissions !== null, policyLength: permissions?.length || 0 },
    },
  ];
  for (const check of checks) {
    if (!check.present || check.weak) {
      addObservation(context, {
        key: check.key, title: check.title, category: "Browser security headers",
        severity: check.severity, confidence: check.present ? "Medium" : "High",
        expected: check.expected, impact: check.impact, remediation: check.remediation,
        page, facts: check.facts,
      });
    }
  }
  addCoverage(context, {
    key: "web.headers", label: "Browser security headers", attempted: true,
    requestStatus: "response-received",
    status: checks.some((check) => !check.present || check.weak) ? "SUSPECTED" : "NOT REPRODUCED",
    details: checks.length + " policy checks evaluated conservatively; architecture-specific exceptions may apply.",
  });
}

function contentChecks(context: ScanContext, page: URL, response: PublicPageResponse, crawlStats: CrawlStats): URL[] {
  if (!isHtml(response) || response.bodyStatus === "unavailable" || !response.body) {
    addCoverage(context, { key: "web.content", label: "HTML content and same-origin links", attempted: false, requestStatus: "response-received", status: "NOT TESTED", error: "A complete HTML response was not available." });
    return [];
  }
  const parsed = tokenizeHtml(response.body);
  const links: URL[] = [];
  let mixedContent = 0;
  let insecureForms = 0;
  let externalResourcesWithoutIntegrity = 0;
  let parsedLinkCount = 0;
  let offOriginLinks = 0;
  let queryLinks = 0;
  let excludedActionLinks = 0;
  let staticLinks = 0;
  let cappedLinks = 0;
  const scanElements = new Set(["img", "script", "iframe", "frame", "source", "audio", "video", "object", "embed"]);
  for (const token of parsed.tokens) {
    if (token.type !== "start" || !token.attributes) continue;
    const attrs = token.attributes;
    const rawSource = attrs.get("src") || (token.name === "object" ? attrs.get("data") : undefined);
    if (scanElements.has(token.name || "") && rawSource) {
      try {
        const source = new URL(rawSource, page);
        if (source.protocol === "http:") mixedContent += 1;
        if (token.name === "script" && source.origin !== page.origin && !attrs.has("integrity")) externalResourcesWithoutIntegrity += 1;
      } catch { /* malformed markup is not a confirmed issue */ }
    }
    if (token.name === "link" && attrs.get("href") && /\bstylesheet\b/i.test(attrs.get("rel") || "")) {
      try {
        const source = new URL(attrs.get("href") || "", page);
        if (source.protocol === "http:") mixedContent += 1;
        if (source.origin !== page.origin && !attrs.has("integrity")) externalResourcesWithoutIntegrity += 1;
      } catch { /* malformed markup is ignored */ }
    }
    if (token.name === "form") {
      const action = attrs.get("action");
      if (action) {
        try {
          const actionUrl = new URL(action, page);
          if (actionUrl.protocol === "http:") insecureForms += 1;
        } catch { /* malformed action is ignored */ }
      }
      continue;
    }
    if (token.name !== "a" && token.name !== "area") continue;
    const href = attrs.get("href");
    if (!href) continue;
    parsedLinkCount += 1;
    if (parsedLinkCount > MAX_LINKS_PER_PAGE) { cappedLinks += 1; continue; }
    if (href.includes("?")) { queryLinks += 1; crawlStats.query += 1; continue; }
    let candidate: URL | undefined;
    try {
      const raw = new URL(href, page);
      if (raw.origin !== page.origin) { offOriginLinks += 1; crawlStats.offOrigin += 1; continue; }
      candidate = safeHtmlPageUrl(href, page, page.origin);
    } catch { continue; }
    if (!candidate) continue;
    if (isStaticPath(candidate)) { staticLinks += 1; crawlStats.static += 1; continue; }
    if (stateChangingPath(candidate)) { excludedActionLinks += 1; crawlStats.action += 1; continue; }
    if (!links.some((entry) => entry.href === candidate?.href)) links.push(candidate);
  }
  if (mixedContent > 0) addObservation(context, {
    key: "web.content.mixed-content", title: "HTTPS page references insecure HTTP content",
    category: "Transport and embedded content", severity: "Medium", confidence: "High",
    expected: "Active content and sensitive embedded resources load using HTTPS.",
    impact: "An HTTP resource can be modified in transit; script or frame content can affect the HTTPS page.",
    remediation: "Change insecure resource URLs to HTTPS or remove the resource, then test the page in a browser.",
    page, facts: { insecureResourceReferences: mixedContent },
  });
  if (insecureForms > 0) addObservation(context, {
    key: "web.content.insecure-form", title: "HTTPS page submits a form over HTTP",
    category: "Transport and embedded content", severity: "High", confidence: "High",
    expected: "Forms on an HTTPS page submit only to HTTPS endpoints.",
    impact: "Form values may be exposed or altered in transit after leaving the HTTPS page.",
    remediation: "Serve the form destination over HTTPS and update the form action.",
    page, facts: { insecureFormCount: insecureForms },
  });
  if (externalResourcesWithoutIntegrity > 0) addObservation(context, {
    key: "web.content.external-integrity", title: "External script or stylesheet lacks Subresource Integrity",
    category: "Transport and embedded content", severity: "Low", confidence: "Medium",
    expected: "Third-party scripts and stylesheets use a reviewed integrity attribute where the resource supports stable content.",
    impact: "The page cannot verify a fixed hash before using the referenced third-party asset.",
    remediation: "Use Subresource Integrity for stable third-party assets, or self-host and pin reviewed dependencies.",
    page, facts: { externalResourcesWithoutIntegrity },
  });
  addCoverage(context, {
    key: "web.content", label: "HTML security and same-origin links", attempted: true,
    requestStatus: "response-received",
    status: parsed.truncated || cappedLinks > 0 ? "INCONCLUSIVE"
      : mixedContent > 0 || insecureForms > 0 || externalResourcesWithoutIntegrity > 0 ? "SUSPECTED" : "NOT REPRODUCED",
    details: "Parsed " + parsed.tokens.length + " bounded HTML tokens" + (parsed.truncated ? " (parser cap reached)" : "") +
      "; found " + parsedLinkCount + " links, " + offOriginLinks + " off-origin, " + queryLinks + " query-string, " +
      excludedActionLinks + " action-like, " + staticLinks + " static-file links skipped, and " + cappedLinks + " links beyond the per-page cap.",
  });
  return links;
}

function responseSurfaceChecks(context: ScanContext, page: URL, response: PublicPageResponse): void {
  if (response.status < 200 || response.status >= 300) return;
  const allowOrigin = responseHeader(response, "access-control-allow-origin");
  const allowCredentials = responseHeader(response, "access-control-allow-credentials");
  if (allowOrigin === "*") addObservation(context, {
    key: "web.cors.wildcard", title: "Wildcard CORS origin was observed",
    category: "Cross-origin policy", severity: "Info", confidence: "High", status: "OBSERVED",
    expected: "Cross-origin access is limited to the origins and resources the application intends to expose.",
    impact: "A wildcard permits any origin to read responses that browsers classify as public; it does not grant access to credentialed responses and no sensitive data access was tested.",
    remediation: "Review whether the resource is intentionally public. For sensitive resources, return an explicit origin allowlist and test preflight behavior.",
    page, facts: { wildcardOrigin: true, allowCredentials: allowCredentials?.toLowerCase() === "true", originHeaderSent: false },
  });
  addCoverage(context, {
    key: "web.cors", label: "CORS response policy", attempted: allowOrigin === "*",
    requestStatus: "response-received",
    status: allowOrigin === "*" ? "OBSERVED" : "NOT TESTED",
    details: allowOrigin === "*"
      ? "Wildcard Access-Control-Allow-Origin observed; no Origin header or credentials were sent, so resource read access was not tested."
      : "Origin reflection and preflight behavior were not tested; absence of a wildcard header is not a CORS pass.",
  });

  const cookies = response.cookieFlagCounts;
  if (cookies && cookies.setCookieCount > 0) {
    const missingSecure = Math.max(0, cookies.setCookieCount - cookies.secureCount);
    const missingHttpOnly = Math.max(0, cookies.setCookieCount - cookies.httpOnlyCount);
    const missingSameSite = Math.max(0, cookies.setCookieCount - cookies.sameSiteCount);
    if (missingSecure > 0) addObservation(context, {
      key: "web.cookies.secure", title: "One or more cookies omit the Secure attribute",
      category: "Cookie configuration", severity: "Medium", confidence: "High",
      expected: "Cookies intended for HTTPS use are marked Secure.",
      impact: "A cookie without Secure may be sent over an HTTP connection if one is reachable.",
      remediation: "Set Secure on cookies that should only travel over HTTPS; validate legacy and development flows separately.",
      page, facts: { cookieCount: cookies.setCookieCount, missingSecureCount: missingSecure },
    });
    if (missingHttpOnly > 0) addObservation(context, {
      key: "web.cookies.httponly", title: "One or more cookies omit HttpOnly",
      category: "Cookie configuration", severity: "Low", confidence: "Medium",
      expected: "Session cookies that do not require JavaScript access are marked HttpOnly.",
      impact: "Scripts running in the page may read cookies that are intended to protect a session; cookie purpose was not identified.",
      remediation: "Set HttpOnly on session cookies that do not need to be read by browser scripts.",
      page, facts: { cookieCount: cookies.setCookieCount, missingHttpOnlyCount: missingHttpOnly },
    });
    if (missingSameSite > 0) addObservation(context, {
      key: "web.cookies.samesite", title: "One or more cookies omit SameSite",
      category: "Cookie configuration", severity: "Low", confidence: "Medium",
      expected: "Cookies use an appropriate SameSite policy, with CSRF protections tested for the application.",
      impact: "Cross-site requests may include cookies depending on browser defaults and cookie purpose.",
      remediation: "Set SameSite=Lax or Strict when product flows allow; review cross-site login and embedding requirements before tightening.",
      page, facts: { cookieCount: cookies.setCookieCount, missingSameSiteCount: missingSameSite },
    });
    addCoverage(context, {
      key: "web.cookies", label: "Cookie security attributes", attempted: true,
      requestStatus: "response-received",
      status: missingSecure || missingHttpOnly || missingSameSite ? "SUSPECTED" : "NOT REPRODUCED",
      details: cookies.setCookieCount + " Set-Cookie header(s) counted; names and values were not retained.",
    });
  } else {
    addCoverage(context, {
      key: "web.cookies", label: "Cookie security attributes", attempted: true,
      requestStatus: "response-received", status: "NOT REPRODUCED",
      details: "No Set-Cookie headers were observed on this response.",
    });
  }

  const serverBanner = responseHeader(response, "server");
  const poweredBy = responseHeader(response, "x-powered-by");
  const exposesVersion = Boolean([serverBanner, poweredBy].some((value) => value && /\d+\.\d/.test(value)));
  if (exposesVersion) addObservation(context, {
    key: "web.headers.version-banner", title: "A response header exposes a software version",
    category: "Information exposure", severity: "Info", confidence: "High", status: "OBSERVED",
    expected: "Infrastructure headers disclose only details needed by clients.",
    impact: "Version strings can help an attacker identify software to research; no outdated component was verified.",
    remediation: "Remove unnecessary version details from Server or X-Powered-By headers where practical.",
    page, facts: { serverHeaderPresent: serverBanner !== null, poweredByHeaderPresent: poweredBy !== null },
  });
  addCoverage(context, {
    key: "web.headers.banner", label: "Software version disclosure", attempted: true,
    requestStatus: "response-received", status: exposesVersion ? "OBSERVED" : "NOT REPRODUCED",
    details: exposesVersion ? "A software-version pattern was present; header values are not stored." : "No numeric software-version pattern was observed in Server or X-Powered-By.",
  });
}

function makePageScope(scope: ScopeConfig, page: URL, remainingBytes: number): ScopeConfig {
  const configuredPageBytes = scope.budgets.maxWebScanResponseBytes ?? 2_000_000;
  const pageByteLimit = Math.max(1024, Math.min(2_000_000, configuredPageBytes, remainingBytes));
  return {
    ...scope,
    approvedServices: Array.from(new Set([...scope.approvedServices, "passive-public-review"])),
    publicReadOnlyPages: [page.href],
    budgets: {
      ...scope.budgets,
      maxRequestsPerAudit: Math.max(1, scope.budgets.maxRequestsPerAudit),
      maxPublicPages: Math.max(1, scope.budgets.maxPublicPages),
      maxPublicBytesPerPage: pageByteLimit,
      timeoutMs: Math.min(30_000, Math.max(scope.budgets.timeoutMs, scope.budgets.webScanTimeoutMs ?? 10_000)),
    },
  };
}

function safeTransportFailure(error: unknown): { message: string; requestStatus: "not-sent" | "unknown" } {
  const message = error instanceof Error ? error.message : "";
  if (/no request was sent|non-public|reserved address|invalid address/i.test(message)) {
    return { message: "DNS or scope validation blocked the request before a connection.", requestStatus: "not-sent" };
  }
  if (/timed out|timeout/i.test(message)) return { message: "The DNS lookup or HTTPS request timed out.", requestStatus: "unknown" };
  if (/cancel/i.test(message)) return { message: "The scan was cancelled.", requestStatus: "unknown" };
  if (/certificate|tls|ssl/i.test(message)) return { message: "HTTPS certificate validation failed.", requestStatus: "unknown" };
  return { message: "The HTTPS request failed before a usable page response was received.", requestStatus: "unknown" };
}
function aborted(signal?: AbortSignal): boolean { return Boolean(signal?.aborted); }
async function waitForDelay(delayMs: number, signal?: AbortSignal): Promise<boolean> {
  if (delayMs <= 0) return !aborted(signal);
  if (!signal) { await new Promise((resolve) => setTimeout(resolve, delayMs)); return true; }
  if (signal.aborted) return false;
  return await new Promise((resolve) => {
    const finish = (value: boolean): void => { clearTimeout(timer); signal.removeEventListener("abort", onAbort); resolve(value); };
    const timer = setTimeout(() => finish(true), delayMs);
    const onAbort = (): void => finish(false);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}
function validBudget(value: number | undefined, fallback: number, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value)) return fallback;
  return Math.max(minimum, Math.min(maximum, Number(value)));
}

/** Crawl and assess unauthenticated same-origin HTTPS pages without sending test payloads. */
export async function executeWebScan(options: WebScanOptions): Promise<AuditResult & { cancelled?: boolean }> {
  const { scope, signal } = options;
  if ((scope.mode !== "scanner" && scope.mode !== "laboratory") || !scope.approvedServices.includes("web-scan")) {
    throw new Error('Scope must approve the "web-scan" service in scanner mode.');
  }
  const target = parseWebScanTarget(options.target);
  const maxPagesBudget = validBudget(scope.budgets.maxWebScanPages, 100, 1, 500);
  const maxDepthBudget = validBudget(scope.budgets.maxWebScanDepth, 4, 0, 8);
  const maxRequests = validBudget(scope.budgets.maxWebScanRequests, 250, 1, 2000);
  const maxDurationMs = validBudget(scope.budgets.maxWebScanDurationMs, 180_000, 1000, 300_000);
  const maxBytes = validBudget(scope.budgets.maxWebScanBytes, 50_000_000, 1024, 500_000_000);
  const maxPages = validBudget(options.maxPages, maxPagesBudget, 1, maxPagesBudget);
  const maxDepth = validBudget(options.maxDepth, maxDepthBudget, 0, maxDepthBudget);
  const delayMs = validBudget(scope.budgets.webScanDelayMs, 100, 0, 5000);
  const transport = options.transport;

  const context: ScanContext = { target, findings: new Map(), coverage: [] };
  const queue: QueuedPage[] = [{ url: target, depth: 0 }];
  const queued = new Set([target.href]);
  const visited = new Set<string>();
  const startedAt = performance.now();
  let requests = 0;
  let responseBytes = 0;
  let totalLinks = 0;
  let stoppedReason = "";
  let tlsValidatedResponses = 0;
  const crawlStats: CrawlStats = { offOrigin: 0, query: 0, action: 0, static: 0, frontier: 0 };

  while (queue.length > 0) {
    if (aborted(signal)) { stoppedReason = "cancelled"; break; }
    if (performance.now() - startedAt >= maxDurationMs) { stoppedReason = "duration budget reached"; break; }
    if (requests >= maxPages) { stoppedReason = "page budget reached"; break; }
    if (requests >= maxRequests) { stoppedReason = "request budget reached"; break; }
    if (responseBytes >= maxBytes) { stoppedReason = "total response-byte budget reached"; break; }
    if (maxBytes - responseBytes < 1024) { stoppedReason = "remaining response-byte budget is below the minimum request size"; break; }
    const current = queue.shift();
    if (!current || visited.has(current.url.href)) continue;
    visited.add(current.url.href);
    requests += 1;
    const suffix = "page-" + requests;
    const remainingDuration = Math.max(1, maxDurationMs - (performance.now() - startedAt));
    const requestScope = makePageScope(scope, current.url, maxBytes - responseBytes);
    const requestSignal = signal
      ? AbortSignal.any([signal, AbortSignal.timeout(Math.min(requestScope.budgets.timeoutMs, remainingDuration))])
      : AbortSignal.timeout(Math.min(requestScope.budgets.timeoutMs, remainingDuration));

    let response: PublicPageResponse;
    try {
      response = transport
        ? await transport(current.url, requestScope, requestSignal)
        : await passivePublicGet(current.url, makePageScope(scope, current.url, maxBytes - responseBytes), undefined, requestSignal);
      if (aborted(signal)) { stoppedReason = "cancelled"; break; }
    } catch (error) {
      const failure = safeTransportFailure(error);
      addCoverage(context, {
        key: "web.fetch." + suffix, label: "Fetch " + safeUrl(current.url), attempted: true,
        requestStatus: failure.requestStatus, status: "NOT TESTED", error: failure.message,
      });
      if (aborted(signal)) { stoppedReason = "cancelled"; break; }
      if (!(await waitForDelay(delayMs, signal))) { stoppedReason = "cancelled"; break; }
      continue;
    }

    responseBytes += response.bytes;
    if (response.tlsCertificateValidation === "validated") tlsValidatedResponses += 1;
    const media = reportMediaType(response);
    addCoverage(context, {
      key: "web.fetch." + suffix, label: "Fetch " + safeUrl(current.url), attempted: true,
      requestStatus: "response-received",
      status: response.status >= 200 && response.status < 400 ? "NOT REPRODUCED" : "INCONCLUSIVE",
      details: "HTTP " + response.status + "; " + media + "; " + response.bytes + " response body bytes processed in memory; " +
        Math.round(response.elapsedMs) + " ms. Redirects and response bodies are not saved.",
    });

    securityHeaderChecks(context, current.url, response);
    responseSurfaceChecks(context, current.url, response);
    let links: URL[] = [];
    if (response.status >= 200 && response.status < 300 && isHtml(response)) {
      links = contentChecks(context, current.url, response, crawlStats);
    } else {
      addCoverage(context, {
        key: "web.content", label: "HTML security and same-origin links", attempted: false,
        requestStatus: "response-received", status: "NOT TESTED", error: "The response was not a successful HTML page.",
      });
    }
    totalLinks += links.length;
    if (current.depth < maxDepth) {
      for (const link of links) {
        if (visited.has(link.href) || queued.has(link.href)) continue;
        if (stateChangingPath(link)) { crawlStats.action += 1; continue; }
        if (isStaticPath(link)) { crawlStats.static += 1; continue; }
        if (queue.length >= MAX_FRONTIER) { crawlStats.frontier += 1; continue; }
        queue.push({ url: link, depth: current.depth + 1 });
        queued.add(link.href);
      }
    }
    if (!(await waitForDelay(delayMs, signal))) { stoppedReason = "cancelled"; break; }
  }

  if (stoppedReason === "cancelled") {
    addCoverage(context, { key: "web.execution", label: "Web scan execution", attempted: false, status: "NOT TESTED", error: "Cancelled by the operator; prior observations are retained and remaining pages were not requested." });
  } else if (stoppedReason) {
    addCoverage(context, { key: "web.execution", label: "Web scan execution", attempted: false, status: "INCONCLUSIVE", details: stoppedReason });
  } else {
    addCoverage(context, { key: "web.execution", label: "Web scan execution", attempted: true, status: "NOT REPRODUCED", details: "The discovered in-scope queue completed within the selected page, request, duration, and byte budgets." });
  }
  addCoverage(context, {
    key: "web.crawl", label: "Same-origin crawl coverage", attempted: true,
    status: stoppedReason ? "INCONCLUSIVE" : "NOT REPRODUCED",
    details: visited.size + " unique route(s) attempted; " + queue.length + " queued route(s) not requested; " +
      totalLinks + " candidate same-origin HTML links. " + crawlStats.offOrigin + " off-origin, " + crawlStats.query +
      " query-string, " + crawlStats.action + " action-like, " + crawlStats.static +
      " static-file, and " + crawlStats.frontier + " frontier-capped links skipped. " + requests + "/" + maxRequests +
      " requests and " + responseBytes + "/" + maxBytes + " response body bytes processed in memory. Bodies are discarded after parsing; a received network chunk may exceed the remaining in-memory cap. Depth " + maxDepth +
      "; duration " + Math.round(performance.now() - startedAt) + " ms/" + maxDurationMs + " ms.",
  });
  if (tlsValidatedResponses > 0) {
    addObservation(context, {
      key: "web.transport.tls", title: "HTTPS certificate and hostname validation succeeded",
      category: "Transport security", severity: "Info", confidence: "High", status: "OBSERVED",
      expected: "The HTTPS certificate chain is trusted and matches the target hostname.",
      impact: "TLS validation succeeded for the scanned connections; this does not assess certificate expiry policy or all TLS configuration.",
      remediation: "No action is indicated by this observation. Review certificate lifecycle and TLS configuration through your normal operations process.",
      page: target, facts: { validatedHttpsResponses: tlsValidatedResponses },
    });
  }
  addCoverage(context, {
    key: "web.tls", label: "HTTPS certificate and hostname validation", attempted: requests > 0,
    status: tlsValidatedResponses > 0 ? "OBSERVED" : "NOT TESTED",
    requestStatus: tlsValidatedResponses > 0 ? "response-received" : requests > 0 ? "unknown" : "not-sent",
    details: tlsValidatedResponses
      ? "TLS certificate chain and hostname validation succeeded for " + tlsValidatedResponses +
        " response(s). Cipher suite, protocol support, and certificate lifecycle policy were not assessed."
      : "No validated HTTPS response was received.",
  });
  const findings = Array.from(context.findings.values()).map((item) => makeFinding(context, item));
  return { findings, coverage: context.coverage, cancelled: stoppedReason === "cancelled" };
}

export function scannerBudgetSummary(scope: ScopeConfig): Record<string, number> {
  return {
    maxPages: validBudget(scope.budgets.maxWebScanPages, 100, 1, 500),
    maxDepth: validBudget(scope.budgets.maxWebScanDepth, 4, 0, 8),
    maxRequests: validBudget(scope.budgets.maxWebScanRequests, 250, 1, 2000),
    maxDurationMs: validBudget(scope.budgets.maxWebScanDurationMs, 180_000, 1000, 300_000),
    maxBytes: validBudget(scope.budgets.maxWebScanBytes, 50_000_000, 1024, 500_000_000),
  };
}
