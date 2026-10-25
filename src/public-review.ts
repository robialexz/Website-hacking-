import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";

import type { AuditEvidence, AuditFinding, AuditResult, CoverageItem, Severity } from "./audit.ts";
import { assertPublicPageInScope } from "./scope.ts";
import type { ScopeConfig } from "./scope.ts";

export const PUBLIC_REVIEW_CHECKS_PER_PAGE = 4;

export interface PublicPageResponse {
  readonly status: number;
  readonly headers: Headers;
  readonly body: string;
  readonly bytes: number;
  readonly elapsedMs: number;
}

export type PublicPageTransport = (url: URL, scope: ScopeConfig) => Promise<PublicPageResponse>;

interface PassivePublicGetDependencies {
  resolveAddress: typeof resolvePinnedPublicAddress;
  makeRequest: typeof httpsRequest;
}

interface PublicReviewOptions {
  scope: ScopeConfig;
  transport?: PublicPageTransport;
}

const SAFE_RESPONSE_HEADERS = [
  "content-type",
  "content-length",
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
] as const;

const REQUIRED_SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
] as const;

function isPublicIpv4(address: string): boolean {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const [a, b, c] = parts;
  if (
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 192 && b === 88 && c === 99) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  ) return false;
  return true;
}

/** Return true only for global unicast addresses; special, private, and reserved ranges are denied. */
export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return isPublicIpv4(address);
  if (family !== 6) return false;
  const normalized = address.toLowerCase().split("%")[0];
  if (normalized === "::" || normalized === "::1" || normalized.startsWith("::ffff:")) return false;
  const hextets = normalized.split(":");
  const firstHextet = Number.parseInt(hextets[0] || "0", 16);
  const secondHextet = Number.parseInt(hextets[1] || "0", 16);
  if (firstHextet < 0x2000 || firstHextet > 0x3fff) return false;
  if (
    (firstHextet === 0x2001 && (secondHextet <= 0x01ff || secondHextet === 0x0db8)) ||
    firstHextet === 0x2002 ||
    firstHextet === 0x3fff
  ) return false;
  return true;
}

function timeoutPromise<T>(promise: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    promise.then(
      (value) => { clearTimeout(timer); resolve(value); },
      (error) => { clearTimeout(timer); reject(error); },
    );
  });
}

async function resolvePinnedPublicAddress(hostname: string, timeoutMs: number): Promise<{ address: string; family: number }> {
  if (isIP(hostname) !== 0) throw new Error("Public review requires a DNS hostname, not an IP address.");
  const records = await timeoutPromise(dnsLookup(hostname, { all: true, verbatim: true }), timeoutMs, "DNS resolution timed out.");
  if (!records.length || records.some((record) => !isPublicAddress(record.address))) {
    throw new Error("DNS returned a non-public or reserved address; no request was sent.");
  }
  return records[0];
}

function safeHeadersFromResponse(headers: Record<string, string | string[] | undefined>): Headers {
  const safe = new Headers();
  for (const name of SAFE_RESPONSE_HEADERS) {
    const value = headers[name];
    if (typeof value === "string") safe.set(name, value.slice(0, 400));
    else if (Array.isArray(value)) safe.set(name, value.join(", ").slice(0, 400));
  }
  return safe;
}

function contentType(headers: Headers): string {
  return headers.get("content-type") || "unknown";
}

function isHtml(headers: Headers): boolean {
  const type = contentType(headers).toLowerCase();
  return type.includes("text/html") || type.includes("application/xhtml+xml");
}

/** One GET to one exact scope entry. The DNS answer is checked and pinned to the HTTPS connection. */
export async function passivePublicGet(
  value: string | URL,
  scope: ScopeConfig,
  dependencies: PassivePublicGetDependencies = { resolveAddress: resolvePinnedPublicAddress, makeRequest: httpsRequest },
): Promise<PublicPageResponse> {
  const url = assertPublicPageInScope(value, scope);
  if (!scope.approvedServices.includes("passive-public-review")) {
    throw new Error('Scope must approve the "passive-public-review" service');
  }
  const startedAt = Date.now();
  const timeoutMs = scope.budgets.timeoutMs;
  const address = await dependencies.resolveAddress(url.hostname, timeoutMs);
  const remainingMs = Math.max(1, timeoutMs - (Date.now() - startedAt));
  const maxBytes = scope.budgets.maxPublicBytesPerPage;

  return new Promise((resolve, reject) => {
    let settled = false;
    let bodyBytes = 0;
    const chunks: Buffer[] = [];
    let totalTimer: ReturnType<typeof setTimeout>;

    const finish = (error?: Error, response?: PublicPageResponse): void => {
      if (settled) return;
      settled = true;
      clearTimeout(totalTimer);
      if (error) reject(error);
      else if (response) resolve(response);
      else reject(new Error("Public page request ended without a response."));
    };

    const request = dependencies.makeRequest(url, {
      method: "GET",
      agent: false,
      maxHeaderSize: 16 * 1024,
      servername: url.hostname,
      lookup: (hostname, lookupOptions, callback) => {
        if (hostname.toLowerCase() !== url.hostname.toLowerCase()) {
          const error = new Error("Unexpected hostname during the pinned HTTPS connection.");
          if (lookupOptions?.all) callback(error, []);
          else callback(error, "", 0);
          return;
        }
        if (lookupOptions?.all) callback(null, [address]);
        else callback(null, address.address, address.family);
      },
      headers: {
        accept: "text/html,application/xhtml+xml",
        "accept-encoding": "identity",
        "user-agent": "RevenueGuardLab/0.2 public-page-review",
      },
    }, (response) => {
      const responseHeaders = safeHeadersFromResponse(response.headers);
      const status = response.statusCode || 0;
      const elapsedMs = Date.now() - startedAt;
      const encoding = (response.headers["content-encoding"] || "").toString().toLowerCase();
      const claimedLength = Number(response.headers["content-length"] || 0);

      if (encoding && encoding !== "identity") {
        response.destroy();
        finish(new Error("Compressed public responses are not accepted by this bounded review."));
        return;
      }
      if (claimedLength > maxBytes) {
        response.destroy();
        finish(new Error("Public page exceeded the configured response byte limit."));
        return;
      }
      if (status < 200 || status >= 300 || !isHtml(responseHeaders)) {
        response.destroy();
        finish(undefined, { status, headers: responseHeaders, body: "", bytes: 0, elapsedMs });
        return;
      }

      response.on("data", (chunk: Buffer | string) => {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        bodyBytes += buffer.byteLength;
        if (bodyBytes > maxBytes) {
          response.destroy();
          request.destroy(new Error("Public page exceeded the configured response byte limit."));
          finish(new Error("Public page exceeded the configured response byte limit."));
          return;
        }
        chunks.push(buffer);
      });
      response.on("end", () => {
        finish(undefined, {
          status,
          headers: responseHeaders,
          body: Buffer.concat(chunks).toString("utf8"),
          bytes: bodyBytes,
          elapsedMs: Date.now() - startedAt,
        });
      });
      response.on("error", (error) => finish(error instanceof Error ? error : new Error("Public page response failed.")));
    });

    totalTimer = setTimeout(() => request.destroy(new Error("Public page request timed out.")), remainingMs);
    request.setTimeout(remainingMs, () => request.destroy(new Error("Public page request timed out.")));
    request.on("error", (error) => finish(error instanceof Error ? error : new Error("Public page request failed.")));
    request.end();
  });
}

function decodeHtmlText(value: string): string {
  const decodeCodePoint = (code: number): string => Number.isInteger(code) && code >= 0 && code <= 0x10ffff && !(code >= 0xd800 && code <= 0xdfff)
    ? String.fromCodePoint(code)
    : "\uFFFD";
  return value.replace(/<[^>]*>/g, " ").replace(/&amp;/gi, "&").replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">").replace(/&quot;/gi, "\"").replace(/&#39;|&apos;/gi, "'")
    .replace(/&#(\d+);/g, (_match, code: string) => decodeCodePoint(Number(code)))
    .replace(/&#x([\da-f]+);/gi, (_match, code: string) => decodeCodePoint(Number.parseInt(code, 16)))
    .replace(/\s+/g, " ").trim();
}

function attribute(tag: string, name: string): string | undefined {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`\\b${escaped}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i").exec(tag);
  return match?.[1] ?? match?.[2] ?? match?.[3];
}

function pageMetadata(html: string): { titleLength: number; hasTitle: boolean; descriptionLength: number; hasDescription: boolean; h1Count: number } {
  const titleMatch = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(html);
  const title = titleMatch ? decodeHtmlText(titleMatch[1]) : "";
  const metaTags = html.match(/<meta\b[^>]*>/gi) || [];
  const descriptionTag = metaTags.find((tag) => attribute(tag, "name")?.toLowerCase() === "description");
  const description = descriptionTag ? decodeHtmlText(attribute(descriptionTag, "content") || "") : "";
  return {
    titleLength: title.length,
    hasTitle: title.length > 0,
    descriptionLength: description.length,
    hasDescription: description.length > 0,
    h1Count: (html.match(/<h1\b[^>]*>/gi) || []).length,
  };
}

function imageAccessibility(html: string): { imageCount: number; missingAltCount: number } {
  const images = html.match(/<img\b[^>]*>/gi) || [];
  const missingAltCount = images.filter((tag) => attribute(tag, "alt") === undefined).length;
  return { imageCount: images.length, missingAltCount };
}

function pageEvidence(url: URL, response: PublicPageResponse): AuditEvidence {
  const headers: Record<string, string> = {};
  for (const name of SAFE_RESPONSE_HEADERS) {
    const value = response.headers.get(name);
    if (value) headers[name] = value;
  }
  return {
    page: {
      url: url.href,
      status: response.status,
      contentType: contentType(response.headers),
      elapsedMs: response.elapsedMs,
      bytes: response.bytes,
      headers,
    },
    note: "One unauthenticated GET to an explicitly scoped page. Redirects were not followed; HTML was parsed in memory and the full body was not stored.",
  };
}

function makePublicFinding(input: {
  key: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: "High" | "Medium" | "Low";
  target: string;
  endpoint: string;
  expected: string;
  actual: string;
  impact: string;
  remediation: string;
  evidence: AuditEvidence;
}): AuditFinding {
  return {
    ...input,
    status: "SUSPECTED",
    component: input.endpoint,
    preconditions: "The page was fetched once without credentials using an exact HTTPS URL from publicReadOnlyPages.",
    reproduction: ["Review the recorded page response and the listed observation.", "Validate the recommendation in the site's own test or authoring environment before making changes."],
    severityRationale: "This is a passive page-level observation. It does not demonstrate an exploitable vulnerability or quantify business impact.",
    retestStatus: "NOT RETESTED",
  };
}

function coverage(input: Omit<CoverageItem, "controlVerified">): CoverageItem {
  return { ...input, controlVerified: false };
}

/** Perform one low-impact unauthenticated GET per exact approved page; do not crawl, follow redirects, or submit forms. */
export async function executePublicReview(options: PublicReviewOptions): Promise<AuditResult> {
  const { scope } = options;
  if (scope.mode !== "laboratory" || !scope.approvedServices.includes("passive-public-review")) {
    throw new Error('Scope must approve the "passive-public-review" service in laboratory mode');
  }
  if (scope.publicReadOnlyPages.length === 0) {
    throw new Error("Add exact public HTTPS pages to publicReadOnlyPages in the local scope.json before starting a passive review.");
  }
  if (scope.publicReadOnlyPages.length > scope.budgets.maxPublicPages) {
    throw new Error("The configured public page list exceeds its request budget.");
  }

  const transport = options.transport ?? passivePublicGet;
  const findings: AuditFinding[] = [];
  const coverageItems: CoverageItem[] = [];

  for (let index = 0; index < scope.publicReadOnlyPages.length; index += 1) {
    const pageValue = scope.publicReadOnlyPages[index];
    const url = assertPublicPageInScope(pageValue, scope);
    const suffix = `page-${index + 1}`;
    let response: PublicPageResponse;
    try {
      response = await transport(url, scope);
    } catch (error) {
      const message = error instanceof Error ? error.message.slice(0, 240) : "Request failed.";
      coverageItems.push(coverage({ key: `public.fetch.${suffix}`, label: `Fetch approved page ${index + 1}`, attempted: true, status: "NOT TESTED", error: message }));
      for (const [key, label] of [["headers", "Security response headers"], ["metadata", "Page metadata"], ["accessibility", "Image alt text"]] as const) {
        coverageItems.push(coverage({ key: `public.${key}.${suffix}`, label: `${label} · page ${index + 1}`, attempted: false, status: "NOT TESTED", error: "No page response was available." }));
      }
      continue;
    }

    const evidence = pageEvidence(url, response);
    const responseDetails = `HTTP ${response.status}; ${response.bytes} body bytes read; ${response.elapsedMs} ms; ${contentType(response.headers)}.`;
    coverageItems.push(coverage({ key: `public.fetch.${suffix}`, label: `Fetch approved page ${index + 1}`, attempted: true, status: "NOT REPRODUCED", details: `${responseDetails} One request only; no redirects or page assets were fetched.` }));

    const isSuccessfulHtml = response.status >= 200 && response.status < 300 && isHtml(response.headers) && response.body.length > 0;
    const missingHeaders = REQUIRED_SECURITY_HEADERS.filter((name) => !response.headers.has(name));
    if (response.status >= 200 && response.status < 300 && missingHeaders.length > 0) {
      coverageItems.push(coverage({ key: `public.headers.${suffix}`, label: `Security response headers · page ${index + 1}`, attempted: true, status: "SUSPECTED", details: `Missing: ${missingHeaders.join(", ")}. Header recommendations depend on the site's architecture.` }));
      findings.push(makePublicFinding({
        key: "public.missing-security-headers",
        title: "Public page is missing baseline security response headers",
        category: "Web configuration",
        severity: "Low",
        confidence: "High",
        target: url.origin,
        endpoint: url.pathname,
        expected: "Consider sending browser security headers appropriate to the site's architecture.",
        actual: `The HTTPS response did not include: ${missingHeaders.join(", ")}.`,
        impact: "These headers add browser-side defense in depth. Their absence alone does not establish an exploitable vulnerability.",
        remediation: "Review a suitable Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy for this site.",
        evidence,
      }));
    } else {
      coverageItems.push(coverage({
        key: `public.headers.${suffix}`,
        label: `Security response headers · page ${index + 1}`,
        attempted: response.status >= 200 && response.status < 300,
        status: response.status >= 200 && response.status < 300 ? "NOT REPRODUCED" : "NOT TESTED",
        details: response.status >= 200 && response.status < 300 ? "All listed baseline headers were present." : "The response was not a 2xx page; headers were not assessed as a page configuration.",
        ...(response.status >= 200 && response.status < 300 ? {} : { error: "Response status was outside the range used for page checks; redirects were not followed." }),
      }));
    }

    if (!isSuccessfulHtml) {
      for (const [key, label] of [["metadata", "Page metadata"], ["accessibility", "Image alt text"]] as const) {
        coverageItems.push(coverage({ key: `public.${key}.${suffix}`, label: `${label} · page ${index + 1}`, attempted: false, status: "NOT TESTED", error: "Response was not a non-empty 2xx HTML page; no redirect or follow-up request was made." }));
      }
      continue;
    }

    const metadata = pageMetadata(response.body);
    const metadataIssues = [
      !metadata.hasTitle ? "missing title" : metadata.titleLength > 70 ? "title longer than 70 characters" : "",
      !metadata.hasDescription ? "missing meta description" : "",
      metadata.h1Count !== 1 ? `found ${metadata.h1Count} H1 headings` : "",
    ].filter(Boolean);
    if (metadataIssues.length > 0) {
      coverageItems.push(coverage({ key: `public.metadata.${suffix}`, label: `Page metadata · page ${index + 1}`, attempted: true, status: "SUSPECTED", details: `${metadataIssues.join("; ")}. Title length ${metadata.titleLength}; description length ${metadata.descriptionLength}; H1 count ${metadata.h1Count}.` }));
      findings.push(makePublicFinding({
        key: "public.page-metadata",
        title: "Public page has incomplete or unclear search metadata",
        category: "Search visibility",
        severity: "Low",
        confidence: "Medium",
        target: url.origin,
        endpoint: url.pathname,
        expected: "Use a concise page title, a meaningful meta description, and a clear primary heading where appropriate.",
        actual: `Observed ${metadataIssues.join("; ")}. The page text itself was not stored in the report.`,
        impact: "Search snippets and page structure may be less clear. This observation does not predict ranking or traffic.",
        remediation: "Review the page title, meta description, and main heading in the site's content management workflow.",
        evidence,
      }));
    } else {
      coverageItems.push(coverage({ key: `public.metadata.${suffix}`, label: `Page metadata · page ${index + 1}`, attempted: true, status: "NOT REPRODUCED", details: `Title length ${metadata.titleLength}; description length ${metadata.descriptionLength}; one H1 heading.` }));
    }

    const accessibility = imageAccessibility(response.body);
    if (accessibility.missingAltCount > 0) {
      coverageItems.push(coverage({ key: `public.accessibility.${suffix}`, label: `Image alt text · page ${index + 1}`, attempted: true, status: "SUSPECTED", details: `${accessibility.missingAltCount} of ${accessibility.imageCount} image tags lacked an alt attribute.` }));
      findings.push(makePublicFinding({
        key: "public.images-missing-alt",
        title: "Some page images have no alt attribute",
        category: "Accessibility",
        severity: "Low",
        confidence: "Medium",
        target: url.origin,
        endpoint: url.pathname,
        expected: "Provide descriptive alternative text for informative images; use an empty alt value for decorative images.",
        actual: `${accessibility.missingAltCount} of ${accessibility.imageCount} observed image tags lacked an alt attribute.`,
        impact: "Some visitors using assistive technology may not receive the image's information.",
        remediation: "Review each image in context and add suitable alt text or an explicit empty alt attribute when the image is decorative.",
        evidence,
      }));
    } else {
      coverageItems.push(coverage({ key: `public.accessibility.${suffix}`, label: `Image alt text · page ${index + 1}`, attempted: true, status: "NOT REPRODUCED", details: `${accessibility.imageCount} image tag(s) observed; each had an alt attribute.` }));
    }
  }

  return { findings, coverage: coverageItems };
}
