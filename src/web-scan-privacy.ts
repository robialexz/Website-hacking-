import type { AuditFinding } from "./audit.ts";

const BOOLEAN_FACTS = new Set([
  "hstsPresent", "cspPresent", "usesUnsafeSource", "cspFrameAncestors", "permissionsPolicyPresent",
  "wildcardOrigin", "allowCredentials", "originHeaderSent", "serverHeaderPresent", "poweredByHeaderPresent",
]);
const NUMBER_FACTS = new Set([
  "hstsMaxAge", "directiveCount", "policyLength", "insecureResourceReferences", "insecureFormCount",
  "externalResourcesWithoutIntegrity", "cookieCount", "missingSecureCount", "missingHttpOnlyCount",
  "missingSameSiteCount", "validatedHttpsResponses",
]);
const REFERRER_POLICIES = new Set([
  "no-referrer", "no-referrer-when-downgrade", "same-origin", "origin", "strict-origin",
  "origin-when-cross-origin", "strict-origin-when-cross-origin", "unsafe-url",
]);
const CSP_DIRECTIVES = new Set(["script-src", "object-src", "base-uri", "frame-ancestors"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function safeOrigin(target: string): string {
  try {
    const parsed = new URL(target);
    if (parsed.protocol !== "https:" || parsed.username || parsed.password) return "unknown target";
    return parsed.origin;
  } catch {
    return "unknown target";
  }
}

export function sanitizeWebScanChecks(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) return {};
  const output: Record<string, unknown> = {};
  for (const [key, fact] of Object.entries(value)) {
    if (BOOLEAN_FACTS.has(key) && typeof fact === "boolean") {
      output[key] = fact;
    } else if (NUMBER_FACTS.has(key) && typeof fact === "number" && Number.isSafeInteger(fact) && fact >= 0) {
      output[key] = fact;
    } else if (key === "hstsMaxAge" && fact === "invalid-or-missing") {
      output[key] = fact;
    } else if (key === "missingDefensiveDirectives" && Array.isArray(fact)) {
      output[key] = fact.filter((item): item is string => typeof item === "string" && CSP_DIRECTIVES.has(item));
    } else if (key === "xContentTypeOptions" && typeof fact === "string") {
      const normalized = fact.toLowerCase();
      output[key] = normalized === "absent" || normalized === "nosniff" ? normalized : "invalid";
    } else if (key === "referrerPolicy" && typeof fact === "string") {
      const normalized = fact.toLowerCase().split(",").map((item) => item.trim()).filter(Boolean).at(-1) || "";
      output[key] = normalized === "absent" || REFERRER_POLICIES.has(normalized) ? normalized : "invalid";
    } else if (key === "xFrameOptions" && typeof fact === "string") {
      const normalized = fact.toLowerCase();
      output[key] = normalized === "absent" || normalized === "deny" || normalized === "sameorigin" ? normalized : "invalid";
    }
  }
  return output;
}

/** Remove route-level and response-header values before a web finding is written to local history. */
export function sanitizeWebScanFinding(finding: AuditFinding): AuditFinding {
  const rawWebScanEvidence: unknown = finding.evidence.webScan;
  const webScan: Record<string, unknown> = isRecord(rawWebScanEvidence) ? rawWebScanEvidence : {};
  const rawPageCount = webScan.pageCount;
  const fromActual = /Observed on (\d+) page\(s\)\./.exec(finding.actual)?.[1];
  const pageCount = typeof rawPageCount === "number" && Number.isSafeInteger(rawPageCount) && rawPageCount >= 0
    ? rawPageCount
    : fromActual ? Number(fromActual) : 1;
  const origin = safeOrigin(finding.target);

  return {
    ...finding,
    target: origin,
    endpoint: origin,
    actual: `Observed on ${pageCount} page(s). Sample paths omitted for privacy.`,
    reproduction: [
      "Review the aggregate observation in the technical report; route paths are omitted.",
      "Validate behavior in the application's own test environment before changing policy.",
    ],
    evidence: {
      webScan: {
        pageCount,
        samplePaths: [],
        checks: sanitizeWebScanChecks(webScan.checks),
      },
      note: "Aggregate observations only; web-scan paths were omitted from local history.",
    },
  };
}
