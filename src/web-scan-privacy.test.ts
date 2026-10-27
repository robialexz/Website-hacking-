import assert from "node:assert/strict";
import { test } from "node:test";

import type { AuditFinding } from "./audit.ts";
import { sanitizeWebScanFinding } from "./web-scan-privacy.ts";

test("persisted web-scan findings omit route paths and retain aggregate checks", () => {
  const marker = "account-session-7f2a91";
  const origin = "https://scan.example.net";
  const finding: AuditFinding = {
    key: "web.headers.csp",
    title: "Content Security Policy missing or weak",
    category: "Browser security headers",
    severity: "Medium",
    status: "SUSPECTED",
    confidence: "High",
    target: `${origin}/private/${marker}`,
    endpoint: `/private/${marker}`,
    component: "HTTP response or rendered HTML",
    preconditions: "The affected route was fetched once.",
    expected: "A policy is returned.",
    actual: `Observed on 3 page(s). Sample paths: /private/${marker}.`,
    reproduction: [`Review /private/${marker}.`],
    impact: "A policy may reduce injection impact.",
    severityRationale: "Triage estimate.",
    remediation: "Configure a policy.",
    evidence: {
      webScan: {
        pageCount: 3,
        samplePaths: [`/private/${marker}`],
        checks: {
          cspPresent: false,
          directiveCount: 0,
          xContentTypeOptions: marker,
          referrerPolicy: marker,
          xFrameOptions: marker,
          unknownHeaderValue: marker,
        },
      },
      note: `Sample /private/${marker}`,
    },
    retestStatus: "NOT RETESTED",
  };

  const stored = sanitizeWebScanFinding(finding);

  assert.doesNotMatch(JSON.stringify(stored), new RegExp(marker));
  assert.equal(stored.target, origin);
  assert.equal(stored.endpoint, origin);
  assert.equal(stored.actual, "Observed on 3 page(s). Sample paths omitted for privacy.");
  assert.deepEqual(stored.evidence, {
    webScan: {
      pageCount: 3,
      samplePaths: [],
      checks: { cspPresent: false, directiveCount: 0, xContentTypeOptions: "invalid", referrerPolicy: "invalid", xFrameOptions: "invalid" },
    },
    note: "Aggregate observations only; web-scan paths were omitted from local history.",
  });
  assert.deepEqual(stored.reproduction, [
    "Review the aggregate observation in the technical report; route paths are omitted.",
    "Validate behavior in the application's own test environment before changing policy.",
  ]);
});
