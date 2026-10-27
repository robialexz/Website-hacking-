import assert from "node:assert/strict";
import { test } from "node:test";

import { executeWebScan, parseWebScanTarget } from "./web-scan.ts";
import type { PublicPageResponse } from "./public-review.ts";
import type { ScopeConfig } from "./scope.ts";

function scannerScope(budgets: Partial<ScopeConfig["budgets"]> = {}): ScopeConfig {
  return {
    mode: "scanner",
    approvedOrigins: ["http://127.0.0.1:8765"],
    approvedPathPrefixes: ["/lab/"],
    approvedServices: ["revenueguard-demo", "web-scan"],
    sourceDirectories: ["./src"],
    testAccounts: [],
    approvedCallbacks: [],
    publicReadOnlyPages: [],
    resetProcedure: "Synthetic fixture only.",
    budgets: {
      maxRequestsPerAudit: 32,
      maxConcurrentAudits: 1,
      timeoutMs: 2500,
      maxSourceFiles: 500,
      maxSourceBytes: 2_000_000,
      maxPublicPages: 4,
      maxPublicBytesPerPage: 1_000_000,
      maxWebScanRequests: 10,
      maxWebScanPages: 10,
      maxWebScanDepth: 4,
      maxWebScanDurationMs: 10_000,
      maxWebScanBytes: 50_000,
      maxWebScanResponseBytes: 20_000,
      webScanTimeoutMs: 2_500,
      webScanDelayMs: 0,
      ...budgets,
    },
  };
}

function response(body: string, headers: Record<string, string> = {}, extra: Partial<PublicPageResponse> = {}): PublicPageResponse {
  return {
    status: 200,
    headers: new Headers({ "content-type": "text/html; charset=utf-8", ...headers }),
    body,
    bodyStatus: "complete",
    bytes: Buffer.byteLength(body),
    elapsedMs: 2,
    ...extra,
  };
}

test("accepts only public HTTPS target URLs without secrets or action-like paths", () => {
  assert.equal(parseWebScanTarget("https://example.com/app/").href, "https://example.com/app/");
  for (const target of [
    "http://example.com/",
    "https://user:secret@example.com/",
    "https://example.com:8443/",
    "https://example.com/?token=secret",
    "https://example.com/#fragment",
    "https://127.0.0.1/",
    "https://localhost/",
    "https://example.com/logout",
    "https://example.com/logout;jsessionid=abc123",
    "https://example.com/login/a1B2c3D4",
    "https://example.com/magic-link/ab12cd34ef",
    "https://example.com/r/a1B2c3D4",
    "https://example.com/r/AbCdEfGhIjKlMnOpQrStUvWx",
    "https://example.com/%75nsubscribe/opaque-token",
    "https://example.com/a%2fb",
  ]) assert.throws(() => parseWebScanTarget(target), /HTTPS|target|path|URL/i, target);
});

test("crawls bounded same-origin links and records path-free passive observations", async () => {
  const visited: string[] = [];
  const root = "https://example.com/";
  const body = `<a href="/about">About</a>
    <a href="/users/123456789012/profile">Profile</a>
    <a href="https://outside.example/">External</a>
    <a href="/?token=secret">Query</a>
    <a href="/logout">Action</a>
    <a href="/%75nsubscribe/opaque-token">Encoded action</a>
    <a href="/account/token/opaque-token">Token route</a>
    <a href="/logout;jsessionid=secret-token">Matrix action</a>
    <a href="/login/a1B2c3D4">Login token</a>
    <a href="/magic-link/ab12cd34ef">Magic link</a>
    <a href="/r/a1B2c3D4">Opaque route token</a>
    <a href="/r/AbCdEfGhIjKlMnOpQrStUvWx">Alphabetic opaque token</a>
    <a href="/asset.css">Asset</a>
    <form action="http://example.com/submit"></form>
    <script src="http://cdn.example/app.js"></script>
    <script src="https://cdn.example/vendor.js"></script>`;
  const result = await executeWebScan({
    scope: scannerScope(), target: root, maxPages: 3, maxDepth: 2,
    transport: async (url) => {
      visited.push(url.href);
      return response(url.pathname === "/about" ? "<h1>About</h1>" : body, {
        "access-control-allow-origin": "*",
        "server": "nginx/1.24.0",
      }, {
        cookieFlagCounts: { setCookieCount: 1, secureCount: 0, httpOnlyCount: 0, sameSiteCount: 0 },
      });
    },
  });

  assert.deepEqual(visited, [root, "https://example.com/about"]);
  const findingKeys = result.findings.map((finding) => finding.key);
  for (const key of ["web.content.insecure-form", "web.content.mixed-content", "web.cors.wildcard", "web.cookies.secure", "web.headers.version-banner"]) {
    assert.ok(findingKeys.includes(key), `expected ${key}`);
  }
  const reportText = JSON.stringify(result);
  assert.ok(reportText.includes("[PATH OMITTED]"));
  assert.ok(!reportText.includes("123456789012"));
  assert.ok(!reportText.includes("a1B2c3D4"));
  assert.ok(!reportText.includes("secret-token"));
  assert.ok(!reportText.includes("token=secret"));
  assert.ok(!reportText.includes("<form"));
  const crawl = result.coverage.find((item) => item.key === "web.crawl");
  assert.match(crawl?.details || "", /off-origin/);
  assert.match(crawl?.details || "", /query-string/);
  assert.match(crawl?.details || "", /action-like/);
});

test("honors page and depth budgets and never fetches excluded links", async () => {
  const visited: string[] = [];
  const result = await executeWebScan({
    scope: scannerScope(), target: "https://example.com/", maxPages: 1, maxDepth: 1,
    transport: async (url) => {
      visited.push(url.href);
      return response('<a href="/second">Next</a>');
    },
  });
  assert.deepEqual(visited, ["https://example.com/"]);
  assert.match(result.coverage.find((item) => item.key === "web.execution")?.details || "", /page budget/);
  assert.equal(result.cancelled, false);
});

test("stops before requesting another page when the total response-byte budget is exhausted", async () => {
  const visited: string[] = [];
  const result = await executeWebScan({
    scope: scannerScope({ maxWebScanBytes: 1024 }),
    target: "https://example.com/",
    maxPages: 5,
    maxDepth: 2,
    transport: async (url) => {
      visited.push(url.href);
      return response('<a href="/second">Next</a>', {}, { bytes: 1024 });
    },
  });
  assert.deepEqual(visited, ["https://example.com/"]);
  assert.match(result.coverage.find((item) => item.key === "web.execution")?.details || "", /total response-byte budget reached/);
});

test("does not treat an empty or partial CSP as a protective policy", async () => {
  const empty = await executeWebScan({
    scope: scannerScope(), target: "https://example.com/", maxPages: 1, maxDepth: 0,
    transport: async () => response("<h1>Page</h1>", { "content-security-policy": "" }),
  });
  assert.ok(empty.findings.some((finding) => finding.key === "web.headers.csp"));

  const partial = await executeWebScan({
    scope: scannerScope(), target: "https://example.com/", maxPages: 1, maxDepth: 0,
    transport: async () => response("<h1>Page</h1>", { "content-security-policy": "style-src 'self'" }),
  });
  assert.ok(partial.findings.some((finding) => finding.key === "web.headers.csp"));
});

test("DNS failures and redirects return incomplete coverage without following targets", async () => {
  let requests = 0;
  const failed = await executeWebScan({
    scope: scannerScope(), target: "https://example.com/",
    transport: async () => { throw new Error("DNS returned a non-public or reserved address; no request was sent."); },
  });
  assert.equal(failed.findings.length, 0);
  assert.equal(failed.coverage.find((item) => item.key === "web.fetch.page-1")?.requestStatus, "not-sent");

  const redirected = await executeWebScan({
    scope: scannerScope(), target: "https://example.com/", maxPages: 2,
    transport: async () => {
      requests += 1;
      return response("", { location: "https://outside.example/private?token=secret" }, { status: 302, bodyStatus: "unavailable", bytes: 0 });
    },
  });
  assert.equal(requests, 1);
  assert.doesNotMatch(JSON.stringify(redirected), /outside\.example|token=secret/);
  assert.equal(redirected.coverage.filter((item) => item.key === "web.fetch.page-1").length, 1);
});

test("cancellation before a request makes no transport call and records an honest cancelled result", async () => {
  const controller = new AbortController();
  controller.abort();
  let calls = 0;
  const result = await executeWebScan({
    scope: scannerScope(), target: "https://example.com/", signal: controller.signal,
    transport: async () => { calls += 1; return response("<h1>Never fetched</h1>"); },
  });
  assert.equal(calls, 0);
  assert.equal(result.cancelled, true);
  assert.equal(result.coverage.find((item) => item.key === "web.execution")?.status, "NOT TESTED");
});

test("cancellation during a request discards a late result and prevents later routes", async () => {
  const controller = new AbortController();
  let calls = 0;
  const result = await executeWebScan({
    scope: scannerScope(), target: "https://example.com/", signal: controller.signal,
    transport: async () => {
      calls += 1;
      controller.abort();
      return response('<a href="/second">Next</a>');
    },
  });
  assert.equal(calls, 1);
  assert.equal(result.cancelled, true);
  assert.equal(result.findings.length, 0);
});
