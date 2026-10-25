import assert from "node:assert/strict";
import test from "node:test";

import { executeAudit, isCompleteRetest } from "./audit.ts";
import { createLabState, handleLabRequest } from "./lab-target.ts";
import type { ScopeConfig, ScopedFetchResponse } from "./scope.ts";

const scope: ScopeConfig = {
  mode: "laboratory",
  approvedOrigins: ["http://127.0.0.1:8765"],
  approvedPathPrefixes: ["/lab/"],
  approvedServices: ["revenueguard-demo", "source-review", "passive-public-review"],
  sourceDirectories: ["./src"],
  testAccounts: [
    { name: "alice", role: "user" },
    { name: "bob", role: "user" },
    { name: "admin", role: "admin" },
  ],
  approvedCallbacks: [],
  publicReadOnlyPages: [],
  resetProcedure: "POST /api/lab/profile resets synthetic state.",
  budgets: { maxRequestsPerAudit: 32, maxConcurrentAudits: 1, timeoutMs: 2500, maxSourceFiles: 500, maxSourceBytes: 2_000_000, maxPublicPages: 4, maxPublicBytesPerPage: 1_000_000 },
};

function transportFor(profile: "vulnerable" | "secure") {
  const state = createLabState();
  const requested: string[] = [];
  const transport = async (
    url: string | URL,
    _config: ScopeConfig,
    init: RequestInit = {},
  ): Promise<ScopedFetchResponse> => {
    const target = new URL(url);
    requested.push(`${init.method || "GET"} ${target.pathname}${target.search}`);
    const response = handleLabRequest({
      method: init.method || "GET",
      url: target.href,
      headers: Object.fromEntries(new Headers(init.headers).entries()),
      body: typeof init.body === "string" ? init.body : undefined,
    }, profile, state);
    return { status: response.status, headers: new Headers(response.headers), text: response.body };
  };
  return { transport, requested };
}

test("audit reproduces only the expected synthetic vulnerable behaviors", async () => {
  const { transport, requested } = transportFor("vulnerable");
  const result = await executeAudit({ scope, transport });

  const confirmed = result.findings.filter((finding) => finding.status === "CONFIRMED");
  const suspected = result.findings.filter((finding) => finding.status === "SUSPECTED");
  assert.deepEqual(confirmed.map((finding) => finding.key).sort(), [
    "authz.admin",
    "authz.idor",
    "input.reflected-html",
    "input.search-bypass",
    "logic.coupon-reuse",
    "server.path-traversal",
  ]);
  assert.equal(suspected.length, 1);
  assert.equal(suspected[0].key, "dependency.synthetic-warning");
  assert.equal(result.coverage.length, 7);
  assert.equal(result.coverage.filter((item) => item.attempted).length, 7);
  assert.equal(isCompleteRetest(result), true);
  assert.equal(requested.length, 9);
  assert(requested.every((request) => request.includes("/lab/api/")));
  assert(result.findings.every((finding) => finding.evidence !== undefined));
});

test("secure controls remove confirmed findings while retaining an honest synthetic dependency warning", async () => {
  const { transport } = transportFor("secure");
  const result = await executeAudit({ scope, transport });

  assert.deepEqual(result.findings.map((finding) => finding.key), ["dependency.synthetic-warning"]);
  assert.equal(result.findings[0].status, "SUSPECTED");
  assert(result.coverage.every((item) => item.attempted));
  assert.equal(isCompleteRetest(result), true);
});

test("failed requests are recorded as not reproduced rather than fabricated findings", async () => {
  const transport = async (): Promise<ScopedFetchResponse> => {
    throw new Error("synthetic timeout");
  };
  const result = await executeAudit({ scope, transport });
  assert.equal(result.findings.length, 0);
  assert(result.coverage.every((item) => item.status === "NOT REPRODUCED"));
  assert(result.coverage.every((item) => item.error === "synthetic timeout"));
  assert.equal(isCompleteRetest(result), false);
});

test("HTTP 5xx responses cannot make a secure retest claim findings are fixed", async () => {
  const transport = async (): Promise<ScopedFetchResponse> => ({
    status: 500,
    headers: new Headers({ "content-type": "text/plain" }),
    text: "synthetic server error",
  });
  const result = await executeAudit({ scope, transport });
  assert.equal(result.findings.length, 0);
  assert(result.coverage.every((item) => item.error?.includes("HTTP 500")));
  assert.equal(isCompleteRetest(result), false);
});

