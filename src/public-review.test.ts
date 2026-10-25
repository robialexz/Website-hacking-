import assert from "node:assert/strict";
import test from "node:test";

import { executePublicReview, isPublicAddress } from "./public-review.ts";
import type { PublicPageResponse, PublicPageTransport } from "./public-review.ts";
import type { ScopeConfig } from "./scope.ts";

function scope(pages: string[] = ["https://nodbim.com/"]): ScopeConfig {
  return {
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
    publicReadOnlyPages: pages,
    resetProcedure: "POST /api/lab/profile resets synthetic state.",
    budgets: { maxRequestsPerAudit: 32, maxConcurrentAudits: 1, timeoutMs: 2500, maxSourceFiles: 500, maxSourceBytes: 2_000_000, maxPublicPages: 4, maxPublicBytesPerPage: 1_000_000 },
  };
}

test("passive review reads each exact page once and stores no HTML body", async () => {
  const requested: string[] = [];
  const transport: PublicPageTransport = async (url) => {
    requested.push(url.href);
    return {
      status: 200,
      headers: new Headers({
        "content-type": "text/html; charset=utf-8",
        "content-length": "157",
        "strict-transport-security": "max-age=31536000",
      }),
      body: "<title>Useful service</title><meta name='description' content='A useful service'><h1>Useful service</h1><img src='/private-content.jpg'><p>PRIVATE_PAGE_BODY_MARKER</p>",
      bytes: 157,
      elapsedMs: 84,
    };
  };

  const result = await executePublicReview({ scope: scope(), transport });
  assert.deepEqual(requested, ["https://nodbim.com/"]);
  assert.equal(result.coverage.length, 4);
  assert.equal(result.coverage.filter((item) => item.attempted).length, 4);
  assert(result.findings.some((item) => item.key === "public.missing-security-headers"));
  assert(result.findings.some((item) => item.key === "public.images-missing-alt"));
  assert.equal(result.findings.some((item) => item.key === "public.page-metadata"), false);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_PAGE_BODY_MARKER|Useful service|private-content\.jpg/);
});

test("passive review does not follow redirects or disclose Location values", async () => {
  let requestCount = 0;
  const transport: PublicPageTransport = async () => {
    requestCount += 1;
    return {
      status: 302,
      headers: new Headers({ "content-type": "text/html", location: "https://outside.example/private?token=do-not-store" }),
      body: "",
      bytes: 0,
      elapsedMs: 19,
    };
  };

  const result = await executePublicReview({ scope: scope(), transport });
  assert.equal(requestCount, 1);
  assert.equal(result.coverage.find((item) => item.key === "public.metadata.page-1")?.attempted, false);
  assert.doesNotMatch(JSON.stringify(result), /outside\.example|do-not-store|Location/);
});

test("passive review reports DNS or connection failures as incomplete coverage", async () => {
  const failing: PublicPageTransport = async () => { throw new Error("DNS returned a non-public or reserved address; no request was sent."); };
  const result = await executePublicReview({ scope: scope(), transport: failing });
  assert.equal(result.findings.length, 0);
  assert.equal(result.coverage[0].attempted, true);
  assert.equal(result.coverage[0].status, "NOT TESTED");
  assert(result.coverage.slice(1).every((item) => !item.attempted && item.error));
});

test("public address classifier rejects private, reserved, and local ranges", () => {
  for (const address of ["127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "198.18.0.1", "224.0.0.1", "::1", "fc00::1", "fe80::1", "2001:2::1", "2001:20::1", "2001:db8::1", "2002::1", "3fff::1", "::ffff:127.0.0.1"]) {
    assert.equal(isPublicAddress(address), false, `${address} should be rejected`);
  }
  for (const address of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]) {
    assert.equal(isPublicAddress(address), true, `${address} should be accepted`);
  }
});
