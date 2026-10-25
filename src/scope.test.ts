import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mock, test } from "node:test";

import { assertInScope, assertPublicPageInScope, loadScopeConfig, scopedFetch } from "./scope.ts";
import type { ScopeConfig } from "./scope.ts";

function scope(overrides: Omit<Partial<ScopeConfig>, "budgets"> & { budgets?: Partial<ScopeConfig["budgets"]> } = {}): ScopeConfig {
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
    publicReadOnlyPages: [],
    resetProcedure: "POST /api/lab/profile resets synthetic state.",
    ...overrides,
    budgets: {
      maxRequestsPerAudit: 32,
      maxConcurrentAudits: 1,
      timeoutMs: 2500,
      maxSourceFiles: 500,
      maxSourceBytes: 2_000_000,
      maxPublicPages: 4,
      maxPublicBytesPerPage: 1_000_000,
      ...overrides.budgets,
    },
  };
}

function withScopeFile(value: unknown, run: (path: string) => void): void {
  const directory = mkdtempSync(join(tmpdir(), "revenueguard-scope-"));
  const path = join(directory, "scope.json");
  try {
    writeFileSync(path, JSON.stringify(value));
    run(path);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test("loads a strict laboratory scope and rejects public or malformed origins", () => {
  withScopeFile(scope(), (path) => {
    const loaded = loadScopeConfig(path);
    assert.equal(loaded.mode, "laboratory");
    assert.deepEqual(loaded.approvedOrigins, ["http://127.0.0.1:8765"]);
    assert.deepEqual(loaded.approvedPathPrefixes, ["/lab/"]);
    assert.deepEqual(loaded.sourceDirectories, ["./src"]);
    assert.equal(loaded.budgets.maxRequestsPerAudit, 32);
    assert.equal(loaded.budgets.maxSourceFiles, 500);
  });
  withScopeFile(scope({ approvedServices: ["revenueguard-demo"] }), (path) => {
    assert.deepEqual(loadScopeConfig(path).approvedServices, ["revenueguard-demo"]);
  });
  withScopeFile(scope({ approvedServices: ["revenueguard-demo", "unknown-review"] }), (path) => {
    assert.throws(() => loadScopeConfig(path), /approvedServices/i);
  });

  for (const origin of [
    "https://127.0.0.1:8765",
    "http://example.com:8765",
    "http://127.0.0.1",
    "http://user:pass@127.0.0.1:8765",
    "http://127.0.0.1:65536",
  ]) {
    withScopeFile(scope({ approvedOrigins: [origin] }), (path) => {
      assert.throws(() => loadScopeConfig(path), /origin|loopback|port|protocol/i);
    });
  }
  withScopeFile(scope({ mode: "production" as "laboratory" }), (path) => {
    assert.throws(() => loadScopeConfig(path), /laboratory/i);
  });

  for (const sourceDirectory of ["../outside", "/", "./src/../../outside", "src\\..\\outside"]) {
    withScopeFile(scope({ sourceDirectories: [sourceDirectory] }), (path) => {
      assert.throws(() => loadScopeConfig(path), /sourceDirectories/i);
    });
  }
  withScopeFile(scope({ sourceDirectories: ["/tmp/approved-project/src"] }), (path) => {
    assert.deepEqual(loadScopeConfig(path).sourceDirectories, ["/tmp/approved-project/src"]);
  });

  withScopeFile(scope({ approvedCallbacks: ["https://example.com/callback"] }), (path) => {
    assert.throws(() => loadScopeConfig(path), /callback integrations are not supported/i);
  });
  for (const page of ["http://nodbim.com/", "https://127.0.0.1/", "https://[2606:4700:4700::1111]/", "https://internal/", "https://nodbim.com:8443/", "https://nodbim.com/?token=secret", "https://user:pass@nodbim.com/"]) {
    withScopeFile(scope({ publicReadOnlyPages: [page] }), (path) => {
      assert.throws(() => loadScopeConfig(path), /publicReadOnlyPages/i);
    });
  }
  withScopeFile(scope({ publicReadOnlyPages: ["https://nodbim.com/"] }), (path) => {
    assert.deepEqual(loadScopeConfig(path).publicReadOnlyPages, ["https://nodbim.com/"]);
  });

  withScopeFile(scope({ budgets: { maxRequestsPerAudit: 32, maxConcurrentAudits: 2, timeoutMs: 2500, maxSourceFiles: 500, maxSourceBytes: 2_000_000 } }), (path) => {
    assert.throws(() => loadScopeConfig(path), /maxConcurrentAudits/i);
  });

  const legacy: Record<string, unknown> = {
    ...scope(),
    approvedServices: ["revenueguard-demo"],
    budgets: { maxRequestsPerAudit: 32, maxConcurrentAudits: 1, timeoutMs: 2500 },
  };
  delete legacy.publicReadOnlyPages;
  withScopeFile(legacy, (path) => {
    const loaded = loadScopeConfig(path);
    assert.deepEqual(loaded.approvedServices, ["revenueguard-demo"]);
    assert.equal(loaded.budgets.maxSourceFiles, 500);
    assert.equal(loaded.budgets.maxSourceBytes, 2_000_000);
    assert.deepEqual(loaded.publicReadOnlyPages, []);
    assert.equal(loaded.budgets.maxPublicPages, 4);
  });

  const legacyWithSource: Record<string, unknown> = {
    ...scope(),
    approvedServices: ["revenueguard-demo", "source-review"],
    budgets: { maxRequestsPerAudit: 32, maxConcurrentAudits: 1, timeoutMs: 2500 },
  };
  delete legacyWithSource.publicReadOnlyPages;
  withScopeFile(legacyWithSource, (path) => {
    assert.deepEqual(loadScopeConfig(path).approvedServices, ["revenueguard-demo", "source-review"]);
  });
});

test("assertInScope permits exact configured loopback origins and approved paths only", () => {
  const config = scope({ approvedOrigins: ["http://127.0.0.1:8765", "http://[::1]:9876"] });
  assert.doesNotThrow(() => assertInScope("http://127.0.0.1:8765/lab/report", config));
  assert.doesNotThrow(() => assertInScope("http://[::1]:9876/lab/report", config));
  for (const url of [
    "https://127.0.0.1:8765/lab/report",
    "http://127.0.0.1/lab/report",
    "http://127.0.0.1:8766/lab/report",
    "http://127.0.0.1:8765/laboratory/report",
    "http://127.0.0.1:8765.evil.example/lab/report",
    "http://user:pass@127.0.0.1:8765/lab/report",
    "http://192.168.0.1:8765/lab/report",
    "http://127.0.0.1:8765/lab/%2e%2e/api/session",
  ]) {
    assert.throws(() => assertInScope(url, config), /scope|origin|credential|port|protocol|path/i);
  }
});

test("passive public scope requires an exact canonical configured page", () => {
  const config = scope({ publicReadOnlyPages: ["https://nodbim.com/"] });
  assert.equal(assertPublicPageInScope("https://nodbim.com/", config).href, "https://nodbim.com/");
  for (const page of ["https://nodbim.com/about", "https://other.example/", "https://nodbim.com/?source=test"]) {
    assert.throws(() => assertPublicPageInScope(page, config), /publicReadOnlyPages|scope/i);
  }
});

test("scopedFetch returns status, headers, and text from an in-scope response", async (t) => {
  mock.method(globalThis, "fetch", async () => new Response("lab response", {
    status: 201, headers: { "x-lab": "active" },
  }));
  t.after(() => mock.restoreAll());

  const result = await scopedFetch("http://127.0.0.1:8765/lab/report", scope());
  assert.equal(result.status, 201);
  assert.equal(result.headers.get("x-lab"), "active");
  assert.equal(result.text, "lab response");
});

test("scopedFetch counts failed and successful requests against one audit budget", async (t) => {
  const fetchMock = mock.method(globalThis, "fetch", async () => new Response("ok"));
  t.after(() => mock.restoreAll());
  const config = scope({ budgets: { maxRequestsPerAudit: 1, maxConcurrentAudits: 1, timeoutMs: 2500 } });

  await scopedFetch("http://127.0.0.1:8765/lab/first", config);
  await assert.rejects(scopedFetch("http://127.0.0.1:8765/lab/second", config), /budget/i);
  assert.equal(fetchMock.mock.callCount(), 1);
});

test("scopedFetch applies the configured timeout", async (t) => {
  mock.method(globalThis, "fetch", async (_url, init) => new Promise((_resolve, reject) => {
    init?.signal?.addEventListener("abort", () => reject(new Error("aborted by timeout")), { once: true });
  }));
  t.after(() => mock.restoreAll());
  const config = scope({ budgets: { maxRequestsPerAudit: 1, maxConcurrentAudits: 1, timeoutMs: 10 } });

  await assert.rejects(scopedFetch("http://127.0.0.1:8765/lab/slow", config), /timed out/i);
});

test("scopedFetch rejects redirects without making a second request", async (t) => {
  const fetchMock = mock.method(globalThis, "fetch", async () => new Response(null, {
    status: 302, headers: { location: "http://example.com/outside" },
  }));
  t.after(() => mock.restoreAll());

  await assert.rejects(scopedFetch("http://127.0.0.1:8765/lab/redirect", scope()), /redirect destination is outside/i);
  assert.equal(fetchMock.mock.callCount(), 1);
});

test("scopedFetch rejects an explicit follow redirect option before making a request", async (t) => {
  const fetchMock = mock.method(globalThis, "fetch", async () => new Response("should not run"));
  t.after(() => mock.restoreAll());
  await assert.rejects(
    scopedFetch("http://127.0.0.1:8765/lab/redirect", scope(), { redirect: "follow" }),
    /redirects are disabled/i,
  );
  assert.equal(fetchMock.mock.callCount(), 0);
});
