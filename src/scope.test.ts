import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mock, test } from "node:test";

import { assertInScope, loadScopeConfig, scopedFetch } from "./scope.ts";
import type { ScopeConfig } from "./scope.ts";

function scope(overrides: Partial<ScopeConfig> = {}): ScopeConfig {
  return {
    mode: "laboratory",
    approvedOrigins: ["http://127.0.0.1:8765"],
    approvedPathPrefixes: ["/lab/"],
    budgets: { maxRequestsPerAudit: 32, maxConcurrentAudits: 1, timeoutMs: 2500 },
    ...overrides,
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
    assert.equal(loaded.budgets.maxRequestsPerAudit, 32);
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
