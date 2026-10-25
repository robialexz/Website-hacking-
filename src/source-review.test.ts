import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import test from "node:test";

import { executeSourceReview } from "./source-review.ts";
import type { ScopeConfig } from "./scope.ts";

const scope: ScopeConfig = {
  mode: "laboratory",
  approvedOrigins: ["http://127.0.0.1:8765"],
  approvedPathPrefixes: ["/lab/"],
  approvedServices: ["revenueguard-demo", "source-review", "passive-public-review"],
  sourceDirectories: ["./src"],
  testAccounts: [],
  approvedCallbacks: [],
  publicReadOnlyPages: [],
  resetProcedure: "POST /api/lab/profile resets synthetic state.",
  budgets: { maxRequestsPerAudit: 32, maxConcurrentAudits: 1, timeoutMs: 2500, maxSourceFiles: 500, maxSourceBytes: 2_000_000, maxPublicPages: 4, maxPublicBytesPerPage: 1_000_000 },
};

async function withProject(run: (projectRoot: string) => Promise<void>): Promise<void> {
  const projectRoot = mkdtempSync(join(tmpdir(), "revenueguard-source-"));
  try {
    mkdirSync(join(projectRoot, "src"));
    await run(projectRoot);
  } finally {
    rmSync(projectRoot, { recursive: true, force: true });
  }
}

test("source review reports dynamic evaluation with file and line evidence", async () => {
  await withProject(async (projectRoot) => {
    writeFileSync(join(projectRoot, "src", "handler.ts"), "export function run(input: string) {\n  return eval(input);\n}\n");

    const result = await executeSourceReview({ scope, projectRoot });
    const finding = result.findings.find((item) => item.key === "source.dynamic-evaluation");
    assert.equal(finding?.status, "SUSPECTED");
    assert.equal(finding?.endpoint, "src/handler.ts:2");
    assert.equal(finding?.evidence.source?.line, 2);
    assert.match(finding?.evidence.source?.excerpt || "", /eval\(input\)/);
    assert(result.coverage.length >= 3);
    assert(result.coverage.every((item) => item.attempted));
  });
});

test("source review redacts hard-coded secret values from evidence", async () => {
  await withProject(async (projectRoot) => {
    const secret = ["sk", "live", "1234567890abcdef"].join("_");
    writeFileSync(join(projectRoot, "src", "config.ts"), `const API_KEY = "${secret}";\n`);

    const result = await executeSourceReview({ scope, projectRoot });
    const finding = result.findings.find((item) => item.key === "source.hard-coded-credential");
    assert.equal(finding?.status, "SUSPECTED");
    assert.match(finding?.evidence.source?.excerpt || "", /REDACTED/);
    assert.doesNotMatch(JSON.stringify(finding?.evidence), new RegExp(secret));
  });
});

test("source review redacts unrelated quoted tokens on a matched code line", async () => {
  await withProject(async (projectRoot) => {
    const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature-secret-value";
    const jsonSecret = "unrelated-json-secret-value";
    const commentSecret = "shortsecret1234";
    writeFileSync(join(projectRoot, "src", "handler.ts"), `const result = eval(input); const jwt = "${jwt}"; const config = { token: "${jsonSecret}" }; // api_key=${commentSecret}\n`);

    const result = await executeSourceReview({ scope, projectRoot });
    const finding = result.findings.find((item) => item.key === "source.dynamic-evaluation");
    assert(finding);
    assert.match(String(finding.evidence.source?.excerpt), /REDACTED/);
    assert.doesNotMatch(JSON.stringify(finding.evidence), new RegExp(jwt.replaceAll(".", "\\.")));
    assert.doesNotMatch(JSON.stringify(finding.evidence), new RegExp(jsonSecret));
    assert.doesNotMatch(JSON.stringify(finding.evidence), new RegExp(commentSecret));
  });
});

test("source review redacts the remainder of an unclosed multiline literal", async () => {
  await withProject(async (projectRoot) => {
    const openingSecret = "multiline-short-secret-1234";
    const continuationSecret = "continuation-secret-5678";
    writeFileSync(join(projectRoot, "src", "handler.ts"), "const result = eval(input); const note = `" + openingSecret + "\n" + continuationSecret + "`; const later = eval(input);\n");

    const result = await executeSourceReview({ scope, projectRoot });
    const findings = result.findings.filter((item) => item.key === "source.dynamic-evaluation");
    assert.equal(findings.length, 2);
    assert.doesNotMatch(JSON.stringify(findings), new RegExp(openingSecret));
    assert.doesNotMatch(JSON.stringify(findings), new RegExp(continuationSecret));
  });
});

test("source review skips comments and does not follow symlinked directories", async () => {
  await withProject(async (projectRoot) => {
    const outside = mkdtempSync(join(tmpdir(), "revenueguard-outside-"));
    try {
      writeFileSync(join(projectRoot, "src", "comment.ts"), "// eval(userInput) is only an example\nexport const safe = true;\n");
      writeFileSync(join(outside, "escaped.ts"), "eval(userInput);\n");
      try {
        await import("node:fs").then(({ symlinkSync }) => symlinkSync(outside, join(projectRoot, "src", "linked"), "dir"));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EPERM") throw error;
      }

      const result = await executeSourceReview({ scope, projectRoot });
      assert.equal(result.findings.some((item) => item.endpoint.includes("comment.ts")), false);
      assert.equal(result.findings.some((item) => item.endpoint.includes("escaped.ts")), false);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });
});

test("source review distinguishes dynamic HTML values from fixed UI markup", async () => {
  await withProject(async (projectRoot) => {
    writeFileSync(join(projectRoot, "src", "view.ts"), [
      'const safe = `<p>${label ? "Ready" : "Idle"}</p>`;',
      'element.innerHTML = active ? "<p>Ready</p>" : "<p>Idle</p>";',
      "element.innerHTML = userInput;",
    ].join("\n"));

    const result = await executeSourceReview({ scope, projectRoot });
    const htmlFindings = result.findings.filter((item) => item.key === "source.dynamic-html-sink");
    assert.equal(htmlFindings.length, 1);
    assert.equal(htmlFindings[0].endpoint, "src/view.ts:3");
  });
});

test("source review accepts an explicitly scoped sibling project directory", async () => {
  await withProject(async (projectRoot) => {
    const external = mkdtempSync(join(dirname(realpathSync(projectRoot)), "revenueguard-external-project-"));
    try {
      mkdirSync(join(external, "src"));
      writeFileSync(join(external, "package.json"), "{}\n");
      writeFileSync(join(external, "src", "route.ts"), "export const value = eval(input);\n");
      const externalScope: ScopeConfig = { ...scope, sourceDirectories: [join(external, "src")] };

      const result = await executeSourceReview({ scope: externalScope, projectRoot });
      const finding = result.findings.find((item) => item.key === "source.dynamic-evaluation");
      assert.equal(finding?.status, "SUSPECTED");
      assert.equal(finding?.endpoint, `${basename(external)}/src/route.ts:1`);
      assert.doesNotMatch(finding?.endpoint || "", /tmp|Users/);
    } finally {
      rmSync(external, { recursive: true, force: true });
    }
  });
});
