import { createHash } from "node:crypto";
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { basename, dirname, extname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";

import type { AuditEvidence, AuditFinding, AuditResult, CoverageItem, Severity } from "./audit.ts";
import type { ScopeConfig } from "./scope.ts";

export const SOURCE_REVIEW_CHECK_COUNT = 4;

interface SourceReviewOptions {
  scope: ScopeConfig;
  projectRoot: string;
}

interface SourceFile {
  relativePath: string;
  content: string;
  sha256: string;
}

interface ApprovedSourceRoot {
  directory: string;
  label: string;
}

interface CollectionResult {
  files: SourceFile[];
  truncated: boolean;
}

interface Rule {
  key: string;
  label: string;
  pattern: RegExp;
  title: string;
  category: string;
  severity: Severity;
  confidence: "High" | "Medium" | "Low";
  expected: string;
  impact: string;
  severityRationale: string;
  remediation: string;
}

const SOURCE_EXTENSIONS = new Set([".cjs", ".js", ".jsx", ".mjs", ".ts", ".tsx"]);
const SKIPPED_DIRECTORIES = new Set([".git", ".next", ".nuxt", "build", "coverage", "dist", "generated", "node_modules", "vendor"]);
const RULES: readonly Rule[] = [
  {
    key: "source.dynamic-evaluation",
    label: "Dynamic code evaluation",
    pattern: /\b(?:eval\s*\(|new\s+Function\s*\()/,
    title: "Source contains a dynamic code evaluation call",
    category: "Unsafe code construction",
    severity: "High",
    confidence: "Medium",
    expected: "Application input should not be interpreted as executable source code.",
    impact: "If attacker-controlled data reaches this call, it may execute with the application's privileges.",
    severityRationale: "The pattern is sensitive, but static matching cannot establish whether its argument is attacker controlled or reachable.",
    remediation: "Remove dynamic evaluation. Replace it with explicit parsing, fixed dispatch tables, or a constrained expression parser.",
  },
  {
    key: "source.disabled-tls-validation",
    label: "TLS certificate validation disabled",
    pattern: /(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0\b)/,
    title: "Source appears to disable TLS certificate validation",
    category: "Transport security",
    severity: "High",
    confidence: "High",
    expected: "TLS clients should verify the remote certificate chain and hostname.",
    impact: "A client that skips certificate validation may accept an intercepted or impersonated server.",
    severityRationale: "The configuration pattern directly disables a security control; runtime reachability and environment are not established.",
    remediation: "Remove the override and configure a trusted certificate chain. Keep certificate verification enabled in tests and production.",
  },
  {
    key: "source.hard-coded-credential",
    label: "Credential-like value in source",
    pattern: /\b(?:api[_-]?key|client[_-]?secret|password|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*["'`][^"'`]{16,}["'`]/i,
    title: "Source contains a credential-like hard-coded value",
    category: "Secrets management",
    severity: "High",
    confidence: "Medium",
    expected: "Credentials should be injected from a secret store or environment at runtime.",
    impact: "A genuine credential committed to source may be copied, reused, or exposed with the repository.",
    severityRationale: "The value is redacted from evidence and could be a placeholder; verify whether it is a live credential.",
    remediation: "Move the value to a secret manager, rotate it if it was real, and remove it from source history where appropriate.",
  },
  {
    key: "source.dynamic-html-sink",
    label: "Dynamic HTML insertion",
    pattern: /\.innerHTML\s*=|\.insertAdjacentHTML\s*\(/,
    title: "Source appears to insert a non-literal value as HTML",
    category: "Browser input handling",
    severity: "Medium",
    confidence: "Low",
    expected: "Untrusted values should be inserted as text or encoded for the exact HTML context.",
    impact: "If the inserted value is attacker controlled, it may create script-capable markup in a browser context.",
    severityRationale: "The source pattern is heuristic; static analysis does not prove that the value is untrusted or executes in a browser.",
    remediation: "Prefer textContent or DOM node construction. If HTML is required, use a vetted sanitizer and enforce a restrictive Content Security Policy.",
  },
];

function pathInside(parent: string, child: string): boolean {
  const path = relative(parent, child);
  return path !== "" && path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path);
}

function containsSymlink(path: string): boolean {
  const parsed = parse(path);
  let current = parsed.root;
  for (const segment of relative(parsed.root, path).split(sep).filter(Boolean)) {
    current = join(current, segment);
    if (lstatSync(current).isSymbolicLink()) return true;
  }
  return false;
}

function safeProjectDirectory(projectRoot: string, sourceDirectory: string): ApprovedSourceRoot {
  const root = realpathSync(projectRoot);
  const candidate = isAbsolute(sourceDirectory) ? resolve(sourceDirectory) : resolve(root, sourceDirectory);
  const insideProject = pathInside(root, candidate);
  if (!insideProject && !isAbsolute(sourceDirectory)) throw new Error(`Approved source directory is outside the project: ${sourceDirectory}`);
  if (containsSymlink(candidate)) throw new Error(`Approved source directory contains a symlink: ${sourceDirectory}`);
  const stats = lstatSync(candidate);
  if (!stats.isDirectory()) throw new Error(`Approved source path is not a directory: ${sourceDirectory}`);
  const resolved = realpathSync(candidate);
  if (insideProject && !pathInside(root, resolved)) throw new Error(`Approved source directory resolves outside the project: ${sourceDirectory}`);

  let label = relative(root, resolved).split(sep).join("/");
  if (!insideProject) {
    let projectDirectory = resolved;
    let hasProjectMarker = false;
    for (let depth = 0; depth < 8; depth += 1) {
      if (["package.json", "pyproject.toml", "Cargo.toml", "go.mod", "composer.json", ".git"].some((marker) => existsSync(join(projectDirectory, marker)))) {
        hasProjectMarker = true;
        break;
      }
      const parent = dirname(projectDirectory);
      if (parent === projectDirectory) break;
      projectDirectory = parent;
    }
    if (!hasProjectMarker) throw new Error(`Approved external source directory is not inside a recognizable local project: ${sourceDirectory}`);
    const sourceSuffix = relative(projectDirectory, resolved).split(sep).join("/");
    label = [basename(projectDirectory), sourceSuffix].filter(Boolean).join("/");
  }
  return { directory: resolved, label };
}

function collectFiles(scope: ScopeConfig, projectRoot: string): CollectionResult {
  const root = realpathSync(projectRoot);
  const files: SourceFile[] = [];
  let totalBytes = 0;
  let truncated = false;

  const visit = (directory: string, approvedRoot: ApprovedSourceRoot, depth: number): void => {
    if (truncated) return;
    if (depth > 12) { truncated = true; return; }
    const entries = readdirSync(directory, { withFileTypes: true }).sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (truncated) return;
      if (entry.isSymbolicLink()) continue;
      const absolutePath = join(directory, entry.name);
      if (entry.isDirectory()) {
        if (!SKIPPED_DIRECTORIES.has(entry.name) && !entry.name.startsWith(".")) visit(absolutePath, approvedRoot, depth + 1);
        continue;
      }
      if (!entry.isFile() || !SOURCE_EXTENSIONS.has(extname(entry.name).toLowerCase())) continue;

      const stats = lstatSync(absolutePath);
      if (stats.isSymbolicLink() || !stats.isFile()) continue;
      if (stats.size > scope.budgets.maxSourceBytes || totalBytes + stats.size > scope.budgets.maxSourceBytes || files.length >= scope.budgets.maxSourceFiles) {
        truncated = true;
        return;
      }

      const content = readFileSync(absolutePath, "utf8");
      totalBytes += stats.size;
      const pathFromSourceRoot = relative(approvedRoot.directory, absolutePath).split(sep).join("/");
      const filePath = pathInside(root, absolutePath)
        ? relative(root, absolutePath).split(sep).join("/")
        : `${approvedRoot.label}/${pathFromSourceRoot}`;
      if (!pathInside(approvedRoot.directory, absolutePath)) continue;
      files.push({
        relativePath: filePath,
        content,
        sha256: createHash("sha256").update(content).digest("hex"),
      });
    }
  };

  for (const sourceDirectory of scope.sourceDirectories) {
    const approvedRoot = safeProjectDirectory(root, sourceDirectory);
    visit(approvedRoot.directory, approvedRoot, 0);
    if (truncated) break;
  }
  return { files, truncated };
}

function maskCodeLine(line: string, lexicalState: { active: boolean; quote: string | null }): string {
  const chars = [...line];
  let index = 0;
  while (index < chars.length) {
    if (lexicalState.active) {
      if (chars[index] === "*" && chars[index + 1] === "/") {
        chars[index] = " ";
        chars[index + 1] = " ";
        index += 2;
        lexicalState.active = false;
      } else {
        chars[index] = " ";
        index += 1;
      }
      continue;
    }

    if (lexicalState.quote !== null) {
      const quote = lexicalState.quote;
      if (chars[index] === "\\") {
        chars[index] = " ";
        if (index + 1 < chars.length) chars[index + 1] = " ";
        index += 2;
        continue;
      }
      const closes = chars[index] === quote;
      chars[index] = " ";
      index += 1;
      if (closes) lexicalState.quote = null;
      continue;
    }

    if (chars[index] === "/" && chars[index + 1] === "/") {
      for (let rest = index; rest < chars.length; rest += 1) chars[rest] = " ";
      break;
    }
    if (chars[index] === "/" && chars[index + 1] === "*") {
      chars[index] = " ";
      chars[index + 1] = " ";
      index += 2;
      lexicalState.active = true;
      continue;
    }

    const quote = chars[index];
    if (quote === "'" || quote === "\"" || quote === "`") {
      lexicalState.quote = quote;
      chars[index] = " ";
      index += 1;
      continue;
    }

    if (chars[index] === "/" && /[=(:,\[{!]\s*$/.test(chars.slice(0, index).join(""))) {
      let end = index + 1;
      let inCharacterClass = false;
      while (end < chars.length) {
        if (chars[end] === "\\") { end += 2; continue; }
        if (chars[end] === "[") inCharacterClass = true;
        if (chars[end] === "]") inCharacterClass = false;
        if (chars[end] === "/" && !inCharacterClass) { end += 1; while (/[a-z]/i.test(chars[end] || "")) end += 1; break; }
        end += 1;
      }
      if (end <= chars.length && chars[end - 1] !== "/") end = index + 1;
      for (let masked = index; masked < end; masked += 1) chars[masked] = " ";
      index = end;
      continue;
    }
    index += 1;
  }
  return chars.join("");
}

function redactSourceExcerpt(line: string): string {
  return line
    // Mask every quoted literal on a finding line; a different rule may have matched
    // the line while an unrelated string on it contains a secret.
    .replace(/"(?:\\.|[^"\\])*(?:"|$)|'(?:\\.|[^'\\])*(?:'|$)|`(?:\\.|[^`\\])*(?:`|$)/g, '"[REDACTED]"')
    .replace(/\/\*.*?\*\//g, " ")
    .replace(/\/\/.*$/, "")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, "Bearer [REDACTED]")
    .replace(/\bsk_(?:live|test)_[A-Za-z0-9_-]{8,}\b/g, "[REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED_TOKEN]")
    .replace(/\b[A-Za-z0-9_-]{32,}\b/g, "[REDACTED_TOKEN]")
    .replace(/\b\d{8,}\b/g, "[REDACTED_NUMBER]")
    .replace(/[ \t]{2,}/g, " [REDACTED] ")
    .slice(0, 240);
}

function matchesRule(rule: Rule, original: string, code: string): boolean {
  if (rule.key === "source.hard-coded-credential") return rule.pattern.test(original);
  if (rule.key !== "source.dynamic-html-sink") return rule.pattern.test(code);
  if (!rule.pattern.test(code)) return false;
  return /\.innerHTML\s*=\s*[$A-Z_a-z][\w$]*(?:\s*\.\s*[$A-Z_a-z][\w$]*)*\s*(?:;|$)/.test(code)
    || /\.innerHTML\s*=\s*[^;\n]*\+\s*[$A-Z_a-z]/.test(code)
    || /\.innerHTML\s*=\s*`[^`]*\$\{/.test(original)
    || /\.insertAdjacentHTML\s*\(\s*["'`]before(?:begin|end|afterbegin|afterend)["'`]\s*,\s*(?:[$A-Z_a-z]|`[^`]*\$\{)/.test(original);
}

function makeFinding(rule: Rule, file: SourceFile, lineNumber: number, codeLine: string): AuditFinding {
  const evidence: AuditEvidence = {
    source: {
      path: file.relativePath,
      line: lineNumber,
      excerpt: redactSourceExcerpt(codeLine.trim()),
      sha256: file.sha256,
    },
    note: "Read-only static pattern match. No source was executed and this does not prove exploitability.",
  };
  return {
    key: rule.key,
    title: rule.title,
    category: rule.category,
    severity: rule.severity,
    status: "SUSPECTED",
    confidence: rule.confidence,
    target: "Approved local source directories",
    endpoint: `${file.relativePath}:${lineNumber}`,
    component: file.relativePath,
    preconditions: "A local source directory was explicitly listed in scope.json.",
    expected: rule.expected,
    actual: `A static source pattern matched at ${file.relativePath}:${lineNumber}. Manual validation is required; no runtime behavior was tested.`,
    reproduction: [
      `Open ${file.relativePath} at line ${lineNumber}.`,
      "Review the surrounding code and data flow to determine whether the pattern is reachable and unsafe.",
    ],
    impact: rule.impact,
    severityRationale: rule.severityRationale,
    remediation: rule.remediation,
    evidence,
    retestStatus: "NOT RETESTED",
  };
}

/** Read only the explicitly approved project-relative source directories. No code is executed and no network request is made. */
export async function executeSourceReview(options: SourceReviewOptions): Promise<AuditResult> {
  const { scope, projectRoot } = options;
  if ((scope.mode !== "laboratory" && scope.mode !== "scanner") || !scope.approvedServices.includes("source-review")) {
    throw new Error('Scope must approve the "source-review" service in scanner mode');
  }

  const collection = collectFiles(scope, projectRoot);
  const findings: AuditFinding[] = [];
  const matches = new Map<string, number>();
  for (const rule of RULES) matches.set(rule.key, 0);

  for (const file of collection.files) {
    const lines = file.content.split(/\r?\n/);
    const lexicalState: { active: boolean; quote: string | null } = { active: false, quote: null };
    for (let index = 0; index < lines.length; index += 1) {
      const original = lines[index];
      const code = maskCodeLine(original, lexicalState);
      if (!code.trim()) continue;
      for (const rule of RULES) {
        if (!matchesRule(rule, original, code)) continue;
        if (rule.key === "source.hard-coded-credential" && /example|placeholder|changeme|dummy|sample|rg_test/i.test(original)) continue;
        matches.set(rule.key, (matches.get(rule.key) || 0) + 1);
        findings.push(makeFinding(rule, file, index + 1, code));
        break;
      }
    }
  }

  const attempted = collection.files.length > 0;
  const budgetNote = collection.truncated ? "Source review stopped when the configured file or byte limit was reached; results are incomplete." : undefined;
  const coverage: CoverageItem[] = RULES.map((rule) => {
    const matched = matches.get(rule.key) || 0;
    return {
      key: rule.key,
      label: rule.label,
      attempted,
      status: !attempted ? "NOT TESTED" : matched > 0 ? "SUSPECTED" : "NOT REPRODUCED",
      controlVerified: false,
      ...(!attempted ? { error: "No supported source files were found in the approved directories." } : {}),
      ...(budgetNote ? { error: budgetNote } : {}),
    };
  });
  return { findings, coverage };
}
