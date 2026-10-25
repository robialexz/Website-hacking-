# Getting started

RevenueGuard Lab provides three separate workflows:

- **Local security audit:** fixed, non-destructive checks against the bundled synthetic app at `127.0.0.1:8765`.
- **Approved source review:** read-only pattern checks against explicitly listed JavaScript and TypeScript directories on disk.
- **Public-page review:** bounded observations from one unauthenticated GET to each exact HTTPS page in local `scope.json`. GET requests can still trigger side effects on some sites, so this review is not guaranteed to be read-only.

The dynamic audit never targets public sites. The source review makes no network requests and does not execute project code. The public-page review does not perform vulnerability probes, crawl pages, follow redirects, or send credentials; a GET can still trigger an action on a site.

## Start the lab

Requirements: Node.js 26 or newer. There are no runtime packages to install.

```sh
git clone https://github.com/robialexz/revenueguard-lab.git
cd revenueguard-lab
npm start
```

Open <http://127.0.0.1:8765>. The server listens on loopback only. If the browser cannot connect, check that your local environment permits loopback servers and that port 8765 is available.

## Try the synthetic audit

1. Leave **Demo profile** on **Vulnerable examples** and select **Run local audit**.
2. Open a finding to review the expected behavior, observed response, evidence, and suggested remediation.
3. Switch the profile to **Secure controls** and select **Retest findings**.
4. Open a run report from **Recent audit runs** to view coverage and execution logs.

All records, roles, discount codes, dependency markers, and fake files belong to the disposable fixture. The reports describe that fixture only.

## Review a local source project

The generated `scope.json` enables only `revenueguard-demo`. To opt in to local source review, add `source-review` to `approvedServices`. The source directory list starts with:

```json
"sourceDirectories": ["./src"]
```

To review another project on the same machine, add the exact local source directory to that array. A relative path must remain inside the RevenueGuard project. An absolute path is accepted when it resolves to a directory inside a recognizable local project. The configured directory and each file are checked for symlinks; symlinked entries are skipped.

Restart RevenueGuard Lab after editing `scope.json` so the dashboard and queue reload the scope.

The scanner reads regular `.js`, `.jsx`, `.cjs`, `.mjs`, `.ts`, and `.tsx` files, up to the scope budgets. It skips generated, dependency, hidden, and build output folders. The default caps are 500 files and 2 MB total. If a cap stops the scan, the coverage report marks the result incomplete.

Select **Review approved source**. The four current checks look for:

- `eval()` and `new Function()` calls
- disabled TLS certificate validation
- credential-like literals assigned to secret-shaped names
- non-literal values assigned to `innerHTML` or passed to `insertAdjacentHTML`

Every source match is **Suspected**. Findings include the relative file and line, a redacted code excerpt, a SHA-256 file hash, and a remediation suggestion. These pattern checks can miss issues and produce false positives; validate the surrounding code manually. The app does not patch source files.

## Review an approved public page

The checked-in `scope.example.json` enables only `revenueguard-demo` and leaves `publicReadOnlyPages` empty. To opt in, add `passive-public-review` to `approvedServices` and one or more exact canonical HTTPS page URLs to the local `scope.json`, for example:

```json
"publicReadOnlyPages": ["https://example.com/"]
```

Do not include a query string, fragment, credentials, or a nondefault port. The default budget allows at most four pages and caps each HTML response at 1 MB. Restart the app after editing the scope.

Select **Review approved pages** to make one direct, unauthenticated GET per listed page. The request sends no cookies, authorization, or referrer; it does not follow redirects, fetch assets, parse links for follow-up, submit forms, or retry. DNS answers must all be public addresses, and the connection is pinned to a checked address with TLS verification enabled.

Before every run, the app displays the exact page list and asks you to confirm that you own or have permission to review it and that each URL is safe to request. Some sites attach actions to GET routes, so do not include tokenized or state-changing URLs. The app cannot guarantee that a GET is side-effect-free.

Each report lists the exact pages captured with the job's scope. It stores response status, timing/byte measurements, selected security-header values, and page metadata counts, but not the HTML body or arbitrary response headers. Results are **Suspected** observations about response headers, basic search metadata, or image alt attributes. They are not an active security assessment, a ranking prediction, or a revenue estimate.

## Scope settings

`scope.json` is local and excluded from source control. Its fields describe the exact enabled capabilities:

- `approvedOrigins` and `approvedPathPrefixes` remain literal loopback scope for the synthetic app.
- `approvedServices` starts with only the synthetic demo. Add `source-review` or `passive-public-review` only when you intend to enable those separate capabilities.
- `sourceDirectories` is the source-file allowlist.
- `testAccounts` names only the synthetic fixture identities.
- `approvedCallbacks` must stay empty in this release.
- `publicReadOnlyPages` is the exact HTTPS page allowlist for public-page review; the field name does not guarantee a GET has no side effects.
- `budgets` limits requests, worker concurrency, source files/bytes, public pages/response bytes, and timeouts.
- `resetProcedure` describes the supported synthetic profile reset.

Older generated scope files preserve their existing `approvedServices` list and get safe in-memory defaults for newer budgets and an empty `publicReadOnlyPages` list. Existing origins, paths, and source directories are preserved. Interrupted jobs are marked failed after restart and are not replayed automatically. Restart the app after editing this file.

## Verify changes

```sh
npm test
```

The tests use in-process synthetic fixtures and mocked transports. They do not start the HTTP server or contact external targets.
