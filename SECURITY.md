# Security policy

RevenueGuard is a local, single-operator website security baseline scanner. It is not a hosted multi-user service. The dashboard listens only on `127.0.0.1:8765`; do not expose it to a network.

## Web scan boundaries

- A run uses one public DNS origin, HTTPS port 443, and unauthenticated GET requests.
- The scanner rejects IP literal targets and private/reserved DNS answers, pins the checked address, validates TLS, and does not follow redirects.
- The crawler stays on the starting origin and enforces page, depth, request, duration, per-request timeout, response-body retention, and pacing limits.
- It skips query-string links, static files, obvious action-like paths, and ambiguous encoded paths. These filters are heuristic and cannot prove a GET route has no side effect.
- The scanner does not send cookies, credentials, payloads, or form submissions and does not execute JavaScript.
- The operator's per-run authorization and safe-GET confirmations are self-attestations, not independent proof of ownership or permission.
- Findings are limited passive observations. No finding does not establish that a site is secure.

## Data handling

Run history is stored locally in `data/revenueguard.sqlite`. It includes the starting URL with its path, timestamps, coverage, findings, and execution logs. Response bodies, cookie names, and cookie values are not retained. Job APIs and reports show the origin and redacted sample paths. There is no automatic retention period or per-run deletion screen; stop the app and remove the SQLite file to clear history. Remove configured page URLs separately from local `scope.json`.

## Report a vulnerability

If you find a security defect in RevenueGuard itself, use GitHub's **Report a vulnerability** option if private vulnerability reporting is enabled for the repository. Otherwise, contact the repository owner through their GitHub profile before sharing exploit details publicly.
