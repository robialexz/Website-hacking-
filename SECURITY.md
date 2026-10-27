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

Run history is stored locally in `data/revenueguard.sqlite`. For `web-scan` jobs, the exact starting path is held in process memory only while the run is queued or active. SQLite stores the origin, aggregate page counts, and normalized check facts; findings and reports omit route paths. Web-scan response bodies and cookie names or values are not retained, and response-header values are reduced to a small set of safe labels before storage. Startup migrates paths saved by earlier web-scan builds. The migration updates active records but cannot erase prior backups or guarantee forensic removal from SQLite journal or free-page copies. Other exact-page workflows may save configured URL paths in job or scope snapshots, and local source reviews may retain file names and evidence needed for their reports. There is no automatic retention period or per-run deletion screen; stop the app and remove the SQLite file to clear active history. Remove configured page URLs separately from local `scope.json`.

## Report a vulnerability

If you find a security defect in RevenueGuard itself, use GitHub's **Report a vulnerability** option if private vulnerability reporting is enabled for the repository. Otherwise, contact the repository owner through their GitHub profile before sharing exploit details publicly.
