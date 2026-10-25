# Contributing

Thanks for helping improve RevenueGuard Lab. Keep changes consistent with its purpose: a local security learning lab built around synthetic fixtures.

## Set up locally

- Use Node.js 26 or newer.
- Clone the repository and run `npm start` from its root.
- Open http://127.0.0.1:8765 in a browser.
- Run the test suite with `npm test` before opening a pull request.

The project has no third-party runtime dependencies. The server creates ignored local state in `data/` and `scope.json`; do not add either to a commit.

## Contribution guidelines

- Keep audit traffic fixed to the repository's synthetic loopback demo.
- Do not add arbitrary target URLs, public-target discovery, external callbacks, or real-user data.
- Use harmless, deterministic fixture data. Explain clearly when a check is a canary or simulation rather than a verified vulnerability class.
- Preserve evidence redaction, request limits, timeouts, and redirect blocking.
- Add or update tests for behavioral changes, and update the README when user-facing behavior changes.
- Keep the application dependency-free unless maintainers agree to a specific need.

## Pull requests

1. Describe the user-visible change and its safety impact.
2. Include tests for new or changed behavior.
3. Run `npm test` and report the result.
4. Keep changes focused; do not include local database files, scope overrides, secrets, or unrelated formatting changes.

## Reporting a security issue

Please follow [SECURITY.md](SECURITY.md). Do not publish exploit details for a real external system in this repository.

