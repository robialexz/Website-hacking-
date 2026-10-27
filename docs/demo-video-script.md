# RevenueGuard: 60-second product demo

**Format:** browser screen recording with English narration and captions  
**Length:** 60 seconds  
**Target:** a public HTTPS website the operator owns and has confirmed is safe for unauthenticated GET requests. Do not use a third-party target without written permission.

## Storyboard

| Time | Screen and action | Narration | Caption |
|---|---|---|---|
| 00:00–00:05 | Show the app at `http://127.0.0.1:8765`. Keep the loopback address visible. | “RevenueGuard is a local website security baseline scanner.” | **Local scanner · one operator** |
| 00:05–00:12 | Paste the authorized HTTPS origin and starting page. Keep the domain visible; hide sensitive path segments if needed. | “Choose one website you own or are authorized to review.” | **One authorized HTTPS origin** |
| 00:12–00:20 | Show page/depth controls and the displayed request, duration, timeout, byte, and delay limits. Check both attestations. | “Review the scan limits and confirm authorization and safe GET requests for this run.” | **Bounded · unauthenticated · same-origin** |
| 00:20–00:30 | Start the scan. Show the active progress state and Stop control while the scan runs. | “The crawler follows eligible same-origin links and can be stopped while it runs.” | **No login · no form submissions · no payloads** |
| 00:30–00:43 | Show the completed run, a few findings, and the coverage summary. Do not imply every category will always produce a finding. | “Review observations alongside coverage, skipped routes, and any limits that stopped the run.” | **Evidence and coverage for this run** |
| 00:43–00:54 | Open the technical report. Hold on target origin, scope note, findings, and coverage. | “The report explains what RevenueGuard checked and what it did not test.” | **A baseline scan is not a full security verdict** |
| 00:54–01:00 | Return to dashboard and show local-only status. | “RevenueGuard runs locally and keeps scan history on this machine.” | **Local-first · authorized testing only** |

## Capture checklist

1. Use a disposable RevenueGuard copy with Node.js 24.15 or newer. Run `npm start` from the project directory and open `http://127.0.0.1:8765`.
2. Choose only a site you own or have explicit permission to assess, and confirm the selected routes are safe for unauthenticated GET requests. Exclude tokenized or state-changing paths.
3. Verify the displayed budgets before recording. Do not raise them just to make the capture look more impressive.
4. Keep the loopback app address visible. Hide personal browser data, notifications, credentials, local filesystem paths, and sensitive target paths.
5. Narrate only the findings and coverage actually shown. Empty results, partial coverage, or a cancelled scan must not be described as proof that a website is secure.
6. If the scan fails or produces incomplete coverage, stop the recording and correct the test setup before capturing a new take.

## Product limits to state

The demo shows selected response-header checks, TLS certificate/hostname validation, cookie attribute counts, wildcard CORS observations, version banners, mixed content, form destinations, and external SRI markers. It does not log in, test access control or injection, follow redirects, execute JavaScript, submit forms, or prove a site secure. The app is local and single-operator; it is not a hosted multi-user service.
