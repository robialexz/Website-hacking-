# RevenueGuard Lab: 60-second demo video

**Format:** browser-only screen recording with voice-over and English captions  
**Length:** exactly 60 seconds  
**Purpose:** show a truthful local walkthrough: run the vulnerable synthetic fixture, inspect evidence, switch to secure controls, and retest.

## 60-second storyboard

| Time | Screen and exact action | Narration | English on-screen caption |
|---|---|---|---|
| 00:00–00:04 (4s) | Start on the dashboard. Keep the browser address bar visible at `http://127.0.0.1:8765`. No click. | “RevenueGuard Lab is a local security training fixture.” | **RevenueGuard Lab** · Local security training fixture |
| 00:04–00:10 (6s) | In **Demo profile**, choose **Vulnerable examples**. Click **Run local audit** once. | “Choose vulnerable examples, then run the local audit.” | **Synthetic data · loopback-only** |
| 00:10–00:20 (10s) | Wait for the newest entry under **Recent audit runs** to show **complete**. Hold on the summary and findings. In a clean first run, the expected summary is 7/7 checks, 6 confirmed fixture behaviors, and 1 suspected fictional dependency marker. | “Seven fixed checks run against the bundled synthetic app. The summary tracks this fixture, not real sites.” | **Seven fixed checks · one local fixture** |
| 00:20–00:32 (12s) | In **Latest findings**, locate **A synthetic user's record is visible to another user** and click **View evidence →**. Keep the finding detail dialog visible, including expected and observed behavior. | “Open a finding to review expected and observed behavior, evidence, impact, and a suggested fix.” | **Evidence from the synthetic fixture** |
| 00:32–00:38 (6s) | Close the dialog with **×**. Change **Demo profile** to **Secure controls**. Let the profile-switch toast appear, then settle. | “Switching profiles resets the synthetic state.” | **Secure controls · synthetic state reset** |
| 00:38–00:48 (10s) | Click **Retest findings** once. Wait for the newest run to show **complete**. Use a brief edit to skip idle time if needed. | “Retest runs the same checks against the secure controls.” | **Retest the same seven checks** |
| 00:48–00:55 (7s) | Hold on **Coverage checks** and the findings table. In a clean run, show 7/7 coverage and prior confirmed examples marked **FIXED AND RETESTED**. The fictional dependency marker remains suspected. | “A complete retest marks prior confirmed examples fixed only after the expected controls verify.” | **Fix status requires verified controls** |
| 00:55–01:00 (5s) | Click **Scope & safety** in the sidebar. Hold on the loopback origin and the empty public-page list from the checked-in example scope. | “Active checks stay on loopback. Public-page review is separate, uses exact approved URLs, and asks before sending one GET.” | **Active: loopback · public: exact allowlist + per-run confirmation** |

## Capture setup

1. Prepare a separate disposable local copy for recording. Start with no prior `scope.json` or `data/revenueguard.sqlite` so the walkthrough has a clean scope file and run history. On first start, the app creates these local files. Do not clear or replace data in a working copy to prepare the demo.
2. Use Node.js 26 or newer. No `npm install`, API key, database server, or internet connection is needed. Start the app from the project root with `npm start` before recording.
3. Open exactly `http://127.0.0.1:8765` in a clean browser profile. Use a desktop viewport large enough to show the dashboard, close unrelated tabs, and keep the address bar visible. Keep the terminal out of frame.
4. If useful, do a pre-roll health check at `http://127.0.0.1:8765/api/health`; with the checked-in example scope's empty `publicReadOnlyPages`, it should report `bind: "127.0.0.1"`, `externalNetwork: false`, and `dynamicAuditExternalNetwork: false`. Do not include the pre-roll check in the final cut.
5. Confirm the first run finishes before opening a finding. After switching to **Secure controls**, wait for the retest to finish before recording the final result. If coverage is incomplete or the run fails, stop and fix the local setup; do not narrate it as a verified fix.

## Technical and privacy checklist

- [ ] Keep the browser on `127.0.0.1:8765`; this walkthrough uses the empty public-page list from the checked-in example scope.
- [ ] Keep the browser address bar visible so the loopback-only origin is clear.
- [ ] Use only the included synthetic users, records, discount, dependency marker, and in-memory fake file. No real customer data or host files are part of the demo.
- [ ] Do not show `data/revenueguard.sqlite`, `scope.json`, a SQLite viewer, file manager, terminal, browser developer tools, or local filesystem paths. The SQLite file contains local run history and evidence.
- [ ] Use a clean browser profile and hide unrelated tabs, notifications, autofill prompts, bookmarks, and personal account details.
- [ ] Do not add an origin or change any approved pages. The checked-in example scope enables only the synthetic demo and leaves public review disabled; the script makes no outbound requests.
- [ ] Keep capture software, browser extensions, and overlays from introducing external pages or personal information into the recording.
- [ ] If recording policy calls for a disconnected network, prepare the disposable copy first, then disconnect before launching. The app itself needs no internet connection.

## Claims and recording validation

The script is grounded in `README.md`, `public/index.html`, `public/app.js`, `src/server.ts`, `src/audit.ts`, `src/source-review.ts`, `src/public-review.ts`, `src/lab-target.ts`, `src/scope.ts`, and `scope.example.json`. The local UI flow and guardrails are present in code. The expected clean-run result is six confirmed vulnerable fixture behaviors plus one suspected fictional dependency marker; a complete secure-profile retest should verify all seven checks and mark earlier confirmed findings fixed.

That result and the timing have not been validated in a live recording environment. Confirm both during pre-roll. If the first run does not complete with 7/7 coverage, or the secure retest does not complete with verified controls, omit the corresponding claims and resolve the local setup before recording.
