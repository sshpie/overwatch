**Overwatch** (https://github.com/sshpie/overwatch) is a passive web-application security assessment tool. It attaches to a real, already-authenticated browser session and analyzes the traffic the user generates—without sending any of its own requests.

### Core idea
A human logs into a target application in Chrome/Edge (or any Chromium browser) and uses it normally. Overwatch rides that session via the Chrome DevTools Protocol (CDP), reads response bodies from the browser’s cache, runs a fixed taxonomy of detectors, and surfaces security-relevant findings (wildcard entitlements, leaked credentials/PII, misconfigurations, etc.). From the server’s perspective it is indistinguishable from ordinary user traffic because it *is* that traffic.

### Claude Code integration (“live” mode)
The primary live workflow uses **Claude Code** + the `chrome-devtools` MCP:

1. Launch the browser with remote debugging enabled:
   ```bash
   google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/ow-profile
   ```
2. Log in and browse the authorized target.
3. Point a Claude Code session at the debugging port (`http://127.0.0.1:9222`) and instruct it to watch the session and call out vulnerabilities as you browse.

Claude Code observes the real authenticated traffic in real time and reports findings. No extra requests are ever issued.

### Packaged CLI mode (no AI required)
The same detector logic is available as a standalone `overwatch` command that connects to the same debugging port, captures exchanges, runs the detectors, deduplicates, severity-sorts, redacts sensitive data, and outputs a report (text or JSON). It also supports offline analysis of HAR files.

### Key technical points
- **Zero outbound requests** of its own — pure observation via CDP (`Network.enable` + `Network.getResponseBody` on `loadingFinished` events).
- Detectors are pure functions over request/response “Exchange” objects (examples: wildcard entitlements, AI reasoning/tool-schema leaks, PII to third parties, wildcard CORS, JWT exposure, IDOR-style UUIDs in paths, etc.).
- Automatic redaction of credentials, JWTs, cookies, etc.
- Findings are treated as *candidates*, not confirmed exploits.
- Core (HAR scanning) needs only the Python standard library; live mode adds a WebSocket client.

### Ethical / practical constraints emphasized in the repo
- Scope is strictly user-defined and limited to applications the operator is authorized to assess.
- No active probing, no crafted payloads, no risk of write/delete/DoS side-effects.
- Credentials are redacted in all outputs.

In short, Overwatch turns a normal authenticated browser session (driven by a human, optionally observed/analyzed by Claude Code) into a passive “security dashcam.” It is not an active scanner or autonomous pentester; it only reports what the real application traffic already reveals.

### Screenshots
One authorized session on an enterprise O'Reilly Learning account. Credentials and the account UUID are boxed out in the first frame.

![Capturing a response body over CDP](docs/img/01-cdp-capture.png)
![Findings surfaced from the AI Answers endpoint](docs/img/02-answers-ai-findings.png)
![Verify-only discipline and the positive controls](docs/img/03-entitlement-and-verify-only.png)
![Critical: client-controlled royalty attribution](docs/img/04-critical-royalty-attribution.png)
